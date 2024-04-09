//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # ECDSA Keys in Generic Types
//!
//! This is a wrapper for Rust Crypto. Basically it
//! is implemented using generic types and traits. Generic types
//! may let the user to manually include concrete crates like
//! `p256`, `p384`, `digest`, etc. This is unfriendly to users.
//! To make it easier for an user to use, there are two wrappers:
//! * The [`EcdsaKeys`] generic struct is wrapped in an enum named [`ECDSAKeys`].
//! * The [`EcdsaSigner`] generic struct is wrapped in an enum named [`super::SigStoreSigner`].
//!
//! The [`ECDSAKeys`] has two enums due to their underlying elliptic curves, s.t.
//! * `P256`
//! * `P384`
//! To have an uniform interface for all kinds of asymmetric keys, [`ECDSAKeys`]
//! is also wrapped in [`super::super::SigStoreKeyPair`] enum.
//!
//! The [`super::SigStoreSigner`] enum includes two enums for [`EcdsaSigner`]:
//! * `ECDSA_P256_SHA256_ASN1`
//! * `ECDSA_P384_SHA384_ASN1`
//!
//! # EC Key Pair Operations
//!
//! *Not recommend to directly use this mod. Use [`ECDSAKeys`], [`super::super::SigStoreKeyPair`] for
//! key pair and [`super::SigStoreSigner`] for signing instead*
//!  
//! When to generate an EC key pair, a specific elliptic curve
//! should be chosen. Supported elliptic curves are listed
//! <https://github.com/RustCrypto/elliptic-curves#crates>.
//!
//! For example, use `P256` as elliptic curve, and `ECDSA_P256_SHA256_ASN1` as
//! signing scheme
//!
//! ```rust
//! use sigstore::crypto::signing_key::{ecdsa::ec::{EcdsaKeys,EcdsaSigner}, KeyPair, Signer};
//!
//! let ec_key_pair = EcdsaKeys::<p256::NistP256>::new().unwrap();
//!
//! // export the pem encoded public key.
//! let pubkey = ec_key_pair.public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ec_key_pair.private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // sign with the new key, using Sha256 as the digest scheme.
//! // In fact, the signing scheme is ECDSA_P256_SHA256_ASN1 here.
//! let ec_signer = EcdsaSigner::<_, sha2::Sha256>::from_ecdsa_keys(&ec_key_pair).unwrap();
//!
//! let signature = ec_signer.sign(b"some message");
//! ```

use std::{marker::PhantomData, ops::Add};

use digest::{
    core_api::BlockSizeUser,
    typenum::{
        bit::{B0, B1},
        UInt, UTerm,
    },
    Digest, FixedOutput, FixedOutputReset,
};
use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    PrimeCurve, SignatureSize, SigningKey,
};
use elliptic_curve::{
    bigint::ArrayEncoding,
    generic_array::ArrayLength,
    ops::{Invert, Reduce},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::CtOption,
    zeroize::Zeroizing,
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey, Scalar, SecretKey,
};
use pkcs8::{AssociatedOid, DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use signature::DigestSigner;

use crate::{
    crypto::{
        signing_key::{
            kdf, KeyPair, Signer, COSIGN_PRIVATE_KEY_PEM_LABEL, PRIVATE_KEY_PEM_LABEL,
            SIGSTORE_PRIVATE_KEY_PEM_LABEL,
        },
        verification_key::CosignVerificationKey,
        SigningScheme,
    },
    errors::*,
};

use super::ECDSAKeys;

/// The generic parameter for `C` can be chosen from the following:
/// * `p256::NistP256`: `P-256`, also known as `secp256r1` or `prime256v1`.
/// * `p384::NistP384`: `P-384`, also known as `secp384r1`.
///
/// More elliptic curves, please refer to
/// <https://github.com/RustCrypto/elliptic-curves#crates>.
#[derive(Clone, Debug)]
pub struct EcdsaKeys<C>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
{
    ec_seckey: SecretKey<C>,
    public_key: PublicKey<C>,
}

impl<C> EcdsaKeys<C>
where
    C: Curve + AssociatedOid + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Create a new `EcdsaKeys` Object, the generic parameter indicates
    /// the elliptic curve. Please refer to
    /// <https://github.com/RustCrypto/elliptic-curves#crates> for curves.
    /// The secret key (private key) will be randomly
    /// generated.
    pub fn new() -> Result<Self> {
        let ec_seckey: SecretKey<C> = SecretKey::random(&mut rand::rngs::OsRng);

        let public_key = ec_seckey.public_key();
        Ok(EcdsaKeys {
            ec_seckey,
            public_key,
        })
    }

    /// Builds a `EcdsaKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(private_key: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(private_key)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                let pkcs8 = pkcs8::PrivateKeyInfo::try_from(&der[..]).map_err(|e| {
                    SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                })?;
                let ec_seckey = SecretKey::<C>::from_sec1_der(pkcs8.private_key)?;
                Self::from_private_key(ec_seckey)
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`]
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let pem_data = std::str::from_utf8(pem_data)?;
        let (label, document) = pkcs8::SecretDocument::from_pem(pem_data)
            .map_err(|e| SigstoreError::PKCS8DerError(e.to_string()))?;
        match label {
            PRIVATE_KEY_PEM_LABEL => {
                let ec_seckey =
                    SecretKey::<C>::from_pkcs8_der(document.as_bytes()).map_err(|e| {
                        SigstoreError::PKCS8Error(format!(
                            "Convert from pkcs8 pem to ecdsa private key failed: {e}"
                        ))
                    })?;
                Self::from_private_key(ec_seckey)
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 asn.1 private key.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        let ec_seckey = SecretKey::<C>::from_pkcs8_der(private_key).map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ecdsa private key failed: {e}"
            ))
        })?;
        Self::from_private_key(ec_seckey)
    }

    /// Builds a `EcdsaKeys` from a private key.
    fn from_private_key(ec_seckey: SecretKey<C>) -> Result<Self> {
        let public_key = ec_seckey.public_key();
        Ok(Self {
            ec_seckey,
            public_key,
        })
    }

    /// Convert the [`EcdsaKeys`] into [`ECDSAKeys`].
    pub fn to_wrapped_ecdsa_keys(&self) -> Result<ECDSAKeys> {
        let priv_key = self.private_key_to_der()?;
        ECDSAKeys::from_der(&priv_key[..])
    }
}

impl<C> KeyPair for EcdsaKeys<C>
where
    C: Curve + AssociatedOid + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        self.public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
    }

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        self.ec_seckey
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
    }

    /// Return the public key in asn.1 SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .public_key
            .to_public_key_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))?
            .to_vec())
    }

    /// Return the private key in asn.1 pkcs8 format.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let pkcs8 = self
            .ec_seckey
            .to_pkcs8_der()
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        Ok(pkcs8.to_bytes())
    }

    /// Return the encrypted private key in PEM-encoded format.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        let der = self.private_key_to_der()?;
        let pem = match password.len() {
            0 => pem::Pem::new(PRIVATE_KEY_PEM_LABEL, der.to_vec()),
            _ => pem::Pem::new(
                SIGSTORE_PRIVATE_KEY_PEM_LABEL,
                kdf::encrypt(&der, password)?,
            ),
        };
        let pem = pem::encode(&pem);
        Ok(zeroize::Zeroizing::new(pem))
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        let pem = self.public_key_to_pem()?;
        CosignVerificationKey::from_pem(pem.as_bytes(), signing_scheme)
    }
}

/// `EcdsaSigner` is used to generate a ECDSA signature.
/// The generic parameter `C` here can be chosen from
///
/// * `p256::NistP256`: `P-256`, also known as `secp256r1` or `prime256v1`.
/// * `p384::NistP384`: `P-384`, also known as `secp384r1`.
///
/// More elliptic curves, please refer to
/// <https://github.com/RustCrypto/elliptic-curves#crates>.
///
/// And the parameter `D` indicates the digest algorithm.
///
/// For concrete digest algorithms, please refer to
/// <https://github.com/RustCrypto/hashes#supported-algorithms>.
#[derive(Clone, Debug)]
pub struct EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::Uint> + SignPrimitive<C>,
    C::Uint: for<'a> From<&'a Scalar<C>>,
    SignatureSize<C>: ArrayLength<u8>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldBytesSize<C>> + FixedOutputReset,
{
    signing_key: SigningKey<C>,
    ecdsa_keys: EcdsaKeys<C>,
    _marker: PhantomData<D>,
}

impl<C, D> EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::Uint> + SignPrimitive<C>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
    C::Uint: for<'a> From<&'a Scalar<C>>,
    SignatureSize<C>: ArrayLength<u8>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldBytesSize<C>> + FixedOutputReset,
{
    /// Create a new `EcdsaSigner` from the given `EcdsaKeys` and `SignatureDigestAlgorithm`
    pub fn from_ecdsa_keys(ecdsa_keys: &EcdsaKeys<C>) -> Result<Self> {
        let signing_key = ecdsa::SigningKey::<C>::from_pkcs8_der(
            &ecdsa_keys.private_key_to_der()?[..],
        )
        .map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ecdsa private key failed: {e}"
            ))
        })?;

        Ok(Self {
            signing_key,
            ecdsa_keys: ecdsa_keys.clone(),
            _marker: PhantomData,
        })
    }

    /// Return the ref to the keypair inside the signer
    pub fn ecdsa_keys(&self) -> &EcdsaKeys<C> {
        &self.ecdsa_keys
    }
}

impl<C, D> Signer for EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::Uint> + SignPrimitive<C>,
    SigningKey<C>: ecdsa::signature::Signer<ecdsa::Signature<C>>,
    C::Uint: for<'a> From<&'a Scalar<C>>,
    <<C as Curve>::FieldBytesSize as Add>::Output:
        Add<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>>,
    <<<C as Curve>::FieldBytesSize as Add>::Output as Add<
        UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>,
    >>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
    <<C as Curve>::Uint as ArrayEncoding>::ByteSize: ModulusSize,
    <C as Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldBytesSize<C>> + FixedOutputReset,
{
    /// Sign the given message, and generate a signature.
    /// The message will firstly be hashed with the given
    /// digest algorithm `D`. And then, ECDSA signature
    /// algorithm will sign the digest.
    ///
    /// The outcome digest will be encoded in `asn.1`.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = D::new();
        digest::Digest::update(&mut hasher, msg);
        let (sig, _recovery_id) = self.signing_key.try_sign_digest(hasher)?;

        Ok(sig.to_der().to_bytes().to_vec())
    }

    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.ecdsa_keys
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::crypto::{
        signing_key::{tests::MESSAGE, KeyPair, Signer},
        verification_key::CosignVerificationKey,
        Signature, SigningScheme,
    };

    use super::{EcdsaKeys, EcdsaSigner};

    const PASSWORD: &[u8] = b"123";

    /// This test will try to read an unencrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ecdsa_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/ecdsa_private.key")
            .expect("read tests/data/keys/ecdsa_private.key failed.");
        let key = EcdsaKeys::<p256::NistP256>::from_pem(&content);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from unencrypted PEM file."
        );
    }

    /// This test will try to read an encrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ecdsa_from_encrypted_pem() {
        let content = fs::read("tests/data/keys/ecdsa_encrypted_private.key")
            .expect("read tests/data/keys/ecdsa_encrypted_private.key failed.");
        let key = EcdsaKeys::<p256::NistP256>::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from encrypted PEM file"
        );
    }

    /// This test will try to encrypt a ecdsa keypair and
    /// return the pem-encoded contents.
    #[test]
    fn ecdsa_to_encrypted_pem() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        let key = key.private_key_to_encrypted_pem(PASSWORD);
        assert!(
            key.is_ok(),
            "can not export private key in encrypted PEM format."
        );
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// it into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_pem() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        let key = key
            .private_key_to_pem()
            .expect("export private key to PEM format failed.");
        let key = EcdsaKeys::<p256::NistP256>::from_pem(key.as_bytes());
        assert!(key.is_ok(), "can not create EcdsaKeys from PEM string.");
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// it into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_der() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        let key = key
            .private_key_to_der()
            .expect("export private key to DER format failed.");
        let key = EcdsaKeys::<p256::NistP256>::from_der(&key);
        assert!(key.is_ok(), "can not create EcdsaKeys from DER bytes.")
    }

    /// This test will generate a ecdsa-P256 keypair.
    /// And then use the verification key interface to instantial
    /// a VerificationKey object.
    #[test]
    fn ecdsa_generate_public_key() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        assert!(
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::default(),).is_ok()
        );
        let pubkey = key
            .public_key_to_der()
            .expect("export private key to DER format failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey, &SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from der bytes."
        );
    }

    /// This test will generate a ecdsa-P256 keypair.
    /// And then derive a `CosignVerificationKey` from it.
    #[test]
    fn ecdsa_derive_verification_key() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        assert!(
            key.to_verification_key(&SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `to_verification_key`."
        );
    }

    /// This test will do the following things:
    /// * Generate a ecdsa-P256 keypair.
    /// * Sign the MESSAGE with the private key and digest algorithm SHA256,
    /// then generate a signature.
    /// * Verify the signature using the public key.
    #[test]
    fn ecdsa_sign_and_verify() {
        let key =
            EcdsaKeys::<p256::NistP256>::new().expect("create ecdsa keys with P256 curve failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        let signer = EcdsaSigner::<_, sha2::Sha256>::from_ecdsa_keys(&key)
            .expect("create EcdsaSigner from ecdsa keys failed.");

        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("signing message failed.");
        let verification_key = CosignVerificationKey::from_pem(
            pubkey.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("convert CosignVerificationKey from public key failed.");
        let signature = Signature::Raw(&sig);
        assert!(
            verification_key
                .verify_signature(signature, MESSAGE.as_bytes())
                .is_ok(),
            "can not verify the signature."
        );
    }
}
