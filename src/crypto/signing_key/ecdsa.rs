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

//! # ECDSA Key Generation and Signing
//! This is a wrapper for Rust Crypto
//!
//! # Generate EC Key Pair and Export Public & Private Key
//!
//! When to generate an EC key pair, a specific elliptic curve
//! should be chosen. Supported elliptic curves are listed
//! https://github.com/RustCrypto/elliptic-curves#crates.
//!
//! For example, use `P256`
//!
//! ```rust
//! use sigstore::crypto::signing_key::{ecdsa::{EcdsaKeys,EcdsaSigner}, KeyPair, Signer};
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

use std::{convert::TryFrom, marker::PhantomData, ops::Add};

use digest::{
    core_api::BlockSizeUser,
    typenum::{
        bit::{B0, B1},
        UInt, UTerm,
    },
    Digest, FixedOutput, FixedOutputReset,
};
use ecdsa::{hazmat::SignPrimitive, PrimeCurve, SignatureSize, SigningKey};
use elliptic_curve::{
    bigint::ArrayEncoding,
    generic_array::ArrayLength,
    ops::{Invert, Reduce},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::CtOption,
    zeroize::Zeroizing,
    AffineArithmetic, AffinePoint, Curve, FieldSize, ProjectiveArithmetic, PublicKey, Scalar,
    SecretKey,
};
use pkcs8::{der::Encode, AssociatedOid, DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use signature::DigestSigner;
use x509_parser::nom::AsBytes;

use crate::{
    crypto::{CosignVerificationKey, SignatureDigestAlgorithm},
    errors::*,
};

use super::{
    kdf, KeyPair, Signer, COSIGN_PRIVATE_KEY_PEM_LABEL, PRIVATE_KEY_PEM_LABEL,
    SIGSTORE_PRIVATE_KEY_PEM_LABEL,
};

/// The generic parameter for `C` can be chosen from the following:
/// * `p256::NistP256`: `P-256`, also known as `secp256r1` or `prime256v1`.
/// * `p384::NistP384`: `P-384`, also known as `secp384r1`.
///
/// More elliptic curves, please refer to
/// https://github.com/RustCrypto/elliptic-curves#crates.
#[derive(Clone)]
pub struct EcdsaKeys<C>
where
    C: Curve + ProjectiveArithmetic + pkcs8::AssociatedOid,
{
    ec_seckey: SecretKey<C>,
    public_key: PublicKey<C>,
}

impl<C> EcdsaKeys<C>
where
    C: Curve + AssociatedOid + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    /// Create a new `EcdsaKeys` Object, the generic parameter indicates
    /// the elliptic curve. Please refer to
    /// https://github.com/RustCrypto/elliptic-curves#crates for curves.
    /// The secret key (private key) will be randomly
    /// generated.
    pub fn new() -> Result<Self> {
        let ec_seckey: SecretKey<C> = SecretKey::random(rand::rngs::OsRng);

        let public_key = ec_seckey.public_key();
        Ok(EcdsaKeys {
            ec_seckey,
            public_key,
        })
    }

    /// Builds a `EcdsaKeys` from encrypted pkcs8 PEM-encided private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(private_key: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(private_key)?;
        match &key.tag[..] {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(&key.contents, password)?;
                let pkcs8 = pkcs8::PrivateKeyInfo::try_from(&der[..]).map_err(|e| {
                    SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {}", e))
                })?;
                let ec_seckey = SecretKey::<C>::from_sec1_der(pkcs8.private_key)?;
                Self::from_private_key(ec_seckey)
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {}",
                tag
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
                            "Convert from pkcs8 pem to ecdsa private key failed: {}",
                            e
                        ))
                    })?;
                Self::from_private_key(ec_seckey)
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {}",
                tag
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 asn.1 private key.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        let ec_seckey = SecretKey::<C>::from_pkcs8_der(private_key).map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ecdsa private key failed: {}",
                e,
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
}

impl<C> KeyPair for EcdsaKeys<C>
where
    C: Curve + AssociatedOid + ProjectiveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
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
            0 => pem::Pem {
                tag: PRIVATE_KEY_PEM_LABEL.to_string(),
                contents: der
                    .to_vec()
                    .map_err(|e| SigstoreError::PKCS8DerError(e.to_string()))?,
            },
            _ => pem::Pem {
                tag: SIGSTORE_PRIVATE_KEY_PEM_LABEL.to_string(),
                contents: kdf::encrypt(&der, password)?,
            },
        };
        let pem = pem::encode(&pem);
        Ok(zeroize::Zeroizing::new(pem))
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(
        &self,
        signature_digest_algorithm: SignatureDigestAlgorithm,
    ) -> Result<CosignVerificationKey> {
        let pem = self.public_key_to_pem()?;
        CosignVerificationKey::from_pem(pem.as_bytes(), signature_digest_algorithm)
    }
}

/// `EcdsaSigner` is used to generate a ECDSA signature.
/// The generic parameter `C` here can be chosen from
///
/// * `p256::NistP256`: `P-256`, also known as `secp256r1` or `prime256v1`.
/// * `p384::NistP384`: `P-384`, also known as `secp384r1`.
///
/// More elliptic curves, please refer to
/// https://github.com/RustCrypto/elliptic-curves#crates.
///
/// And the parameter `D` indicates the digest algorithm.
///
/// For concrete digest algorithms, please refer to
/// https://github.com/RustCrypto/hashes#supported-algorithms.
#[derive(Clone)]
pub struct EcdsaSigner<C, D>
where
    C: PrimeCurve + ProjectiveArithmetic + AssociatedOid,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    C::UInt: for<'a> From<&'a Scalar<C>>,
    SignatureSize<C>: ArrayLength<u8>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldSize<C>> + FixedOutputReset,
{
    signing_key: SigningKey<C>,
    ecdsa_keys: EcdsaKeys<C>,
    _marker: PhantomData<D>,
}

impl<C, D> EcdsaSigner<C, D>
where
    C: PrimeCurve + ProjectiveArithmetic + AssociatedOid,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
    C::UInt: for<'a> From<&'a Scalar<C>>,
    SignatureSize<C>: ArrayLength<u8>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldSize<C>> + FixedOutputReset,
{
    /// Create a new `EcdsaSigner` from the given `EcdsaKeys` and `SignatureDigestAlgorithm`
    pub fn from_ecdsa_keys(ecdsa_keys: &EcdsaKeys<C>) -> Result<Self> {
        let signing_key =
            ecdsa::SigningKey::<C>::from_pkcs8_der(ecdsa_keys.private_key_to_der()?.as_bytes())
                .map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 der to ecdsa private key failed: {}",
                        e,
                    ))
                })?;

        Ok(Self {
            signing_key,
            ecdsa_keys: ecdsa_keys.clone(),
            _marker: PhantomData,
        })
    }
}

impl<C, D> Signer for EcdsaSigner<C, D>
where
    C: PrimeCurve + ProjectiveArithmetic + AssociatedOid,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + Reduce<C::UInt> + SignPrimitive<C>,
    SigningKey<C>: ecdsa::signature::Signer<ecdsa::Signature<C>>,
    C::UInt: for<'a> From<&'a Scalar<C>>,
    <<<C as Curve>::UInt as ArrayEncoding>::ByteSize as Add>::Output:
        Add<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>>,
    <<<<C as Curve>::UInt as ArrayEncoding>::ByteSize as Add>::Output as Add<
        UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>,
    >>::Output: ArrayLength<u8>,
    SignatureSize<C>: ArrayLength<u8>,
    <<C as Curve>::UInt as ArrayEncoding>::ByteSize: ModulusSize,
    <C as AffineArithmetic>::AffinePoint: ToEncodedPoint<C>,
    <C as AffineArithmetic>::AffinePoint: FromEncodedPoint<C>,
    D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldSize<C>> + FixedOutputReset,
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
        let sig = self.signing_key.try_sign_digest(hasher)?.to_der();

        Ok(sig.as_bytes().to_vec())
    }

    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.ecdsa_keys
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ring::signature::ECDSA_P256_SHA256_ASN1;

    use crate::crypto::{
        signing_key::{tests::MESSAGE, KeyPair, Signer},
        CosignVerificationKey, Signature, SignatureDigestAlgorithm,
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
        assert!(CosignVerificationKey::from_pem(
            pubkey.as_bytes(),
            SignatureDigestAlgorithm::Sha256
        )
        .is_ok());
        let pubkey = key
            .public_key_to_der()
            .expect("export private key to DER format failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey, &ECDSA_P256_SHA256_ASN1).is_ok(),
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
            key.to_verification_key(SignatureDigestAlgorithm::Sha256)
                .is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `to_verification_key`."
        );
        assert!(
            CosignVerificationKey::from_key_pair(&key, SignatureDigestAlgorithm::Sha256).is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `from_key_pair`."
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
        let verification_key =
            CosignVerificationKey::from_pem(pubkey.as_bytes(), SignatureDigestAlgorithm::Sha256)
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
