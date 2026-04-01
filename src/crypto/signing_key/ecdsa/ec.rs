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
//!
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
//! <https://docs.rs/aws-lc-rs/1.14.1/aws_lc_rs/signature/index.html#statics>
//!
//! For example, use `P256` as elliptic curve, and `ECDSA_P256_SHA256_ASN1` as
//! signing scheme
//!
//! ```rust
//! use sigstore::crypto::signing_key::{ecdsa::ec::{EcdsaKeys,EcdsaSigner}, KeyPair, Signer};
//! use aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
//!
//! let ec_key_pair = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
//!
//! // export the pem encoded public key.
//! let pubkey = ec_key_pair.public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ec_key_pair.private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // sign with the new key, using Sha256 as the digest scheme.
//! // In fact, the signing scheme is ECDSA_P256_SHA256_ASN1 here.
//! let ec_signer = EcdsaSigner::from_ecdsa_keys(&ec_key_pair).unwrap();
//!
//! let signature = ec_signer.sign(b"some message");
//! ```

use std::sync::Arc;

use crate::crypto::signing_key::Zeroizing;
use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair as _,
};

use crate::crypto::signing_key::PUBLIC_KEY_PEM_LABEL;
use crate::{
    crypto::{
        SigningScheme,
        signing_key::{
            COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL,
            SIGSTORE_PRIVATE_KEY_PEM_LABEL, Signer, kdf,
        },
        verification_key::CosignVerificationKey,
    },
    errors::*,
};

use super::ECDSAKeys;

#[derive(Clone, Debug)]
pub struct EcdsaKeys {
    // EcdsaKeyPair does not allow cloning. Therefore, use Arc to wrap it and key thread safe.
    key_pair: Arc<EcdsaKeyPair>,
}

impl EcdsaKeys {
    /// Create a new `EcdsaKeys` Object, the signing_algorithm parameter indicates the elliptic
    /// curve to be used. Please refer to
    /// <https://docs.rs/aws-lc-rs/1.14.1/aws_lc_rs/signature/index.html#statics> for supported
    /// curves. The secret key (private key) will be randomly generated.
    pub fn new(signing_algorithm: &'static EcdsaSigningAlgorithm) -> Result<Self> {
        let key_pair = aws_lc_rs::signature::EcdsaKeyPair::generate(signing_algorithm)
            .map_err(|_| SigstoreError::FailedToGenerateEcdsaKeys)?;
        Ok(EcdsaKeys {
            key_pair: Arc::new(key_pair),
        })
    }

    /// Builds a `EcdsaKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(
        private_key: &[u8],
        password: &[u8],
        signing_algorithm: &'static EcdsaSigningAlgorithm,
    ) -> Result<Self> {
        let key = pem::parse(private_key)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(
                    signing_algorithm,
                    &der,
                )
                .map_err(|e| {
                    SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                })?;
                Ok(Self {
                    key_pair: Arc::new(key_pair),
                })
            }
            PRIVATE_KEY_PEM_LABEL if password.is_empty() => {
                Self::from_pem(private_key, signing_algorithm)
            }
            PRIVATE_KEY_PEM_LABEL if !password.is_empty() => {
                Err(SigstoreError::PrivateKeyDecryptError(
                    "Unencrypted private key but password provided".into(),
                ))
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`]
    pub fn from_pem(
        pem_data: &[u8],
        signing_algorithm: &'static EcdsaSigningAlgorithm,
    ) -> Result<Self> {
        let pem_data = std::str::from_utf8(pem_data)?;
        let (label, document) = pkcs8::SecretDocument::from_pem(pem_data)
            .map_err(|e| SigstoreError::PKCS8DerError(e.to_string()))?;
        match label {
            PRIVATE_KEY_PEM_LABEL => {
                let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(
                    signing_algorithm,
                    document.as_bytes(),
                )
                .map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 pem to ecdsa private key failed: {e}"
                    ))
                })?;
                Ok(Self {
                    key_pair: Arc::new(key_pair),
                })
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 asn.1 private key.
    pub fn from_der(
        private_key: &[u8],
        signing_algorithm: &'static EcdsaSigningAlgorithm,
    ) -> Result<Self> {
        let key_pair = aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(
            signing_algorithm,
            private_key,
        )
        .map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ecdsa private key failed: {e}"
            ))
        })?;
        Ok(Self {
            key_pair: Arc::new(key_pair),
        })
    }

    /// Convert the [`EcdsaKeys`] into [`ECDSAKeys`].
    pub fn to_wrapped_ecdsa_keys(&self) -> Result<ECDSAKeys> {
        let priv_key = self.private_key_to_der()?;
        ECDSAKeys::from_der(&priv_key[..])
    }
}

impl KeyPair for EcdsaKeys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        self.key_pair
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
            .map(|der| {
                let pem = pem::Pem::new(PUBLIC_KEY_PEM_LABEL, der.as_ref());
                pem::encode(&pem)
            })
    }

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        self.key_pair
            .private_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
            .map(|der| {
                let pem = pem::Pem::new(PRIVATE_KEY_PEM_LABEL, der.as_ref());
                Zeroizing::new(pem::encode(&pem))
            })
    }

    /// Return the public key in asn.1 SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        self.key_pair
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
            .map(|der| der.as_ref().to_owned())
    }

    /// Return the private key in asn.1 pkcs8 format.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.key_pair
            .private_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
            .map(|der| Zeroizing::new(der.as_ref().to_owned()))
    }

    // /// Return the encrypted private key in PEM-encoded format.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        let der = self.private_key_to_der()?;
        let pem = pem::Pem::new(
            SIGSTORE_PRIVATE_KEY_PEM_LABEL,
            kdf::encrypt(&der, password)?,
        );
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
///
/// The elliptic curve and digest algorithms is defined in the key used by the
/// signer.
///
/// Refer to EcdsaKeys to more details about all supported elliptic curves.
#[allow(deprecated)]
#[derive(Clone, Debug)]
pub struct EcdsaSigner {
    ecdsa_keys: EcdsaKeys,
}

#[allow(deprecated)]
impl EcdsaSigner {
    /// Create a new `EcdsaSigner` from the given `EcdsaKeys` and `SignatureDigestAlgorithm`
    pub fn from_ecdsa_keys(ecdsa_keys: &EcdsaKeys) -> Result<Self> {
        Ok(Self {
            ecdsa_keys: ecdsa_keys.clone(),
        })
    }

    /// Return the ref to the keypair inside the signer
    pub fn ecdsa_keys(&self) -> &EcdsaKeys {
        &self.ecdsa_keys
    }

    /// Returns the digest algorithm according to the elliptic curve of
    /// the ECDSA keypair.
    fn get_digest_algorithm(&self) -> Result<&'static digest::Algorithm> {
        if self.ecdsa_keys.key_pair.algorithm() == &ECDSA_P256_SHA256_ASN1_SIGNING {
            Ok(&digest::SHA256)
        } else if self.ecdsa_keys.key_pair.algorithm() == &ECDSA_P384_SHA384_ASN1_SIGNING {
            Ok(&digest::SHA384)
        } else {
            Err(SigstoreError::UnsupportedAlgorithmError)
        }
    }
}

impl Signer for EcdsaSigner {
    /// Sign the given message, and generate a signature. The message will firstly be hashed with
    /// the given digest algorithm from ECDSA key pair. And then, ECDSA signature algorithm will
    /// sign the digest.
    ///
    /// The outcome digest will be encoded in `asn.1`.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let digest_algorithm = self.get_digest_algorithm()?;
        let digest = digest::digest(digest_algorithm, msg);
        let sig = self
            .ecdsa_keys
            .key_pair
            .sign_digest(&digest)
            .map_err(|_| SigstoreError::FailedToSignError)?;
        Ok(sig.as_ref().to_vec())
    }

    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.ecdsa_keys
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    use rstest::rstest;

    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{KeyPair, Signer, tests::MESSAGE},
        verification_key::CosignVerificationKey,
    };

    use super::{EcdsaKeys, EcdsaSigner};

    const PASSWORD: &[u8] = b"123";
    const EMPTY_PASSWORD: &[u8] = b"";

    /// This test will try to read an unencrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ecdsa_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/ecdsa_private.key")
            .expect("read tests/data/keys/ecdsa_private.key failed.");
        let key = EcdsaKeys::from_pem(&content, &ECDSA_P256_SHA256_ASN1_SIGNING);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from unencrypted PEM file."
        );
    }

    /// This test will try to read an encrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[rstest]
    #[case("tests/data/keys/ecdsa_encrypted_private.key", PASSWORD)]
    #[case::empty_password(
        "tests/data/keys/cosign_generated_encrypted_empty_private.key",
        EMPTY_PASSWORD
    )]
    #[case::empty_password_unencrypted("tests/data/keys/ecdsa_private.key", EMPTY_PASSWORD)]
    fn ecdsa_from_encrypted_pem(#[case] keypath: &str, #[case] password: &[u8]) {
        let content = fs::read(keypath).expect("read key failed.");
        let key =
            EcdsaKeys::from_encrypted_pem(&content, password, &ECDSA_P256_SHA256_ASN1_SIGNING);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from encrypted PEM file"
        );
    }

    /// This test will try to encrypt a ecdsa keypair and
    /// return the pem-encoded contents.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ecdsa_to_encrypted_pem(#[case] password: &[u8]) {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        let key = key.private_key_to_encrypted_pem(password);
        assert!(
            key.is_ok(),
            "can not export private key in encrypted PEM format."
        );
    }

    /// This test will ensure that an unencrypted
    /// keypair will fail to read if a non-empty
    /// password is given.
    #[test]
    fn ecdsa_error_unencrypted_pem_password() {
        let content = fs::read("tests/data/keys/ecdsa_private.key").expect("read key failed.");
        let key =
            EcdsaKeys::from_encrypted_pem(&content, PASSWORD, &ECDSA_P256_SHA256_ASN1_SIGNING);
        assert!(
            key.is_err_and(|e| e
                .to_string()
                .contains("Unencrypted private key but password provided")),
            "read unencrypted key with password"
        );
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// it into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_pem() {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        let key = key
            .private_key_to_pem()
            .expect("export private key to PEM format failed.");
        let key = EcdsaKeys::from_pem(key.as_bytes(), &ECDSA_P256_SHA256_ASN1_SIGNING);
        assert!(key.is_ok(), "can not create EcdsaKeys from PEM string.");
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// it into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ecdsa_to_and_from_encrypted_pem(#[case] password: &[u8]) {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        let key = key
            .private_key_to_encrypted_pem(password)
            .expect("export private key to PEM format failed.");
        let key = EcdsaKeys::from_encrypted_pem(
            key.as_bytes(),
            password,
            &ECDSA_P256_SHA256_ASN1_SIGNING,
        );
        assert!(key.is_ok(), "can not create EcdsaKeys from PEM string.");
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// it into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_der() {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        let key = key
            .private_key_to_der()
            .expect("export private key to DER format failed.");
        let key = EcdsaKeys::from_der(&key, &ECDSA_P256_SHA256_ASN1_SIGNING);
        assert!(key.is_ok(), "can not create EcdsaKeys from DER bytes.")
    }

    /// This test will generate a ecdsa-P256 keypair.
    /// And then use the verification key interface to instantial
    /// a VerificationKey object.
    #[test]
    fn ecdsa_generate_public_key() {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
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
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        assert!(
            key.to_verification_key(&SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `to_verification_key`."
        );
    }

    /// This test will do the following things:
    /// * Generate a ecdsa-P256 keypair.
    /// * Sign the MESSAGE with the private key and digest algorithm SHA256,
    ///   then generate a signature.
    /// * Verify the signature using the public key.
    #[test]
    fn ecdsa_sign_and_verify() {
        let key = EcdsaKeys::new(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("create ecdsa keys with P256 curve failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        let signer =
            EcdsaSigner::from_ecdsa_keys(&key).expect("create EcdsaSigner from ecdsa keys failed.");

        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("signing message failed.");
        let verification_key = CosignVerificationKey::from_pem(
            pubkey.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("convert CosignVerificationKey from public key failed.");
        let signature = Signature::Raw(&sig);
        verification_key
            .verify_signature(signature, MESSAGE.as_bytes())
            .expect("can not verify the signature.");
    }
}
