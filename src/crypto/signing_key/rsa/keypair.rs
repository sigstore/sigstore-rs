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

//! # RSA Key Pair
//!
//! This module provides RSA key pair operations backed by `aws-lc-rs`.
//! [`RSAKeys`] implements the [`KeyPair`] trait and provides import and
//! export operations from/to DER and PEM bytes.
//!
//! Supported key sizes are 2048, 3072, and 4096 bits.
//!
//! # RSA Key Pair Operations
//!
//! For example, we generate an RSA key pair and export:
//!
//! ```rust
//! use sigstore::crypto::signing_key::{rsa::keypair::RSAKeys, KeyPair};
//!
//! let rsa_keys = RSAKeys::new(2048).unwrap();
//!
//! // export the pem encoded public key.
//! let pubkey = rsa_keys.public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey_pem = rsa_keys.private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // import the key pair from the encrypted pem.
//! let rsa_keys2 = RSAKeys::from_encrypted_pem(privkey_pem.as_bytes(), b"password").unwrap();
//! ```

use aws_lc_rs::{
    encoding::AsDer,
    rsa::KeySize,
    signature::{KeyPair as AwsKeyPair, RsaKeyPair},
};

use crate::{
    crypto::{CosignVerificationKey, SigStoreSigner, SigningScheme},
    errors::*,
};

use crate::crypto::signing_key::{
    COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL, RSA_PRIVATE_KEY_PEM_LABEL,
    SIGSTORE_PRIVATE_KEY_PEM_LABEL, kdf,
};

use super::{DigestAlgorithm, PaddingScheme, RSASigner};

fn bit_size_to_key_size(bit_size: usize) -> Result<KeySize> {
    match bit_size {
        2048 => Ok(KeySize::Rsa2048),
        3072 => Ok(KeySize::Rsa3072),
        4096 => Ok(KeySize::Rsa4096),
        other => Err(SigstoreError::InvalidKeyFormat {
            error: format!("Unsupported RSA key size {other}; must be 2048, 3072, or 4096"),
        }),
    }
}

/// An RSA key pair.
#[derive(Clone, Debug)]
pub struct RSAKeys {
    /// PKCS#8 DER-encoded private key.
    pub(super) pkcs8_der: zeroize::Zeroizing<Vec<u8>>,
    /// DER-encoded SubjectPublicKeyInfo.
    spki_der: Vec<u8>,
}

impl RSAKeys {
    /// Create a new `RSAKeys` object.
    /// The private key will be randomly generated.
    /// `bit_size` must be 2048, 3072, or 4096.
    pub fn new(bit_size: usize) -> Result<Self> {
        let key_size = bit_size_to_key_size(bit_size)?;
        let kp = RsaKeyPair::generate(key_size)
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
        let pkcs8 = kp
            .as_der()
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
        let spki = kp
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
        Ok(Self {
            pkcs8_der: zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()),
            spki_der: spki.as_ref().to_vec(),
        })
    }

    /// Builds a `RSAKeys` from a pkcs8 asn.1 private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let kp =
            RsaKeyPair::from_pkcs8(der).map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        let spki = kp
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))?;
        // Validate key size.
        modulus_to_key_size(kp.public_modulus_len())?;
        Ok(Self {
            pkcs8_der: zeroize::Zeroizing::new(der.to_vec()),
            spki_der: spki.as_ref().to_vec(),
        })
    }

    /// Builds a `RSAKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                Self::from_pkcs8_der(&der)
            }
            RSA_PRIVATE_KEY_PEM_LABEL | PRIVATE_KEY_PEM_LABEL if password.is_empty() => {
                Self::from_pem(encrypted_pem)
            }
            RSA_PRIVATE_KEY_PEM_LABEL | PRIVATE_KEY_PEM_LABEL if !password.is_empty() => {
                Err(SigstoreError::PrivateKeyDecryptError(
                    "Unencrypted private key but password provided".into(),
                ))
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `RSAKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`] or
    /// [`RSA_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let key = pem::parse(pem_data)?;
        match key.tag() {
            PRIVATE_KEY_PEM_LABEL => Self::from_pkcs8_der(key.contents()),
            RSA_PRIVATE_KEY_PEM_LABEL => {
                // Traditional PKCS#1 format — aws-lc-rs can import via from_der.
                let kp = RsaKeyPair::from_der(key.contents())
                    .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
                let pkcs8 = kp
                    .as_der()
                    .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
                let spki = kp
                    .public_key()
                    .as_der()
                    .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))?;
                modulus_to_key_size(kp.public_modulus_len())?;
                Ok(Self {
                    pkcs8_der: zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()),
                    spki_der: spki.as_ref().to_vec(),
                })
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `RSAKeys` from a pkcs8 asn.1 private key.
    /// Alias for [`RSAKeys::from_pkcs8_der`].
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(der)
    }

    /// `to_sigstore_signer` will create the [`crate::crypto::SigStoreSigner`] using
    /// this RSA key pair.
    pub fn to_sigstore_signer(
        &self,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Result<SigStoreSigner> {
        let signer = RSASigner::new(self.clone(), digest_algorithm, padding_scheme);
        Ok(match (&signer.digest, &signer.padding) {
            (DigestAlgorithm::Sha256, PaddingScheme::PSS) => SigStoreSigner::RSA_PSS_SHA256(signer),
            (DigestAlgorithm::Sha256, PaddingScheme::PKCS1v15) => {
                SigStoreSigner::RSA_PKCS1_SHA256(signer)
            }
        })
    }
}

/// Validate that the RSA public modulus length (in bytes) is 256, 384, or 512
/// (i.e. 2048, 3072, or 4096 bit key).
fn modulus_to_key_size(modulus_len: usize) -> Result<()> {
    match modulus_len {
        256 | 384 | 512 => Ok(()),
        n => Err(SigstoreError::InvalidKeyFormat {
            error: format!(
                "Unsupported RSA key size {} bits; must be 2048, 3072, or 4096",
                n * 8
            ),
        }),
    }
}

impl KeyPair for RSAKeys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        let pem = pem::Pem::new("PUBLIC KEY", self.spki_der.clone());
        Ok(pem::encode(&pem))
    }

    /// Return the public key in asn.1 SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.spki_der.clone())
    }

    /// Return the encrypted asn.1 pkcs8 private key.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<zeroize::Zeroizing<String>> {
        let encrypted = kdf::encrypt(&self.pkcs8_der, password)?;
        let pem = pem::Pem::new(SIGSTORE_PRIVATE_KEY_PEM_LABEL, encrypted);
        Ok(zeroize::Zeroizing::new(pem::encode(&pem)))
    }

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<zeroize::Zeroizing<String>> {
        let pem = pem::Pem::new(PRIVATE_KEY_PEM_LABEL, self.pkcs8_der.as_slice().to_vec());
        Ok(zeroize::Zeroizing::new(pem::encode(&pem)))
    }

    /// Return the private key in asn.1 pkcs8 format.
    fn private_key_to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    /// Derive the relative [`crate::crypto::CosignVerificationKey`].
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        CosignVerificationKey::from_der(&self.spki_der, signing_scheme)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rstest::rstest;

    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{
            KeyPair, Signer,
            rsa::{DigestAlgorithm, PaddingScheme, RSASigner},
            tests::MESSAGE,
        },
        verification_key::CosignVerificationKey,
    };

    use super::RSAKeys;

    const PASSWORD: &[u8] = b"123";
    const EMPTY_PASSWORD: &[u8] = b"";
    const KEY_SIZE: usize = 2048;

    /// This test will try to read an unencrypted rsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn rsa_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/rsa_private.key")
            .expect("read tests/data/keys/rsa_private.key failed.");
        let key = RSAKeys::from_pem(&content);
        assert!(
            key.is_ok(),
            "can not create RSAKeys from unencrypted PEM: {:?}",
            key
        );
    }

    /// This test will try to read an encrypted rsa
    /// private key file, which is generated by `sigstore`.
    #[rstest]
    #[case("tests/data/keys/rsa_encrypted_private.key", PASSWORD)]
    #[case("tests/data/keys/rsa_private.key", EMPTY_PASSWORD)]
    fn rsa_from_encrypted_pem(#[case] keypath: &str, #[case] password: &[u8]) {
        let content = fs::read(keypath).expect("read key failed.");
        let key = RSAKeys::from_encrypted_pem(&content, password);
        assert!(
            key.is_ok(),
            "can not create RSAKeys from encrypted PEM: {:?}",
            key
        );
    }

    /// This test will try to encrypt a rsa keypair and
    /// return the pem-encoded contents. The bit size
    /// of the rsa key is [`KEY_SIZE`].
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(PASSWORD)]
    fn rsa_to_encrypted_pem(#[case] password: &[u8]) {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
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
    fn rsa_error_unencrypted_pem_password() {
        let content = fs::read("tests/data/keys/rsa_private.key").expect("read key failed.");
        let key = RSAKeys::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_err_and(|e| e
                .to_string()
                .contains("Unencrypted private key but password provided")),
            "read unencrypted key with password"
        );
    }

    /// This test will generate a RSAKeys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn rsa_to_and_from_pem() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let key = key
            .private_key_to_pem()
            .expect("export private key to PEM format failed.");
        let key = RSAKeys::from_pem(key.as_bytes());
        assert!(key.is_ok(), "can not create RSAKeys from PEM string.");
    }

    /// This test will generate a RSAKeys, encode the private key
    /// into encrypted pem, and decode a new key from the generated
    /// pem-encoded private key.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn rsa_to_and_from_encrypted_pem(#[case] password: &[u8]) {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let key = key
            .private_key_to_encrypted_pem(password)
            .expect("export private key to PEM format failed.");
        let key = RSAKeys::from_encrypted_pem(key.as_bytes(), password);
        assert!(key.is_ok(), "can not create RSAKeys from PEM string.");
    }

    /// This test will generate a RSAKeys, encode the private key
    /// into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn rsa_to_and_from_der() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let der = key.private_key_to_der().expect("export to DER failed.");
        assert!(RSAKeys::from_der(&der).is_ok());
    }

    /// This test will generate a rsa keypair.
    /// And then use the verification key interface to instantiate
    /// a [`CosignVerificationKey`] object from both PEM and DER.
    #[test]
    fn rsa_generate_public_key() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let pubkey = key.public_key_to_pem().expect("export public key failed.");
        assert!(
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::RSA_PSS_SHA256(0))
                .is_ok()
        );
        let pubkey = key
            .public_key_to_der()
            .expect("export public key DER failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey, &SigningScheme::RSA_PSS_SHA256(0)).is_ok()
        );
    }

    /// This test will generate a rsa keypair.
    /// And then derive a [`CosignVerificationKey`] from it
    /// using [`crate::crypto::signing_key::KeyPair::to_verification_key`].
    #[test]
    fn rsa_derive_verification_key() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        assert!(
            key.to_verification_key(&SigningScheme::RSA_PSS_SHA256(0))
                .is_ok(),
            "failed to derive verification key from RSAKeys"
        );
    }

    /// This test will do the following things:
    /// * Generate a rsa keypair.
    /// * Sign the MESSAGE with `RSA_PSS_SHA256`
    /// * Verify the signature using the public key.
    #[test]
    fn rsa_sign_and_verify() {
        let rsa_keys = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let pubkey = rsa_keys
            .public_key_to_pem()
            .expect("export public key failed.");
        let signer = RSASigner::new(rsa_keys, DigestAlgorithm::Sha256, PaddingScheme::PSS);
        let sig = signer.sign(MESSAGE.as_bytes()).expect("signing failed.");
        let vk =
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::RSA_PSS_SHA256(0))
                .expect("create verification key failed.");
        assert!(
            vk.verify_signature(Signature::Raw(&sig), MESSAGE.as_bytes())
                .is_ok()
        );
    }
}
