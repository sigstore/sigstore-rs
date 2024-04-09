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

//! # RSA Key Pair
//!
//! This is a wrapper for Rust Crypto. RSA Key Pair
//! is the struct [`RSAKeys`], which implements [`KeyPair`]
//! trait, and provides different exportation and importation operations
//! from/to der/pem bytes.
//!
//! # RSA Key Pair Operations
//!
//! For example, we generate an RSA key pair and export.
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

use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey, pss::BlindedSigningKey, RsaPrivateKey,
    RsaPublicKey,
};

use crate::{
    crypto::{CosignVerificationKey, SigStoreSigner, SigningScheme},
    errors::*,
};

use crate::crypto::signing_key::{
    kdf, KeyPair, COSIGN_PRIVATE_KEY_PEM_LABEL, PRIVATE_KEY_PEM_LABEL, RSA_PRIVATE_KEY_PEM_LABEL,
    SIGSTORE_PRIVATE_KEY_PEM_LABEL,
};

use super::{DigestAlgorithm, PaddingScheme, RSASigner};

#[derive(Clone, Debug)]
pub struct RSAKeys {
    pub(crate) private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RSAKeys {
    /// Create a new `RSAKeys` Object.
    /// The private key will be randomly
    /// generated.
    pub fn new(bit_size: usize) -> Result<Self> {
        let mut rng = rand::rngs::OsRng {};
        let private_key = RsaPrivateKey::new(&mut rng, bit_size)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create a new `RSAKeys` Object from given `RSAKeys` Object.
    pub fn from_rsa_privatekey_key(key: &RSAKeys) -> Result<Self> {
        let priv_key = key.private_key_to_der()?;
        RSAKeys::from_der(&priv_key)
    }

    /// Builds a `RSAKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                let pkcs8 = pkcs8::PrivateKeyInfo::try_from(&der[..]).map_err(|e| {
                    SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                })?;
                let private_key = RsaPrivateKey::try_from(pkcs8).map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 pem to rsa private key failed: {e}"
                    ))
                })?;
                Ok(Self::from(private_key))
            }

            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `RSAKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`]
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem = std::str::from_utf8(pem)?;
        let (label, document) = pkcs8::SecretDocument::from_pem(pem)
            .map_err(|e| SigstoreError::PKCS8DerError(e.to_string()))?;

        match label {
            PRIVATE_KEY_PEM_LABEL => {
                let pkcs8 = pkcs8::PrivateKeyInfo::try_from(document.as_bytes()).map_err(|e| {
                    SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                })?;
                let private_key = RsaPrivateKey::try_from(pkcs8).map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 pem to rsa private key failed: {e}"
                    ))
                })?;
                Ok(Self::from(private_key))
            }

            RSA_PRIVATE_KEY_PEM_LABEL => {
                let private_key = RsaPrivateKey::from_pkcs1_der(document.as_bytes())?;
                Ok(Self::from(private_key))
            }

            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `RSAKeys` from a pkcs8 asn.1 private key.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der_bytes).map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to rsa private key failed: {e}"
            ))
        })?;
        Ok(Self::from(private_key))
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this rsa key pair.
    pub fn to_sigstore_signer(
        &self,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Result<SigStoreSigner> {
        let private_key = self.private_key.clone();
        Ok(match padding_scheme {
            PaddingScheme::PSS => match digest_algorithm {
                DigestAlgorithm::Sha256 => {
                    SigStoreSigner::RSA_PSS_SHA256(RSASigner::RSA_PSS_SHA256(
                        BlindedSigningKey::<sha2::Sha256>::new(private_key),
                        self.clone(),
                    ))
                }
                DigestAlgorithm::Sha384 => {
                    SigStoreSigner::RSA_PSS_SHA384(RSASigner::RSA_PSS_SHA384(
                        BlindedSigningKey::<sha2::Sha384>::new(private_key),
                        self.clone(),
                    ))
                }
                DigestAlgorithm::Sha512 => {
                    SigStoreSigner::RSA_PSS_SHA512(RSASigner::RSA_PSS_SHA512(
                        BlindedSigningKey::<sha2::Sha512>::new(private_key),
                        self.clone(),
                    ))
                }
            },
            PaddingScheme::PKCS1v15 => match digest_algorithm {
                DigestAlgorithm::Sha256 => {
                    SigStoreSigner::RSA_PKCS1_SHA256(RSASigner::RSA_PKCS1_SHA256(
                        SigningKey::<sha2::Sha256>::new(private_key),
                        self.clone(),
                    ))
                }
                DigestAlgorithm::Sha384 => {
                    SigStoreSigner::RSA_PKCS1_SHA384(RSASigner::RSA_PKCS1_SHA384(
                        SigningKey::<sha2::Sha384>::new(private_key),
                        self.clone(),
                    ))
                }
                DigestAlgorithm::Sha512 => {
                    SigStoreSigner::RSA_PKCS1_SHA512(RSASigner::RSA_PKCS1_SHA512(
                        SigningKey::<sha2::Sha512>::new(private_key),
                        self.clone(),
                    ))
                }
            },
        })
    }
}

impl From<RsaPrivateKey> for RSAKeys {
    fn from(private_key: RsaPrivateKey) -> Self {
        Self {
            private_key: private_key.clone(),
            public_key: RsaPublicKey::from(private_key),
        }
    }
}

impl KeyPair for RSAKeys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        self.public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
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

    /// Return the encrypted asn.1 pkcs8 private key.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<zeroize::Zeroizing<String>> {
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

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<zeroize::Zeroizing<String>> {
        self.private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
    }

    /// Return the private key in asn.1 pkcs8 format.
    fn private_key_to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let pkcs8 = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        Ok(pkcs8.to_bytes())
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        let der = self.public_key_to_der()?;
        let res = CosignVerificationKey::from_der(&der, signing_scheme)?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::crypto::{
        signing_key::{
            rsa::{DigestAlgorithm, PaddingScheme, RSASigner},
            tests::MESSAGE,
            KeyPair, Signer,
        },
        verification_key::CosignVerificationKey,
        Signature, SigningScheme,
    };

    use super::RSAKeys;

    const PASSWORD: &[u8] = b"123";
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
            "can not create RSAKeys from unencrypted PEM file."
        );
    }

    /// This test will try to read an encrypted rsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn rsa_from_encrypted_pem() {
        let content = fs::read("tests/data/keys/rsa_encrypted_private.key")
            .expect("read tests/data/keys/rsa_encrypted_private.key failed.");
        let key = RSAKeys::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_ok(),
            "can not create RSAKeys from encrypted PEM file"
        );
    }

    /// This test will try to encrypt a rsa keypair and
    /// return the pem-encoded contents. The bit size
    /// of the rsa key is [`KEY_SIZE`].
    #[test]
    fn rsa_to_encrypted_pem() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let key = key.private_key_to_encrypted_pem(PASSWORD);
        assert!(
            key.is_ok(),
            "can not export private key in encrypted PEM format."
        );
    }

    /// This test will generate a RSAKeys, encode the private key
    /// it into pem, and decode a new key from the generated pem-encoded
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
    /// it into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn rsa_to_and_from_der() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let key = key
            .private_key_to_der()
            .expect("export private key to DER format failed.");
        let key = RSAKeys::from_der(&key);
        assert!(key.is_ok(), "can not create RSAKeys from DER bytes.")
    }

    /// This test will generate a rsa keypair.
    /// And then use the verification key interface to instantial
    /// a VerificationKey object.
    #[test]
    fn rsa_generate_public_key() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        assert!(CosignVerificationKey::from_pem(
            pubkey.as_bytes(),
            &SigningScheme::RSA_PSS_SHA256(0),
        )
        .is_ok());
        let pubkey = key
            .public_key_to_der()
            .expect("export private key to DER format failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey, &SigningScheme::RSA_PSS_SHA256(0)).is_ok(),
            "can not create CosignVerificationKey from der bytes."
        );
    }

    /// This test will generate a rsa keypair.
    /// And then derive a `CosignVerificationKey` from it.
    #[test]
    fn rsa_derive_verification_key() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed.");
        assert!(
            key.to_verification_key(&SigningScheme::RSA_PSS_SHA256(0))
                .is_ok(),
            "can not create CosignVerificationKey from RSAKeys via `to_verification_key`."
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
            .expect("export private key to PEM format failed.");
        let signer =
            RSASigner::from_rsa_keys(&rsa_keys, DigestAlgorithm::Sha256, PaddingScheme::PSS);

        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("signing message failed.");
        let verification_key =
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::RSA_PSS_SHA256(0))
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
