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

//! # Ed25519 Keys
//!
//! This is a wrapper for Rust Crypto. There two main types in this mod:
//! * [`Ed25519Keys`]: provides basic key pair operaions
//! * [`Ed25519Signer`]: provides signing operaion
//!
//! The `signing_key` will wrap [`Ed25519Keys`] into [`super::SigStoreKeyPair`] enum,
//! and [`Ed25519Signer`] into [`SigStoreSigner`] enum.
//!
//! # Ed25519 Key Operaions
//!
//! We give an example for the mod
//! ```rust
//! use sigstore::crypto::signing_key::ed25519::Ed25519Keys;
//! use sigstore::crypto::{signing_key::KeyPair, Signature};
//!
//! // generate a new Ed25519 key pair
//! let ed25519_key_pair = Ed25519Keys::new().unwrap();
//!
//! // export the pem encoded public key.
//! let pubkey = ed25519_key_pair.public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ed25519_key_pair.private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // also, we can import a Ed25519 using functions with the prefix
//! // `Ed25519Keys::from_`. These functions will treat the given
//! // data as Ed25519 private key in PKCS8 format. For example:
//! // let ed25519_key_pair_import = Ed25519Keys::from_pem(PEM_CONTENT).unwrap();
//!
//! // convert this Ed25519 key into an [`super::SigStoreSigner`] enum to sign some data.
//! let ed25519_signer = ed25519_key_pair.to_sigstore_signer().unwrap();
//!
//! // test message to be signed
//! let message = b"some message";
//!
//! // sign using
//! let signature = ed25519_signer.sign(message).unwrap();
//!
//! // export the [`CosignVerificationKey`] from the [`super::SigStoreSigner`], which
//! // is used to verify the signature.
//! let verification_key = ed25519_signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature),message).is_ok());
//! ```

use ed25519::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};

use ed25519::KeypairBytes;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::{
    crypto::{verification_key::CosignVerificationKey, SigningScheme},
    errors::*,
};

use super::{
    kdf, KeyPair, SigStoreSigner, Signer, COSIGN_PRIVATE_KEY_PEM_LABEL, PRIVATE_KEY_PEM_LABEL,
    SIGSTORE_PRIVATE_KEY_PEM_LABEL,
};

#[derive(Debug, Clone)]
pub struct Ed25519Keys {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Keys {
    /// Create a new `Ed25519Keys` Object.
    /// The private key will be randomly
    /// generated.
    pub fn new() -> Result<Self> {
        let mut csprng = rand::rngs::OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a new `Ed25519Keys` Object from given `Ed25519Keys` Object.
    pub fn from_ed25519key(key: &Ed25519Keys) -> Result<Self> {
        let priv_key = key.private_key_to_der()?;
        Ed25519Keys::from_der(&priv_key[..])
    }

    /// Builds a `Ed25519Keys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                let pkcs8 =
                    ed25519_dalek::pkcs8::PrivateKeyInfo::try_from(&der[..]).map_err(|e| {
                        SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                    })?;
                let key_pair_bytes = KeypairBytes::try_from(pkcs8).map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 pem to ed25519 private key failed: {e}"
                    ))
                })?;
                Self::from_key_pair_bytes(key_pair_bytes)
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `Ed25519Keys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`]
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem = std::str::from_utf8(pem)?;
        let (label, document) = pkcs8::SecretDocument::from_pem(pem)
            .map_err(|e| SigstoreError::PKCS8DerError(e.to_string()))?;

        match label {
            PRIVATE_KEY_PEM_LABEL => {
                let pkcs8 = ed25519_dalek::pkcs8::PrivateKeyInfo::try_from(document.as_bytes())
                    .map_err(|e| {
                        SigstoreError::PKCS8Error(format!("Read PrivateKeyInfo failed: {e}"))
                    })?;
                let key_pair_bytes = KeypairBytes::try_from(pkcs8).map_err(|e| {
                    SigstoreError::PKCS8Error(format!(
                        "Convert from pkcs8 pem to ed25519 private key failed: {e}"
                    ))
                })?;
                Self::from_key_pair_bytes(key_pair_bytes)
            }

            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `Ed25519Keys` from a pkcs8 asn.1 private key.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        let key_pair_bytes = KeypairBytes::from_pkcs8_der(der_bytes).map_err(|e| {
            SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ed25519 private key failed: {e}"
            ))
        })?;
        Self::from_key_pair_bytes(key_pair_bytes)
    }

    /// Builds a `Ed25519Keys` from a `KeypairBytes`.
    fn from_key_pair_bytes(key_pair_bytes: KeypairBytes) -> Result<Self> {
        let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(
            &key_pair_bytes.to_bytes().ok_or_else(|| {
                SigstoreError::PKCS8SpkiError("No public key info in given key_pair_bytes.".into())
            })?,
        )?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this ed25519 private key.
    pub fn to_sigstore_signer(&self) -> Result<SigStoreSigner> {
        Ok(SigStoreSigner::ED25519(Ed25519Signer::from_ed25519_keys(
            self,
        )?))
    }
}

impl KeyPair for Ed25519Keys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        self.verifying_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
    }

    /// Return the public key in asn.1 SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .verifying_key
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
        self.signing_key
            .to_pkcs8_der()
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))?
            .to_pem(PRIVATE_KEY_PEM_LABEL, pkcs8::LineEnding::LF)
            .map_err(|e| SigstoreError::PKCS8SpkiError(e.to_string()))
    }

    /// Return the private key in asn.1 pkcs8 format.
    fn private_key_to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let pkcs8 = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        Ok(pkcs8.to_bytes())
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(
        &self,
        _signature_digest_algorithm: &SigningScheme,
    ) -> Result<CosignVerificationKey> {
        let der = self.public_key_to_der()?;
        let res = CosignVerificationKey::from_der(&der, &SigningScheme::ED25519)?;
        Ok(res)
    }
}

#[derive(Debug)]
pub struct Ed25519Signer {
    key_pair: Ed25519Keys,
}

impl Ed25519Signer {
    pub fn from_ed25519_keys(ed25519_keys: &Ed25519Keys) -> Result<Self> {
        Ok(Self {
            key_pair: ed25519_keys.clone(),
        })
    }

    /// Return the ref to the keypair inside the signer
    pub fn ed25519_keys(&self) -> &Ed25519Keys {
        &self.key_pair
    }
}

impl Signer for Ed25519Signer {
    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.key_pair
    }

    /// Sign the given message using Ed25519
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let signature = self.key_pair.signing_key.try_sign(msg)?;
        Ok(signature.to_vec())
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

    use super::{Ed25519Keys, Ed25519Signer};

    const PASSWORD: &[u8] = b"123";

    /// This test will try to read an unencrypted ed25519
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ed25519_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/ed25519_private.key")
            .expect("read tests/data/keys/ed25519_private.key failed.");
        let key = Ed25519Keys::from_pem(&content);
        assert!(
            key.is_ok(),
            "can not create Ed25519Keys from unencrypted PEM file."
        );
    }

    /// This test will try to read an encrypted ed25519
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ed25519_from_encrypted_pem() {
        let content = fs::read("tests/data/keys/ed25519_encrypted_private.key")
            .expect("read tests/data/keys/ed25519_encrypted_private.key failed.");
        let key = Ed25519Keys::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_ok(),
            "can not create Ed25519Keys from encrypted PEM file"
        );
    }

    /// This test will try to encrypt a ed25519 keypair and
    /// return the pem-encoded contents.
    #[test]
    fn ed25519_to_encrypted_pem() {
        let key = Ed25519Keys::new().expect("create Ed25519 keys failed.");
        let key = key.private_key_to_encrypted_pem(PASSWORD);
        assert!(
            key.is_ok(),
            "can not export private key in encrypted PEM format."
        );
    }

    /// This test will generate a Ed25519Keys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn ed25519_to_and_from_pem() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let key = key
            .private_key_to_pem()
            .expect("export private key to PEM format failed.");
        let key = Ed25519Keys::from_pem(key.as_bytes());
        assert!(key.is_ok(), "can not create Ed25519Keys from PEM string.");
    }

    /// This test will generate a Ed25519Keys, encode the private key
    /// it into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn ed25519_to_and_from_der() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let key = key
            .private_key_to_der()
            .expect("export private key to DER format failed.");
        let key = Ed25519Keys::from_der(&key);
        assert!(key.is_ok(), "can not create Ed25519Keys from DER bytes.")
    }

    /// This test will generate a ed25519 keypair.
    /// And then use the verification key interface to instantial
    /// a VerificationKey object.
    #[test]
    fn ed25519_generate_public_key() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        assert!(
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::ED25519).is_ok(),
            "can not convert public key in PEM format into CosignVerificationKey.",
        );
        let pubkey = key
            .public_key_to_der()
            .expect("export private key to DER format failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey, &SigningScheme::ED25519).is_ok(),
            "can not create CosignVerificationKey from der bytes."
        );
    }

    /// This test will generate a ed25519 keypair.
    /// And then derive a `CosignVerificationKey` from it.
    #[test]
    fn ecdsa_derive_verification_key() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        assert!(
            key.to_verification_key(&SigningScheme::ED25519).is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `to_verification_key`.",
        );
    }

    /// This test will do the following things:
    /// * Generate a ed25519 keypair.
    /// * Sign the MESSAGE with the private key then generate a signature.
    /// * Verify the signature using the public key.
    #[test]
    fn ed25519_sign_and_verify() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let pubkey = key
            .public_key_to_pem()
            .expect("export private key to PEM format failed.");
        let signer = Ed25519Signer::from_ed25519_keys(&key)
            .expect("create Ed25519Signer from ed25519 keys failed.");

        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("signing message failed.");
        let verification_key =
            CosignVerificationKey::from_pem(pubkey.as_bytes(), &SigningScheme::ED25519)
                .expect("convert CosignVerificationKey from public key failed.");
        let signature = Signature::Raw(&sig);
        assert!(
            verification_key
                .verify_signature(signature, MESSAGE.as_bytes())
                .is_ok(),
            "can not verify the signature.",
        );
    }
}
