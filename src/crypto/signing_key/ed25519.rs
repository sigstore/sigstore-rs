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
//! This module provides Ed25519 key pair operations backed by `aws-lc-rs`.
//! There are two main types:
//! * [`Ed25519Keys`]: provides key pair operations
//! * [`Ed25519Signer`]: provides signing operations
//!
//! The `signing_key` module wraps [`Ed25519Keys`] into [`super::SigStoreKeyPair`],
//! and [`Ed25519Signer`] into [`SigStoreSigner`].
//!
//! # Ed25519 Key Operations
//!
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
//! // also, we can import an Ed25519 key using functions with the prefix
//! // `Ed25519Keys::from_`. These functions treat the given data as an
//! // Ed25519 private key in PKCS#8 format. For example:
//! // let ed25519_key_pair_import = Ed25519Keys::from_pem(PEM_CONTENT).unwrap();
//!
//! // convert this Ed25519 key into a [`super::SigStoreSigner`] enum to sign some data.
//! let ed25519_signer = ed25519_key_pair.to_sigstore_signer().unwrap();
//!
//! // test message to be signed
//! let message = b"some message";
//!
//! // sign the message
//! let signature = ed25519_signer.sign(message).unwrap();
//!
//! // export the [`sigstore::crypto::verification_key::CosignVerificationKey`] from the
//! // [`super::SigStoreSigner`], which is used to verify the signature.
//! let verification_key = ed25519_signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature), message).is_ok());
//! ```

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as AwsKeyPair},
};

use crate::{
    crypto::{SigningScheme, verification_key::CosignVerificationKey},
    errors::*,
};

use super::{
    COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL, SIGSTORE_PRIVATE_KEY_PEM_LABEL,
    SigStoreSigner, Signer, kdf,
};

/// An Ed25519 key pair.
#[derive(Clone)]
pub struct Ed25519Keys {
    /// PKCS#8 DER encoding of the private key.
    pkcs8_der: zeroize::Zeroizing<Vec<u8>>,
    /// DER-encoded SubjectPublicKeyInfo.
    spki_der: Vec<u8>,
}

impl std::fmt::Debug for Ed25519Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Keys").finish_non_exhaustive()
    }
}

impl Ed25519Keys {
    /// Create a new `Ed25519Keys` object.
    /// The private key will be randomly generated.
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        Self::from_pkcs8_der(pkcs8.as_ref())
    }

    /// Build from raw PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let kp = Ed25519KeyPair::from_pkcs8(der)
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        let spki_der = kp
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?
            .as_ref()
            .to_vec();
        Ok(Self {
            pkcs8_der: zeroize::Zeroizing::new(der.to_vec()),
            spki_der,
        })
    }

    /// Builds a `Ed25519Keys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                Self::from_pkcs8_der(&der)
            }
            PRIVATE_KEY_PEM_LABEL if password.is_empty() => Self::from_pem(encrypted_pem),
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

    /// Builds a `Ed25519Keys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`].
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let key = pem::parse(pem_data)?;
        match key.tag() {
            PRIVATE_KEY_PEM_LABEL => Self::from_pkcs8_der(key.contents()),
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `Ed25519Keys` from a pkcs8 asn.1 private key.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(der)
    }

    /// Create a new `Ed25519Keys` object from a given `Ed25519Keys` object.
    pub fn from_ed25519key(key: &Ed25519Keys) -> Result<Self> {
        Self::from_pkcs8_der(&key.pkcs8_der)
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this Ed25519 private key.
    pub fn to_sigstore_signer(&self) -> Result<SigStoreSigner> {
        Ok(SigStoreSigner::ED25519(Ed25519Signer::from_ed25519_keys(
            self,
        )?))
    }
}

impl KeyPair for Ed25519Keys {
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

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(
        &self,
        _signing_scheme: &SigningScheme,
    ) -> Result<CosignVerificationKey> {
        CosignVerificationKey::from_der(&self.spki_der, &SigningScheme::ED25519)
    }
}

/// An Ed25519 signer.
#[derive(Debug)]
pub struct Ed25519Signer {
    key_pair: Ed25519Keys,
}

impl Ed25519Signer {
    /// Create a new `Ed25519Signer` from the given `Ed25519Keys`.
    pub fn from_ed25519_keys(ed25519_keys: &Ed25519Keys) -> Result<Self> {
        Ok(Self {
            key_pair: ed25519_keys.clone(),
        })
    }

    /// Return the ref to the keypair inside the signer.
    pub fn ed25519_keys(&self) -> &Ed25519Keys {
        &self.key_pair
    }
}

impl Signer for Ed25519Signer {
    /// Return the ref to the keypair inside the signer.
    fn key_pair(&self) -> &dyn KeyPair {
        &self.key_pair
    }

    /// Sign the given message using Ed25519.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let kp = Ed25519KeyPair::from_pkcs8(&self.key_pair.pkcs8_der)
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;
        Ok(kp.sign(msg).as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rstest::rstest;

    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{KeyPair, Signer, tests::MESSAGE},
        verification_key::CosignVerificationKey,
    };

    use super::{Ed25519Keys, Ed25519Signer};

    const PASSWORD: &[u8] = b"123";
    const EMPTY_PASSWORD: &[u8] = b"";

    /// This test will try to read an unencrypted ed25519
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ed25519_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/ed25519_private.key")
            .expect("read tests/data/keys/ed25519_private.key failed.");
        let key = Ed25519Keys::from_pem(&content);
        assert!(
            key.is_ok(),
            "can not create Ed25519Keys from unencrypted PEM file: {:?}",
            key
        );
    }

    /// This test will try to read an encrypted ed25519
    /// private key file, which is generated by `sigstore`.
    #[rstest]
    #[case("tests/data/keys/ed25519_encrypted_private.key", PASSWORD)]
    #[case::empty_password("tests/data/keys/ed25519_private.key", EMPTY_PASSWORD)]
    fn ed25519_from_encrypted_pem(#[case] keypath: &str, #[case] password: &[u8]) {
        let content = fs::read(keypath).expect("read key failed.");
        let key = Ed25519Keys::from_encrypted_pem(&content, password);
        assert!(
            key.is_ok(),
            "can not create Ed25519Keys from encrypted PEM file: {:?}",
            key
        );
    }

    /// This test will try to encrypt an ed25519 keypair and
    /// return the pem-encoded contents.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ed25519_to_encrypted_pem(#[case] password: &[u8]) {
        let key = Ed25519Keys::new().expect("create Ed25519 keys failed.");
        assert!(
            key.private_key_to_encrypted_pem(password).is_ok(),
            "can not export private key in encrypted PEM format."
        );
    }

    /// This test will ensure that an unencrypted
    /// keypair will fail to read if a non-empty
    /// password is given.
    #[test]
    fn ed25519_error_unencrypted_pem_password() {
        let content = fs::read("tests/data/keys/ed25519_private.key").expect("read key failed.");
        let key = Ed25519Keys::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_err_and(|e| e
                .to_string()
                .contains("Unencrypted private key but password provided")),
            "read unencrypted key with password"
        );
    }

    /// This test will generate an Ed25519Keys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn ed25519_to_and_from_pem() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let pem = key.private_key_to_pem().expect("export to PEM failed.");
        let key2 = Ed25519Keys::from_pem(pem.as_bytes());
        assert!(key2.is_ok(), "can not create Ed25519Keys from PEM string.");
    }

    /// This test will generate an Ed25519Keys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ed25519_to_and_from_encrypted_pem(#[case] password: &[u8]) {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let pem = key
            .private_key_to_encrypted_pem(password)
            .expect("export to encrypted PEM failed.");
        let key2 = Ed25519Keys::from_encrypted_pem(pem.as_bytes(), password);
        assert!(key2.is_ok(), "can not create Ed25519Keys from PEM string.");
    }

    /// This test will generate an Ed25519Keys, encode the private key
    /// into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn ed25519_to_and_from_der() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let der = key.private_key_to_der().expect("export to DER failed.");
        let key2 = Ed25519Keys::from_der(&der);
        assert!(key2.is_ok(), "can not create Ed25519Keys from DER bytes.");
    }

    /// This test will generate a ed25519 keypair.
    /// And then use the verification key interface to instantiate
    /// a VerificationKey object.
    #[test]
    fn ed25519_generate_public_key() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let pubkey_pem = key
            .public_key_to_pem()
            .expect("export public key to PEM format failed.");
        assert!(
            CosignVerificationKey::from_pem(pubkey_pem.as_bytes(), &SigningScheme::default())
                .is_ok(),
            "can not create CosignVerificationKey from PEM bytes."
        );
        let pubkey_der = key
            .public_key_to_der()
            .expect("export public key to DER format failed.");
        assert!(
            CosignVerificationKey::from_der(&pubkey_der, &SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from DER bytes."
        );
    }

    /// This test will generate a ed25519 keypair.
    /// And then derive a `CosignVerificationKey` from it.
    #[test]
    fn ed25519_derive_verification_key() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        assert!(
            key.to_verification_key(&SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from Ed25519Keys via `to_verification_key`."
        );
    }

    /// This test will do the following things:
    /// * Generate an ed25519 keypair.
    /// * Sign the MESSAGE with the private key,
    ///   then generate a signature.
    /// * Verify the signature using the public key.
    #[test]
    fn ed25519_sign_and_verify() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let signer = Ed25519Signer::from_ed25519_keys(&key).expect("create signer failed.");
        let sig = signer.sign(MESSAGE.as_bytes()).expect("signing failed.");
        let pubkey_pem = key.public_key_to_pem().expect("export public key failed.");
        let vk = CosignVerificationKey::from_pem(pubkey_pem.as_bytes(), &SigningScheme::ED25519)
            .expect("create CosignVerificationKey failed.");
        assert!(
            vk.verify_signature(Signature::Raw(&sig), MESSAGE.as_bytes())
                .is_ok()
        );
    }
}
