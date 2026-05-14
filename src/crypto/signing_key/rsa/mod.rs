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

//! # RSA Signer
//!
//! RSA Signer supports the following padding schemes:
//! * `PSS`
//! * `PKCS#1 v1.5`
//!
//! And the following digest algorithms:
//! * `Sha256`
//!
//! Per the Sigstore algorithm registry only SHA-256 is required for RSA,
//! so `RSA_PSS_SHA384`, `RSA_PSS_SHA512`, `RSA_PKCS1_SHA384`, and
//! `RSA_PKCS1_SHA512` have been removed.
//!
//! # RSA Signer Operation
//!
//! A [`RSASigner`] can be derived from a [`RSAKeys`]
//! ```rust
//! use sigstore::crypto::signing_key::{rsa::{RSASigner, keypair::RSAKeys, DigestAlgorithm, PaddingScheme}, KeyPair, Signer};
//! use sigstore::crypto::Signature;
//!
//! let rsa_keys = RSAKeys::new(2048).unwrap();
//!
//! // create a signer
//! let signer = RSASigner::from_rsa_keys(&rsa_keys, DigestAlgorithm::Sha256, PaddingScheme::PSS);
//!
//! // test message to be signed
//! let message = b"some message";
//!
//! // sign
//! let signature_data = signer.sign(message).unwrap();
//!
//! // export the [`CosignVerificationKey`] from the [`RSASigner`], which
//! // is used to verify the signature.
//! let verification_key = signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature_data), message).is_ok());
//! ```

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair},
};

use self::keypair::RSAKeys;
use super::{KeyPair, Signer};
use crate::{crypto::CosignVerificationKey, errors::*};

pub mod keypair;

pub const DEFAULT_KEY_SIZE: usize = 2048;

/// Different digest algorithms used in
/// RSA-based signing algorithm.
pub enum DigestAlgorithm {
    Sha256,
}

/// Different padding schemes used in
/// RSA-based signing algorithm.
/// * `PSS`: Probabilistic Signature Scheme, more secure than `PKCS1v15`.
/// * `PKCS1v15`: also known as simply PKCS1, is a simple padding
///   scheme developed for use with RSA keys.
pub enum PaddingScheme {
    PSS,
    PKCS1v15,
}

/// RSA signing scheme families:
/// * `PKCS1v15`: PKCS#1 1.5 padding for RSA signatures.
/// * `PSS`: RSA PSS padding for RSA signatures.
///
/// Both schemes support the following digest algorithms:
/// * `Sha256`
pub struct RSASigner {
    pub(crate) digest: DigestAlgorithm,
    pub(crate) padding: PaddingScheme,
    key_pair: RSAKeys,
}

impl std::fmt::Debug for RSASigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RSASigner").finish_non_exhaustive()
    }
}

impl RSASigner {
    /// Create a new `RSASigner` from an [`RSAKeys`] key pair, digest algorithm,
    /// and padding scheme.
    pub fn new(key_pair: RSAKeys, digest: DigestAlgorithm, padding: PaddingScheme) -> Self {
        Self {
            digest,
            padding,
            key_pair,
        }
    }

    /// Create a new `RSASigner` from a reference to an [`RSAKeys`] key pair.
    pub fn from_rsa_keys(
        rsa_keys: &RSAKeys,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Self {
        Self::new(rsa_keys.clone(), digest_algorithm, padding_scheme)
    }

    /// Return the ref to the [`RSAKeys`] inside the `RSASigner`.
    pub fn rsa_keys(&self) -> &RSAKeys {
        &self.key_pair
    }

    /// Return the related [`CosignVerificationKey`] of this `RSASigner`.
    pub fn to_verification_key(&self) -> Result<CosignVerificationKey> {
        use crate::crypto::SigningScheme;
        let scheme = match (&self.digest, &self.padding) {
            (DigestAlgorithm::Sha256, PaddingScheme::PSS) => SigningScheme::RSA_PSS_SHA256(0),
            (DigestAlgorithm::Sha256, PaddingScheme::PKCS1v15) => {
                SigningScheme::RSA_PKCS1_SHA256(0)
            }
        };
        self.key_pair.to_verification_key(&scheme)
    }
}

impl Signer for RSASigner {
    /// `sign` will sign the given data, and return the signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let kp = RsaKeyPair::from_pkcs8(&self.key_pair.pkcs8_der)
            .map_err(|e| SigstoreError::PKCS8Error(e.to_string()))?;

        let alg = match (&self.digest, &self.padding) {
            (DigestAlgorithm::Sha256, PaddingScheme::PSS) => &RSA_PSS_SHA256,
            (DigestAlgorithm::Sha256, PaddingScheme::PKCS1v15) => &RSA_PKCS1_SHA256,
        };

        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(alg, &rng, msg, &mut sig)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        Ok(sig)
    }

    /// Return the ref to the [`KeyPair`] trait object inside the `RSASigner`.
    fn key_pair(&self) -> &dyn KeyPair {
        &self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{DEFAULT_KEY_SIZE, DigestAlgorithm, PaddingScheme, RSASigner, keypair::RSAKeys};
    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{KeyPair, Signer, tests::MESSAGE},
    };

    #[rstest]
    #[case(
        DigestAlgorithm::Sha256,
        PaddingScheme::PKCS1v15,
        SigningScheme::RSA_PKCS1_SHA256(0)
    )]
    #[case(
        DigestAlgorithm::Sha256,
        PaddingScheme::PSS,
        SigningScheme::RSA_PSS_SHA256(0)
    )]
    fn rsa_schemes(
        #[case] digest_algorithm: DigestAlgorithm,
        #[case] padding_scheme: PaddingScheme,
        #[case] signing_scheme: SigningScheme,
    ) {
        let rsa_keys = RSAKeys::new(DEFAULT_KEY_SIZE).expect("RSA keys generated failed.");
        let signer = RSASigner::from_rsa_keys(&rsa_keys, digest_algorithm, padding_scheme);
        let sig = signer.sign(MESSAGE.as_bytes()).expect("sign failed.");
        let vk = rsa_keys
            .to_verification_key(&signing_scheme)
            .expect("derive CosignVerificationKey failed.");
        let signature = Signature::Raw(&sig);
        vk.verify_signature(signature, MESSAGE.as_bytes())
            .expect("can not verify the signature.");
    }
}
