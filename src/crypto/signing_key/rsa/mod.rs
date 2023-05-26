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

//! # RSA Signer
//!
//! RSA Signer support the following padding schemes:
//! * `PSS`
//! * `PKCS#1 v1.5`
//!
//! And the following digest algorithms:
//! * `Sha256`
//! * `Sha384`
//! * `Sha512`
//!
//! # RSA Signer Operaion
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
//! // export the [`CosignVerificationKey`] from the [`SigStoreSigner`], which
//! // is used to verify the signature.
//! let verification_key = signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature_data),message).is_ok());
//! ```

use ::rsa::{
    pkcs1v15::SigningKey,
    pss::BlindedSigningKey,
    signature::{Keypair, RandomizedSigner, SignatureEncoding},
};

use self::keypair::RSAKeys;

use crate::{crypto::CosignVerificationKey, errors::*};

use super::{KeyPair, Signer};

pub mod keypair;

pub const DEFAULT_KEY_SIZE: usize = 2048;

/// Different digest algorithms used in
/// RSA-based signing algorithm.
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Different padding schemes used in
/// RSA-based signing algorithm.
/// * `PSS`: Probabilistic Signature Scheme, more secure than `PKCS1v15`.
/// * `PKCS1v15`: also known as simply PKCS1, is a simple padding
/// scheme developed for use with RSA keys.
pub enum PaddingScheme {
    PSS,
    PKCS1v15,
}

/// Rsa signing scheme families:
/// * `PKCS1v15`: PKCS#1 1.5 padding for RSA signatures.
/// * `PSS`: RSA PSS padding for RSA signatures.
///
/// Both schemes support the following digest algorithms:
/// * `Sha256`
/// * `Sha384`
/// * `Sha512`
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSASigner {
    RSA_PSS_SHA256(BlindedSigningKey<sha2::Sha256>, RSAKeys),
    RSA_PSS_SHA384(BlindedSigningKey<sha2::Sha384>, RSAKeys),
    RSA_PSS_SHA512(BlindedSigningKey<sha2::Sha512>, RSAKeys),
    RSA_PKCS1_SHA256(SigningKey<sha2::Sha256>, RSAKeys),
    RSA_PKCS1_SHA384(SigningKey<sha2::Sha384>, RSAKeys),
    RSA_PKCS1_SHA512(SigningKey<sha2::Sha512>, RSAKeys),
}

/// helper to generate match arms
macro_rules! iter_on_rsa {
    ($domain: ident, $match_item: expr, $signer: ident, $key: ident, $func: expr) => {
        match $match_item {
            $domain::RSA_PSS_SHA256($signer, $key) => $func,
            $domain::RSA_PSS_SHA384($signer, $key) => $func,
            $domain::RSA_PSS_SHA512($signer, $key) => $func,
            $domain::RSA_PKCS1_SHA256($signer, $key) => $func,
            $domain::RSA_PKCS1_SHA384($signer, $key) => $func,
            $domain::RSA_PKCS1_SHA512($signer, $key) => $func,
        }
    };
}

impl RSASigner {
    pub fn from_rsa_keys(
        rsa_keys: &RSAKeys,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Self {
        let private_key = rsa_keys.private_key.clone();
        match padding_scheme {
            PaddingScheme::PSS => match digest_algorithm {
                DigestAlgorithm::Sha256 => RSASigner::RSA_PSS_SHA256(
                    BlindedSigningKey::<sha2::Sha256>::new(private_key),
                    rsa_keys.clone(),
                ),
                DigestAlgorithm::Sha384 => RSASigner::RSA_PSS_SHA384(
                    BlindedSigningKey::<sha2::Sha384>::new(private_key),
                    rsa_keys.clone(),
                ),
                DigestAlgorithm::Sha512 => RSASigner::RSA_PSS_SHA512(
                    BlindedSigningKey::<sha2::Sha512>::new(private_key),
                    rsa_keys.clone(),
                ),
            },
            PaddingScheme::PKCS1v15 => match digest_algorithm {
                DigestAlgorithm::Sha256 => RSASigner::RSA_PKCS1_SHA256(
                    SigningKey::<sha2::Sha256>::new(private_key),
                    rsa_keys.clone(),
                ),
                DigestAlgorithm::Sha384 => RSASigner::RSA_PKCS1_SHA384(
                    SigningKey::<sha2::Sha384>::new(private_key),
                    rsa_keys.clone(),
                ),
                DigestAlgorithm::Sha512 => RSASigner::RSA_PKCS1_SHA512(
                    SigningKey::<sha2::Sha512>::new(private_key),
                    rsa_keys.clone(),
                ),
            },
        }
    }

    /// Return the ref to the [`RSAKeys`] inside the RSASigner
    pub fn rsa_keys(&self) -> &RSAKeys {
        iter_on_rsa!(RSASigner, self, _signer, key, key)
    }

    /// Return the related [`CosignVerificationKey`] of this RSASigner
    pub fn to_verification_key(&self) -> Result<CosignVerificationKey> {
        Ok(match self {
            RSASigner::RSA_PSS_SHA256(signer, _) => {
                CosignVerificationKey::RSA_PSS_SHA256(signer.verifying_key())
            }
            RSASigner::RSA_PSS_SHA384(signer, _) => {
                CosignVerificationKey::RSA_PSS_SHA384(signer.verifying_key())
            }
            RSASigner::RSA_PSS_SHA512(signer, _) => {
                CosignVerificationKey::RSA_PSS_SHA512(signer.verifying_key())
            }
            RSASigner::RSA_PKCS1_SHA256(signer, _) => {
                CosignVerificationKey::RSA_PKCS1_SHA256(signer.verifying_key())
            }
            RSASigner::RSA_PKCS1_SHA384(signer, _) => {
                CosignVerificationKey::RSA_PKCS1_SHA384(signer.verifying_key())
            }
            RSASigner::RSA_PKCS1_SHA512(signer, _) => {
                CosignVerificationKey::RSA_PKCS1_SHA512(signer.verifying_key())
            }
        })
    }
}

impl Signer for RSASigner {
    /// `sign` will sign the given data, and return the signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        Ok(iter_on_rsa!(
            RSASigner,
            self,
            signer,
            _key,
            signer.sign_with_rng(&mut rng, msg).to_vec()
        ))
    }

    /// Return the ref to the [`KeyPair`] trait object inside the RSASigner
    fn key_pair(&self) -> &dyn KeyPair {
        iter_on_rsa!(RSASigner, self, _signer, key, key)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{keypair::RSAKeys, DigestAlgorithm, PaddingScheme, RSASigner, DEFAULT_KEY_SIZE};
    use crate::crypto::{
        signing_key::{tests::MESSAGE, KeyPair, Signer},
        Signature, SigningScheme,
    };

    #[rstest]
    #[case(
        DigestAlgorithm::Sha256,
        PaddingScheme::PKCS1v15,
        SigningScheme::RSA_PKCS1_SHA256(0)
    )]
    #[case(
        DigestAlgorithm::Sha384,
        PaddingScheme::PKCS1v15,
        SigningScheme::RSA_PKCS1_SHA384(0)
    )]
    #[case(
        DigestAlgorithm::Sha512,
        PaddingScheme::PKCS1v15,
        SigningScheme::RSA_PKCS1_SHA512(0)
    )]
    #[case(
        DigestAlgorithm::Sha256,
        PaddingScheme::PSS,
        SigningScheme::RSA_PSS_SHA256(0)
    )]
    #[case(
        DigestAlgorithm::Sha384,
        PaddingScheme::PSS,
        SigningScheme::RSA_PSS_SHA384(0)
    )]
    #[case(
        DigestAlgorithm::Sha512,
        PaddingScheme::PSS,
        SigningScheme::RSA_PSS_SHA512(0)
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
