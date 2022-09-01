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

//! # Keys for Signing
//! Here are the key pair operations for signing keys.
//!
//! # Generate keypair and Signing Data
//!
//! ```rust
//! use sigstore::crypto::signing_key::SigStoreSigner;
//! use sigstore::crypto::signing_key::KeyPair;
//! use sigstore::crypto::signing_key::SigningScheme;
//!
//! // generate a key pair for ECDSA_P256_SHA256_ASN1
//! let signer = SigStoreSigner::new(SigningScheme::ECDSA_P256_SHA256_ASN1).unwrap();
//!
//! // signing some message and get the message
//! let sig = signer.sign(b"test message").unwrap();
//!
//! // get the public key to verify
//! let pub_key = signer.public_key_to_pem().unwrap();
//!
//! // also, you can export the sigstore encrypted private key
//! let private_key = signer.private_key_to_encrypted_pem(b"password").unwrap();
//! ```

use elliptic_curve::zeroize::Zeroizing;
use p256::NistP256;
use p384::NistP384;
use sha2::{Sha256, Sha384};

use crate::errors::*;

use self::{
    ecdsa::{EcdsaKeys, EcdsaSigner},
    ed25519::{Ed25519Keys, Ed25519Signer},
};

use super::{CosignVerificationKey, SignatureDigestAlgorithm};

pub mod ecdsa;
pub mod ed25519;
pub mod kdf;
pub mod rsa;

/// Defatult signing algorithm used in sigstore.
pub const SIGSTORE_DEFAULT_SIGNING_ALGORITHM: SigningScheme = SigningScheme::ECDSA_P256_SHA256_ASN1;

/// The label for pem of cosign generated encrypted private keys.
pub const COSIGN_PRIVATE_KEY_PEM_LABEL: &str = "ENCRYPTED COSIGN PRIVATE KEY";

/// The label for pem of public keys.
pub const PUBLIC_KEY_PEM_LABEL: &str = "PUBLIC KEY";

/// The label for pem of sigstore generated encrypted private keys.
pub const SIGSTORE_PRIVATE_KEY_PEM_LABEL: &str = "ENCRYPTED SIGSTORE PRIVATE KEY";

/// The label for pem of private keys.
pub const PRIVATE_KEY_PEM_LABEL: &str = "PRIVATE KEY";

/// Every signing scheme must implement this interface.
/// All private export methods using the wrapper `Zeroizing`.
/// It will tell the compiler when the
/// result der object is dropped, the relative memory will
/// be flushed to zero to avoid leavint the private key in
/// the ram.
pub trait KeyPair {
    /// `public_key_to_pem` will export the PEM-encoded public key.
    fn public_key_to_pem(&self) -> Result<String>;

    /// `public_key_to_der` will export the asn.1 PKIX public key.
    fn public_key_to_der(&self) -> Result<Vec<u8>>;

    /// `private_key_to_encrypted_pem` will export the encrypted asn.1 pkcs8 private key.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>>;

    /// `private_key_to_pem` will export the PEM-encoded pkcs8 private key.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>>;

    /// `private_key_to_der` will export the asn.1 pkcs8 private key.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>>;

    /// `to_verification_key` will derive the `CosignVerificationKey` from
    /// the public key.
    fn to_verification_key(
        &self,
        signature_digest_algorithm: SignatureDigestAlgorithm,
    ) -> Result<CosignVerificationKey>;
}

/// Different digital signature algorithms.
/// * `ECDSA_P256_SHA256_ASN1`: ASN.1 DER-encoded ECDSA
/// signatures using the P-256 curve and SHA-256.
/// * `ECDSA_P384_SHA384_ASN1`: ASN.1 DER-encoded ECDSA
/// signatures using the P-384 curve and SHA-384.
/// * `ED25519`: ECDSA signature using SHA2-512
/// as the digest function and curve edwards25519. The
/// signature format please refer
/// to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.6).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub enum SigningScheme {
    // TODO: Support RSA
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ED25519,
}

pub trait Signer {
    /// `key_pair` will return the reference to the inside `KeyPair`.
    fn key_pair(&self) -> &dyn KeyPair;

    /// `sign` will sign the given data, and return the signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

/// `SigStoreSigner` is an easy-to-use interface
/// to use for non-specific generic parameter
/// signing.
pub struct SigStoreSigner {
    signer: Box<dyn Signer>,
    signing_scheme: SigningScheme,
}

impl SigStoreSigner {
    /// Create a key-pair due to the given signing scheme
    pub fn new(signing_scheme: SigningScheme) -> Result<Self> {
        Ok(Self {
            signer: match signing_scheme {
                SigningScheme::ECDSA_P256_SHA256_ASN1 => {
                    Box::new(EcdsaSigner::<_, Sha256>::from_ecdsa_keys(&EcdsaKeys::<
                        NistP256,
                    >::new(
                    )?)?)
                }
                SigningScheme::ECDSA_P384_SHA384_ASN1 => {
                    Box::new(EcdsaSigner::<_, Sha384>::from_ecdsa_keys(&EcdsaKeys::<
                        NistP384,
                    >::new(
                    )?)?)
                }
                SigningScheme::ED25519 => {
                    Box::new(Ed25519Signer::from_ed25519_keys(&Ed25519Keys::new()?)?)
                }
            },
            signing_scheme,
        })
    }

    /// `sign` will sign the given message, output
    /// the asn.1 encoded signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign(msg)
    }

    /// `public_key_to_pem` will export the PEM-encoded public key.
    pub fn public_key_to_pem(&self) -> Result<String> {
        self.signer.key_pair().public_key_to_pem()
    }

    /// `public_key_to_der` will export the asn.1 PKIX public key.
    pub fn public_key_to_der(&self) -> Result<Vec<u8>> {
        self.signer.key_pair().public_key_to_der()
    }

    /// `private_key_to_encrypted_pem` will export the encrypted asn.1 pkcs8 private key.
    pub fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        self.signer
            .key_pair()
            .private_key_to_encrypted_pem(password)
    }

    /// `private_key_to_pem` will export the PEM-encoded pkcs8 private key.
    pub fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        self.signer.key_pair().private_key_to_pem()
    }

    /// `private_key_to_der` will export the asn.1 pkcs8 private key.
    pub fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.signer.key_pair().private_key_to_der()
    }

    /// `to_verification_key` will derive the `CosignVerificationKey` from
    /// the `SigStoreSigner`.
    pub fn to_verification_key(&self) -> Result<CosignVerificationKey> {
        let digest_scheme = match self.signing_scheme {
            SigningScheme::ECDSA_P256_SHA256_ASN1 => SignatureDigestAlgorithm::Sha256,
            SigningScheme::ECDSA_P384_SHA384_ASN1 => SignatureDigestAlgorithm::Sha384,
            // Here the wildcard helps to handle those do not need a
            // digest scheme parameter.
            _ => SignatureDigestAlgorithm::Sha256,
        };

        self.signer.key_pair().to_verification_key(digest_scheme)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::crypto::{
        signing_key::{SigStoreSigner, SigningScheme},
        CosignVerificationKey, Signature,
    };

    /// This is a test MESSAGE used to be signed by all signing test.
    pub const MESSAGE: &str = r#"{
        "critical": {
            "identity": {
                "docker-reference": "registry-testing.svc.lan/busybox"
            },
            "image": {
                "docker-manifest-digest": "sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"
            },
            "type": "cosign container image signature"
        },
        "optional": null
    }"#;

    /// This test will do the following things:
    /// * Randomly generate a key pair due to the given signing scheme.
    /// * Signing the MESSAGE and generate a signature using
    /// the private key.
    /// * Derive the verification key using both `from_sigstore_signer`
    /// and `to_verification_key`.
    /// * Verify the signature with the public key.
    #[rstest]
    #[case(SigningScheme::ECDSA_P256_SHA256_ASN1)]
    #[case(SigningScheme::ECDSA_P384_SHA384_ASN1)]
    #[case(SigningScheme::ED25519)]
    fn sigstore_signing(#[case] signing_scheme: SigningScheme) {
        let signer = SigStoreSigner::new(signing_scheme).expect(&format!(
            "create SigStoreSigner with {:?} failed",
            signing_scheme
        ));
        let _pubkey = signer
            .public_key_to_pem()
            .expect("export public key in PEM format failed.");
        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("sign message failed.");
        let _verification_key = signer
            .to_verification_key()
            .expect("derive signer into verification key failed.");
        let verification_key = CosignVerificationKey::from_sigstore_signer(&signer)
            .expect("derive verification key from signer failed.");
        let signature = Signature::Raw(&sig);
        let verify_res = verification_key.verify_signature(signature, MESSAGE.as_bytes());
        assert!(verify_res.is_ok(), "can not verify the signature.");
    }
}
