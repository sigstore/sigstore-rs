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

//! # Keys Interface
//!
//! This mod includes asymmetric key pair generation, exporting/importing,
//! signing and verification key derivation. All the above features are
//! given by two enums:
//! * [`SigStoreKeyPair`]: an abstraction for asymmetric encryption key pairs.
//! * [`SigStoreSigner`]: an abstraction for digital signing algorithms.
//!
//! The [`SigStoreKeyPair`] now includes the key types of the following algorithms:
//! * [`SigStoreKeyPair::RSA`]: RSA key pair
//! * [`SigStoreKeyPair::ECDSA`]: Elliptic curve key pair
//! * [`SigStoreKeyPair::ED25519`]: Edwards curve-25519 key pair
//!
//! The [`SigStoreSigner`] now includes the following signing schemes:
//! * [`SigStoreSigner::RSA_PSS_SHA256`]: RSA signatures using PSS padding and SHA-256.
//! * [`SigStoreSigner::RSA_PSS_SHA384`]: RSA signatures using PSS padding and SHA-384.
//! * [`SigStoreSigner::RSA_PSS_SHA512`]: RSA signatures using PSS padding and SHA-512.
//! * [`SigStoreSigner::RSA_PKCS1_SHA256`]: RSA signatures using PKCS#1v1.5 padding and SHA-256.
//! * [`SigStoreSigner::RSA_PKCS1_SHA384`]: RSA signatures using PKCS#1v1.5 padding and SHA-384.
//! * [`SigStoreSigner::RSA_PKCS1_SHA512`]: RSA signatures using PKCS#1v1.5 padding and SHA-512.
//! * [`SigStoreSigner::ECDSA_P256_SHA256_ASN1`]: ASN.1 DER-encoded ECDSA
//! signatures using the P-256 curve and SHA-256.
//! * [`SigStoreSigner::ECDSA_P384_SHA384_ASN1`]: ASN.1 DER-encoded ECDSA
//! signatures using the P-384 curve and SHA-384.
//! * [`SigStoreSigner::ED25519`]: ECDSA signature using SHA2-512
//! as the digest function and curve edwards25519.
//!
//! # Simple Usages
//!
//! ```rust
//! use sigstore::crypto::signing_key::SigStoreSigner;
//! use sigstore::crypto::SigningScheme;
//! use sigstore::crypto::Signature;
//!
//! let test_data = b"test message";
//! // generate a key pair for ECDSA_P256_SHA256_ASN1
//! let signer = SigningScheme::ECDSA_P256_SHA256_ASN1.create_signer().unwrap();
//!
//! // signing some message and get the message
//! let sig = signer.sign(test_data).unwrap();
//!
//! // get the public key to verify
//! let verification_key = signer.to_verification_key().unwrap();
//!
//! // do verification
//! let res = verification_key.verify_signature(
//!     Signature::Raw(&sig),
//!     test_data,
//! );
//!
//! assert!(res.is_ok());
//! ```
//!
//! More use cases please refer to <`https://github.com/sigstore/sigstore-rs/tree/main/examples/key_interface`>

use elliptic_curve::zeroize::Zeroizing;

use crate::errors::*;

use self::{
    ecdsa::{ec::EcdsaSigner, ECDSAKeys},
    ed25519::{Ed25519Keys, Ed25519Signer},
    rsa::{keypair::RSAKeys, DigestAlgorithm, PaddingScheme, RSASigner},
};

use super::{verification_key::CosignVerificationKey, SigningScheme};

pub mod ecdsa;
pub mod ed25519;
pub mod kdf;
pub mod rsa;

/// The label for pem of cosign generated encrypted private keys.
pub const COSIGN_PRIVATE_KEY_PEM_LABEL: &str = "ENCRYPTED COSIGN PRIVATE KEY";

/// The label for pem of public keys.
pub const PUBLIC_KEY_PEM_LABEL: &str = "PUBLIC KEY";

/// The label for pem of sigstore generated encrypted private keys.
pub const SIGSTORE_PRIVATE_KEY_PEM_LABEL: &str = "ENCRYPTED SIGSTORE PRIVATE KEY";

/// The label for pem of private keys.
pub const PRIVATE_KEY_PEM_LABEL: &str = "PRIVATE KEY";

/// The label for pem of RSA private keys.
pub const RSA_PRIVATE_KEY_PEM_LABEL: &str = "RSA PRIVATE KEY";

/// Every signing scheme must implement this interface.
/// All private export methods using the wrapper `Zeroizing`.
/// It will tell the compiler when the
/// result der object is dropped, the relative memory will
/// be flushed to zero to avoid leaving the private key in
/// the ram.
pub trait KeyPair {
    /// `public_key_to_pem` will export the PEM-encoded public key.
    fn public_key_to_pem(&self) -> Result<String>;

    /// `public_key_to_der` will export the asn.1 PKIX public key.
    fn public_key_to_der(&self) -> Result<Vec<u8>>;

    /// `private_key_to_encrypted_pem` will export the encrypted asn.1 pkcs8 private key.
    /// This encryption follows the go-lang version in
    /// <https://github.com/sigstore/cosign/blob/main/pkg/cosign/keys.go#L139> using nacl secretbox.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>>;

    /// `private_key_to_pem` will export the PEM-encoded pkcs8 private key.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>>;

    /// `private_key_to_der` will export the asn.1 pkcs8 private key.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>>;

    /// `to_verification_key` will derive the `CosignVerificationKey` from
    /// the public key.
    fn to_verification_key(
        &self,
        signature_digest_algorithm: &SigningScheme,
    ) -> Result<CosignVerificationKey>;
}

/// Wrapper for different kinds of keys.
pub enum SigStoreKeyPair {
    ECDSA(ECDSAKeys),
    ED25519(Ed25519Keys),
    RSA(RSAKeys),
}

impl std::fmt::Display for SigStoreKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigStoreKeyPair::ECDSA(_) => write!(f, "EC Key"),
            SigStoreKeyPair::ED25519(_) => write!(f, "Ed25519 Key"),
            SigStoreKeyPair::RSA(_) => write!(f, "RSA Key"),
        }
    }
}

/// This macro helps to reduce duplicated code.
macro_rules! sigstore_keypair_from {
    ($func: ident ($($args:expr),*)) => {
        if let Ok(keys) = ECDSAKeys::$func($($args,)*) {
            Ok(SigStoreKeyPair::ECDSA(keys))
        } else if let Ok(keys) = Ed25519Keys::$func($($args,)*) {
            Ok(SigStoreKeyPair::ED25519(keys))
        } else if let Ok(keys) = RSAKeys::$func($($args,)*) {
            Ok(SigStoreKeyPair::RSA(keys))
        } else {
            Err(SigstoreError::KeyParseError("Unsupported key type".to_string()))
        }
    }
}

/// This macro helps to reduce duplicated code.
macro_rules! sigstore_keypair_code {
    ($func: ident ($($args:expr),*), $obj:ident) => {
        match $obj {
            SigStoreKeyPair::ECDSA(keys) => keys.as_inner().$func($($args,)*),
            SigStoreKeyPair::ED25519(keys) => keys.$func($($args,)*),
            SigStoreKeyPair::RSA(keys) => keys.$func($($args,)*),
        }
    }
}

impl SigStoreKeyPair {
    /// Builds a `SigStoreKeyPair` from pkcs8 PEM-encoded private key.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        sigstore_keypair_from!(from_pem(pem_data))
    }

    /// Builds a `SigStoreKeyPair` from pkcs8 DER-encoded private key.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        sigstore_keypair_from!(from_der(private_key))
    }

    /// Builds a `SigStoreKeyPair` from encrypted pkcs8 PEM-encoded private key.
    pub fn from_encrypted_pem(pem_data: &[u8], password: &[u8]) -> Result<Self> {
        sigstore_keypair_from!(from_encrypted_pem(pem_data, password))
    }

    /// `public_key_to_pem` will export the PEM-encoded public key.
    pub fn public_key_to_pem(&self) -> Result<String> {
        sigstore_keypair_code!(public_key_to_pem(), self)
    }

    /// `public_key_to_der` will export the asn.1 PKIX public key.
    pub fn public_key_to_der(&self) -> Result<Vec<u8>> {
        sigstore_keypair_code!(public_key_to_der(), self)
    }

    /// `private_key_to_encrypted_pem` will export the encrypted asn.1 pkcs8 private key.
    /// This encryption follows the go-lang version in
    /// <https://github.com/sigstore/cosign/blob/main/pkg/cosign/keys.go#L139> using nacl secretbox.
    pub fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        sigstore_keypair_code!(private_key_to_encrypted_pem(password), self)
    }

    /// `private_key_to_pem` will export the PEM-encoded pkcs8 private key.
    pub fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        sigstore_keypair_code!(private_key_to_pem(), self)
    }

    /// `private_key_to_der` will export the asn.1 pkcs8 private key.
    pub fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        sigstore_keypair_code!(private_key_to_der(), self)
    }

    /// `to_verification_key` will derive the `CosignVerificationKey` from
    /// the public key.
    pub fn to_verification_key(
        &self,
        signing_scheme: &SigningScheme,
    ) -> Result<CosignVerificationKey> {
        sigstore_keypair_code!(to_verification_key(signing_scheme), self)
    }

    /// Convert this KeyPair into a [`SigStoreSigner`] due to the given
    /// signing scheme. If the key type does not match the given
    /// signing scheme, an error will occur.
    pub fn to_sigstore_signer(&self, signing_scheme: &SigningScheme) -> Result<SigStoreSigner> {
        match self {
            SigStoreKeyPair::ECDSA(keys) => match signing_scheme {
                SigningScheme::ECDSA_P256_SHA256_ASN1 => match keys {
                    ECDSAKeys::P256(key) => {
                        let signer = EcdsaSigner::from_ecdsa_keys(key)?;
                        Ok(SigStoreSigner::ECDSA_P256_SHA256_ASN1(signer))
                    }
                    ECDSAKeys::P384(_) => Err(SigstoreError::UnmatchedKeyAndSigningScheme {
                        key_typ: keys.to_string(),
                        scheme: signing_scheme.to_string(),
                    }),
                },
                SigningScheme::ECDSA_P384_SHA384_ASN1 => match keys {
                    ECDSAKeys::P384(key) => {
                        let signer = EcdsaSigner::from_ecdsa_keys(key)?;
                        Ok(SigStoreSigner::ECDSA_P384_SHA384_ASN1(signer))
                    }
                    ECDSAKeys::P256(_) => Err(SigstoreError::UnmatchedKeyAndSigningScheme {
                        key_typ: keys.to_string(),
                        scheme: signing_scheme.to_string(),
                    }),
                },
                _ => Err(SigstoreError::UnmatchedKeyAndSigningScheme {
                    key_typ: self.to_string(),
                    scheme: signing_scheme.to_string(),
                }),
            },
            SigStoreKeyPair::ED25519(keys) => {
                if *signing_scheme != SigningScheme::ED25519 {
                    Err(SigstoreError::UnmatchedKeyAndSigningScheme {
                        key_typ: self.to_string(),
                        scheme: signing_scheme.to_string(),
                    })
                } else {
                    keys.to_sigstore_signer()
                }
            }
            SigStoreKeyPair::RSA(keys) => match signing_scheme {
                SigningScheme::RSA_PSS_SHA256(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha256, PaddingScheme::PSS)
                }
                SigningScheme::RSA_PSS_SHA384(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha384, PaddingScheme::PSS)
                }
                SigningScheme::RSA_PSS_SHA512(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha512, PaddingScheme::PSS)
                }
                SigningScheme::RSA_PKCS1_SHA256(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha256, PaddingScheme::PKCS1v15)
                }
                SigningScheme::RSA_PKCS1_SHA384(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha384, PaddingScheme::PKCS1v15)
                }
                SigningScheme::RSA_PKCS1_SHA512(_) => {
                    keys.to_sigstore_signer(DigestAlgorithm::Sha512, PaddingScheme::PKCS1v15)
                }
                _ => Err(SigstoreError::UnmatchedKeyAndSigningScheme {
                    key_typ: self.to_string(),
                    scheme: signing_scheme.to_string(),
                }),
            },
        }
    }
}

/// `Signer` trait is an abstraction of a specific set of asymmetric
/// private key, hash function and (if needs) padding algorithm. This
/// trait helps to construct the `SigStoreSigner` enum.
pub trait Signer {
    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair;

    /// `sign` will sign the given data, and return the signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum SigStoreSigner {
    RSA_PSS_SHA256(RSASigner),
    RSA_PSS_SHA384(RSASigner),
    RSA_PSS_SHA512(RSASigner),
    RSA_PKCS1_SHA256(RSASigner),
    RSA_PKCS1_SHA384(RSASigner),
    RSA_PKCS1_SHA512(RSASigner),
    ECDSA_P256_SHA256_ASN1(EcdsaSigner<p256::NistP256, sha2::Sha256>),
    ECDSA_P384_SHA384_ASN1(EcdsaSigner<p384::NistP384, sha2::Sha384>),
    ED25519(Ed25519Signer),
}

impl SigStoreSigner {
    /// Return the inner `Signer` of the enum. This function
    /// is useful in the inner interface conversion.
    fn as_inner(&self) -> &dyn Signer {
        match self {
            SigStoreSigner::ECDSA_P256_SHA256_ASN1(inner) => inner,
            SigStoreSigner::ECDSA_P384_SHA384_ASN1(inner) => inner,
            SigStoreSigner::ED25519(inner) => inner,
            SigStoreSigner::RSA_PSS_SHA256(inner) => inner,
            SigStoreSigner::RSA_PSS_SHA384(inner) => inner,
            SigStoreSigner::RSA_PSS_SHA512(inner) => inner,
            SigStoreSigner::RSA_PKCS1_SHA256(inner) => inner,
            SigStoreSigner::RSA_PKCS1_SHA384(inner) => inner,
            SigStoreSigner::RSA_PKCS1_SHA512(inner) => inner,
        }
    }

    /// `sign` will sign the given data, and return the signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.as_inner().sign(msg)
    }

    /// `to_verification_key` will derive the verification_key for the `SigStoreSigner`.
    pub fn to_verification_key(&self) -> Result<CosignVerificationKey> {
        let signing_scheme = match self {
            SigStoreSigner::ECDSA_P256_SHA256_ASN1(_) => SigningScheme::ECDSA_P256_SHA256_ASN1,
            SigStoreSigner::ECDSA_P384_SHA384_ASN1(_) => SigningScheme::ECDSA_P384_SHA384_ASN1,
            SigStoreSigner::ED25519(_) => SigningScheme::ED25519,
            SigStoreSigner::RSA_PSS_SHA256(_) => SigningScheme::RSA_PSS_SHA256(0),
            SigStoreSigner::RSA_PSS_SHA384(_) => SigningScheme::RSA_PSS_SHA384(0),
            SigStoreSigner::RSA_PSS_SHA512(_) => SigningScheme::RSA_PSS_SHA512(0),
            SigStoreSigner::RSA_PKCS1_SHA256(_) => SigningScheme::RSA_PKCS1_SHA256(0),
            SigStoreSigner::RSA_PKCS1_SHA384(_) => SigningScheme::RSA_PKCS1_SHA384(0),
            SigStoreSigner::RSA_PKCS1_SHA512(_) => SigningScheme::RSA_PKCS1_SHA512(0),
        };
        self.as_inner()
            .key_pair()
            .to_verification_key(&signing_scheme)
    }

    /// `key_pair` will return the reference of the `SigStoreKeyPair` enum due to `SigStoreSigner`.
    pub fn to_sigstore_keypair(&self) -> Result<SigStoreKeyPair> {
        Ok(match self {
            SigStoreSigner::ECDSA_P256_SHA256_ASN1(inner) => {
                SigStoreKeyPair::ECDSA(inner.ecdsa_keys().to_wrapped_ecdsa_keys()?)
            }
            SigStoreSigner::ECDSA_P384_SHA384_ASN1(inner) => {
                SigStoreKeyPair::ECDSA(inner.ecdsa_keys().to_wrapped_ecdsa_keys()?)
            }
            SigStoreSigner::ED25519(inner) => {
                SigStoreKeyPair::ED25519(Ed25519Keys::from_ed25519key(inner.ed25519_keys())?)
            }
            SigStoreSigner::RSA_PSS_SHA256(inner) => SigStoreKeyPair::RSA(inner.rsa_keys().clone()),
            SigStoreSigner::RSA_PSS_SHA384(inner) => SigStoreKeyPair::RSA(inner.rsa_keys().clone()),
            SigStoreSigner::RSA_PSS_SHA512(inner) => SigStoreKeyPair::RSA(inner.rsa_keys().clone()),
            SigStoreSigner::RSA_PKCS1_SHA256(inner) => {
                SigStoreKeyPair::RSA(inner.rsa_keys().clone())
            }
            SigStoreSigner::RSA_PKCS1_SHA384(inner) => {
                SigStoreKeyPair::RSA(inner.rsa_keys().clone())
            }
            SigStoreSigner::RSA_PKCS1_SHA512(inner) => {
                SigStoreKeyPair::RSA(inner.rsa_keys().clone())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::crypto::{verification_key::CosignVerificationKey, Signature, SigningScheme};

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
        let signer = signing_scheme
            .create_signer()
            .unwrap_or_else(|_| panic!("create SigStoreSigner with {:?} failed", signing_scheme));
        let key_pair = signer
            .to_sigstore_keypair()
            .expect("convert SigStoreSigner to SigStoreKeypair failed.");
        let _pubkey = key_pair
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
