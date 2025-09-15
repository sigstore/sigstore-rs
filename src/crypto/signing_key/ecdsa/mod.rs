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

//! # ECDSA Key Enums
//!
//! This is a wrapper for [`EcdsaKeys`] and [`EcdsaSigner`]. Because
//! both [`EcdsaKeys`] and [`EcdsaSigner`] are generic types, they
//! may let the user to manually include concrete underlying elliptic
//! curves like `p256`, `p384`, and concrete digest algorithm crates
//! like `sha2`. To avoid this, we use [`ECDSAKeys`] enum to wrap
//! the generic type [`EcdsaKeys`].
//!
//! # EC Key Pair Operations
//!
//! This wrapper provides two underlying elliptic curves, s.t.
//! * `P256`: `P-256`, also known as `secp256r1` or `prime256v1`.
//! * `P384`: `P-384`, also known as `secp384r1`.
//!
//! We take `P256` for example to show the operaions:
//! ```rust
//! use sigstore::crypto::signing_key::ecdsa::{ECDSAKeys, EllipticCurve};
//! use sigstore::crypto::Signature;
//!
//! // generate a new EC-P256 key pair
//! let ec_key_pair = ECDSAKeys::new(EllipticCurve::P256).unwrap();
//!
//! // export the pem encoded public key.
//! // here `as_inner()` will return the reference of `KeyPair` trait object
//! // underlying this `ECDSAKeys` for key pair operaions.
//! let pubkey = ec_key_pair.as_inner().public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ec_key_pair.as_inner().private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // also, we can import an [`ECDSAKeys`] of unknown elliptic curve at compile
//! // time using functions with the prefix `ECDSAKeys::from_`. These functions
//! // will try to decode the given ecdsa private key using all [`EllipticCurve`]
//! // enums (suppose the given private key is in PKCS8 format. The PKCS8
//! // format will carry the key algorithm and its underlying elliptic curve
//! // identity). If one of them succeeds, return the enum. If all fail, return
//! // an error. For example:
//! // let ec_key_pair_import = ECDSAKeys::from_pem(PEM_CONTENT).unwrap();
//!
//! // convert this EC key into an [`SigStoreSigner`] enum to sign some data.
//! // Although different EC key can combine with different digest algorithms to
//! // form a signing scheme, `P256` is recommended to work with `Sha256` and
//! // `P384` is recommended to work with `Sha384`. So here we do not include
//! // extra parameter `SignatureDigestAlgorithm` for `to_sigstore_signer()`.
//! let ec_signer = ec_key_pair.to_sigstore_signer().unwrap();
//!
//! // test message to be signed
//! let message = b"some message";
//!
//! // sign using
//! let signature_data = ec_signer.sign(message).unwrap();
//!
//! // export the [`CosignVerificationKey`] from the [`SigStoreSigner`], which
//! // is used to verify the signature.
//! let verification_key = ec_signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature_data),message).is_ok());
/// ```
use crate::errors::*;

use self::ec::{EcdsaKeys, EcdsaSigner};

use super::{KeyPair, SigStoreSigner};

pub mod ec;

pub enum ECDSAKeys {
    P256(EcdsaKeys<p256::NistP256>),
    P384(EcdsaKeys<p384::NistP384>),
}

impl std::fmt::Display for ECDSAKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ECDSAKeys::P256(_) => write!(f, "ECDSA P256"),
            ECDSAKeys::P384(_) => write!(f, "ECDSA P384"),
        }
    }
}

/// The types of supported elliptic curves:
/// * `P256`: `P-256`, also known as `secp256r1` or `prime256v1`.
/// * `P384`: `P-384`, also known as `secp384r1`.
pub enum EllipticCurve {
    P256,
    P384,
}

/// This macro helps to reduce duplicated code.
macro_rules! iterate_on_curves {
    ($func: ident ($($args:expr),*), $errorinfo: literal) => {
        if let Ok(keys) = EcdsaKeys::<p256::NistP256>::$func($($args,)*) {
            Ok(ECDSAKeys::P256(keys))
        } else if let Ok(keys) = EcdsaKeys::<p384::NistP384>::$func($($args,)*) {
            Ok(ECDSAKeys::P384(keys))
        } else {
            Err(SigstoreError::KeyParseError($errorinfo.to_string()))
        }
    }
}

impl ECDSAKeys {
    /// Create a new [`ECDSAKeys`] due to the given [`EllipticCurve`].
    pub fn new(curve: EllipticCurve) -> Result<Self> {
        Ok(match curve {
            EllipticCurve::P256 => ECDSAKeys::P256(EcdsaKeys::<p256::NistP256>::new()?),
            EllipticCurve::P384 => ECDSAKeys::P384(EcdsaKeys::<p384::NistP384>::new()?),
        })
    }

    /// Return the inner `KeyPair` of the enum. This function
    /// is useful in the inner interface conversion.
    pub fn as_inner(&self) -> &dyn KeyPair {
        match self {
            ECDSAKeys::P256(inner) => inner,
            ECDSAKeys::P384(inner) => inner,
        }
    }

    /// Builds a `EcdsaKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`super::COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`super::SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    pub fn from_encrypted_pem(private_key: &[u8], password: &[u8]) -> Result<Self> {
        iterate_on_curves!(
            from_encrypted_pem(private_key, password),
            "Ecdsa keys from encrypted PEM private key"
        )
    }

    /// Builds a `EcdsaKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`super::PRIVATE_KEY_PEM_LABEL`]
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        iterate_on_curves!(from_pem(pem_data), "Ecdsa keys from PEM private key")
    }

    /// Builds a `EcdsaKeys` from a pkcs8 asn.1 private key.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        iterate_on_curves!(from_der(private_key), "Ecdsa keys from DER private key")
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this Ecdsa private key. This function does not receive any parameter
    /// to indicate the digest algorthm, because the common signing schemes
    /// for ecdsa-p256 is `ECDSA_P256_SHA256`, and for ecdsa-p384 is
    /// `ECDSA_P384_SHA384`.
    pub fn to_sigstore_signer(&self) -> Result<SigStoreSigner> {
        Ok(match self {
            ECDSAKeys::P256(inner) => {
                SigStoreSigner::ECDSA_P256_SHA256_ASN1(
                    EcdsaSigner::<_, sha2::Sha256>::from_ecdsa_keys(inner)?,
                )
            }
            ECDSAKeys::P384(inner) => {
                SigStoreSigner::ECDSA_P384_SHA384_ASN1(
                    EcdsaSigner::<_, sha2::Sha384>::from_ecdsa_keys(inner)?,
                )
            }
        })
    }
}
