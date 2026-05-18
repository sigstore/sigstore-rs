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
//! This module provides [`ECDSAKeys`], a curve-tagged enum that wraps
//! [`EcdsaKeys`] for each supported elliptic curve. The curve is selected
//! at runtime rather than via generic type parameters.
//!
//! # EC Key Pair Operations
//!
//! Three elliptic curves are supported:
//! * `P256`: P-256, also known as secp256r1 or prime256v1 (paired with SHA-256)
//! * `P384`: P-384, also known as secp384r1 (paired with SHA-384)
//! * `P521`: P-521, also known as secp521r1 (paired with SHA-512)
//!
//! We take `P256` as an example to show the operations:
//! ```rust
//! use sigstore::crypto::signing_key::ecdsa::{ECDSAKeys, EllipticCurve};
//! use sigstore::crypto::Signature;
//!
//! // generate a new EC-P256 key pair
//! let ec_key_pair = ECDSAKeys::new(EllipticCurve::P256).unwrap();
//!
//! // export the pem encoded public key.
//! // here `as_inner()` returns a reference to the [`KeyPair`] trait object
//! // underlying this [`ECDSAKeys`] for key pair operations.
//! let pubkey = ec_key_pair.as_inner().public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ec_key_pair.as_inner().private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // also, we can import an [`ECDSAKeys`] of unknown elliptic curve using
//! // functions with the prefix `ECDSAKeys::from_`. These functions try to
//! // decode the given ECDSA private key (in PKCS#8 format) against each
//! // supported curve in order, returning the first that succeeds.
//! // For example:
//! // let ec_key_pair_import = ECDSAKeys::from_pem(PEM_CONTENT).unwrap();
//!
//! // convert this EC key into a [`sigstore::crypto::signing_key::SigStoreSigner`]
//! // enum to sign some data. The digest algorithm is chosen automatically
//! // based on the curve (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
//! let ec_signer = ec_key_pair.to_sigstore_signer().unwrap();
//!
//! // test message to be signed
//! let message = b"some message";
//!
//! // sign the message
//! let signature_data = ec_signer.sign(message).unwrap();
//!
//! // export the [`sigstore::crypto::verification_key::CosignVerificationKey`]
//! // from the [`sigstore::crypto::signing_key::SigStoreSigner`],
//! // which is used to verify the signature.
//! let verification_key = ec_signer.to_verification_key().unwrap();
//!
//! // verify
//! assert!(verification_key.verify_signature(Signature::Raw(&signature_data), message).is_ok());
//! ```

use crate::errors::*;

use self::ec::{EcdsaKeys, EcdsaSigner};
use super::{KeyPair, SigStoreSigner};

pub mod ec;

/// The elliptic curves supported for ECDSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    P256,
    P384,
    P521,
}

impl std::fmt::Display for EllipticCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EllipticCurve::P256 => write!(f, "P256"),
            EllipticCurve::P384 => write!(f, "P384"),
            EllipticCurve::P521 => write!(f, "P521"),
        }
    }
}

/// An ECDSA key pair for one of the supported curves.
pub enum ECDSAKeys {
    P256(EcdsaKeys),
    P384(EcdsaKeys),
    P521(EcdsaKeys),
}

impl std::fmt::Display for ECDSAKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ECDSAKeys::P256(_) => write!(f, "ECDSA P256"),
            ECDSAKeys::P384(_) => write!(f, "ECDSA P384"),
            ECDSAKeys::P521(_) => write!(f, "ECDSA P521"),
        }
    }
}

impl ECDSAKeys {
    /// Create a new key pair for the given curve.
    pub fn new(curve: EllipticCurve) -> Result<Self> {
        match curve {
            EllipticCurve::P256 => EcdsaKeys::new(EllipticCurve::P256).map(ECDSAKeys::P256),
            EllipticCurve::P384 => EcdsaKeys::new(EllipticCurve::P384).map(ECDSAKeys::P384),
            EllipticCurve::P521 => EcdsaKeys::new(EllipticCurve::P521).map(ECDSAKeys::P521),
        }
    }

    /// Return a reference to the inner [`KeyPair`] trait object.
    pub fn as_inner(&self) -> &dyn KeyPair {
        match self {
            ECDSAKeys::P256(k) | ECDSAKeys::P384(k) | ECDSAKeys::P521(k) => k,
        }
    }

    pub(crate) fn inner(&self) -> &EcdsaKeys {
        match self {
            ECDSAKeys::P256(k) | ECDSAKeys::P384(k) | ECDSAKeys::P521(k) => k,
        }
    }

    /// Build an [`ECDSAKeys`] from encrypted pkcs8 PEM-encoded private key.
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_encrypted_pem(private_key: &[u8], password: &[u8]) -> Result<Self> {
        EcdsaKeys::from_encrypted_pem(private_key, password).and_then(|k| k.to_wrapped_ecdsa_keys())
    }

    /// Build an [`ECDSAKeys`] from a pkcs8 PEM-encoded private key.
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        EcdsaKeys::from_pem(pem_data).and_then(|k| k.to_wrapped_ecdsa_keys())
    }

    /// Build an [`ECDSAKeys`] from pkcs8 DER bytes.
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        EcdsaKeys::from_der(private_key).and_then(|k| k.to_wrapped_ecdsa_keys())
    }

    /// Build a [`SigStoreSigner`] from this key pair using the default scheme
    /// for each curve (P256→SHA256, P384→SHA384, P521→SHA512).
    pub fn to_sigstore_signer(&self) -> Result<SigStoreSigner> {
        let signer = EcdsaSigner::from_ecdsa_keys(self.inner())?;
        Ok(match self {
            ECDSAKeys::P256(_) => SigStoreSigner::ECDSA_P256_SHA256_ASN1(signer),
            ECDSAKeys::P384(_) => SigStoreSigner::ECDSA_P384_SHA384_ASN1(signer),
            ECDSAKeys::P521(_) => SigStoreSigner::ECDSA_P521_SHA512_ASN1(signer),
        })
    }
}
