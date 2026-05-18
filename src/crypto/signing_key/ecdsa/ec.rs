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

//! # ECDSA Keys
//!
//! This module provides ECDSA key pair operations backed by `aws-lc-rs`.
//! The curve is selected at runtime rather than via generic type parameters.
//! There are two main types:
//! * [`EcdsaKeys`]: provides key pair operations (P-256, P-384, P-521)
//! * [`EcdsaSigner`]: provides signing operations
//!
//! The [`EcdsaKeys`] struct is wrapped in the [`super::ECDSAKeys`] enum,
//! which in turn is wrapped in [`super::super::SigStoreKeyPair`].
//!
//! The [`super::super::SigStoreSigner`] enum includes variants for each
//! supported curve/hash combination:
//! * `ECDSA_P256_SHA256_ASN1`
//! * `ECDSA_P384_SHA384_ASN1`
//! * `ECDSA_P521_SHA512_ASN1`
//!
//! # EC Key Pair Operations
//!
//! *Not recommended to use this module directly. Use [`super::ECDSAKeys`] or
//! [`super::super::SigStoreKeyPair`] for key pairs and
//! [`super::super::SigStoreSigner`] for signing instead.*
//!
//! When generating an EC key pair, a specific elliptic curve must be chosen.
//! Supported curves are [`super::EllipticCurve::P256`],
//! [`super::EllipticCurve::P384`], and [`super::EllipticCurve::P521`].
//!
//! For example, using P-256 with `ECDSA_P256_SHA256_ASN1` as the signing scheme:
//!
//! ```rust
//! use sigstore::crypto::signing_key::{ecdsa::{ec::{EcdsaKeys, EcdsaSigner}, EllipticCurve}, KeyPair, Signer};
//!
//! let ec_key_pair = EcdsaKeys::new(EllipticCurve::P256).unwrap();
//!
//! // export the pem encoded public key.
//! let pubkey = ec_key_pair.public_key_to_pem().unwrap();
//!
//! // export the private key using sigstore encryption.
//! let privkey = ec_key_pair.private_key_to_encrypted_pem(b"password").unwrap();
//!
//! // sign with the new key.
//! let ec_signer = EcdsaSigner::from_ecdsa_keys(&ec_key_pair).unwrap();
//!
//! let signature = ec_signer.sign(b"some message").unwrap();
//! ```

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
        ECDSA_P521_SHA512_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair as AwsKeyPair,
    },
};

use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use pkcs8::PrivateKeyInfo;
use x509_cert::der::Decode;

use crate::{
    crypto::{
        SigningScheme,
        signing_key::{
            COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL,
            SIGSTORE_PRIVATE_KEY_PEM_LABEL, Signer, kdf,
        },
        verification_key::CosignVerificationKey,
    },
    errors::*,
};

use super::EllipticCurve;

/// Maps an [`EllipticCurve`] to the matching aws-lc-rs signing algorithm.
fn signing_alg(curve: EllipticCurve) -> &'static EcdsaSigningAlgorithm {
    match curve {
        EllipticCurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        EllipticCurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        EllipticCurve::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
    }
}

/// Detect the [`EllipticCurve`] from a PKCS#8 DER blob by inspecting the
/// named-curve OID embedded in the `AlgorithmIdentifier` parameters.
fn curve_from_pkcs8_der(der: &[u8]) -> Result<EllipticCurve> {
    let pki =
        PrivateKeyInfo::from_der(der).map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let params = pki
        .algorithm
        .parameters
        .ok_or_else(|| SigstoreError::KeyParsingError("missing algorithm parameters".into()))?;
    let oid = params
        .decode_as::<const_oid::ObjectIdentifier>()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    match oid {
        SECP_256_R_1 => Ok(EllipticCurve::P256),
        SECP_384_R_1 => Ok(EllipticCurve::P384),
        SECP_521_R_1 => Ok(EllipticCurve::P521),
        other => Err(SigstoreError::KeyParsingError(format!(
            "unsupported curve OID: {other}"
        ))),
    }
}

/// An ECDSA key pair.  Supports P-256, P-384, and P-521.
#[derive(Clone)]
pub struct EcdsaKeys {
    /// The curve this key uses.
    pub(crate) curve: EllipticCurve,
    /// PKCS#8 DER encoding of the private key (used for cloning / export).
    pkcs8_der: zeroize::Zeroizing<Vec<u8>>,
    /// DER-encoded SubjectPublicKeyInfo (cached).
    spki_der: Vec<u8>,
}

impl std::fmt::Debug for EcdsaKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaKeys")
            .field("curve", &self.curve)
            .field(
                "spki",
                &pem::encode(&pem::Pem::new("PUBLIC KEY", self.spki_der.clone())),
            )
            .finish_non_exhaustive()
    }
}

impl EcdsaKeys {
    /// Create a new `EcdsaKeys` object for the given elliptic curve.
    /// The secret key (private key) will be randomly generated.
    pub fn new(curve: EllipticCurve) -> Result<Self> {
        let rng = SystemRandom::new();
        let alg = signing_alg(curve);
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
        let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref())
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
        let spki_der = kp
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?
            .as_ref()
            .to_vec();
        Ok(Self {
            curve,
            pkcs8_der: zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()),
            spki_der,
        })
    }

    /// Build an `EcdsaKeys` from raw PKCS#8 DER bytes.
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let curve = curve_from_pkcs8_der(der)?;
        let alg = signing_alg(curve);
        let kp = EcdsaKeyPair::from_pkcs8(alg, der)
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
        let spki_der = kp
            .public_key()
            .as_der()
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?
            .as_ref()
            .to_vec();
        Ok(Self {
            curve,
            pkcs8_der: zeroize::Zeroizing::new(der.to_vec()),
            spki_der,
        })
    }

    /// Builds a `EcdsaKeys` from encrypted pkcs8 PEM-encoded private key.
    /// The label should be [`COSIGN_PRIVATE_KEY_PEM_LABEL`] or
    /// [`SIGSTORE_PRIVATE_KEY_PEM_LABEL`].
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_encrypted_pem(pem_data: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(pem_data)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                // The KDF payload is a PKCS#8 blob.
                Self::from_pkcs8_der(&der)
            }
            PRIVATE_KEY_PEM_LABEL if password.is_empty() => Self::from_pem(pem_data),
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

    /// Builds a `EcdsaKeys` from a pkcs8 PEM-encoded private key.
    /// The label of PEM should be [`PRIVATE_KEY_PEM_LABEL`].
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let key = pem::parse(pem_data)?;
        match key.tag() {
            PRIVATE_KEY_PEM_LABEL => Self::from_pkcs8_der(key.contents()),
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds a `EcdsaKeys` from a pkcs8 asn.1 private key.
    /// The elliptic curve is detected automatically from the key's OID.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(der)
    }

    /// Return a signer backed by this key pair.
    pub fn to_signer(&self) -> Result<EcdsaSigner> {
        EcdsaSigner::from_ecdsa_keys(self)
    }

    /// Convert the [`EcdsaKeys`] into [`super::ECDSAKeys`].
    pub fn to_wrapped_ecdsa_keys(&self) -> Result<super::ECDSAKeys> {
        Ok(match self.curve {
            EllipticCurve::P256 => super::ECDSAKeys::P256(self.clone()),
            EllipticCurve::P384 => super::ECDSAKeys::P384(self.clone()),
            EllipticCurve::P521 => super::ECDSAKeys::P521(self.clone()),
        })
    }
}

impl KeyPair for EcdsaKeys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        let pem = pem::Pem::new("PUBLIC KEY", self.spki_der.clone());
        Ok(pem::encode(&pem))
    }

    /// Return the public key in asn.1 SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.spki_der.clone())
    }

    /// Return the encrypted private key in PEM-encoded format.
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
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        CosignVerificationKey::from_der(&self.spki_der, signing_scheme)
    }
}

/// An ECDSA signer.
pub struct EcdsaSigner {
    key_pair: EcdsaKeys,
    inner: EcdsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("curve", &self.key_pair.curve)
            .finish_non_exhaustive()
    }
}

impl EcdsaSigner {
    /// Create a new `EcdsaSigner` from the given `EcdsaKeys`.
    pub fn from_ecdsa_keys(keys: &EcdsaKeys) -> Result<Self> {
        let rng = SystemRandom::new();
        let alg = signing_alg(keys.curve);
        let inner = EcdsaKeyPair::from_pkcs8(alg, &keys.pkcs8_der)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        Ok(Self {
            key_pair: keys.clone(),
            inner,
            rng,
        })
    }

    /// Return the ref to the keypair inside the signer.
    pub fn ecdsa_keys(&self) -> &EcdsaKeys {
        &self.key_pair
    }
}

impl Signer for EcdsaSigner {
    /// Sign the given message and generate an ASN.1 DER-encoded ECDSA signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .inner
            .sign(&self.rng, msg)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        Ok(sig.as_ref().to_vec())
    }

    /// Return the ref to the keypair inside the signer.
    fn key_pair(&self) -> &dyn KeyPair {
        &self.key_pair
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

    use super::{EcdsaKeys, EcdsaSigner, curve_from_pkcs8_der};
    use crate::crypto::signing_key::ecdsa::EllipticCurve;
    use crate::crypto::signing_key::ed25519::Ed25519Keys;

    const PASSWORD: &[u8] = b"123";
    const EMPTY_PASSWORD: &[u8] = b"";

    /// This test will try to read an unencrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[test]
    fn ecdsa_from_unencrypted_pem() {
        let content = fs::read("tests/data/keys/ecdsa_private.key")
            .expect("read tests/data/keys/ecdsa_private.key failed.");
        let key = EcdsaKeys::from_pem(&content);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from unencrypted PEM file: {:?}",
            key
        );
    }

    /// This test will try to read an encrypted ecdsa
    /// private key file, which is generated by `sigstore`.
    #[rstest]
    #[case("tests/data/keys/ecdsa_encrypted_private.key", PASSWORD)]
    #[case::empty_password(
        "tests/data/keys/cosign_generated_encrypted_empty_private.key",
        EMPTY_PASSWORD
    )]
    #[case::empty_password_unencrypted("tests/data/keys/ecdsa_private.key", EMPTY_PASSWORD)]
    fn ecdsa_from_encrypted_pem(#[case] keypath: &str, #[case] password: &[u8]) {
        let content = fs::read(keypath).expect("read key failed.");
        let key = EcdsaKeys::from_encrypted_pem(&content, password);
        assert!(
            key.is_ok(),
            "can not create EcdsaKeys from encrypted PEM file: {:?}",
            key
        );
    }

    /// This test will try to encrypt a ecdsa keypair and
    /// return the pem-encoded contents.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ecdsa_to_encrypted_pem(#[case] password: &[u8]) {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
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
    fn ecdsa_error_unencrypted_pem_password() {
        let content = fs::read("tests/data/keys/ecdsa_private.key").expect("read key failed.");
        let key = EcdsaKeys::from_encrypted_pem(&content, PASSWORD);
        assert!(
            key.is_err_and(|e| e
                .to_string()
                .contains("Unencrypted private key but password provided")),
            "read unencrypted key with password"
        );
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_pem() {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
        let pem = key
            .private_key_to_pem()
            .expect("export private key to PEM format failed.");
        let key2 = EcdsaKeys::from_pem(pem.as_bytes());
        assert!(key2.is_ok(), "can not create EcdsaKeys from PEM string.");
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// into pem, and decode a new key from the generated pem-encoded
    /// private key.
    #[rstest]
    #[case(PASSWORD)]
    #[case::empty_password(EMPTY_PASSWORD)]
    fn ecdsa_to_and_from_encrypted_pem(#[case] password: &[u8]) {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
        let pem = key
            .private_key_to_encrypted_pem(password)
            .expect("export private key to PEM format failed.");
        let key2 = EcdsaKeys::from_encrypted_pem(pem.as_bytes(), password);
        assert!(key2.is_ok(), "can not create EcdsaKeys from PEM string.");
    }

    /// This test will generate a EcdsaKeys, encode the private key
    /// into der, and decode a new key from the generated der-encoded
    /// private key.
    #[test]
    fn ecdsa_to_and_from_der() {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
        let der = key
            .private_key_to_der()
            .expect("export private key to DER format failed.");
        let key2 = EcdsaKeys::from_der(&der);
        assert!(key2.is_ok(), "can not create EcdsaKeys from DER bytes.");
    }

    /// This test will generate a ecdsa-P256 keypair.
    /// And then use the verification key interface to instantiate
    /// a VerificationKey object.
    #[test]
    fn ecdsa_generate_public_key() {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
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

    /// This test will generate a ecdsa-P256 keypair.
    /// And then derive a `CosignVerificationKey` from it.
    #[test]
    fn ecdsa_derive_verification_key() {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
        assert!(
            key.to_verification_key(&SigningScheme::default()).is_ok(),
            "can not create CosignVerificationKey from EcdsaKeys via `to_verification_key`."
        );
    }

    /// This test will do the following things:
    /// * Generate a ecdsa-P256 keypair.
    /// * Sign the MESSAGE with the private key using ECDSA_P256_SHA256_ASN1,
    ///   then generate a signature.
    /// * Verify the signature using the public key.
    #[test]
    fn ecdsa_sign_and_verify() {
        let key = EcdsaKeys::new(EllipticCurve::P256).expect("create ecdsa keys failed.");
        let signer = EcdsaSigner::from_ecdsa_keys(&key).expect("create signer failed.");
        let sig = signer
            .sign(MESSAGE.as_bytes())
            .expect("signing message failed.");
        let pubkey_pem = key
            .public_key_to_pem()
            .expect("export public key to PEM format failed.");
        let verification_key = CosignVerificationKey::from_pem(
            pubkey_pem.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("convert CosignVerificationKey from public key failed.");
        assert!(
            verification_key
                .verify_signature(Signature::Raw(&sig), MESSAGE.as_bytes())
                .is_ok(),
            "can not verify the signature."
        );
    }

    /// Verify that `curve_from_pkcs8_der` correctly detects the curve for each
    /// supported elliptic curve.
    #[rstest]
    #[case(EllipticCurve::P256)]
    #[case(EllipticCurve::P384)]
    #[case(EllipticCurve::P521)]
    fn curve_from_pkcs8_der_detects_curve(#[case] curve: EllipticCurve) {
        let key = EcdsaKeys::new(curve).expect("create ecdsa keys failed.");
        let der = key
            .private_key_to_der()
            .expect("export private key to DER failed.");
        let detected = curve_from_pkcs8_der(&der).expect("curve detection failed.");
        assert_eq!(detected, curve);
    }

    /// Verify that `curve_from_pkcs8_der` returns an error on garbage input.
    #[test]
    fn curve_from_pkcs8_der_invalid_der() {
        let result = curve_from_pkcs8_der(b"not valid der");
        assert!(result.is_err(), "expected error on invalid DER");
    }

    /// Verify that `curve_from_pkcs8_der` returns an error when the OID is not
    /// one of the three supported EC curves (e.g. an Ed25519 key).
    #[test]
    fn curve_from_pkcs8_der_unsupported_oid() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed.");
        let der = key
            .private_key_to_der()
            .expect("export ed25519 key to DER failed.");
        let result = curve_from_pkcs8_der(&der);
        assert!(result.is_err(), "expected error for non-EC key");
    }
}
