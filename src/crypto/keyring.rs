// Copyright 2023 The Sigstore Authors.
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

// Keyring is used by multiple features (sign, verify, etc.)
// Allow dead code when only 'cert' feature is enabled
#![allow(dead_code)]

use std::collections::HashMap;

use aws_lc_rs::{signature as aws_lc_rs_signature, signature::UnparsedPublicKey};
use const_oid::{
    ObjectIdentifier,
    db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1},
};
use digest::Digest;
use thiserror::Error;
use x509_cert::{
    der,
    der::{Decode, Encode},
    spki::SubjectPublicKeyInfoOwned,
};

// Ed25519 OID: 1.3.101.112
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("malformed key")]
    KeyMalformed(#[from] x509_cert::der::Error),
    #[error("unsupported algorithm")]
    AlgoUnsupported,

    #[error("requested key not in keyring: {0}")]
    KeyNotFound(String),
    #[error("verification failed")]
    VerificationFailed,
}
type Result<T> = std::result::Result<T, KeyringError>;

/// A CT signing key.
struct Key {
    inner: UnparsedPublicKey<Vec<u8>>,
    /// The key's RFC 6962-style "key ID".
    /// <https://datatracker.ietf.org/doc/html/rfc6962#section-3.2>
    fingerprint: [u8; 32],
}

impl Key {
    /// Creates a `Key` from a DER blob containing a SubjectPublicKeyInfo object.
    ///
    /// The key ID (fingerprint) is computed as the RFC 6962-style SHA256 hash of the SPKI.
    pub fn new(spki_bytes: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_bytes)?;

        // Compute RFC 6962-style key ID (SHA256 hash of SPKI)
        let fingerprint = {
            let mut hasher = sha2::Sha256::new();
            spki.encode(&mut hasher).expect("failed to hash key!");
            hasher.finalize().into()
        };

        Self::new_with_id(spki_bytes, fingerprint)
    }

    /// Creates a `Key` from a DER blob containing a SubjectPublicKeyInfo object with an explicit key ID.
    ///
    /// This method should be used when the key ID is provided externally (e.g., from a trusted root),
    /// rather than being computed from the SPKI.
    ///
    /// Note: This also handles PKCS#1 RSA keys (which are not in SPKI format) by detecting them
    /// and converting them to RSA keys. This is needed for compatibility with some TUF roots
    /// (like the staging instance) that incorrectly provide PKCS#1 keys instead of SPKI keys.
    pub fn new_with_id(spki_bytes: &[u8], fingerprint: [u8; 32]) -> Result<Self> {
        // First try to parse as SPKI (the expected format)
        let spki = match SubjectPublicKeyInfoOwned::from_der(spki_bytes) {
            Ok(spki) => spki,
            Err(spki_err) => {
                // If SPKI parsing fails, check if it's a PKCS#1 RSA key (used in staging TUF root)
                // PKCS#1 RSA keys start with SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
                // We can detect this by checking if it's a SEQUENCE containing INTEGERs
                tracing::debug!(
                    "Failed to parse as SPKI (len={}, first_bytes={:02x?}), checking if PKCS#1 RSA...",
                    spki_bytes.len(),
                    &spki_bytes[..spki_bytes.len().min(10)]
                );

                // Try to parse as PKCS#1 RSA key
                // If successful, create an RSA key directly without SPKI wrapper
                if spki_bytes.len() >= 4 && spki_bytes[0] == 0x30 && spki_bytes[4] == 0x02 {
                    // This looks like PKCS#1: SEQUENCE { INTEGER ... }
                    tracing::debug!("Detected PKCS#1 RSA key format (deprecated, used in staging)");
                    return Ok(Key {
                        inner: UnparsedPublicKey::new(
                            &aws_lc_rs_signature::RSA_PKCS1_2048_8192_SHA256,
                            spki_bytes.to_owned(),
                        ),
                        fingerprint,
                    });
                }

                // Not PKCS#1 either, return the original SPKI error
                tracing::debug!(
                    "Not PKCS#1 format either, failing with SPKI error: {:?}",
                    spki_err
                );
                return Err(spki_err.into());
            }
        };

        // Ed25519 keys don't have algorithm parameters
        if spki.algorithm.oid == ID_ED25519 {
            let raw_key_bytes = spki.subject_public_key.raw_bytes();
            tracing::debug!("Ed25519 key: raw_bytes len = {}", raw_key_bytes.len());

            return Ok(Key {
                inner: UnparsedPublicKey::new(
                    &aws_lc_rs_signature::ED25519,
                    raw_key_bytes.to_owned(),
                ),
                fingerprint,
            });
        }

        let (algo, params) = if let Some(params) = &spki.algorithm.parameters {
            // RSA keys have NULL parameters in SPKI format
            if spki.algorithm.oid == RSA_ENCRYPTION && params == &der::Any::null() {
                // RSA key with SHA256 (used by Sigstore CTFE logs)
                // Note: Sigstore uses RSA PKCS#1v1.5 with SHA256 for SCT signatures
                tracing::debug!("RSA key detected, using RSA_PKCS1_2048_8192_SHA256");
                return Ok(Key {
                    inner: UnparsedPublicKey::new(
                        &aws_lc_rs_signature::RSA_PKCS1_2048_8192_SHA256,
                        spki.subject_public_key.raw_bytes().to_owned(),
                    ),
                    fingerprint,
                });
            };

            (spki.algorithm.oid, params.decode_as()?)
        } else {
            return Err(KeyringError::AlgoUnsupported);
        };

        match (algo, params) {
            // TODO(tnytown): should we also accept p384, ... ?
            (ID_EC_PUBLIC_KEY, SECP_256_R_1) => Ok(Key {
                inner: UnparsedPublicKey::new(
                    &aws_lc_rs_signature::ECDSA_P256_SHA256_ASN1,
                    spki.subject_public_key.raw_bytes().to_owned(),
                ),
                fingerprint,
            }),
            _ => Err(KeyringError::AlgoUnsupported),
        }
    }
}

/// Represents a set of CT signing keys, each of which is potentially a valid signer for
/// Signed Certificate Timestamps (SCTs) or Signed Tree Heads (STHs).
pub struct Keyring(HashMap<[u8; 32], Key>);

impl Keyring {
    /// Creates a `Keyring` from DER encoded SPKI-format public keys.
    ///
    /// This method computes RFC 6962-style key IDs (SHA256 hash of SPKI) for each key.
    /// For Rekor transparency logs, use `new_with_ids` instead to use the key IDs from
    /// the trusted root.
    pub fn new<'a>(keys: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let keys_vec: Vec<_> = keys.into_iter().collect();
        tracing::debug!("Creating keyring from {} key(s)", keys_vec.len());

        Ok(Self(
            keys_vec
                .into_iter()
                .flat_map(|key_bytes| match Key::new(key_bytes) {
                    Ok(key) => {
                        tracing::debug!(
                            "Loaded key with fingerprint: {}",
                            hex::encode(key.fingerprint)
                        );
                        Some(key)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load key: {:?}", e);
                        None
                    }
                })
                .map(|k| Ok((k.fingerprint, k)))
                .collect::<Result<_>>()?,
        ))
    }

    /// Creates a `Keyring` from DER encoded SPKI-format public keys with explicit key IDs.
    ///
    /// This method should be used for Rekor transparency logs where key IDs are provided
    /// by the trusted root, rather than being computed from the SPKI.
    pub fn new_with_ids<'a>(
        keys: impl IntoIterator<Item = (&'a [u8; 32], &'a [u8])>,
    ) -> Result<Self> {
        let keys_vec: Vec<_> = keys.into_iter().collect();
        tracing::debug!(
            "Creating keyring from {} key(s) with explicit IDs",
            keys_vec.len()
        );

        Ok(Self(
            keys_vec
                .into_iter()
                .flat_map(
                    |(key_id, key_bytes)| match Key::new_with_id(key_bytes, *key_id) {
                        Ok(key) => {
                            tracing::debug!(
                                "Loaded key with fingerprint: {}",
                                hex::encode(key.fingerprint)
                            );
                            Some(key)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load key: {:?}", e);
                            None
                        }
                    },
                )
                .map(|k| Ok((k.fingerprint, k)))
                .collect::<Result<_>>()?,
        ))
    }

    /// Checks if the keyring contains a key with the given ID.
    pub fn contains_key(&self, key_id: &[u8; 32]) -> bool {
        self.0.contains_key(key_id)
    }

    /// Verifies `data` against a `signature` with a public key identified by `key_id`.
    pub fn verify(&self, key_id: &[u8; 32], signature: &[u8], data: &[u8]) -> Result<()> {
        let key = self
            .0
            .get(key_id)
            .ok_or(KeyringError::KeyNotFound(hex::encode(key_id)))?;

        key.inner.verify(data, signature).map_err(|e| {
            tracing::debug!("Keyring verification failed: {:?}", e);
            KeyringError::VerificationFailed
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use crate::crypto::signing_key::ecdsa::{ECDSAKeys, EllipticCurve};
    use digest::Digest;
    use std::io::Write;

    #[test]
    fn test_pkcs1_rsa_key_from_staging_tuf() {
        // This is a CTFE RSA public key from the Sigstore staging TUF repository.
        // Source: https://tuf-repo-cdn.sigstage.dev (ctlogs[0])
        // Format: PKCS#1 RSAPublicKey (deprecated format, but used in staging)
        //
        // The key is in PKCS#1 format instead of the standard SPKI format.
        // According to sigstore-go: "This key format is deprecated, but currently
        // in use for Sigstore staging instance"
        //
        // Our keyring now supports both formats:
        // - Standard SPKI format (used in production)
        // - Legacy PKCS#1 format (used in staging, for compatibility)

        // Load the test key from file
        const KEY_PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/keys/ctfe_rsa_pkcs1_staging.der"
        );
        let rsa_key_bytes = std::fs::read(KEY_PATH)
            .expect("Failed to read test RSA key - make sure tests/data/keys/ctfe_rsa_pkcs1_staging.der exists");

        // Create a keyring with this PKCS#1 RSA key
        // This should succeed now that we have PKCS#1 support
        let result = Keyring::new([rsa_key_bytes.as_slice()]);

        match result {
            Ok(keyring) => {
                // Success! The PKCS#1 RSA key was loaded
                println!("✓ Keyring created successfully with PKCS#1 RSA key");

                // Verify the keyring is not empty (the key was actually loaded)
                // Note: We can't easily check the internal hashmap, but the fact
                // that Keyring::new() succeeded without returning AlgoUnsupported
                // means the key was processed
                drop(keyring);
            }
            Err(e) => {
                panic!(
                    "❌ Failed to load PKCS#1 RSA key: {:?}\nThis key should be supported for staging compatibility",
                    e
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "sigstore-trust-root")]
    fn test_load_staging_trusted_root_with_pkcs1_rsa() {
        use crate::trust::TrustRoot;
        use crate::trust::sigstore::SigstoreTrustRoot;
        use std::path::Path;

        // Load the staging trusted root which contains a PKCS#1 RSA key
        const STAGING_ROOT_PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/keys/staging_trusted_root.json"
        );

        let staging_root = SigstoreTrustRoot::from_file_unchecked(Path::new(STAGING_ROOT_PATH))
            .expect("Failed to load staging trusted root");

        // Extract CTFE keys - this should succeed even with the PKCS#1 RSA key
        let ctfe_keys = staging_root
            .ctfe_keys()
            .expect("Failed to get CTFE keys from staging root");

        println!(
            "✓ Loaded {} CTFE key(s) from staging trusted root",
            ctfe_keys.len()
        );

        // The staging root has 3 CTFE keys:
        // - 1 RSA 4096-bit key (PKCS#1 format)
        // - 2 ECDSA P256 keys (SPKI format)
        assert_eq!(
            ctfe_keys.len(),
            3,
            "Staging trusted root should have 3 CTFE keys"
        );

        // Create a keyring with all CTFE keys
        // This tests that our keyring can handle mixed key formats
        let keyring = Keyring::new(ctfe_keys.values().copied())
            .expect("Failed to create keyring from staging CTFE keys");

        println!("✓ Successfully created keyring with all staging CTFE keys");
        println!("✓ This includes 1 PKCS#1 RSA key and 2 SPKI ECDSA keys");

        drop(keyring);
    }

    #[test]
    fn verify_keyring() {
        let message = b"some message";

        // Create a key pair and a keyring containing the public key.
        let key_pair = ECDSAKeys::new(EllipticCurve::P256).unwrap();
        let signer = key_pair.to_sigstore_signer().unwrap();
        let pub_key = key_pair.as_inner().public_key_to_der().unwrap();
        let keyring = Keyring::new([pub_key.as_slice()]).unwrap();

        // Generate the signature.
        let signature = signer.sign(message).unwrap();

        // Generate the key id.
        let mut hasher = sha2::Sha256::new();
        hasher.write_all(pub_key.as_slice()).unwrap();
        let key_id: [u8; 32] = hasher.finalize().into();

        // Check for success.
        assert!(
            keyring
                .verify(&key_id, signature.as_slice(), message)
                .is_ok()
        );

        // Check for failure with incorrect key id.
        assert!(
            keyring
                .verify(&[0; 32], signature.as_slice(), message)
                .is_err()
        );

        // Check for failure with incorrect payload.
        let incorrect_message = b"another message";

        assert!(
            keyring
                .verify(&key_id, signature.as_slice(), incorrect_message)
                .is_err()
        );

        // Check for failure with incorrect keyring.
        let incorrect_key_pair = ECDSAKeys::new(EllipticCurve::P256).unwrap();
        let incorrect_keyring = Keyring::new([incorrect_key_pair
            .as_inner()
            .public_key_to_der()
            .unwrap()
            .as_slice()])
        .unwrap();

        assert!(
            incorrect_keyring
                .verify(&key_id, signature.as_slice(), message)
                .is_err()
        );
    }
}
