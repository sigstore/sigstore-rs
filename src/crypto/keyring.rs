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

use std::collections::HashMap;

use aws_lc_rs::{signature as aws_lc_rs_signature, signature::UnparsedPublicKey};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1};
use digest::Digest;
use thiserror::Error;
use x509_cert::{
    der,
    der::{Decode, Encode},
    spki::SubjectPublicKeyInfoOwned,
};

#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("malformed key")]
    KeyMalformed(#[from] x509_cert::der::Error),
    #[error("unsupported algorithm")]
    AlgoUnsupported,

    #[error("requested key not in keyring")]
    KeyNotFound,
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
    pub fn new(spki_bytes: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_bytes)?;
        let (algo, params) = if let Some(params) = &spki.algorithm.parameters {
            // Special-case RSA keys, which don't have SPKI parameters.
            if spki.algorithm.oid == RSA_ENCRYPTION && params == &der::Any::null() {
                // TODO(tnytown): Do we need to support RSA keys?
                return Err(KeyringError::AlgoUnsupported);
            };

            (spki.algorithm.oid, params.decode_as()?)
        } else {
            return Err(KeyringError::AlgoUnsupported);
        };

        match (algo, params) {
            // TODO(tnytown): should we also accept ed25519, p384, ... ?
            (ID_EC_PUBLIC_KEY, SECP_256_R_1) => Ok(Key {
                inner: UnparsedPublicKey::new(
                    &aws_lc_rs_signature::ECDSA_P256_SHA256_ASN1,
                    spki.subject_public_key.raw_bytes().to_owned(),
                ),
                fingerprint: {
                    let mut hasher = sha2::Sha256::new();
                    spki.encode(&mut hasher).expect("failed to hash key!");
                    hasher.finalize().into()
                },
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
    pub fn new<'a>(keys: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        Ok(Self(
            keys.into_iter()
                .flat_map(Key::new)
                .map(|k| Ok((k.fingerprint, k)))
                .collect::<Result<_>>()?,
        ))
    }

    /// Verifies `data` against a `signature` with a public key identified by `key_id`.
    pub fn verify(&self, key_id: &[u8; 32], signature: &[u8], data: &[u8]) -> Result<()> {
        let key = self.0.get(key_id).ok_or(KeyringError::KeyNotFound)?;

        key.inner
            .verify(data, signature)
            .or(Err(KeyringError::VerificationFailed))?;

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
