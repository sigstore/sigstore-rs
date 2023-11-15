//
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

use std::{
    cell::OnceCell,
    io::{self, Read},
};

use crate::{
    bundle::required,
    bundle::Version as BundleVersion,
    crypto::certificate::{is_leaf, is_root_ca},
    errors::SigstoreError,
    rekor::models::log_entry,
    rekor::models::{
        log_entry::{InclusionProof, Verification},
        LogEntry,
    },
};

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use pkcs8::der::Decode;
use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::Bundle;
use thiserror::Error;
use x509_cert::Certificate;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Certificate expired before time of signing")]
    CertificateExpired,

    #[error("Certificate malformed")]
    CertificateMalformed,

    #[error("Failed to verify certificate")]
    CertificateVerificationFailure,

    #[error("Certificate cannot be used for verification: {0}")]
    CertificateTypeError(String),

    #[error("Failed to verify that the signature corresponds to the input")]
    SignatureVerificationFailure,

    #[error("{0}")]
    PolicyFailure(String),
}
pub type VerificationResult = Result<(), VerificationError>;

pub struct VerificationMaterials {
    pub input_digest: Vec<u8>,
    pub certificate: Certificate,
    pub signature: Vec<u8>,
    rekor_entry: OnceCell<LogEntry>,
}

impl VerificationMaterials {
    pub fn new<R: Read>(
        input: &mut R,
        certificate: Certificate,
        signature: Vec<u8>,
        offline: bool,
        rekor_entry: Option<LogEntry>,
    ) -> Option<VerificationMaterials> {
        let mut hasher = Sha256::new();
        io::copy(input, &mut hasher).ok()?;

        if offline && rekor_entry.is_none() {
            // offline verification requires a Rekor entry
            return None;
        }

        let rekor_entry = if let Some(rekor_entry) = rekor_entry {
            let cell = OnceCell::new();

            // TODO(tnytown): Switch to setting if offline when Rekor fetching is implemented.
            cell.set(rekor_entry).unwrap();

            cell
        } else {
            Default::default()
        };

        Some(Self {
            input_digest: hasher.finalize().to_vec(),
            rekor_entry,
            certificate,
            signature,
        })
    }

    /// Constructs a VerificationMaterials from the given Bundle.
    ///
    /// For details on bundle semantics, please refer to [VerificationMaterial].
    ///
    /// [VerificationMaterial]: sigstore_protobuf_specs::DevSigstoreBundleV1VerificationMaterial
    ///
    /// TODO(tnytown): Determine if this type should yield SigstoreResult.
    pub fn from_bundle<R: Read>(input: &mut R, bundle: Bundle, offline: bool) -> Option<Self> {
        fn certificate_from_base64(encoded: &str) -> Option<Certificate> {
            Certificate::from_der(&base64.decode(encoded).ok()?).ok()
        }

        let certs = required!(
            bundle;
            verification_material.x_509_certificate_chain.certificates,
            SigstoreError::SigstoreBundleMalformedError("Cannot find required field in bundle".to_string())
        ).ok()?;

        // Parse the certificates. The first entry in the chain MUST be a leaf certificate, and the
        // rest of the chain MUST NOT include a root CA or any intermediate CAs that appear in an
        // independent root of trust.
        let certs = certs
            .iter()
            .map(|cert| certificate_from_base64(cert.raw_bytes.as_ref()?))
            .collect::<Option<Vec<Certificate>>>()?;
        let [leaf_cert, chain_certs @ ..] = &certs[..] else {
            return None;
        };

        if is_leaf(leaf_cert).is_err() {
            return None;
        }

        for chain_cert in chain_certs {
            if is_root_ca(chain_cert).is_ok() {
                return None;
            }
        }

        let signature = base64
            .decode(required!(bundle; message_signature.signature)?)
            .ok()?;
        let tlog_entries = required!(bundle; verification_material.tlog_entries)?;
        if tlog_entries.len() != 1 {
            // Expected exactly one tlog entry.
            return None;
        }
        let tlog_entry = &tlog_entries[0];

        let inclusion_promise = &tlog_entry.inclusion_promise;
        let inclusion_proof = tlog_entry.inclusion_proof.as_ref();

        let has_checkpoint = required!(; inclusion_proof.checkpoint.envelope).is_some();
        match bundle.media_type?.as_str().try_into().ok()? {
            BundleVersion::Bundle0_1 => {
                if inclusion_promise.is_none() {
                    // 0.1 bundle must contain inclusion promise
                    return None;
                }

                if inclusion_proof.is_some() && !has_checkpoint {
                    // TODO(tnytown): Act here.
                }
            }
            BundleVersion::Bundle0_2 => {
                if inclusion_proof.is_none() {
                    // 0.2 bundle must contain inclusion proof
                    return None;
                }
                if !has_checkpoint {
                    // inclusion proofs must contain checkpoints
                    return None;
                }
            }
        }

        let parsed_inclusion_proof = if inclusion_proof.is_some() && has_checkpoint {
            Some(InclusionProof {
                checkpoint: required!(; inclusion_proof.checkpoint.envelope)?.clone(),
                hashes: required!(; inclusion_proof.hashes)?.clone(),
                log_index: required!(; inclusion_proof.log_index)?.parse().ok()?,
                root_hash: required!(; inclusion_proof.log_index)?.clone(),
                tree_size: required!(; inclusion_proof.tree_size)?.parse().ok()?,
            })
        } else {
            None
        };

        let canonicalized_body = {
            let decoded = base64
                .decode(tlog_entry.canonicalized_body.as_ref()?)
                .ok()?;
            serde_json::from_slice(&decoded).ok()?
        };
        // required!(tlog_entry; log_id.key_id)?.clone();
        let entry = LogEntry {
            uuid: "".to_string(),
            body: log_entry::Body::hashedrekord(canonicalized_body),
            attestation: None,
            integrated_time: required!(tlog_entry; integrated_time)?.parse().ok()?,
            log_i_d: "".into(),
            log_index: required!(tlog_entry; log_index)?.parse().ok()?,
            verification: Verification {
                inclusion_proof: parsed_inclusion_proof,
                signed_entry_timestamp: required!(; inclusion_promise.signed_entry_timestamp)?
                    .clone(),
            },
        };

        Self::new(input, leaf_cert.clone(), signature, offline, Some(entry))
    }

    /// Retrieves the [LogEntry] for the materials.
    pub fn rekor_entry(&self) -> &LogEntry {
        // TODO(tnytown): Fetch online Rekor entry, confirm consistency, and get_or_init here.
        self.rekor_entry.get().unwrap()
    }
}
