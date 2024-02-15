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
    io::{self, Read},
    str::FromStr,
};

use crate::{
    bundle::Version as BundleVersion,
    crypto::certificate::{is_leaf, is_root_ca},
    rekor::models as rekor,
};

use crate::Bundle;
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use pkcs8::der::{Decode, EncodePem};
use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{bundle, verification_material},
    rekor::v1::{InclusionProof, TransparencyLogEntry},
};
use thiserror::Error;
use tracing::{debug, error, warn};
use x509_cert::Certificate;

use super::policy::PolicyError;

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

    #[error(transparent)]
    PolicyFailure(#[from] PolicyError),
}
pub type VerificationResult = Result<(), VerificationError>;

pub struct VerificationMaterials {
    pub(crate) input_digest: Vec<u8>,
    pub(crate) certificate: Certificate,
    pub(crate) signature: Vec<u8>,
    rekor_entry: TransparencyLogEntry,

    offline: bool,
}

impl VerificationMaterials {
    pub fn new<R: Read>(
        input: &mut R,
        certificate: Certificate,
        signature: Vec<u8>,
        offline: bool,
        rekor_entry: TransparencyLogEntry,
    ) -> Option<VerificationMaterials> {
        let mut hasher = Sha256::new();
        io::copy(input, &mut hasher).ok()?;

        if matches!(
            rekor_entry,
            TransparencyLogEntry {
                inclusion_promise: None,
                inclusion_proof: None,
                ..
            }
        ) {
            error!("encountered TransparencyLogEntry without any inclusion materials");
            return None;
        }

        Some(Self {
            input_digest: hasher.finalize().to_vec(),
            rekor_entry,
            certificate,
            signature,
            offline,
        })
    }

    /// Constructs a VerificationMaterials from the given Bundle.
    ///
    /// For details on bundle semantics, please refer to [VerificationMaterial].
    ///
    /// [VerificationMaterial]: sigstore_protobuf_specs::dev::sigstore::bundle::v1::VerificationMaterial
    pub fn from_bundle<R: Read>(input: &mut R, bundle: Bundle, offline: bool) -> Option<Self> {
        let (content, mut tlog_entries) = match bundle.verification_material {
            Some(m) => (m.content, m.tlog_entries),
            _ => {
                error!("bundle missing VerificationMaterial");
                return None;
            }
        };

        // Parse the certificates. The first entry in the chain MUST be a leaf certificate, and the
        // rest of the chain MUST NOT include a root CA or any intermediate CAs that appear in an
        // independent root of trust.
        let certs = match content {
            Some(verification_material::Content::X509CertificateChain(ch)) => ch.certificates,
            Some(verification_material::Content::Certificate(cert)) => {
                vec![cert]
            }
            _ => {
                error!("bundle includes unsupported VerificationMaterial Content");
                return None;
            }
        };
        let certs = certs
            .iter()
            .map(|c| c.raw_bytes.as_slice())
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

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

        let signature = match bundle.content? {
            bundle::Content::MessageSignature(s) => s.signature,
            _ => {
                error!("bundle includes unsupported DSSE signature");
                return None;
            }
        };

        if tlog_entries.len() != 1 {
            error!("bundle expected 1 tlog entry; got {}", tlog_entries.len());
            return None;
        }
        let tlog_entry = tlog_entries.remove(0);

        let (inclusion_promise, inclusion_proof) =
            (&tlog_entry.inclusion_promise, &tlog_entry.inclusion_proof);

        // `inclusion_proof` is now a required field in the protobuf spec,
        // but older versions of Rekor didn't provide inclusion proofs.
        //
        // https://github.com/sigstore/sigstore-python/pull/634#discussion_r1182769140
        match BundleVersion::from_str(&bundle.media_type) {
            Ok(BundleVersion::Bundle0_1) => {
                if inclusion_promise.is_none() {
                    error!("bundle must contain inclusion promise");
                    return None;
                }

                if matches!(
                    inclusion_proof,
                    Some(InclusionProof {
                        checkpoint: None,
                        ..
                    })
                ) {
                    debug!("0.1 bundle contains inclusion proof without checkpoint");
                }
            }
            Ok(BundleVersion::Bundle0_2) => {
                if inclusion_proof.is_none() {
                    error!("bundle must contain inclusion proof");
                    return None;
                }

                if matches!(
                    inclusion_proof,
                    Some(InclusionProof {
                        checkpoint: None,
                        ..
                    })
                ) {
                    error!("bundle must contain checkpoint");
                    return None;
                }
            }
            Err(_) => {
                error!("unknown bundle version");
                return None;
            }
        }

        Self::new(input, leaf_cert.clone(), signature, offline, tlog_entry)
    }

    /// Retrieves the [LogEntry] for the materials.
    pub fn rekor_entry(&self) -> Option<&TransparencyLogEntry> {
        let base64_pem_certificate =
            base64.encode(self.certificate.to_pem(pkcs8::LineEnding::LF).ok()?);

        let expected_entry = rekor::Hashedrekord {
            kind: "hashedrekord".to_owned(),
            api_version: "0.0.1".to_owned(),
            spec: rekor::hashedrekord::Spec {
                signature: rekor::hashedrekord::Signature {
                    content: base64.encode(&self.signature),
                    public_key: rekor::hashedrekord::PublicKey::new(base64_pem_certificate),
                },
                data: rekor::hashedrekord::Data {
                    hash: rekor::hashedrekord::Hash {
                        algorithm: rekor::hashedrekord::AlgorithmKind::sha256,
                        value: hex::encode(&self.input_digest),
                    },
                },
            },
        };

        let entry = if !self.offline && self.rekor_entry.inclusion_proof.is_none() {
            warn!("online rekor fetching is not implemented yet, but is necessary for this bundle");
            return None;
        } else {
            &self.rekor_entry
        };

        let actual: serde_json::Value =
            serde_json::from_slice(&self.rekor_entry.canonicalized_body).ok()?;
        let expected: serde_json::Value = serde_json::to_value(expected_entry).ok()?;

        if actual != expected {
            return None;
        }

        Some(entry)
    }
}
