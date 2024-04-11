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

use std::str::FromStr;

use crate::{
    bundle::{models::Version as BundleVersion, Bundle},
    crypto::certificate::{is_leaf, is_root_ca, CertificateValidationError},
    rekor::models as rekor,
};

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{bundle, verification_material},
    rekor::v1::{InclusionProof, TransparencyLogEntry},
};
use thiserror::Error;
use tracing::{debug, error, warn};
use x509_cert::{
    der::{Decode, EncodePem},
    Certificate,
};

use super::policy::PolicyError;

#[derive(Error, Debug)]
pub enum Bundle01ProfileErrorKind {
    #[error("bundle must contain inclusion promise")]
    InclusionPromiseMissing,
}

#[derive(Error, Debug)]
pub enum Bundle02ProfileErrorKind {
    #[error("bundle must contain inclusion proof")]
    InclusionProofMissing,

    #[error("bundle must contain checkpoint")]
    CheckpointMissing,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum BundleProfileErrorKind {
    Bundle01Profile(#[from] Bundle01ProfileErrorKind),

    Bundle02Profile(#[from] Bundle02ProfileErrorKind),

    #[error("unknown bundle profile {0}")]
    Unknown(String),
}

#[derive(Error, Debug)]
pub enum BundleErrorKind {
    #[error("bundle missing VerificationMaterial")]
    VerificationMaterialMissing,

    #[error("bundle includes unsupported VerificationMaterial::Content")]
    VerificationMaterialContentUnsupported,

    #[error("bundle's certificate(s) are malformed")]
    CertificateMalformed(#[source] x509_cert::der::Error),

    #[error("bundle contains a root certificate")]
    RootInChain,

    #[error("bundle does not contain the signing (leaf) certificate")]
    NoLeaf(#[source] CertificateValidationError),

    #[error("bundle does not contain any certificates")]
    CertificatesMissing,

    #[error("bundle does not contain signature")]
    SignatureMissing,

    #[error("bundle includes unsupported DSSE signature")]
    DsseUnsupported,

    #[error("bundle needs 1 tlog entry, got {0}")]
    TlogEntry(usize),

    #[error(transparent)]
    BundleProfile(#[from] BundleProfileErrorKind),
}

#[derive(Error, Debug)]
pub enum CertificateErrorKind {
    #[error("certificate malformed")]
    Malformed(#[source] webpki::Error),

    #[error("certificate expired before time of signing")]
    Expired,

    #[error("certificate verification failed")]
    VerificationFailed(#[source] webpki::Error),
}

#[derive(Error, Debug)]
pub enum SignatureErrorKind {
    #[error("unsupported signature algorithm")]
    AlgoUnsupported(#[source] crate::errors::SigstoreError),

    #[error("signature verification failed")]
    VerificationFailed(#[source] crate::errors::SigstoreError),

    #[error("signature transparency materials are inconsistent")]
    Transparency,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum VerificationError {
    #[error("unable to read input")]
    Input(#[source] std::io::Error),

    Bundle(#[from] BundleErrorKind),

    Certificate(#[from] CertificateErrorKind),

    Signature(#[from] SignatureErrorKind),

    Policy(#[from] PolicyError),
}

pub type VerificationResult = Result<(), VerificationError>;

pub struct CheckedBundle {
    pub(crate) certificate: Certificate,
    pub(crate) signature: Vec<u8>,

    tlog_entry: TransparencyLogEntry,
}

impl TryFrom<Bundle> for CheckedBundle {
    type Error = BundleErrorKind;

    fn try_from(input: Bundle) -> Result<Self, Self::Error> {
        let (content, mut tlog_entries) = match input.verification_material {
            Some(m) => (m.content, m.tlog_entries),
            _ => return Err(BundleErrorKind::VerificationMaterialMissing),
        };

        // Parse the certificates. The first entry in the chain MUST be a leaf certificate, and the
        // rest of the chain MUST NOT include a root CA or any intermediate CAs that appear in an
        // independent root of trust.
        let certs = match content {
            Some(verification_material::Content::X509CertificateChain(ch)) => ch.certificates,
            Some(verification_material::Content::Certificate(cert)) => {
                vec![cert]
            }
            _ => return Err(BundleErrorKind::VerificationMaterialContentUnsupported),
        };
        let certs = certs
            .iter()
            .map(|c| c.raw_bytes.as_slice())
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(BundleErrorKind::CertificateMalformed)?;

        let [leaf_cert, chain_certs @ ..] = &certs[..] else {
            return Err(BundleErrorKind::CertificatesMissing);
        };

        is_leaf(leaf_cert).map_err(BundleErrorKind::NoLeaf)?;

        for chain_cert in chain_certs {
            if is_root_ca(chain_cert).is_ok() {
                return Err(BundleErrorKind::RootInChain);
            }
        }

        let signature = match input.content.ok_or(BundleErrorKind::SignatureMissing)? {
            bundle::Content::MessageSignature(s) => s.signature,
            _ => return Err(BundleErrorKind::DsseUnsupported),
        };

        if tlog_entries.len() != 1 {
            return Err(BundleErrorKind::TlogEntry(tlog_entries.len()));
        }
        let tlog_entry = tlog_entries.remove(0);

        let (inclusion_promise, inclusion_proof) =
            (&tlog_entry.inclusion_promise, &tlog_entry.inclusion_proof);

        // `inclusion_proof` is a required field in the current protobuf spec,
        // but older versions of Rekor didn't provide it. Check invariants
        // here and selectively allow for this case.
        //
        // https://github.com/sigstore/sigstore-python/pull/634#discussion_r1182769140
        let check_01_bundle = || -> Result<(), BundleProfileErrorKind> {
            if inclusion_promise.is_none() {
                return Err(Bundle01ProfileErrorKind::InclusionPromiseMissing)?;
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

            Ok(())
        };
        let check_02_bundle = || -> Result<(), BundleProfileErrorKind> {
            if inclusion_proof.is_none() {
                error!("bundle must contain inclusion proof");
                return Err(Bundle02ProfileErrorKind::InclusionProofMissing)?;
            }

            if matches!(
                inclusion_proof,
                Some(InclusionProof {
                    checkpoint: None,
                    ..
                })
            ) {
                error!("bundle must contain checkpoint");
                return Err(Bundle02ProfileErrorKind::CheckpointMissing)?;
            }

            Ok(())
        };
        match BundleVersion::from_str(&input.media_type) {
            Ok(BundleVersion::Bundle0_1) => check_01_bundle()?,
            Ok(BundleVersion::Bundle0_2) => check_02_bundle()?,
            Err(_) => return Err(BundleProfileErrorKind::Unknown(input.media_type))?,
        }

        Ok(Self {
            certificate: leaf_cert.clone(),
            signature,
            tlog_entry,
        })
    }
}

impl CheckedBundle {
    /// Retrieves and checks consistency of the bundle's [TransparencyLogEntry].
    pub fn tlog_entry(&self, offline: bool, input_digest: &[u8]) -> Option<&TransparencyLogEntry> {
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
                        value: hex::encode(input_digest),
                    },
                },
            },
        };

        let entry = if !offline && self.tlog_entry.inclusion_proof.is_none() {
            warn!("online rekor fetching is not implemented yet, but is necessary for this bundle");
            return None;
        } else {
            &self.tlog_entry
        };

        let actual: serde_json::Value =
            serde_json::from_slice(&self.tlog_entry.canonicalized_body).ok()?;
        let expected: serde_json::Value = serde_json::to_value(expected_entry).ok()?;

        if actual != expected {
            return None;
        }

        Some(entry)
    }
}
