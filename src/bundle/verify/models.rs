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
    bundle::{Bundle, models::Version as BundleVersion},
    crypto::certificate::{CertificateValidationError, is_leaf, is_root_ca},
    rekor::models as rekor,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{bundle, verification_material},
    rekor::v1::{InclusionProof, TransparencyLogEntry},
};
use thiserror::Error;
use tracing::{debug, error, warn};
use x509_cert::{
    Certificate,
    der::{Decode, EncodePem},
};

use super::policy::PolicyError;

/// Computes the DSSE Pre-Authentication Encoding (PAE) for the given payload type and payload.
///
/// PAE is the canonical byte string that is actually signed in a DSSE envelope.
/// It encodes both the payload type and payload length to prevent cross-protocol attacks:
///
/// ```text
/// DSSEv1 <len(type)> <type> <len(payload)> <payload>
/// ```
///
/// See <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>.
pub(crate) fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut result = header.into_bytes();
    result.extend_from_slice(payload);
    result
}

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

    #[error("DSSE envelope must have exactly 1 signature, got {0}")]
    DsseInvalidSignatureCount(usize),

    #[error("DSSE envelope payload cannot be decoded")]
    DssePayloadDecode,

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

    #[error("certificate SCT verification failed")]
    Sct(#[source] crate::crypto::transparency::SCTError),

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

/// Describes how to verify the signature in a [`CheckedBundle`].
#[derive(Debug)]
pub(crate) enum BundleContent {
    /// Classic message signature: `signature` is verified via `verify_prehash(sig, hash(input))`.
    MessageSignature,
    /// DSSE envelope: `signature` is verified via `verify_signature(sig, PAE)` where `signed_data`
    /// holds the PAE bytes.  The `input_digest` from the caller is compared against the
    /// subject digest in the in-toto statement rather than being used for signature verification.
    Dsse {
        /// The DSSE Pre-Authentication Encoding bytes (what was actually signed).
        pae: Vec<u8>,
        /// The sha-256 hex digest extracted from the in-toto statement subject.
        subject_sha256_digest: String,
        /// Canonical JSON serialization of the DSSE envelope (used to verify `envelopeHash`
        /// in the tlog body consistency check).
        envelope_json: Vec<u8>,
        /// Raw payload bytes from the DSSE envelope (used to verify `payloadHash`).
        payload_bytes: Vec<u8>,
    },
}

pub struct CheckedBundle {
    pub(crate) certificate: Certificate,
    pub(crate) signature: Vec<u8>,
    pub(crate) content: BundleContent,

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

        let (signature, bundle_content) = match input
            .content
            .ok_or(BundleErrorKind::SignatureMissing)?
        {
            bundle::Content::MessageSignature(s) => (s.signature, BundleContent::MessageSignature),
            bundle::Content::DsseEnvelope(dsse) => {
                // Serialize the DSSE envelope to canonical JSON for envelopeHash
                // verification.
                // Must happen before .into_iter() consumes signatures below.
                let envelope_json =
                    serde_json::to_vec(&dsse).map_err(|_| BundleErrorKind::DssePayloadDecode)?;

                // The signature inside the envelope is raw bytes (not base64 in the
                // protobuf representation). Spec requires exactly one signature —
                // reject if count != 1.
                if dsse.signatures.len() != 1 {
                    return Err(BundleErrorKind::DsseInvalidSignatureCount(
                        dsse.signatures.len(),
                    ));
                }
                let sig = dsse
                    .signatures
                    .into_iter()
                    .next()
                    .map(|s| s.sig)
                    .expect("sig count already checked to be 1");

                // Compute the DSSE PAE from the in-memory (raw bytes) payload.
                let pae = compute_pae(&dsse.payload_type, &dsse.payload);

                // Extract the subject sha256 digest from the in-toto statement.
                let subject_sha256_digest = extract_dsse_subject_sha256(&dsse.payload)
                    .ok_or(BundleErrorKind::DssePayloadDecode)?;

                let payload_bytes = dsse.payload;

                (
                    sig,
                    BundleContent::Dsse {
                        pae,
                        subject_sha256_digest,
                        envelope_json,
                        payload_bytes,
                    },
                )
            }
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
            // Bundle v0.3 requires a full inclusion proof with checkpoint, same as v0.2.
            // The Sigstore bundle protobuf spec (`tlog_entries` field comment) states that
            // only v0.1 bundles MAY use an inclusion promise without a proof; v0.2 and later
            // MUST include a full inclusion proof with checkpoint.
            // https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
            Ok(BundleVersion::Bundle0_3) => check_02_bundle()?,
            Err(_) => return Err(BundleProfileErrorKind::Unknown(input.media_type))?,
        }

        Ok(Self {
            certificate: leaf_cert.clone(),
            signature,
            content: bundle_content,
            tlog_entry,
        })
    }
}

impl CheckedBundle {
    /// Retrieves and checks consistency of the bundle's [TransparencyLogEntry].
    pub fn tlog_entry(&self, offline: bool, input_digest: &[u8]) -> Option<&TransparencyLogEntry> {
        match &self.content {
            BundleContent::MessageSignature => {
                self.tlog_entry_for_message_signature(offline, input_digest)
            }
            BundleContent::Dsse { .. } => self.tlog_entry_for_dsse(offline),
        }
    }

    fn tlog_entry_for_message_signature(
        &self,
        offline: bool,
        input_digest: &[u8],
    ) -> Option<&TransparencyLogEntry> {
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

    fn tlog_entry_for_dsse(&self, offline: bool) -> Option<&TransparencyLogEntry> {
        let entry = if !offline && self.tlog_entry.inclusion_proof.is_none() {
            warn!("online rekor fetching is not implemented yet, but is necessary for this bundle");
            return None;
        } else {
            &self.tlog_entry
        };

        // For DSSE entries the tlog body kind must be "dsse" and the body must be
        // consistent with the envelope: envelopeHash, payloadHash, signature, and
        // verifier certificate must all match what we have in the bundle.
        let actual: serde_json::Value =
            serde_json::from_slice(&self.tlog_entry.canonicalized_body).ok()?;

        let kind = actual.get("kind").and_then(|v| v.as_str())?;
        if kind != "dsse" {
            warn!(kind, "tlog entry kind is not 'dsse' for DSSE bundle");
            return None;
        }

        let BundleContent::Dsse {
            envelope_json,
            payload_bytes,
            ..
        } = &self.content
        else {
            return None;
        };

        let spec = actual.get("spec")?;

        // 1. Verify envelopeHash algorithm is sha256 and value matches sha256(canonical envelope JSON).
        let env_hash_algo = spec
            .get("envelopeHash")?
            .get("algorithm")
            .and_then(|v| v.as_str())?;
        if env_hash_algo != "sha256" {
            warn!(env_hash_algo, "unsupported envelopeHash algorithm");
            return None;
        }
        let actual_env_hash = spec
            .get("envelopeHash")?
            .get("value")
            .and_then(|v| v.as_str())?;
        let expected_env_hash: [u8; 32] = Sha256::digest(envelope_json).into();
        let actual_env_hash_bytes: [u8; 32] = hex::decode(actual_env_hash)
            .ok()
            .and_then(|v| v.try_into().ok())?;
        if actual_env_hash_bytes != expected_env_hash {
            warn!("tlog dsse envelopeHash mismatch");
            return None;
        }

        // 2. Verify payloadHash algorithm is sha256 and value matches sha256(payload bytes).
        let payload_hash_algo = spec
            .get("payloadHash")?
            .get("algorithm")
            .and_then(|v| v.as_str())?;
        if payload_hash_algo != "sha256" {
            warn!(payload_hash_algo, "unsupported payloadHash algorithm");
            return None;
        }
        let actual_payload_hash = spec
            .get("payloadHash")?
            .get("value")
            .and_then(|v| v.as_str())?;
        let expected_payload_hash: [u8; 32] = Sha256::digest(payload_bytes).into();
        let actual_payload_hash_bytes: [u8; 32] = hex::decode(actual_payload_hash)
            .ok()
            .and_then(|v| v.try_into().ok())?;
        if actual_payload_hash_bytes != expected_payload_hash {
            warn!("tlog dsse payloadHash mismatch");
            return None;
        }
        // 3. Verify the first tlog signature matches the bundle signature.
        let tlog_sig_b64 = spec
            .get("signatures")?
            .as_array()?
            .first()?
            .get("signature")
            .and_then(|v| v.as_str())?;
        let tlog_sig = base64.decode(tlog_sig_b64).ok()?;
        if tlog_sig != self.signature {
            warn!("tlog dsse signature mismatch");
            return None;
        }

        // 4. Verify the tlog verifier matches the bundle's signing certificate.
        let verifier_b64 = spec
            .get("signatures")?
            .as_array()?
            .first()?
            .get("verifier")
            .and_then(|v| v.as_str())?;
        let verifier_pem = base64.decode(verifier_b64).ok()?;
        let expected_cert_pem = self
            .certificate
            .to_pem(pkcs8::LineEnding::LF)
            .ok()?
            .into_bytes();
        if verifier_pem != expected_cert_pem {
            warn!("tlog dsse verifier certificate mismatch");
            return None;
        }

        Some(entry)
    }
}

/// Builds the canonical JSON representation of a DSSE envelope that Rekor uses when
/// computing `envelopeHash`.  The format matches the JSON serialization produced by
/// the Rekor `dsse` entry type (v0.0.1): keys are in alphabetical order, binary
/// fields (`payload`, `sig`) are standard base64-encoded strings.
///
/// Returns `None` if the envelope has no signatures (which is invalid for our purposes).
/// Extract the sha256 digest string from an in-toto Statement v1 payload.
/// Returns `None` if the payload cannot be parsed or has no sha256 subject.
fn extract_dsse_subject_sha256(payload: &[u8]) -> Option<String> {
    let statement: serde_json::Value = serde_json::from_slice(payload).ok()?;
    statement
        .get("subject")?
        .as_array()?
        .first()?
        .get("digest")?
        .get("sha256")?
        .as_str()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle as ProtoBundle;

    use super::*;

    const REAL_BUNDLE_V03: &str = include_str!("../../../tests/data/bundle_v03.json");

    /// Parse the real v0.3 fixture, apply `mutate` to the decoded-then-re-serialised
    /// `canonicalizedBody` JSON value, and build a [`CheckedBundle`] from the result.
    ///
    /// `mutate` receives the full parsed body `serde_json::Value` (keys: `apiVersion`,
    /// `kind`, `spec`) and should modify it in place.  The mutated value is
    /// re-serialised and stored back as `canonicalized_body` bytes in the single tlog
    /// entry before the bundle is converted to a [`CheckedBundle`].
    fn checked_bundle_with_mutated_body(
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<CheckedBundle, BundleErrorKind> {
        let mut proto: ProtoBundle =
            serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse");

        let tlog = proto
            .verification_material
            .as_mut()
            .expect("must have verification_material")
            .tlog_entries
            .get_mut(0)
            .expect("must have one tlog entry");

        let mut body: serde_json::Value =
            serde_json::from_slice(&tlog.canonicalized_body).expect("body must be valid JSON");
        mutate(&mut body);
        tlog.canonicalized_body = serde_json::to_vec(&body).expect("re-serialise must succeed");

        CheckedBundle::try_from(Bundle {
            media_type: proto.media_type,
            verification_material: proto.verification_material,
            content: proto.content,
        })
    }

    #[test]
    fn dsse_tlog_entry_accepts_real_fixture() {
        let bundle = checked_bundle_with_mutated_body(|_| {}).expect("should build CheckedBundle");
        // `offline = true` skips the online fetch guard; the real fixture carries
        // an inclusion proof so it passes the guard even in offline mode.
        assert!(
            bundle.tlog_entry(true, &[]).is_some(),
            "real fixture should produce a valid tlog entry"
        );
    }

    #[rstest]
    // Wrong top-level kind.
    #[case::wrong_kind(
        "wrong kind",
        Box::new(|body: &mut serde_json::Value| {
            body["kind"] = serde_json::json!("hashedrekord");
        }) as Box<dyn FnOnce(&mut serde_json::Value)>
    )]
    // envelopeHash value is a different (all-zeros) 64-hex string.
    #[case::envelope_hash_mismatch(
        "envelope hash mismatch",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["envelopeHash"]["value"] =
                serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        })
    )]
    // envelopeHash algorithm replaced with something other than sha256.
    #[case::unsupported_envelope_hash_algo(
        "unsupported envelopeHash algorithm",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["envelopeHash"]["algorithm"] = serde_json::json!("sha512");
        })
    )]
    // payloadHash value is a different (all-zeros) 64-hex string.
    #[case::payload_hash_mismatch(
        "payload hash mismatch",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["payloadHash"]["value"] =
                serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        })
    )]
    // payloadHash algorithm replaced with something other than sha256.
    #[case::unsupported_payload_hash_algo(
        "unsupported payloadHash algorithm",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["payloadHash"]["algorithm"] = serde_json::json!("sha512");
        })
    )]
    // Signature in tlog body replaced with all-zeros base64.
    #[case::signature_mismatch(
        "signature mismatch",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["signatures"][0]["signature"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0u8; 64]));
        })
    )]
    // Verifier cert in tlog body replaced with a different base64 blob.
    #[case::verifier_cert_mismatch(
        "verifier cert mismatch",
        Box::new(|body: &mut serde_json::Value| {
            body["spec"]["signatures"][0]["verifier"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"not a real cert"));
        })
    )]
    fn dsse_tlog_entry_rejects_tampered_body(
        #[case] description: &str,
        #[case] mutate: Box<dyn FnOnce(&mut serde_json::Value)>,
    ) {
        let bundle =
            checked_bundle_with_mutated_body(mutate).expect("CheckedBundle construction succeeded");
        assert!(
            bundle.tlog_entry(true, &[]).is_none(),
            "tampered body ({description}) should cause tlog_entry to return None"
        );
    }

    // -----------------------------------------------------------------------
    // DSSE signature cardinality
    // -----------------------------------------------------------------------

    /// Build a `CheckedBundle` from the real fixture after setting the number
    /// of DSSE signatures in the envelope to `count` (by cloning / clearing
    /// the first entry).
    fn checked_bundle_with_dsse_sig_count(count: usize) -> Result<CheckedBundle, BundleErrorKind> {
        use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content;

        let mut proto: ProtoBundle =
            serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse");

        let env = match proto.content.as_mut().expect("must have content") {
            Content::DsseEnvelope(e) => e,
            _ => panic!("expected DsseEnvelope"),
        };

        let first = env.signatures.first().cloned().expect("fixture has a sig");
        env.signatures = (0..count).map(|_| first.clone()).collect();

        CheckedBundle::try_from(Bundle {
            media_type: proto.media_type,
            verification_material: proto.verification_material,
            content: proto.content,
        })
    }

    #[rstest]
    #[case::zero_signatures(0, BundleErrorKind::DsseInvalidSignatureCount(0))]
    #[case::two_signatures(2, BundleErrorKind::DsseInvalidSignatureCount(2))]
    fn checked_bundle_rejects_wrong_dsse_sig_count(
        #[case] count: usize,
        #[case] expected_err: BundleErrorKind,
    ) {
        let err = match checked_bundle_with_dsse_sig_count(count) {
            Ok(_) => panic!("wrong signature count must be rejected"),
            Err(e) => e,
        };

        // Compare discriminants so we don't need PartialEq on BundleErrorKind.
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&expected_err),
            "wrong error kind: got {err:?}, expected {expected_err:?}"
        );
        // Also check the count embedded in DsseInvalidSignatureCount.
        if let BundleErrorKind::DsseInvalidSignatureCount(n) = err {
            assert_eq!(n, count, "wrong count in error");
        }
    }

    #[rstest]
    #[case::single_subject_with_sha256(
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "some-artifact",
                    "digest": { "sha256": "abc123def456" }
                }
            ],
            "predicateType": "https://sigstore.dev/cosign/sign/v1",
            "predicate": {}
        }),
        Some("abc123def456")
    )]
    #[case::subject_missing_digest(
        serde_json::json!({ "subject": [{ "name": "artifact" }] }),
        None
    )]
    #[case::empty_subject_array(
        serde_json::json!({ "subject": [] }),
        None
    )]
    fn extract_dsse_subject_sha256_from_json(
        #[case] payload: serde_json::Value,
        #[case] expected: Option<&str>,
    ) {
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            extract_dsse_subject_sha256(&bytes),
            expected.map(str::to_string)
        );
    }

    #[test]
    fn extract_dsse_subject_sha256_invalid_json() {
        assert!(extract_dsse_subject_sha256(b"not valid json").is_none());
    }

    #[rstest]
    #[case::short_payload("application/vnd.in-toto+json", b"hello" as &[u8])]
    #[case::empty_payload("application/vnd.in-toto+json", b"" as &[u8])]
    #[case::empty_type("", b"hello" as &[u8])]
    fn compute_pae_has_correct_structure(#[case] payload_type: &str, #[case] payload: &[u8]) {
        let pae = compute_pae(payload_type, payload);
        let expected = format!(
            "DSSEv1 {} {} {} ",
            payload_type.len(),
            payload_type,
            payload.len()
        )
        .into_bytes()
        .into_iter()
        .chain(payload.iter().copied())
        .collect::<Vec<u8>>();
        assert_eq!(pae, expected);
    }
}
