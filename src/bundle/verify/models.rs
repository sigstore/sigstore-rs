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
    bundle::{Bundle, intoto::InTotoStatementV1, models::Version as BundleVersion},
    crypto::certificate::{CertificateValidationError, is_leaf, is_root_ca},
    rekor::models as rekor,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use sha2::{Digest, Sha256, Sha512};
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

/// Maximum number of subjects accepted in a DSSE in-toto statement, and
/// maximum number of digest entries accepted per subject.
///
/// The statement comes from an untrusted bundle, so the work and memory spent
/// on it before it can be rejected have to be bounded.  Statements over these
/// limits are rejected outright rather than truncated.  The values match
/// sigstore-go's `maxAllowedSubjects` / `maxAllowedSubjectDigests`
/// (`pkg/verify/signature.go`).
pub(crate) const MAX_DSSE_SUBJECTS: usize = 1024;
pub(crate) const MAX_DSSE_SUBJECT_DIGESTS: usize = 32;

#[derive(Error, Debug)]
#[non_exhaustive]
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

    #[error(
        "DSSE envelope's in-toto statement has {0} subjects, exceeding the supported maximum of {MAX_DSSE_SUBJECTS}"
    )]
    DsseTooManySubjects(usize),

    #[error(
        "DSSE envelope's in-toto statement has a subject with {0} digest entries, exceeding the supported maximum of {MAX_DSSE_SUBJECT_DIGESTS}"
    )]
    DsseTooManySubjectDigests(usize),

    #[error("DSSE envelope's in-toto statement has a subject with a malformed {0} digest")]
    DsseSubjectDigestMalformed(&'static str),

    #[error("DSSE envelope's in-toto statement has no subject with a recognized digest")]
    DsseNoRecognizedSubjectDigest,

    #[error("bundle needs 1 tlog entry, got {0}")]
    TlogEntry(usize),

    #[error(transparent)]
    BundleProfile(#[from] BundleProfileErrorKind),
}

#[derive(Error, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum SignatureErrorKind {
    #[error("unsupported signature algorithm")]
    AlgoUnsupported(#[source] crate::errors::SigstoreError),

    #[error("signature verification failed")]
    VerificationFailed(#[source] crate::errors::SigstoreError),

    #[error("signature transparency materials are inconsistent")]
    Transparency,

    #[error("no in-toto statement subject matches the provided artifact digest")]
    SubjectDigestMismatch,

    #[error("artifact digest algorithm {0} is not supported for this bundle content")]
    DigestAlgorithmUnsupported(&'static str),
}

/// An artifact digest, tagged with the algorithm that produced it.
///
/// Sigstore bundles bind a signature to an artifact by digest.  Which digest
/// algorithm is used is the *producer's* choice: cosign and PyPI publish
/// `sha256` subjects, while npm provenance attestations carry `sha512`
/// subjects.  Verification therefore has to be told which algorithm the
/// caller hashed with, rather than assuming SHA-256.
///
/// See [`Verifier::verify_digest_with`](crate::bundle::verify::Verifier::verify_digest_with).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactDigest {
    /// A SHA-256 digest of the artifact.
    Sha256([u8; 32]),
    /// A SHA-512 digest of the artifact.
    Sha512([u8; 64]),
}

impl ArtifactDigest {
    /// The in-toto digest algorithm name (`sha256` or `sha512`), as it appears
    /// as a key in an in-toto statement's subject digest map.
    pub fn algorithm(&self) -> &'static str {
        match self {
            ArtifactDigest::Sha256(_) => "sha256",
            ArtifactDigest::Sha512(_) => "sha512",
        }
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ArtifactDigest::Sha256(d) => d,
            ArtifactDigest::Sha512(d) => d,
        }
    }

    /// The digest as a lowercase hex string, without an algorithm prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Parses one entry of an in-toto subject's digest map into a typed digest.
    ///
    /// Returns `Ok(None)` for algorithms this crate cannot match an artifact
    /// against (`gitCommit`, `dirHash`, ...), which the in-toto DigestSet
    /// guidance tells consumers to ignore.  For the accepted algorithms, a
    /// value that is not hex of exactly the algorithm's digest length can never
    /// be a real digest of that algorithm, so it is rejected outright instead
    /// of being carried around as an unmatchable string.
    pub(crate) fn from_subject_entry(
        algorithm: &str,
        value: &str,
    ) -> Result<Option<Self>, BundleErrorKind> {
        fn decode<const N: usize>(
            algorithm: &'static str,
            value: &str,
        ) -> Result<[u8; N], BundleErrorKind> {
            hex::decode(value)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(BundleErrorKind::DsseSubjectDigestMalformed(algorithm))
        }

        match algorithm {
            "sha256" => Ok(Some(ArtifactDigest::Sha256(decode("sha256", value)?))),
            "sha512" => Ok(Some(ArtifactDigest::Sha512(decode("sha512", value)?))),
            _ => Ok(None),
        }
    }
}

impl From<[u8; 32]> for ArtifactDigest {
    fn from(digest: [u8; 32]) -> Self {
        ArtifactDigest::Sha256(digest)
    }
}

impl From<[u8; 64]> for ArtifactDigest {
    fn from(digest: [u8; 64]) -> Self {
        ArtifactDigest::Sha512(digest)
    }
}

impl From<Sha256> for ArtifactDigest {
    fn from(hasher: Sha256) -> Self {
        ArtifactDigest::Sha256(hasher.finalize().into())
    }
}

impl From<Sha512> for ArtifactDigest {
    fn from(hasher: Sha512) -> Self {
        ArtifactDigest::Sha512(hasher.finalize().into())
    }
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
    /// holds the PAE bytes.  The caller's artifact digest is compared against the
    /// subject digests in the in-toto statement rather than being used for signature verification.
    Dsse {
        /// The DSSE Pre-Authentication Encoding bytes (what was actually signed).
        pae: Vec<u8>,
        /// Every recognized subject digest of the in-toto statement, parsed and
        /// flattened across subjects.  An artifact matches if *any* entry
        /// equals the caller's digest (which carries its algorithm); entries
        /// under algorithms this crate cannot match are not retained.
        subject_digests: Vec<ArtifactDigest>,
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

                let statement = serde_json::from_slice::<InTotoStatementV1>(&dsse.payload)
                    .map_err(|_| BundleErrorKind::DssePayloadDecode)?;

                // Bound the untrusted statement before building any owned
                // representation of it.
                if statement.subject.len() > MAX_DSSE_SUBJECTS {
                    return Err(BundleErrorKind::DsseTooManySubjects(
                        statement.subject.len(),
                    ));
                }

                // Collect every subject digest an artifact could be matched
                // against.  Algorithm keys are matched exactly — in-toto defines
                // them as lowercase strings, and this mirrors sigstore-go's
                // exact map lookup.  Digest values are hex-decoded here, so
                // matching later is a byte comparison and no attacker-controlled
                // strings are retained.
                let mut subject_digests = Vec::new();
                for digests in statement.subject_digests() {
                    if digests.len() > MAX_DSSE_SUBJECT_DIGESTS {
                        return Err(BundleErrorKind::DsseTooManySubjectDigests(digests.len()));
                    }
                    for (algorithm, value) in digests {
                        if let Some(digest) = ArtifactDigest::from_subject_entry(algorithm, value)?
                        {
                            subject_digests.push(digest);
                        }
                    }
                }

                // A statement whose subjects carry no digest we can match
                // against could never bind an artifact, so reject it up front
                // rather than failing later with a mismatch.
                if subject_digests.is_empty() {
                    return Err(BundleErrorKind::DsseNoRecognizedSubjectDigest);
                }

                let payload_bytes = dsse.payload;

                (
                    sig,
                    BundleContent::Dsse {
                        pae,
                        subject_digests,
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

        // Guard the schema-dependent field traversal below (spec.envelopeHash,
        // spec.payloadHash, spec.signatures) which are defined by the dsse v0.0.1
        // body schema.  Fail fast if the version is unexpected rather than
        // silently parsing the wrong fields.
        let api_version = actual.get("apiVersion").and_then(|v| v.as_str())?;
        if api_version != "0.0.1" {
            warn!(
                api_version,
                "unsupported apiVersion in dsse tlog entry body"
            );
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
#[cfg(test)]
mod tests {
    use rstest::rstest;
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle as ProtoBundle;

    use super::*;

    use crate::bundle::verify::test_data::{NPM_SLSA_BUNDLE_V03, NPM_TARBALL_SHA512};

    const REAL_BUNDLE_V03: &str = include_str!("../../../tests/data/bundle_v03.json");

    /// npm provenance attestations describe their subject with a `sha512` digest
    /// and nothing else, so requiring `sha256` made them unverifiable.
    #[test]
    fn checked_bundle_accepts_sha512_only_subject() {
        let bundle: Bundle =
            serde_json::from_str(NPM_SLSA_BUNDLE_V03).expect("fixture must be valid JSON");

        let checked = CheckedBundle::try_from(bundle)
            .expect("npm bundle whose only subject digest is sha512 must build");

        let BundleContent::Dsse {
            subject_digests, ..
        } = &checked.content
        else {
            panic!("expected DSSE content");
        };
        let expected: [u8; 64] = hex::decode(NPM_TARBALL_SHA512)
            .expect("fixture digest must be hex")
            .try_into()
            .expect("fixture digest must be 64 bytes");
        assert_eq!(subject_digests, &vec![ArtifactDigest::Sha512(expected)]);
    }

    /// Build a `CheckedBundle` from the real fixture after applying `mutate` to
    /// the decoded in-toto statement of its DSSE envelope.
    fn checked_bundle_with_envelope(
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<CheckedBundle, BundleErrorKind> {
        use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content;

        let mut proto: ProtoBundle =
            serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse");

        let env = match proto.content.as_mut().expect("must have content") {
            Content::DsseEnvelope(e) => e,
            _ => panic!("expected DsseEnvelope"),
        };
        let mut statement: serde_json::Value =
            serde_json::from_slice(&env.payload).expect("payload must be a JSON statement");
        mutate(&mut statement);
        env.payload = serde_json::to_vec(&statement).expect("re-serialise must succeed");

        CheckedBundle::try_from(Bundle {
            media_type: proto.media_type,
            verification_material: proto.verification_material,
            content: proto.content,
        })
    }

    /// Build a `CheckedBundle` from the real fixture after replacing the in-toto
    /// statement's `subject` array with `subject`.
    fn checked_bundle_with_subjects(
        subject: serde_json::Value,
    ) -> Result<CheckedBundle, BundleErrorKind> {
        checked_bundle_with_envelope(|statement| statement["subject"] = subject)
    }

    /// Extract the retained subject digests from a construction result, or
    /// panic with the construction error.
    fn subject_digests_of(result: Result<CheckedBundle, BundleErrorKind>) -> Vec<ArtifactDigest> {
        let checked = result.unwrap_or_else(|e| panic!("statement must build: {e}"));
        let BundleContent::Dsse {
            subject_digests, ..
        } = checked.content
        else {
            panic!("expected DSSE content");
        };
        subject_digests
    }

    /// The npm fixture's `predicateType` is SLSA provenance, not cosign sign-v1:
    /// bundle verification must not restrict the predicate.
    #[rstest]
    #[case::slsa_provenance("https://slsa.dev/provenance/v1")]
    #[case::spdx("https://spdx.dev/Document")]
    #[case::vendor_specific("https://example.com/custom/v1")]
    fn checked_bundle_accepts_any_predicate_type(#[case] predicate_type: &str) {
        assert!(
            checked_bundle_with_envelope(|statement| {
                statement["predicateType"] = serde_json::json!(predicate_type);
            })
            .is_ok(),
            "any predicateType must be accepted by bundle verification"
        );
    }

    /// Statement `_type` is not restricted at this layer: v0.1 statements —
    /// which older cosign releases produced, with the same `subject` shape —
    /// were accepted by the previous verifier and still are.  sigstore-go's
    /// verifier does not pin `_type` either.
    #[test]
    fn checked_bundle_accepts_statement_v01_type() {
        assert!(
            checked_bundle_with_envelope(|statement| {
                statement["_type"] = serde_json::json!("https://in-toto.io/Statement/v0.1");
            })
            .is_ok(),
            "a v0.1 in-toto statement must be accepted by bundle verification"
        );
    }

    #[test]
    fn checked_bundle_collects_every_subject_digest() {
        let a = ArtifactDigest::Sha256([0xaa; 32]);
        let b = ArtifactDigest::Sha256([0xbb; 32]);
        let c256 = ArtifactDigest::Sha256([0xcc; 32]);
        let c512 = ArtifactDigest::Sha512([0xdd; 64]);

        let digests = subject_digests_of(checked_bundle_with_subjects(serde_json::json!([
            { "name": "a", "digest": { "sha256": a.to_hex() } },
            { "name": "b", "digest": { "sha256": b.to_hex() } },
            { "name": "c", "digest": { "sha256": c256.to_hex(), "sha512": c512.to_hex() } },
        ])));

        assert_eq!(digests, vec![a, b, c256, c512]);
    }

    /// Digest values are hex-decoded at construction, so the case of the hex
    /// cannot affect matching.
    #[test]
    fn checked_bundle_parses_uppercase_hex_digest_values() {
        let digest = ArtifactDigest::Sha256([0xab; 32]);

        let digests = subject_digests_of(checked_bundle_with_subjects(serde_json::json!([
            { "name": "a", "digest": { "sha256": digest.to_hex().to_uppercase() } },
        ])));

        assert_eq!(digests, vec![digest]);
    }

    /// Algorithm keys are matched exactly: in-toto defines DigestSet keys as
    /// lowercase strings, and sigstore-go's map lookup is exact.  A
    /// non-lowercase key is just an unrecognized algorithm.
    #[test]
    fn checked_bundle_does_not_case_fold_algorithm_keys() {
        let err = match checked_bundle_with_subjects(serde_json::json!([
            { "name": "a", "digest": { "SHA256": ArtifactDigest::Sha256([1u8; 32]).to_hex() } },
        ])) {
            Ok(_) => panic!("'SHA256' must not be recognized as 'sha256'"),
            Err(e) => e,
        };

        assert!(
            matches!(err, BundleErrorKind::DsseNoRecognizedSubjectDigest),
            "wrong error kind: got {err:?}"
        );
    }

    /// A value under a recognized algorithm that cannot be a digest of that
    /// algorithm (bad hex, or hex of the wrong length) can never match and is
    /// rejected at construction, before any expensive verification runs.
    #[rstest]
    #[case::sha256_not_hex("sha256", "zz", "sha256")]
    #[case::sha256_odd_length("sha256", "abc", "sha256")]
    #[case::sha256_wrong_length("sha256", "abcdef", "sha256")]
    #[case::sha256_prefixed(
        "sha256",
        "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172",
        "sha256"
    )]
    #[case::sha512_not_hex("sha512", "not hex at all", "sha512")]
    // Valid hex, but 32 bytes cannot be a SHA-512 digest.
    #[case::sha512_wrong_length(
        "sha512",
        "c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172",
        "sha512"
    )]
    fn checked_bundle_rejects_malformed_recognized_digest(
        #[case] algorithm: &str,
        #[case] value: &str,
        #[case] reported: &str,
    ) {
        let err = match checked_bundle_with_subjects(serde_json::json!([
            { "name": "a", "digest": { algorithm: value } },
        ])) {
            Ok(_) => panic!("a malformed {algorithm} digest must be rejected"),
            Err(e) => e,
        };

        assert!(
            matches!(err, BundleErrorKind::DsseSubjectDigestMalformed(got) if got == reported),
            "wrong error kind: got {err:?}"
        );
    }

    /// Unrecognized algorithms are ignored per the in-toto DigestSet consumer
    /// guidance: they are not retained (nothing could ever match them) and
    /// their values are not validated.
    #[test]
    fn checked_bundle_ignores_unrecognized_algorithms() {
        let digest = ArtifactDigest::Sha256([2u8; 32]);

        let digests = subject_digests_of(checked_bundle_with_subjects(serde_json::json!([
            { "name": "a", "digest": {
                "gitCommit": "0123abcd",
                "dirHash": "!! not even hex !!",
                "sha256": digest.to_hex(),
            } },
        ])));

        assert_eq!(digests, vec![digest]);
    }

    /// Builds a subject array with `count` subjects, each carrying one valid
    /// sha256 digest.
    fn subjects_with_count(count: usize) -> serde_json::Value {
        serde_json::Value::Array(
            (0..count)
                .map(|i| {
                    let digest = ArtifactDigest::Sha256([(i % 251) as u8; 32]);
                    serde_json::json!({ "name": format!("s{i}"), "digest": { "sha256": digest.to_hex() } })
                })
                .collect(),
        )
    }

    /// Builds one subject whose digest map has `count` entries (one valid
    /// sha256, the rest unrecognized algorithms).
    fn subject_with_digest_entries(count: usize) -> serde_json::Value {
        let mut digest = serde_json::Map::new();
        digest.insert(
            "sha256".into(),
            serde_json::json!(ArtifactDigest::Sha256([3u8; 32]).to_hex()),
        );
        for i in 1..count {
            digest.insert(format!("algo{i:03}"), serde_json::json!("aabb"));
        }
        serde_json::json!([{ "name": "a", "digest": digest }])
    }

    /// Over-limit statements are rejected outright, never truncated; statements
    /// exactly at the limit still build.  Limits match sigstore-go's.
    #[test]
    fn checked_bundle_bounds_subject_count() {
        assert!(
            checked_bundle_with_subjects(subjects_with_count(MAX_DSSE_SUBJECTS)).is_ok(),
            "a statement with exactly {MAX_DSSE_SUBJECTS} subjects must build"
        );

        let err = match checked_bundle_with_subjects(subjects_with_count(MAX_DSSE_SUBJECTS + 1)) {
            Ok(_) => {
                panic!("a statement with more than {MAX_DSSE_SUBJECTS} subjects must be rejected")
            }
            Err(e) => e,
        };
        assert!(
            matches!(err, BundleErrorKind::DsseTooManySubjects(n) if n == MAX_DSSE_SUBJECTS + 1),
            "wrong error kind: got {err:?}"
        );
    }

    /// Same bound for the digest entries of a single subject; unrecognized
    /// entries count toward the limit (the map itself is what is bounded).
    #[test]
    fn checked_bundle_bounds_digest_entries_per_subject() {
        let digests = subject_digests_of(checked_bundle_with_subjects(
            subject_with_digest_entries(MAX_DSSE_SUBJECT_DIGESTS),
        ));
        assert_eq!(
            digests,
            vec![ArtifactDigest::Sha256([3u8; 32])],
            "only the recognized entry is retained"
        );

        let err = match checked_bundle_with_subjects(subject_with_digest_entries(
            MAX_DSSE_SUBJECT_DIGESTS + 1,
        )) {
            Ok(_) => panic!(
                "a subject with more than {MAX_DSSE_SUBJECT_DIGESTS} digest entries must be rejected"
            ),
            Err(e) => e,
        };
        assert!(
            matches!(err, BundleErrorKind::DsseTooManySubjectDigests(n) if n == MAX_DSSE_SUBJECT_DIGESTS + 1),
            "wrong error kind: got {err:?}"
        );
    }

    /// `from_subject_entry` must accept exactly the digests an
    /// [`ArtifactDigest`] can represent, and parsing a digest's own hex must
    /// yield the digest back.
    #[rstest]
    #[case::sha256(ArtifactDigest::Sha256([5u8; 32]))]
    #[case::sha512(ArtifactDigest::Sha512([6u8; 64]))]
    fn from_subject_entry_round_trips_every_algorithm(#[case] digest: ArtifactDigest) {
        let parsed = ArtifactDigest::from_subject_entry(digest.algorithm(), &digest.to_hex())
            .expect("a digest's own hex must parse")
            .expect("a digest's own algorithm must be recognized");
        assert_eq!(parsed, digest);
    }

    #[rstest]
    #[case::sha256(ArtifactDigest::from(Sha256::new()), "sha256", 32)]
    #[case::sha512(ArtifactDigest::from(Sha512::new()), "sha512", 64)]
    fn artifact_digest_from_hasher(
        #[case] digest: ArtifactDigest,
        #[case] algorithm: &str,
        #[case] len: usize,
    ) {
        assert_eq!(digest.algorithm(), algorithm);
        assert_eq!(digest.as_bytes().len(), len);
        assert_eq!(digest.to_hex().len(), len * 2);
    }

    #[rstest]
    // No subjects at all: nothing to bind an artifact to.
    #[case::empty_subject_list(serde_json::json!([]))]
    // A subject with no digest entries whatsoever.
    #[case::subject_without_digests(serde_json::json!([{ "name": "a", "digest": {} }]))]
    // Digest entries exist, but none under an algorithm we can match against.
    #[case::no_recognized_digest(
        serde_json::json!([{ "name": "a", "digest": { "gitCommit": "abc" } }])
    )]
    fn checked_bundle_rejects_unmatchable_subjects(#[case] subject: serde_json::Value) {
        let err = match checked_bundle_with_subjects(subject) {
            Ok(_) => panic!("statement with no matchable subject must be rejected"),
            Err(e) => e,
        };

        assert!(
            matches!(err, BundleErrorKind::DsseNoRecognizedSubjectDigest),
            "wrong error kind: got {err:?}"
        );
    }

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
