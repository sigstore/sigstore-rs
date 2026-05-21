// Copyright 2026 The Sigstore Authors.
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

//! In-toto Statement v1 types used when parsing DSSE envelope payloads.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::errors::{Result, SigstoreError};

const IN_TOTO_STATEMENT_V1_TYPE: &str = "https://in-toto.io/Statement/v1";
const COSIGN_SIGN_V1_PREDICATE_TYPE: &str = "https://sigstore.dev/cosign/sign/v1";

/// An in-toto Statement v1 as defined in <https://in-toto.io/Statement/v1>.
///
/// This is the JSON object carried inside the DSSE envelope payload field of a
/// Sigstore Bundle v0.3.  The `payload` field of `io::intoto::Envelope` is
/// base64-encoded in the JSON bundle but arrives as raw `Vec<u8>` after the
/// protobuf-serde layer decodes it; these types are used to parse that raw
/// JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct InTotoStatementV1 {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicate: Option<serde_json::Value>,
}

impl InTotoStatementV1 {
    /// Parse an in-toto Statement v1 from raw JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            SigstoreError::UnexpectedError(format!("cannot parse in-toto statement: {e}"))
        })
    }

    /// Enforce that the statement satisfies the subset of the
    /// [in-toto Statement v1 spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
    /// that Sigstore / cosign sign-v1 cares about:
    ///
    /// - `_type` must be `https://in-toto.io/Statement/v1`
    /// - `predicateType` must be `https://sigstore.dev/cosign/sign/v1`
    /// - `subject` must be non-empty
    /// - `subject[0]` must carry a `sha256` digest entry
    ///
    /// # What we currently ignore (and why)
    ///
    /// - **Multiple subjects**: the spec allows any number of subjects.
    ///   Go cosign and sigstore-go both iterate all subjects when matching
    ///   against an artifact digest; we only consume `subject[0]` for now.
    ///   A warning is emitted if more than one subject is present so that
    ///   the behaviour is visible.
    /// - **Extra digest algorithms**: subject digest maps may contain
    ///   entries beyond `sha256` (e.g. `sha512`).  We only read `sha256`
    ///   and silently ignore the rest, matching Go cosign's behaviour.
    /// - **`predicate` field**: not inspected; callers that need to verify
    ///   the predicate payload must do so themselves.
    pub fn validate_cosign_v1(&self) -> Result<()> {
        if self.statement_type != IN_TOTO_STATEMENT_V1_TYPE {
            return Err(SigstoreError::UnexpectedError(format!(
                "unsupported in-toto _type: expected {IN_TOTO_STATEMENT_V1_TYPE}, got {}",
                self.statement_type
            )));
        }

        if self.predicate_type != COSIGN_SIGN_V1_PREDICATE_TYPE {
            return Err(SigstoreError::UnexpectedError(format!(
                "unsupported in-toto predicateType: expected {COSIGN_SIGN_V1_PREDICATE_TYPE}, got {}",
                self.predicate_type
            )));
        }

        if self.subject.is_empty() {
            return Err(SigstoreError::UnexpectedError(
                "in-toto statement has no subjects".to_string(),
            ));
        }

        if self.subject.len() > 1 {
            warn!(
                subject_count = self.subject.len(),
                "in-toto statement has multiple subjects; only the first will be used"
            );
        }

        if !self.subject[0].digest.contains_key("sha256") {
            return Err(SigstoreError::UnexpectedError(
                "in-toto statement subject[0] has no sha256 digest".to_string(),
            ));
        }

        Ok(())
    }

    /// Return the SHA-256 digest of the first subject as a hex string (no
    /// `sha256:` prefix), or an error if the subject list is empty or the
    /// digest is absent.
    pub fn subject_sha256_digest(&self) -> Result<String> {
        self.subject
            .first()
            .and_then(|s| s.digest.get("sha256").cloned())
            .ok_or_else(|| {
                SigstoreError::UnexpectedError(
                    "in-toto statement has no subject with a sha256 digest".to_string(),
                )
            })
    }
}

/// An in-toto subject descriptor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Subject {
    /// Name of the artifact (may be absent in some cosign-produced statements).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Map of digest algorithm → hex-encoded digest value.
    pub digest: BTreeMap<String, String>,
    /// Optional annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const REAL_BUNDLE_V03: &str = include_str!("../../tests/data/bundle_v03.json");

    #[test]
    fn decode_in_toto_statement_from_real_bundle() {
        // Parse the bundle JSON to extract the raw DSSE payload bytes, then
        // parse those as an in-toto Statement v1.
        use base64::{Engine as _, engine::general_purpose::STANDARD as base64};

        let bundle: serde_json::Value =
            serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must be valid JSON");
        let payload_b64 = bundle["dsseEnvelope"]["payload"]
            .as_str()
            .expect("dsseEnvelope.payload must be a string");
        let payload_bytes = base64.decode(payload_b64).expect("payload must be base64");

        let statement =
            InTotoStatementV1::from_json(&payload_bytes).expect("must parse as in-toto statement");

        assert_eq!(
            statement.subject_sha256_digest().unwrap(),
            "c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172"
        );
        assert_eq!(
            statement.predicate_type,
            "https://sigstore.dev/cosign/sign/v1"
        );
        statement
            .validate_cosign_v1()
            .expect("real fixture should satisfy cosign v1 statement constraints");
    }

    #[rstest]
    #[case::subject_missing_sha256_digest(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::new(), // no sha256 key
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    #[case::empty_subject_list(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    fn subject_sha256_digest_returns_err_for_missing_digest(#[case] statement: InTotoStatementV1) {
        assert!(statement.subject_sha256_digest().is_err());
    }

    #[test]
    fn subject_sha256_digest_returns_err_for_invalid_json() {
        // Simulates what callers do: deserialise raw bytes first, then call the method.
        // Invalid JSON must produce a deserialisation error before we even reach the method.
        let result = serde_json::from_slice::<InTotoStatementV1>(b"not valid json");
        assert!(result.is_err());
    }

    #[rstest]
    #[case::valid(
        "https://in-toto.io/Statement/v1",
        "https://sigstore.dev/cosign/sign/v1",
        true
    )]
    #[case::wrong_statement_type(
        "https://example.com/Statement/v1",
        "https://sigstore.dev/cosign/sign/v1",
        false
    )]
    #[case::wrong_predicate_type(
        "https://in-toto.io/Statement/v1",
        "https://example.com/predicate/v1",
        false
    )]
    fn validate_cosign_v1_type_enforcement(
        #[case] statement_type: &str,
        #[case] predicate_type: &str,
        #[case] expected_ok: bool,
    ) {
        let statement = InTotoStatementV1 {
            statement_type: statement_type.to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: predicate_type.to_string(),
            predicate: None,
        };
        assert_eq!(statement.validate_cosign_v1().is_ok(), expected_ok);
    }

    #[rstest]
    #[case::empty_subjects(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    #[case::subject_without_sha256(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha512".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    fn validate_cosign_v1_rejects_invalid_subject(#[case] statement: InTotoStatementV1) {
        assert!(statement.validate_cosign_v1().is_err());
    }

    // Multiple subjects are accepted (with a warn!); only subject[0] is used.
    // Extra digest algorithms beyond sha256 are tolerated and ignored.
    #[rstest]
    #[case::multiple_subjects(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![
                Subject {
                    name: Some("artifact-a".to_string()),
                    digest: BTreeMap::from([("sha256".to_string(), "aaa".to_string())]),
                    annotations: None,
                },
                Subject {
                    name: Some("artifact-b".to_string()),
                    digest: BTreeMap::from([("sha256".to_string(), "bbb".to_string())]),
                    annotations: None,
                },
            ],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    #[case::extra_digest_algorithms(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([
                    ("sha256".to_string(), "abc".to_string()),
                    ("sha512".to_string(), "def".to_string()),
                ]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        }
    )]
    fn validate_cosign_v1_accepts_tolerated_cases(#[case] statement: InTotoStatementV1) {
        assert!(statement.validate_cosign_v1().is_ok());
    }
}
