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

use crate::errors::{Result, SigstoreError};

const IN_TOTO_STATEMENT_V1_TYPE: &str = "https://in-toto.io/Statement/v1";

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
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            SigstoreError::UnexpectedError(format!("cannot parse in-toto statement: {e}"))
        })
    }

    /// Validate the in-toto statement and verify that at least one subject
    /// carries a digest matching `expected_digest`.
    ///
    /// `expected_digest` must be in `algorithm:hex` form (e.g.
    /// `"sha256:abc123"`, `"sha512:def456"`).  An error is returned if the
    /// `':'` separator is missing.
    ///
    /// Checks performed:
    ///
    /// - `_type` must be `https://in-toto.io/Statement/v1`
    /// - `expected_digest` must be in `algorithm:hex` format
    /// - At least one subject must have a digest entry for the extracted
    ///   algorithm whose value equals the extracted hex digest
    ///
    /// The `predicateType` is **not** restricted — any predicate type is
    /// accepted (e.g. `cosign/sign/v1`, SLSA provenance, SBOM, etc.).
    /// Callers that need to enforce a specific predicate type should inspect
    /// [`Self::predicate_type`] after validation.
    pub fn validate(&self, expected_digest: &str) -> Result<()> {
        if self.statement_type != IN_TOTO_STATEMENT_V1_TYPE {
            return Err(SigstoreError::UnexpectedError(format!(
                "unsupported in-toto _type: expected {IN_TOTO_STATEMENT_V1_TYPE}, got {}",
                self.statement_type
            )));
        }

        let (algorithm, digest) = expected_digest.split_once(':').ok_or_else(|| {
            SigstoreError::UnexpectedError(format!(
                "expected_digest must be in 'algorithm:hex' format, got '{expected_digest}'"
            ))
        })?;

        let found = self
            .subject
            .iter()
            .any(|s| s.digest.get(algorithm).is_some_and(|d| d == digest));

        if !found {
            return Err(SigstoreError::UnexpectedError(format!(
                "unable to find subject with mathcing digest; digest: '{algorithm}:{digest}'; subjects: {:?}",
                self.subject
            )));
        }

        Ok(())
    }

    /// Return the SHA-256 digest of the first subject as a hex string (no
    /// `sha256:` prefix), or an error if the subject list is empty or the
    /// digest is absent.
    pub(crate) fn subject_sha256_digest(&self) -> Result<String> {
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

        let has_expected_digest = statement.subject.iter().any(|s| {
            s.digest.get("sha256")
                == Some(
                    &"c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172".to_string(),
                )
        });
        assert!(has_expected_digest);
        assert_eq!(
            statement.predicate_type,
            "https://sigstore.dev/cosign/sign/v1"
        );
        statement
            .validate("sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172")
            .expect("real fixture should satisfy statement constraints");
    }

    #[test]
    fn validate_returns_err_for_invalid_json() {
        // Invalid JSON must produce a deserialisation error before we even reach validate.
        let result = serde_json::from_slice::<InTotoStatementV1>(b"not valid json");
        assert!(result.is_err());
    }

    #[rstest]
    #[case::valid_statement_type("https://in-toto.io/Statement/v1", true)]
    #[case::wrong_statement_type("https://example.com/Statement/v1", false)]
    fn validate_type_enforcement(#[case] statement_type: &str, #[case] expected_ok: bool) {
        let statement = InTotoStatementV1 {
            statement_type: statement_type.to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        };
        assert_eq!(statement.validate("sha256:abc").is_ok(), expected_ok);
    }

    #[test]
    fn validate_accepts_any_predicate_type() {
        // Any predicate type should be accepted — SLSA provenance, SBOM, etc.
        for predicate_type in [
            "https://sigstore.dev/cosign/sign/v1",
            "https://slsa.dev/provenance/v1",
            "https://cyclonedx.org/bom/v1.4",
            "https://example.com/custom/v1",
        ] {
            let statement = InTotoStatementV1 {
                statement_type: "https://in-toto.io/Statement/v1".to_string(),
                subject: vec![Subject {
                    name: Some("artifact".to_string()),
                    digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                    annotations: None,
                }],
                predicate_type: predicate_type.to_string(),
                predicate: None,
            };
            assert!(
                statement.validate("sha256:abc").is_ok(),
                "predicate type {predicate_type} should be accepted"
            );
        }
    }

    #[rstest]
    #[case::empty_subjects(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        },
        "sha256:abc"
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
        },
        "sha256:abc"
    )]
    #[case::no_matching_digest(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "aaa".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        },
        "sha256:bbb"
    )]
    #[case::missing_algorithm_prefix(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        },
        "abc"
    )]
    fn validate_rejects_invalid_subject(
        #[case] statement: InTotoStatementV1,
        #[case] expected_digest: &str,
    ) {
        assert!(statement.validate(expected_digest).is_err());
    }

    #[rstest]
    #[case::digest_in_first_subject(
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
        },
        "sha256:aaa"
    )]
    #[case::digest_in_second_subject(
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
        },
        "sha256:bbb"
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
        },
        "sha256:abc"
    )]
    #[case::sha256_prefix(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        },
        "sha256:abc"
    )]
    #[case::sha512_algorithm(
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha512".to_string(), "def456".to_string())]),
                annotations: None,
            }],
            predicate_type: "https://sigstore.dev/cosign/sign/v1".to_string(),
            predicate: None,
        },
        "sha512:def456"
    )]
    fn validate_accepts_valid_cases(
        #[case] statement: InTotoStatementV1,
        #[case] expected_digest: &str,
    ) {
        assert!(statement.validate(expected_digest).is_ok());
    }
}
