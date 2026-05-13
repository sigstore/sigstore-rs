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

use crate::cosign::constants::{COSIGN_SIGN_V1_PREDICATE_TYPE, IN_TOTO_STATEMENT_V1_TYPE};
use crate::errors::{Result, SigstoreError};

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

    /// Enforce that the statement matches cosign sign/v1 expectations.
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
}
