// Copyright 2025 The Sigstore Authors.
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

//! In-toto attestation statement support for creating DSSE bundles.
//!
//! This module provides a builder API for creating in-toto Statement attestations
//! that can be signed and wrapped in DSSE envelopes.
//!
//! Supports both v0.1 and v1 statement formats:
//! - v0.1: <https://github.com/in-toto/attestation/blob/main/spec/v0.1.0/statement.md>
//! - v1: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The in-toto Statement v0.1 type identifier.
/// Used by older Sigstore implementations and some legacy bundles.
pub const STATEMENT_TYPE_V0_1: &str = "https://in-toto.io/Statement/v0.1";

/// The in-toto Statement v1 type identifier.
/// Used by current Sigstore implementations including GitHub Actions.
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// An in-toto Statement attestation.
///
/// This represents a verifiable claim about one or more software artifacts.
/// Supports both v0.1 and v1 statement formats.
/// Field order matches the canonical JSON serialization used by cosign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Statement {
    /// The statement type (either "<https://in-toto.io/Statement/v0.1>" or "<https://in-toto.io/Statement/v1>")
    #[serde(rename = "_type")]
    pub statement_type: String,

    /// The type of predicate
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// The subjects of this statement (artifacts being attested to)
    pub subject: Vec<Subject>,

    /// The predicate contents (statement-specific data)
    pub predicate: serde_json::Value,
}

/// A subject of an in-toto statement (an artifact being attested to).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    /// The name or identifier of the subject
    pub name: String,

    /// Digests of the subject (algorithm -> hex-encoded digest)
    pub digest: HashMap<String, String>,
}

impl Subject {
    /// Creates a new subject with the given name and a single digest.
    pub fn new(
        name: impl Into<String>,
        algorithm: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        let mut digest_map = HashMap::new();
        digest_map.insert(algorithm.into(), digest.into());
        Self {
            name: name.into(),
            digest: digest_map,
        }
    }

    /// Adds an additional digest algorithm and value to this subject.
    pub fn with_digest(mut self, algorithm: impl Into<String>, digest: impl Into<String>) -> Self {
        self.digest.insert(algorithm.into(), digest.into());
        self
    }
}

/// Builder for creating in-toto Statement attestations.
///
/// # Example
///
/// ```no_run
/// use sigstore::bundle::intoto::{StatementBuilder, Subject};
/// use serde_json::json;
///
/// let statement = StatementBuilder::new()
///     .subject(Subject::new(
///         "myapp-1.0.tar.gz",
///         "sha256",
///         "abc123..."
///     ))
///     .predicate_type("https://slsa.dev/provenance/v1")
///     .predicate(json!({
///         "buildType": "https://example.com/build/v1",
///         "builder": {
///             "id": "https://example.com/builder"
///         }
///     }))
///     .build()
///     .unwrap();
/// ```
pub struct StatementBuilder {
    subjects: Vec<Subject>,
    predicate_type: Option<String>,
    predicate: Option<serde_json::Value>,
}

impl StatementBuilder {
    /// Creates a new statement builder.
    pub fn new() -> Self {
        Self {
            subjects: Vec::new(),
            predicate_type: None,
            predicate: None,
        }
    }

    /// Adds a subject to the statement.
    pub fn subject(mut self, subject: Subject) -> Self {
        self.subjects.push(subject);
        self
    }

    /// Adds multiple subjects to the statement.
    pub fn subjects(mut self, subjects: impl IntoIterator<Item = Subject>) -> Self {
        self.subjects.extend(subjects);
        self
    }

    /// Sets the predicate type for the statement.
    pub fn predicate_type(mut self, predicate_type: impl Into<String>) -> Self {
        self.predicate_type = Some(predicate_type.into());
        self
    }

    /// Sets the predicate contents for the statement.
    pub fn predicate(mut self, predicate: serde_json::Value) -> Self {
        self.predicate = Some(predicate);
        self
    }

    /// Builds the statement using the v1 format.
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<Statement, &'static str> {
        self.build_with_version(STATEMENT_TYPE_V1)
    }

    /// Builds the statement using the v0.1 format (for backward compatibility).
    ///
    /// Returns an error if required fields are missing.
    pub fn build_v0_1(self) -> Result<Statement, &'static str> {
        self.build_with_version(STATEMENT_TYPE_V0_1)
    }

    /// Builds the statement with a specific version.
    ///
    /// Returns an error if required fields are missing.
    fn build_with_version(self, version: &str) -> Result<Statement, &'static str> {
        if self.subjects.is_empty() {
            return Err("Statement must have at least one subject");
        }

        let predicate_type = self
            .predicate_type
            .ok_or("Statement must have a predicateType")?;

        let predicate = self.predicate.ok_or("Statement must have a predicate")?;

        Ok(Statement {
            statement_type: version.to_string(),
            predicate_type,
            subject: self.subjects,
            predicate,
        })
    }
}

impl Default for StatementBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_subject_creation() {
        let subject = Subject::new("myfile.tar.gz", "sha256", "abc123");

        assert_eq!(subject.name, "myfile.tar.gz");
        assert_eq!(subject.digest.get("sha256"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_subject_with_multiple_digests() {
        let subject =
            Subject::new("myfile.tar.gz", "sha256", "abc123").with_digest("sha512", "def456");

        assert_eq!(subject.digest.len(), 2);
        assert_eq!(subject.digest.get("sha256"), Some(&"abc123".to_string()));
        assert_eq!(subject.digest.get("sha512"), Some(&"def456".to_string()));
    }

    #[test]
    fn test_statement_builder() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({
                "buildType": "https://example.com/build/v1"
            }))
            .build()
            .unwrap();

        assert_eq!(statement.statement_type, STATEMENT_TYPE_V1);
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "test.tar.gz");
        assert_eq!(statement.predicate_type, "https://slsa.dev/provenance/v1");
    }

    #[test]
    fn test_statement_builder_missing_subject() {
        let result = StatementBuilder::new()
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({}))
            .build();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Statement must have at least one subject"
        );
    }

    #[test]
    fn test_statement_builder_missing_predicate_type() {
        let result = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate(json!({}))
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Statement must have a predicateType");
    }

    #[test]
    fn test_statement_serialization() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({
                "buildType": "test"
            }))
            .build()
            .unwrap();

        let json = serde_json::to_string(&statement).unwrap();
        let parsed: Statement = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.statement_type, STATEMENT_TYPE_V1);
        assert_eq!(parsed.subject[0].name, "test.tar.gz");
    }

    #[test]
    fn test_statement_v0_1_compatibility() {
        // Test that we can create and parse v0.1 statements
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v0.2")
            .predicate(json!({
                "buildType": "test"
            }))
            .build_v0_1()
            .unwrap();

        assert_eq!(statement.statement_type, STATEMENT_TYPE_V0_1);

        // Test that we can round-trip v0.1 statements
        let json = serde_json::to_string(&statement).unwrap();
        let parsed: Statement = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.statement_type, STATEMENT_TYPE_V0_1);
        assert_eq!(parsed.subject[0].name, "test.tar.gz");
    }

    #[test]
    fn test_statement_accepts_both_versions() {
        // Test parsing a v0.1 statement
        let v0_1_json = r#"{
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicateType": "https://example.com/test",
            "predicate": {}
        }"#;
        let v0_1: Statement = serde_json::from_str(v0_1_json).unwrap();
        assert_eq!(v0_1.statement_type, STATEMENT_TYPE_V0_1);

        // Test parsing a v1 statement
        let v1_json = r#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "test", "digest": {"sha256": "abc123"}}],
            "predicateType": "https://example.com/test",
            "predicate": {}
        }"#;
        let v1: Statement = serde_json::from_str(v1_json).unwrap();
        assert_eq!(v1.statement_type, STATEMENT_TYPE_V1);
    }
}
