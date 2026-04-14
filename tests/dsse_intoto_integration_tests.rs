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

//! Integration tests for DSSE and in-toto statement support.

use base64::prelude::*;
use serde_json::json;
use sigstore::bundle::dsse::DsseEnvelope;
use sigstore::bundle::intoto::{
    STATEMENT_TYPE_V0_1, STATEMENT_TYPE_V1, Statement, StatementBuilder, Subject,
};
use std::fs;

#[test]
fn test_parse_statement_v0_1_from_file() {
    let json_data = fs::read_to_string("tests/data/dsse/statement-v0.1.json")
        .expect("Failed to read statement-v0.1.json");

    let statement: Statement =
        serde_json::from_str(&json_data).expect("Failed to parse v0.1 statement");

    assert_eq!(statement.statement_type, STATEMENT_TYPE_V0_1);
    assert_eq!(statement.predicate_type, "https://slsa.dev/provenance/v0.2");
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, "slsa-provenance-0.0.7.tgz");
    assert!(statement.subject[0].digest.contains_key("sha512"));
}

#[test]
fn test_parse_statement_v1_from_file() {
    let json_data = fs::read_to_string("tests/data/dsse/statement-v1.json")
        .expect("Failed to read statement-v1.json");

    let statement: Statement =
        serde_json::from_str(&json_data).expect("Failed to parse v1 statement");

    assert_eq!(statement.statement_type, STATEMENT_TYPE_V1);
    assert_eq!(statement.predicate_type, "https://slsa.dev/provenance/v1");
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, "myapp-1.0.tar.gz");
    assert!(statement.subject[0].digest.contains_key("sha256"));
    assert!(statement.subject[0].digest.contains_key("sha512"));
}

#[test]
fn test_dsse_envelope_with_real_bundle() {
    // Read the real sigstore bundle from sigstore-go test data
    let bundle_data = fs::read_to_string("tests/data/dsse/dsse.sigstore.json")
        .expect("Failed to read dsse.sigstore.json");

    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_data).expect("Failed to parse bundle");

    // Extract the DSSE envelope
    let dsse_envelope = bundle
        .get("dsseEnvelope")
        .expect("Bundle should have dsseEnvelope");

    // Verify envelope structure
    assert_eq!(
        dsse_envelope.get("payloadType").and_then(|v| v.as_str()),
        Some("application/vnd.in-toto+json")
    );

    let signatures = dsse_envelope
        .get("signatures")
        .and_then(|v| v.as_array())
        .expect("Should have signatures array");
    assert_eq!(signatures.len(), 1, "Should have exactly 1 signature");

    // Decode the base64 payload
    let payload_b64 = dsse_envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .expect("Should have payload");

    let payload_bytes = BASE64_STANDARD
        .decode(payload_b64)
        .expect("Failed to decode base64 payload");

    // Parse as statement
    let statement: Statement =
        serde_json::from_slice(&payload_bytes).expect("Failed to parse statement from payload");

    // Verify it's a v0.1 statement (this is from 2022)
    assert_eq!(statement.statement_type, STATEMENT_TYPE_V0_1);
    assert_eq!(statement.predicate_type, "https://slsa.dev/provenance/v0.2");
}

#[test]
fn test_pae_computation_matches_spec() {
    // Test PAE format matches the DSSE spec
    // Format: "DSSEv1 <type_len> <type> <payload_len> <payload>"

    let statement = StatementBuilder::new()
        .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
        .predicate_type("https://example.com/test")
        .predicate(json!({"test": "data"}))
        .build()
        .unwrap();

    let envelope = DsseEnvelope::from_statement(&statement).unwrap();
    let pae = envelope.pae();

    // PAE should start with "DSSEv1 "
    assert!(pae.starts_with(b"DSSEv1 "));

    // Parse the PAE format
    let pae_str = String::from_utf8_lossy(&pae);
    let parts: Vec<&str> = pae_str.splitn(4, ' ').collect();

    assert_eq!(parts[0], "DSSEv1");
    assert_eq!(parts[1], "28"); // length of "application/vnd.in-toto+json"
    assert_eq!(parts[2], "application/vnd.in-toto+json");

    // The rest is "<payload_len> <payload>"
    let payload_len = envelope.payload().len();
    let expected_prefix = format!("DSSEv1 28 application/vnd.in-toto+json {} ", payload_len);
    assert!(pae.starts_with(expected_prefix.as_bytes()));
}

#[test]
fn test_create_and_decode_statement_roundtrip() {
    // Test that we can create a statement, wrap it in DSSE, and decode it back
    let original = StatementBuilder::new()
        .subject(
            Subject::new("artifact.tar.gz", "sha256", "deadbeef").with_digest("sha512", "cafebabe"),
        )
        .predicate_type("https://slsa.dev/provenance/v1")
        .predicate(json!({
            "buildDefinition": {
                "buildType": "https://example.com/build",
                "externalParameters": {"repo": "example/repo"}
            },
            "runDetails": {
                "builder": {"id": "https://example.com/builder"}
            }
        }))
        .build()
        .unwrap();

    // Wrap in DSSE envelope
    let envelope = DsseEnvelope::from_statement(&original).unwrap();

    // Decode back
    let decoded = envelope.decode_statement().unwrap();

    // Verify round-trip
    assert_eq!(decoded.statement_type, original.statement_type);
    assert_eq!(decoded.predicate_type, original.predicate_type);
    assert_eq!(decoded.subject.len(), original.subject.len());
    assert_eq!(decoded.subject[0].name, original.subject[0].name);
    assert_eq!(decoded.subject[0].digest, original.subject[0].digest);
}

#[test]
fn test_v0_1_and_v1_statements_differ() {
    // Create the same logical statement with both versions
    let v0_1 = StatementBuilder::new()
        .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
        .predicate_type("https://example.com/test")
        .predicate(json!({"key": "value"}))
        .build_v0_1()
        .unwrap();

    let v1 = StatementBuilder::new()
        .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
        .predicate_type("https://example.com/test")
        .predicate(json!({"key": "value"}))
        .build()
        .unwrap();

    // They should differ only in the statement_type
    assert_ne!(v0_1.statement_type, v1.statement_type);
    assert_eq!(v0_1.statement_type, STATEMENT_TYPE_V0_1);
    assert_eq!(v1.statement_type, STATEMENT_TYPE_V1);

    // But other fields should be the same
    assert_eq!(v0_1.predicate_type, v1.predicate_type);
    assert_eq!(v0_1.subject, v1.subject);
    assert_eq!(v0_1.predicate, v1.predicate);
}

#[test]
fn test_multiple_digest_algorithms() {
    // Test that subjects can have multiple digest algorithms
    let statement = StatementBuilder::new()
        .subject(
            Subject::new("file.tar.gz", "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .with_digest("sha512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
                .with_digest("sha384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        )
        .predicate_type("https://example.com/test")
        .predicate(json!({}))
        .build()
        .unwrap();

    assert_eq!(statement.subject[0].digest.len(), 3);
    assert!(statement.subject[0].digest.contains_key("sha256"));
    assert!(statement.subject[0].digest.contains_key("sha512"));
    assert!(statement.subject[0].digest.contains_key("sha384"));
}

#[test]
fn test_multiple_subjects() {
    // Test that statements can have multiple subjects
    let statement = StatementBuilder::new()
        .subject(Subject::new("app-linux.tar.gz", "sha256", "abc123"))
        .subject(Subject::new("app-macos.tar.gz", "sha256", "def456"))
        .subject(Subject::new("app-windows.zip", "sha256", "789012"))
        .predicate_type("https://example.com/test")
        .predicate(json!({}))
        .build()
        .unwrap();

    assert_eq!(statement.subject.len(), 3);
    assert_eq!(statement.subject[0].name, "app-linux.tar.gz");
    assert_eq!(statement.subject[1].name, "app-macos.tar.gz");
    assert_eq!(statement.subject[2].name, "app-windows.zip");
}
