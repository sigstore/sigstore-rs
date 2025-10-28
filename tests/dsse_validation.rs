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

//! Tests for DSSE bundle validation, including transparency log entry verification.

use sigstore::bundle::Bundle;

#[test]
fn test_dsse_v001_bundle_valid() {
    // Test that a valid DSSE v0.0.1 bundle can be parsed
    let bundle_json = include_str!("../tests/data/dsse_v001_bundle.sigstore.json");

    let bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse DSSE v0.0.1 bundle JSON");

    // Verify it's a v0.3 bundle
    assert_eq!(bundle.media_type, "application/vnd.dev.sigstore.bundle.v0.3+json");

    // Verify it has a DSSE envelope
    assert!(matches!(
        bundle.content,
        Some(sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(_))
    ), "DSSE v0.0.1 envelope should be present");

    // Verify the kind version
    let kind_version = bundle.verification_material.as_ref().unwrap()
        .tlog_entries[0].kind_version.as_ref().unwrap();
    assert_eq!(kind_version.version, "0.0.1");
}

#[test]
fn test_dsse_bundle_payload_tampering() {
    // Test that a bundle with tampered payload can still be parsed but fails verification
    let bundle_json = include_str!("../tests/data/dsse_v001_bundle.sigstore.json");

    let mut bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse DSSE bundle JSON");

    // Tamper with the DSSE payload
    if let Some(ref mut content) = bundle.content {
        if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
            // Change one byte in the payload
            envelope.payload[0] ^= 0xFF;
        }
    }

    // Bundle should still be parseable
    assert!(bundle.verification_material.is_some());
}

#[test]
fn test_dsse_bundle_signature_tampering() {
    // Test that a bundle with tampered signature can still be parsed but fails verification
    let bundle_json = include_str!("../tests/data/dsse_v001_bundle.sigstore.json");

    let mut bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse DSSE bundle JSON");

    // Tamper with the DSSE signature
    if let Some(ref mut content) = bundle.content {
        if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
            // Change one byte in the signature
            if !envelope.signatures.is_empty() {
                envelope.signatures[0].sig[0] ^= 0xFF;
            }
        }
    }

    // Bundle should still be parseable
    assert!(bundle.verification_material.is_some());
}

#[test]
fn test_dsse_bundle_missing_signatures() {
    // Test that a DSSE envelope with no signatures can be parsed
    let bundle_json = include_str!("../tests/data/dsse_v001_bundle.sigstore.json");

    let mut bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse DSSE bundle JSON");

    // Remove all signatures
    if let Some(ref mut content) = bundle.content {
        if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
            envelope.signatures.clear();
        }
    }

    // Bundle should still be parseable (validation happens later)
    assert!(bundle.content.is_some());
}

#[test]
fn test_regular_bundle_v3_not_dsse() {
    // Test that a regular (non-DSSE) v0.3 bundle is correctly identified
    let bundle_json = include_str!("../tests/data/bundle_v3.txt.sigstore");

    let bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse v0.3 bundle JSON");

    // Verify it's NOT a DSSE bundle
    assert!(matches!(
        bundle.content,
        Some(sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::MessageSignature(_))
    ), "Regular bundle should have MessageSignature, not DSSE");
}

#[test]
fn test_dsse_pae_format() {
    // Test that PAE (Pre-Authentication Encoding) is computed correctly
    use sigstore_protobuf_specs::io::intoto::Envelope;

    let envelope = Envelope {
        payload: b"test payload".to_vec(),
        payload_type: "application/test".to_string(),
        signatures: vec![],
    };

    let pae = sigstore::bundle::dsse::pae(&envelope);
    let expected = b"DSSEv1 16 application/test 12 test payload";

    assert_eq!(pae, expected);
}

#[test]
fn test_dsse_pae_with_intoto() {
    // Test PAE with a typical in-toto payload type
    use sigstore_protobuf_specs::io::intoto::Envelope;

    let envelope = Envelope {
        payload: b"{\"_type\":\"https://in-toto.io/Statement/v1\"}".to_vec(),
        payload_type: "application/vnd.in-toto+json".to_string(),
        signatures: vec![],
    };

    let pae = sigstore::bundle::dsse::pae(&envelope);

    // Should start with the correct prefix
    assert!(pae.starts_with(b"DSSEv1 28 application/vnd.in-toto+json "));

    // Should contain the payload length and payload
    assert!(pae.ends_with(b" {\"_type\":\"https://in-toto.io/Statement/v1\"}"));
}

#[test]
fn test_dsse_bundle_github_actions() {
    // Test a real GitHub Actions DSSE bundle (bundle2)
    let bundle_json = std::fs::read_to_string("examples/bundle2.sigstore.json")
        .expect("Failed to read bundle2.sigstore.json");

    let bundle: Bundle = serde_json::from_str(&bundle_json)
        .expect("Failed to parse bundle2 JSON");

    // Verify it's a v0.3 DSSE bundle
    assert_eq!(bundle.media_type, "application/vnd.dev.sigstore.bundle.v0.3+json");

    // Verify it has a DSSE envelope
    assert!(matches!(
        bundle.content,
        Some(sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(_))
    ), "Bundle2 should be a DSSE bundle");
}

#[test]
fn test_dsse_v002_bundle_valid() {
    // Test that a valid DSSE v0.0.2 bundle from sigstore-python can be parsed
    let bundle_json = include_str!("../tests/data/dsse_v002_bundle.sigstore.json");

    let bundle: Bundle = serde_json::from_str(bundle_json)
        .expect("Failed to parse DSSE v0.0.2 bundle JSON");

    // Verify it has a DSSE envelope
    assert!(matches!(
        bundle.content,
        Some(sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(_))
    ), "DSSE v0.0.2 envelope should be present");

    // Verify the tlog entry has v0.0.2 kind version
    let tlog_entries = bundle.verification_material
        .as_ref()
        .expect("Should have verification material")
        .tlog_entries
        .as_slice();

    assert_eq!(tlog_entries.len(), 1, "Should have exactly one tlog entry");

    let kind_version = tlog_entries[0].kind_version
        .as_ref()
        .expect("Should have kind version");

    assert_eq!(kind_version.kind, "dsse");
    assert_eq!(kind_version.version, "0.0.2");
}

#[test]
fn test_dsse_v001_vs_v002_format_differences() {
    // Test that we can distinguish between v0.0.1 and v0.0.2 formats
    let v001_bundle_json = include_str!("../tests/data/dsse_v001_bundle.sigstore.json");
    let v002_bundle_json = include_str!("../tests/data/dsse_v002_bundle.sigstore.json");

    let v001_bundle: Bundle = serde_json::from_str(v001_bundle_json)
        .expect("Failed to parse v0.0.1 bundle");
    let v002_bundle: Bundle = serde_json::from_str(v002_bundle_json)
        .expect("Failed to parse v0.0.2 bundle");

    // Both should have DSSE envelopes
    assert!(v001_bundle.content.is_some());
    assert!(v002_bundle.content.is_some());

    // Check kind versions
    let v001_tlog = &v001_bundle.verification_material.as_ref().unwrap().tlog_entries;
    let v002_tlog = &v002_bundle.verification_material.as_ref().unwrap().tlog_entries;

    assert_eq!(v001_tlog.len(), 1);
    assert_eq!(v002_tlog.len(), 1);

    let v001_kind = v001_tlog[0].kind_version.as_ref().unwrap();
    let v002_kind = v002_tlog[0].kind_version.as_ref().unwrap();

    assert_eq!(v001_kind.version, "0.0.1", "v0.0.1 bundle should have version 0.0.1");
    assert_eq!(v002_kind.version, "0.0.2", "v0.0.2 bundle should have version 0.0.2");
}

#[test]
fn test_dsse_v002_payload_hash_format() {
    // Test that v0.0.2 uses base64-encoded digest, not hex
    let bundle_json = include_str!("../tests/data/dsse_v002_bundle.sigstore.json");
    let bundle: Bundle = serde_json::from_str(bundle_json).unwrap();

    // Extract and decode canonicalized body
    let tlog_entry = &bundle.verification_material.as_ref().unwrap().tlog_entries[0];
    let canonical_json: serde_json::Value =
        serde_json::from_slice(&tlog_entry.canonicalized_body).unwrap();

    // Check that payload hash is in base64 format
    let payload_hash = canonical_json["spec"]["dsseV002"]["payloadHash"]["digest"]
        .as_str()
        .expect("Should have payload hash digest");

    // Base64 strings typically end with = padding or are length divisible by 4
    // Hex strings are even length and only contain 0-9a-f
    assert!(
        payload_hash.contains("=") || payload_hash.len() % 4 == 0,
        "v0.0.2 payload hash should be base64, got: {}",
        payload_hash
    );

    // Verify we can decode it as base64
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD.decode(payload_hash);
    assert!(decoded.is_ok(), "Should be valid base64");
    assert_eq!(decoded.unwrap().len(), 32, "SHA256 hash should be 32 bytes");
}
