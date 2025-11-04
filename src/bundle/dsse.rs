// Copyright 2024 The Sigstore Authors.
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

//! DSSE (Dead Simple Signing Envelope) support for Sigstore bundles.
//!
//! This module implements the DSSE specification for creating and verifying
//! Pre-Authentication Encoding (PAE) used in DSSE signatures.
//!
//! See: <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/envelope.md>

use sigstore_protobuf_specs::io::intoto::{Envelope, Signature as DsseSignature};

use crate::bundle::intoto::Statement;

/// The DSSE payload type for in-toto attestations.
pub const PAYLOAD_TYPE_INTOTO: &str = "application/vnd.in-toto+json";

/// A wrapper around the protobuf `Envelope` that provides a convenient API for
/// creating and manipulating DSSE envelopes.
///
/// # Example
///
/// ```no_run
/// use sigstore::bundle::dsse::DsseEnvelope;
/// use sigstore::bundle::intoto::{StatementBuilder, Subject};
/// use serde_json::json;
///
/// let statement = StatementBuilder::new()
///     .subject(Subject::new("myapp.tar.gz", "sha256", "abc123..."))
///     .predicate_type("https://slsa.dev/provenance/v1")
///     .predicate(json!({"buildType": "test"}))
///     .build()
///     .unwrap();
///
/// let mut envelope = DsseEnvelope::from_statement(&statement).unwrap();
///
/// // Compute PAE for signing
/// let pae_bytes = envelope.pae();
///
/// // Add signature (signing logic not shown)
/// let signature_bytes: Vec<u8> = vec![]; // Your signature here
/// envelope.add_signature(signature_bytes, "".to_string());
/// ```
#[derive(Debug, Clone)]
pub struct DsseEnvelope(Envelope);

impl DsseEnvelope {
    /// Creates a new DSSE envelope from an in-toto statement.
    ///
    /// The statement is serialized to JSON as the payload.
    /// The envelope is returned without signatures - use [`Self::add_signature`] to add signatures.
    pub fn from_statement(statement: &Statement) -> Result<Self, serde_json::Error> {
        let payload_json = serde_json::to_vec(statement)?;

        Ok(Self(Envelope {
            payload: payload_json, // Store RAW bytes, not base64!
            payload_type: PAYLOAD_TYPE_INTOTO.to_string(),
            signatures: vec![],
        }))
    }

    /// Creates a DSSE envelope from a raw protobuf `Envelope`.
    pub fn from_envelope(envelope: Envelope) -> Self {
        Self(envelope)
    }

    /// Computes the DSSE Pre-Authentication Encoding (PAE) for this envelope.
    ///
    /// The PAE format is:
    /// ```text
    /// "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    /// ```
    ///
    /// Where:
    /// - `SP` is an ASCII space (0x20)
    /// - `LEN(s)` is the length of string `s` in ASCII decimal
    /// - `type` is the `payloadType` field
    /// - `body` is the `payload` field
    ///
    /// # Example
    ///
    /// ```text
    /// DSSEv1 28 application/vnd.in-toto+json 123 <payload-bytes>
    /// ```
    pub fn pae(&self) -> Vec<u8> {
        let payload_type = &self.0.payload_type;
        let payload = &self.0.payload;

        // Format: "DSSEv1 <type_len> <type> <payload_len> <payload>"
        let mut pae = format!("DSSEv1 {} {} ", payload_type.len(), payload_type).into_bytes();
        pae.extend_from_slice(format!("{} ", payload.len()).as_bytes());
        pae.extend_from_slice(payload);

        pae
    }

    /// Adds a signature to this envelope.
    ///
    /// The signature should be computed over the PAE (Pre-Authentication Encoding) of the envelope.
    /// Use [`Self::pae`] to compute the PAE that should be signed.
    pub fn add_signature(&mut self, signature: Vec<u8>, keyid: String) {
        self.0.signatures.push(DsseSignature {
            keyid,
            sig: signature,
        });
    }

    /// Returns a reference to the underlying protobuf `Envelope`.
    pub fn as_inner(&self) -> &Envelope {
        &self.0
    }

    /// Returns a mutable reference to the underlying protobuf `Envelope`.
    pub fn as_inner_mut(&mut self) -> &mut Envelope {
        &mut self.0
    }

    /// Consumes this wrapper and returns the underlying protobuf `Envelope`.
    pub fn into_inner(self) -> Envelope {
        self.0
    }

    /// Returns the payload of this envelope.
    pub fn payload(&self) -> &[u8] {
        &self.0.payload
    }

    /// Returns the payload type of this envelope.
    pub fn payload_type(&self) -> &str {
        &self.0.payload_type
    }

    /// Returns the signatures in this envelope.
    pub fn signatures(&self) -> &[DsseSignature] {
        &self.0.signatures
    }

    /// Decodes and parses the payload as an in-toto Statement.
    ///
    /// This is a convenience method for DSSE envelopes containing in-toto attestations.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not valid UTF-8 or cannot be parsed as a Statement.
    pub fn decode_statement(&self) -> Result<Statement, serde_json::Error> {
        serde_json::from_slice(&self.0.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::intoto::{StatementBuilder, Subject};
    use serde_json::json;

    #[test]
    fn test_pae_format() {
        // Test the PAE format matches the specification
        let envelope = DsseEnvelope::from_envelope(Envelope {
            payload: b"test payload".to_vec(),
            payload_type: "application/test".to_string(),
            signatures: vec![],
        });

        let result = envelope.pae();
        let expected = b"DSSEv1 16 application/test 12 test payload";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_with_intoto() {
        // Test with a typical in-toto payload type
        let envelope = DsseEnvelope::from_envelope(Envelope {
            payload: b"{\"_type\":\"https://in-toto.io/Statement/v1\"}".to_vec(),
            payload_type: "application/vnd.in-toto+json".to_string(),
            signatures: vec![],
        });

        let result = envelope.pae();

        // Should start with the correct prefix
        assert!(result.starts_with(b"DSSEv1 28 application/vnd.in-toto+json "));

        // Should contain the payload length and payload
        assert!(result.ends_with(b" {\"_type\":\"https://in-toto.io/Statement/v1\"}"));
    }

    #[test]
    fn test_create_envelope() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({"buildType": "test"}))
            .build()
            .unwrap();

        let envelope = DsseEnvelope::from_statement(&statement).unwrap();

        assert_eq!(envelope.payload_type(), PAYLOAD_TYPE_INTOTO);
        assert_eq!(envelope.signatures().len(), 0);

        // Verify the payload matches the statement
        let parsed_statement: crate::bundle::intoto::Statement =
            serde_json::from_slice(envelope.payload()).unwrap();

        assert_eq!(
            parsed_statement.statement_type,
            crate::bundle::intoto::STATEMENT_TYPE_V1
        );
        assert_eq!(parsed_statement.subject[0].name, "test.tar.gz");
    }

    #[test]
    fn test_add_signature() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({"buildType": "test"}))
            .build()
            .unwrap();

        let mut envelope = DsseEnvelope::from_statement(&statement).unwrap();
        let signature = vec![1, 2, 3, 4, 5];

        envelope.add_signature(signature.clone(), "test-key".to_string());

        assert_eq!(envelope.signatures().len(), 1);
        assert_eq!(envelope.signatures()[0].sig, signature);
        assert_eq!(envelope.signatures()[0].keyid, "test-key");
    }

    #[test]
    fn test_pae_with_created_envelope() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({"buildType": "test"}))
            .build()
            .unwrap();

        let envelope = DsseEnvelope::from_statement(&statement).unwrap();
        let pae_result = envelope.pae();

        // PAE should start with the correct format
        assert!(pae_result.starts_with(b"DSSEv1 28 application/vnd.in-toto+json "));

        // PAE should contain the payload
        let payload_str = String::from_utf8(envelope.payload().to_vec()).unwrap();
        assert!(
            String::from_utf8(pae_result)
                .unwrap()
                .contains(&payload_str)
        );
    }

    #[test]
    fn test_accessors() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({"buildType": "test"}))
            .build()
            .unwrap();

        let mut envelope = DsseEnvelope::from_statement(&statement).unwrap();

        // Test accessors
        assert_eq!(envelope.payload_type(), PAYLOAD_TYPE_INTOTO);
        assert!(!envelope.payload().is_empty());
        assert_eq!(envelope.signatures().len(), 0);

        // Test mutable access
        envelope.as_inner_mut().payload_type = "test".to_string();
        assert_eq!(envelope.payload_type(), "test");

        // Test into_inner
        let inner = envelope.into_inner();
        assert_eq!(inner.payload_type, "test");
    }

    #[test]
    fn test_decode_statement() {
        let original_statement = StatementBuilder::new()
            .subject(Subject::new("myapp.tar.gz", "sha256", "deadbeef"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({
                "buildType": "https://example.com/build",
                "builder": {"id": "https://example.com/builder"}
            }))
            .build()
            .unwrap();

        let envelope = DsseEnvelope::from_statement(&original_statement).unwrap();

        // Decode the statement back
        let decoded_statement = envelope.decode_statement().unwrap();

        // Verify it matches the original
        assert_eq!(
            decoded_statement.statement_type,
            original_statement.statement_type
        );
        assert_eq!(
            decoded_statement.predicate_type,
            original_statement.predicate_type
        );
        assert_eq!(decoded_statement.subject.len(), 1);
        assert_eq!(decoded_statement.subject[0].name, "myapp.tar.gz");
        assert_eq!(
            decoded_statement.subject[0].digest.get("sha256"),
            Some(&"deadbeef".to_string())
        );
    }

    #[test]
    fn test_decode_statement_v0_1() {
        // Test that we can decode v0.1 statements
        let v0_1_statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v0.2")
            .predicate(json!({"buildType": "test"}))
            .build_v0_1()
            .unwrap();

        let envelope = DsseEnvelope::from_statement(&v0_1_statement).unwrap();
        let decoded = envelope.decode_statement().unwrap();

        assert_eq!(
            decoded.statement_type,
            crate::bundle::intoto::STATEMENT_TYPE_V0_1
        );
    }
}
