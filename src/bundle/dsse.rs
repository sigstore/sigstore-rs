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

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use sigstore_protobuf_specs::io::intoto::{Envelope, Signature as DsseSignature};

use crate::bundle::intoto::Statement;

/// Compute the DSSE Pre-Authentication Encoding (PAE) for the given envelope.
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
pub fn pae(envelope: &Envelope) -> Vec<u8> {
    let payload_type = &envelope.payload_type;
    let payload = &envelope.payload;

    // Format: "DSSEv1 <type_len> <type> <payload_len> <payload>"
    let mut pae = format!("DSSEv1 {} {} ", payload_type.len(), payload_type).into_bytes();
    pae.extend_from_slice(format!("{} ", payload.len()).as_bytes());
    pae.extend_from_slice(payload);

    pae
}

/// The DSSE payload type for in-toto attestations.
pub const PAYLOAD_TYPE_INTOTO: &str = "application/vnd.in-toto+json";

/// Creates a DSSE envelope from an in-toto statement.
///
/// The statement is serialized to JSON and base64-encoded as the payload.
/// The envelope is returned without signatures - use [`add_signature`] to add signatures.
///
/// # Example
///
/// ```no_run
/// use sigstore::bundle::dsse::create_envelope;
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
/// let envelope = create_envelope(&statement).unwrap();
/// ```
pub fn create_envelope(statement: &Statement) -> Result<Envelope, serde_json::Error> {
    let payload_json = serde_json::to_vec(statement)?;
    let payload_b64 = base64.encode(&payload_json);

    Ok(Envelope {
        payload: payload_b64.into_bytes(),
        payload_type: PAYLOAD_TYPE_INTOTO.to_string(),
        signatures: vec![],
    })
}

/// Adds a signature to a DSSE envelope.
///
/// The signature should be computed over the PAE (Pre-Authentication Encoding) of the envelope.
/// Use [`pae`] to compute the PAE that should be signed.
///
/// # Example
///
/// ```no_run
/// use sigstore::bundle::dsse::{create_envelope, add_signature, pae};
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
/// let mut envelope = create_envelope(&statement).unwrap();
///
/// // Compute PAE and sign it (signing logic not shown)
/// let pae_bytes = pae(&envelope);
/// let signature_bytes: Vec<u8> = vec![]; // Your signature here
///
/// add_signature(&mut envelope, signature_bytes, "".to_string());
/// ```
pub fn add_signature(envelope: &mut Envelope, signature: Vec<u8>, keyid: String) {
    envelope.signatures.push(DsseSignature {
        keyid,
        sig: signature,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::intoto::{StatementBuilder, Subject};
    use serde_json::json;

    #[test]
    fn test_pae_format() {
        // Test the PAE format matches the specification
        let envelope = Envelope {
            payload: b"test payload".to_vec(),
            payload_type: "application/test".to_string(),
            signatures: vec![],
        };

        let result = pae(&envelope);
        let expected = b"DSSEv1 16 application/test 12 test payload";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_with_intoto() {
        // Test with a typical in-toto payload type
        let envelope = Envelope {
            payload: b"{\"_type\":\"https://in-toto.io/Statement/v1\"}".to_vec(),
            payload_type: "application/vnd.in-toto+json".to_string(),
            signatures: vec![],
        };

        let result = pae(&envelope);

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

        let envelope = create_envelope(&statement).unwrap();

        assert_eq!(envelope.payload_type, PAYLOAD_TYPE_INTOTO);
        assert_eq!(envelope.signatures.len(), 0);

        // Decode the payload and verify it matches the statement
        let payload_str = String::from_utf8(envelope.payload.clone()).unwrap();
        let payload_json = base64.decode(payload_str.as_bytes()).unwrap();
        let parsed_statement: crate::bundle::intoto::Statement =
            serde_json::from_slice(&payload_json).unwrap();

        assert_eq!(parsed_statement.statement_type, crate::bundle::intoto::STATEMENT_TYPE_V1);
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

        let mut envelope = create_envelope(&statement).unwrap();
        let signature = vec![1, 2, 3, 4, 5];

        add_signature(&mut envelope, signature.clone(), "test-key".to_string());

        assert_eq!(envelope.signatures.len(), 1);
        assert_eq!(envelope.signatures[0].sig, signature);
        assert_eq!(envelope.signatures[0].keyid, "test-key");
    }

    #[test]
    fn test_pae_with_created_envelope() {
        let statement = StatementBuilder::new()
            .subject(Subject::new("test.tar.gz", "sha256", "abc123"))
            .predicate_type("https://slsa.dev/provenance/v1")
            .predicate(json!({"buildType": "test"}))
            .build()
            .unwrap();

        let envelope = create_envelope(&statement).unwrap();
        let pae_result = pae(&envelope);

        // PAE should start with the correct format
        assert!(pae_result.starts_with(b"DSSEv1 28 application/vnd.in-toto+json "));

        // PAE should contain the base64-encoded payload
        let payload_str = String::from_utf8(envelope.payload.clone()).unwrap();
        assert!(String::from_utf8(pae_result).unwrap().contains(&payload_str));
    }
}
