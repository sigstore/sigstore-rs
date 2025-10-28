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

use sigstore_protobuf_specs::io::intoto::Envelope;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
