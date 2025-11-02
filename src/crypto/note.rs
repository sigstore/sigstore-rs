//
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

//! Note format parsing and verification.
//!
//! This module implements parsing and verification of the note format used by Rekor v2
//! checkpoints. The note format is specified by golang.org/x/mod/sumdb/note and consists
//! of a signed message with one or more cryptographic signatures.
//!
//! # Format
//!
//! A note consists of a text header and signature lines, separated by a blank line:
//!
//! ```text
//! <origin>
//! <tree_size>
//! <root_hash_base64>
//!
//! — <signer_name> <signature_base64>
//! — <witness_name> <signature_base64>
//! ```
//!
//! The signature lines begin with the Unicode em dash (U+2014, "—"), not an ASCII hyphen.
//! Each base64-decoded signature consists of a 4-byte key ID followed by the signature bytes.

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use thiserror::Error;

/// Simple hex encoding helper (to avoid dependency on hex crate)
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Errors that can occur when parsing or verifying notes.
#[derive(Error, Debug)]
pub enum NoteError {
    #[error("note is empty")]
    Empty,

    #[error("note missing blank line separator")]
    MissingSeparator,

    #[error("note has multiple blank line separators")]
    MultipleSeparators,

    #[error("checkpoint origin is empty")]
    EmptyOrigin,

    #[error("checkpoint missing tree size")]
    MissingTreeSize,

    #[error("invalid tree size: {0}")]
    InvalidTreeSize(String),

    #[error("checkpoint missing root hash")]
    MissingRootHash,

    #[error("invalid base64 in root hash: {0}")]
    InvalidRootHashBase64(String),

    #[error("note has no signatures")]
    NoSignatures,

    #[error("invalid signature line format: {0}")]
    InvalidSignatureFormat(String),

    #[error("signature does not start with em dash (U+2014)")]
    SignatureMissingEmDash,

    #[error("invalid base64 in signature: {0}")]
    InvalidSignatureBase64(String),

    #[error("signature too short (must be at least 5 bytes for 4-byte key ID + signature)")]
    SignatureTooShort,

    #[error("no signature found matching key ID")]
    NoMatchingSignature,

    #[error("checkpoint root hash mismatch: expected {expected}, got {actual}")]
    RootHashMismatch { expected: String, actual: String },
}

/// A single signature in a note.
///
/// Each signature consists of:
/// - A name identifying the signer (e.g., "log2025-alpha1.rekor.sigstage.dev")
/// - A 4-byte key ID used to match the signature to a public key
/// - The signature bytes
#[derive(Debug, Clone, PartialEq)]
pub struct NoteSignature {
    /// The name of the signer (appears after the em dash).
    pub name: String,

    /// The 4-byte key ID extracted from the beginning of the decoded signature.
    pub key_id: [u8; 4],

    /// The signature bytes (after the 4-byte key ID).
    pub signature: Vec<u8>,
}

/// A checkpoint header containing the log state.
///
/// The checkpoint consists of:
/// - Origin: The name of the log (e.g., "log2025-alpha1.rekor.sigstage.dev")
/// - Tree size: The number of entries in the log
/// - Root hash: The Merkle tree root hash
/// - Optional metadata lines
#[derive(Debug, Clone, PartialEq)]
pub struct LogCheckpoint {
    /// The origin (log name).
    pub origin: String,

    /// The tree size (number of entries in the log).
    pub tree_size: u64,

    /// The root hash of the Merkle tree (binary).
    pub root_hash: Vec<u8>,

    /// Optional metadata lines (e.g., "Timestamp: 1679349379012118479").
    pub metadata: Vec<String>,
}

/// A signed note containing a checkpoint and signatures.
///
/// This represents a complete note in the format used by Rekor v2 checkpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedNote {
    /// The checkpoint header (before the blank line).
    pub checkpoint: LogCheckpoint,

    /// The raw text of the checkpoint (used for signature verification).
    pub checkpoint_text: String,

    /// The signatures (after the blank line).
    pub signatures: Vec<NoteSignature>,
}

impl LogCheckpoint {
    /// Parse a checkpoint from text lines.
    ///
    /// The checkpoint must have at least 3 lines:
    /// 1. Origin
    /// 2. Tree size (integer)
    /// 3. Root hash (base64)
    /// 4. .. and following lines: More optional metadata
    pub fn from_text(text: &str) -> Result<Self, NoteError> {
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            return Err(NoteError::Empty);
        }

        // Line 0: Origin
        let origin = lines[0].trim();
        if origin.is_empty() {
            return Err(NoteError::EmptyOrigin);
        }

        // Line 1: Tree size
        if lines.len() < 2 {
            return Err(NoteError::MissingTreeSize);
        }
        let tree_size = lines[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| NoteError::InvalidTreeSize(lines[1].to_string()))?;

        // Line 2: Root hash (base64)
        if lines.len() < 3 {
            return Err(NoteError::MissingRootHash);
        }
        let root_hash = base64
            .decode(lines[2].trim())
            .map_err(|e| NoteError::InvalidRootHashBase64(e.to_string()))?;

        // Lines 3+: Optional metadata
        let metadata = lines[3..]
            .iter()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        Ok(LogCheckpoint {
            origin: origin.to_string(),
            tree_size,
            root_hash,
            metadata,
        })
    }

    /// Serialize a checkpoint to text format.
    ///
    /// The output format is:
    /// ```text
    /// <origin>
    /// <tree_size>
    /// <root_hash_base64>
    /// <metadata_line_1>
    /// <metadata_line_2>
    /// ...
    /// ```
    ///
    /// This is the inverse of `from_text()` and can be used for round-trip
    /// serialization or for creating checkpoint text to sign.
    pub fn to_text(&self) -> String {
        let root_hash_b64 = base64.encode(&self.root_hash);
        let mut output = format!("{}\n{}\n{}\n", self.origin, self.tree_size, root_hash_b64);

        // Add metadata lines
        for line in &self.metadata {
            output.push_str(line);
            output.push('\n');
        }

        output
    }
}

impl NoteSignature {
    /// Parse a signature line.
    ///
    /// The line must be in the format: `— <name> <base64_signature>`
    /// The em dash (U+2014) is required at the start.
    pub fn from_line(line: &str) -> Result<Self, NoteError> {
        // Check for em dash at the start
        if !line.starts_with('—') {
            return Err(NoteError::SignatureMissingEmDash);
        }

        // Split into parts: "— <name> <signature>"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(NoteError::InvalidSignatureFormat(
                "signature line must have format: — <name> <base64_signature>".to_string(),
            ));
        }

        let name = parts[1].to_string();
        let sig_base64 = parts[2];

        // Decode the signature
        let sig_bytes = base64
            .decode(sig_base64)
            .map_err(|e| NoteError::InvalidSignatureBase64(e.to_string()))?;

        // Signature must be at least 5 bytes (4-byte key ID + at least 1 byte signature)
        if sig_bytes.len() < 5 {
            return Err(NoteError::SignatureTooShort);
        }

        // Extract 4-byte key ID and signature bytes
        // SAFETY: We've verified above that sig_bytes has at least 5 bytes
        let key_id: [u8; 4] = [sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]];
        let signature = sig_bytes[4..].to_vec();

        Ok(NoteSignature {
            name,
            key_id,
            signature,
        })
    }

    /// Serialize a signature to text format.
    ///
    /// The output format is: `— <name> <base64_signature>`
    /// where the base64_signature encodes the 4-byte key ID followed by the signature bytes.
    pub fn to_line(&self) -> String {
        // Combine key_id (4 bytes) and signature bytes
        let mut sig_bytes = Vec::with_capacity(4 + self.signature.len());
        sig_bytes.extend_from_slice(&self.key_id);
        sig_bytes.extend_from_slice(&self.signature);

        // Encode to base64
        let sig_base64 = base64.encode(&sig_bytes);

        // Format with em dash
        format!("— {} {}", self.name, sig_base64)
    }
}

impl SignedNote {
    /// Parse a complete signed note.
    ///
    /// The note must consist of a checkpoint header and signature lines,
    /// separated by exactly one blank line.
    pub fn from_text(text: &str) -> Result<Self, NoteError> {
        if text.is_empty() {
            return Err(NoteError::Empty);
        }

        // Split by double newline (blank line separator)
        let parts: Vec<&str> = text.split("\n\n").collect();

        if parts.len() < 2 {
            return Err(NoteError::MissingSeparator);
        }

        if parts.len() > 2 {
            return Err(NoteError::MultipleSeparators);
        }

        let checkpoint_text_without_newline = parts[0];
        let signatures_text = parts[1];

        // Parse checkpoint
        let checkpoint = LogCheckpoint::from_text(checkpoint_text_without_newline)?;

        // Parse signatures
        let mut signatures = Vec::new();
        for line in signatures_text.lines() {
            let line = line.trim();
            if !line.is_empty() {
                signatures.push(NoteSignature::from_line(line)?);
            }
        }

        if signatures.is_empty() {
            return Err(NoteError::NoSignatures);
        }

        // The signed text includes the checkpoint text plus a single trailing newline
        // According to golang.org/x/mod/sumdb/note spec
        let checkpoint_text = format!("{}\n", checkpoint_text_without_newline);

        Ok(SignedNote {
            checkpoint,
            checkpoint_text,
            signatures,
        })
    }

    /// Find a signature matching the given 4-byte key ID.
    pub fn find_signature(&self, key_id: &[u8; 4]) -> Option<&NoteSignature> {
        self.signatures.iter().find(|sig| &sig.key_id == key_id)
    }

    /// Verify that the checkpoint root hash matches the expected value.
    pub fn verify_root_hash(&self, expected_root_hash: &[u8]) -> Result<(), NoteError> {
        if self.checkpoint.root_hash != expected_root_hash {
            return Err(NoteError::RootHashMismatch {
                expected: encode_hex(expected_root_hash),
                actual: encode_hex(&self.checkpoint.root_hash),
            });
        }
        Ok(())
    }

    /// Serialize a signed note to text format.
    ///
    /// The output format is:
    /// ```text
    /// <checkpoint_text>
    ///
    /// — <signer1_name> <signature1_base64>
    /// — <signer2_name> <signature2_base64>
    /// ```
    ///
    /// This is the inverse of `from_text()` and can be used for round-trip
    /// serialization.
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        // Add checkpoint text (already includes trailing newline)
        output.push_str(&self.checkpoint_text);

        // Add blank line separator
        output.push('\n');

        // Add signature lines
        for sig in &self.signatures {
            output.push_str(&sig.to_line());
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint_minimal() {
        let text =
            "log2025-alpha1.rekor.sigstage.dev\n736\nrs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=";
        let checkpoint = LogCheckpoint::from_text(text).unwrap();

        assert_eq!(checkpoint.origin, "log2025-alpha1.rekor.sigstage.dev");
        assert_eq!(checkpoint.tree_size, 736);
        assert_eq!(checkpoint.root_hash.len(), 32); // SHA256 hash
        assert!(checkpoint.metadata.is_empty());
    }

    #[test]
    fn test_parse_checkpoint_with_metadata() {
        let text = "example.com\n100\naGVsbG8=\nTimestamp: 1234567890";
        let checkpoint = LogCheckpoint::from_text(text).unwrap();

        assert_eq!(checkpoint.origin, "example.com");
        assert_eq!(checkpoint.tree_size, 100);
        assert_eq!(checkpoint.metadata.len(), 1);
        assert_eq!(checkpoint.metadata[0], "Timestamp: 1234567890");
    }

    #[test]
    fn test_parse_checkpoint_empty_origin() {
        let text = "\n100\naGVsbG8=";
        let result = LogCheckpoint::from_text(text);
        assert!(matches!(result, Err(NoteError::EmptyOrigin)));
    }

    #[test]
    fn test_parse_checkpoint_invalid_tree_size() {
        let text = "example.com\nnot-a-number\naGVsbG8=";
        let result = LogCheckpoint::from_text(text);
        assert!(matches!(result, Err(NoteError::InvalidTreeSize(_))));
    }

    #[test]
    fn test_parse_checkpoint_invalid_hash_base64() {
        let text = "example.com\n100\ninvalid!!!base64";
        let result = LogCheckpoint::from_text(text);
        assert!(matches!(result, Err(NoteError::InvalidRootHashBase64(_))));
    }

    #[test]
    fn test_parse_signature_valid() {
        // Real signature line from Rekor (with valid base64 that decodes to 68 bytes: 4-byte key ID + 64-byte Ed25519 signature)
        let line = "— log2025-alpha1.rekor.sigstage.dev 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=";
        let sig = NoteSignature::from_line(line).unwrap();

        assert_eq!(sig.name, "log2025-alpha1.rekor.sigstage.dev");
        assert_eq!(sig.key_id.len(), 4);
        assert_eq!(sig.signature.len(), 64); // Ed25519 signature
    }

    #[test]
    fn test_parse_signature_missing_em_dash() {
        let line = "- log.example.com c2lnbmF0dXJl";
        let result = NoteSignature::from_line(line);
        assert!(matches!(result, Err(NoteError::SignatureMissingEmDash)));
    }

    #[test]
    fn test_parse_signature_too_short() {
        // Signature that decodes to less than 5 bytes
        let line = "— log.example.com YWJjZA=="; // "abcd" = 4 bytes
        let result = NoteSignature::from_line(line);
        assert!(matches!(result, Err(NoteError::SignatureTooShort)));
    }

    #[test]
    fn test_parse_signed_note_valid() {
        let text = "log2025-alpha1.rekor.sigstage.dev\n736\nrs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=\n\n— log2025-alpha1.rekor.sigstage.dev 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=";
        let note = SignedNote::from_text(text).unwrap();

        assert_eq!(note.checkpoint.origin, "log2025-alpha1.rekor.sigstage.dev");
        assert_eq!(note.checkpoint.tree_size, 736);
        assert_eq!(note.signatures.len(), 1);
        assert_eq!(note.signatures[0].name, "log2025-alpha1.rekor.sigstage.dev");
    }

    #[test]
    fn test_parse_signed_note_with_witness() {
        let text = "log2025-alpha1.rekor.sigstage.dev\n736\nrs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=\n\n— log2025-alpha1.rekor.sigstage.dev 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=\n— witness.example O8PH5AAAAABopO8+4O9uzScQrNEnGdKLYXSPoUjH1Se4n92W+wT/j5Kel/4J2XWE4bEe9bpIVUD6EGOeUDFkSWz/rbDhvVcJ/2OrDw==";
        let note = SignedNote::from_text(text).unwrap();

        assert_eq!(note.signatures.len(), 2);
        assert_eq!(note.signatures[0].name, "log2025-alpha1.rekor.sigstage.dev");
        assert_eq!(note.signatures[1].name, "witness.example");
    }

    #[test]
    fn test_parse_signed_note_missing_separator() {
        let text = "log.example.com\n100\naGVsbG8=\n— log.example.com c2lnbmF0dXJlAA==";
        let result = SignedNote::from_text(text);
        assert!(matches!(result, Err(NoteError::MissingSeparator)));
    }

    #[test]
    fn test_parse_signed_note_no_signatures() {
        let text = "log.example.com\n100\naGVsbG8=\n\n";
        let result = SignedNote::from_text(text);
        assert!(matches!(result, Err(NoteError::NoSignatures)));
    }

    #[test]
    fn test_find_signature_by_key_id() {
        let text = "log.example.com\n100\naGVsbG8=\n\n— log.example.com AQIDBAUAAAAA\n— witness.example BQYHCAUAAAAA";
        let note = SignedNote::from_text(text).unwrap();

        // Find first signature by its key ID
        let key_id_1 = note.signatures[0].key_id;
        let found = note.find_signature(&key_id_1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "log.example.com");

        // Find second signature by its key ID
        let key_id_2 = note.signatures[1].key_id;
        let found = note.find_signature(&key_id_2);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "witness.example");

        // Try to find non-existent key ID
        let fake_key_id = [0xFF, 0xFF, 0xFF, 0xFF];
        let found = note.find_signature(&fake_key_id);
        assert!(found.is_none());
    }

    #[test]
    fn test_verify_root_hash_match() {
        let text = "log.example.com\n100\naGVsbG8=\n\n— log.example.com AQIDBAUAAAAA";
        let note = SignedNote::from_text(text).unwrap();

        // "aGVsbG8=" decodes to "hello"
        let result = note.verify_root_hash(b"hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_root_hash_mismatch() {
        let text = "log.example.com\n100\naGVsbG8=\n\n— log.example.com AQIDBAUAAAAA";
        let note = SignedNote::from_text(text).unwrap();

        let result = note.verify_root_hash(b"wrong");
        assert!(matches!(result, Err(NoteError::RootHashMismatch { .. })));
    }

    #[test]
    fn test_checkpoint_text_preserved() {
        let checkpoint_text = "log.example.com\n100\naGVsbG8=";
        let full_text = format!("{}\n\n— log.example.com AQIDBAUAAAAA", checkpoint_text);
        let note = SignedNote::from_text(&full_text).unwrap();

        // The checkpoint_text includes a trailing newline according to golang.org/x/mod/sumdb/note spec
        assert_eq!(note.checkpoint_text, format!("{}\n", checkpoint_text));
    }

    #[test]
    fn test_checkpoint_to_text() {
        let checkpoint = LogCheckpoint {
            origin: "log.example.com".to_string(),
            tree_size: 12345,
            root_hash: vec![0x01, 0x02, 0x03, 0x04],
            metadata: vec![],
        };

        let text = checkpoint.to_text();

        // Should have origin, tree size, and base64-encoded hash
        assert!(text.contains("log.example.com"));
        assert!(text.contains("12345"));
        assert!(text.contains("AQIDBA==")); // base64 of [0x01, 0x02, 0x03, 0x04]
    }

    #[test]
    fn test_checkpoint_to_text_with_metadata() {
        let checkpoint = LogCheckpoint {
            origin: "log.example.com".to_string(),
            tree_size: 100,
            root_hash: vec![0xde, 0xad, 0xbe, 0xef],
            metadata: vec![
                "Timestamp: 1234567890".to_string(),
                "Extra: data".to_string(),
            ],
        };

        let text = checkpoint.to_text();

        // Should include metadata
        assert!(text.contains("Timestamp: 1234567890"));
        assert!(text.contains("Extra: data"));
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let original = LogCheckpoint {
            origin: "rekor.sigstore.dev".to_string(),
            tree_size: 999,
            root_hash: vec![1, 2, 3, 4, 5, 6, 7, 8],
            metadata: vec!["Info: test".to_string()],
        };

        // Serialize to text
        let text = original.to_text();

        // Parse back
        let parsed = LogCheckpoint::from_text(&text).unwrap();

        // Should match
        assert_eq!(parsed.origin, original.origin);
        assert_eq!(parsed.tree_size, original.tree_size);
        assert_eq!(parsed.root_hash, original.root_hash);
        assert_eq!(parsed.metadata, original.metadata);
    }

    #[test]
    fn test_signature_to_line() {
        let sig = NoteSignature {
            name: "log.example.com".to_string(),
            key_id: [0x01, 0x02, 0x03, 0x04],
            signature: vec![0x05, 0x06, 0x07, 0x08],
        };

        let line = sig.to_line();

        // Should start with em dash
        assert!(line.starts_with("— "));
        // Should contain the name
        assert!(line.contains("log.example.com"));
        // Should contain base64-encoded (key_id + signature)
        assert!(line.contains("AQIDBAUGBwg=")); // base64 of [0x01..0x08]
    }

    #[test]
    fn test_signature_roundtrip() {
        let original = NoteSignature {
            name: "witness.example.com".to_string(),
            key_id: [0xaa, 0xbb, 0xcc, 0xdd],
            signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        };

        // Serialize to line
        let line = original.to_line();

        // Parse back
        let parsed = NoteSignature::from_line(&line).unwrap();

        // Should match
        assert_eq!(parsed.name, original.name);
        assert_eq!(parsed.key_id, original.key_id);
        assert_eq!(parsed.signature, original.signature);
    }

    #[test]
    fn test_signed_note_roundtrip() {
        let text = "log.example.com\n100\naGVsbG8=\n\n— log.example.com AQIDBAUAAAAA\n— witness AQIDBAYHCAk=\n";

        // Parse
        let parsed = SignedNote::from_text(text).unwrap();

        // Serialize back
        let serialized = parsed.to_text();

        // Parse again
        let reparsed = SignedNote::from_text(&serialized).unwrap();

        // Should match original
        assert_eq!(reparsed.checkpoint.origin, parsed.checkpoint.origin);
        assert_eq!(reparsed.checkpoint.tree_size, parsed.checkpoint.tree_size);
        assert_eq!(reparsed.checkpoint.root_hash, parsed.checkpoint.root_hash);
        assert_eq!(reparsed.signatures.len(), parsed.signatures.len());
    }

    #[test]
    fn test_signed_note_to_text_format() {
        let checkpoint = LogCheckpoint {
            origin: "test.log".to_string(),
            tree_size: 42,
            root_hash: vec![0xaa, 0xbb],
            metadata: vec![],
        };

        let checkpoint_text = checkpoint.to_text();

        let sig = NoteSignature {
            name: "signer".to_string(),
            key_id: [1, 2, 3, 4],
            signature: vec![5, 6],
        };

        let signed = SignedNote {
            checkpoint,
            checkpoint_text,
            signatures: vec![sig],
        };

        let text = signed.to_text();

        // Should have checkpoint section
        assert!(text.contains("test.log"));
        assert!(text.contains("42"));

        // Should have blank line
        let parts: Vec<&str> = text.split("\n\n").collect();
        assert_eq!(parts.len(), 2);

        // Should have signature section
        assert!(text.contains("— signer"));
    }
}
