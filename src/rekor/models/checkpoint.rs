use crate::crypto::merkle::{MerkleProofVerifier, Rfc6269Default};
use crate::crypto::{CosignVerificationKey, Signature};
use crate::errors::SigstoreError;
use crate::errors::SigstoreError::ConsistencyProofError;
use crate::rekor::models::checkpoint::ParseCheckpointError::*;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use digest::Output;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Write;
use std::fmt::{Display, Formatter};

/// A checkpoint (also known as a signed tree head) that is served by the log.
/// It represents the log state at a point in time.
/// The `note` field stores this data,
/// and its authenticity can be verified with the data in `signature`.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct SignedCheckpoint {
    pub note: Checkpoint,
    pub signatures: Vec<CheckpointSignature>,
}

/// The metadata that is contained in a checkpoint.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct Checkpoint {
    /// origin is the unique identifier/version string
    pub origin: String,
    /// merkle tree size
    pub size: u64,
    /// merkle tree root hash
    pub hash: [u8; 32],
    /// catches the rest of the content
    pub other_content: Vec<OtherContent>,
}

/// The signature that is contained in a checkpoint.
/// The `key_fingerprint` are the first four bytes of the key hash of the corresponding log public key.
/// This can be used to identity the key which should be used to verify the checkpoint.
/// The actual signature is stored in `raw`.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct CheckpointSignature {
    pub key_fingerprint: [u8; 4],
    pub raw: Vec<u8>,
    pub name: String,
}

/// Checkpoints can contain additional data.
/// The `KeyValue` variant is for lines that are in the format `<KEY>: <VALUE>`.
/// Everything else is stored in the `Value` variant.
#[derive(Debug, PartialEq, Clone, Eq)]
pub enum OtherContent {
    KeyValue(String, String),
    Value(String),
}

impl Display for OtherContent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OtherContent::KeyValue(k, v) => write!(f, "{k}: {v}"),
            OtherContent::Value(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParseCheckpointError {
    DecodeError(String),
}

impl SignedCheckpoint {
    // decode from format used by Rekor for envelopes (signed notes)
    // See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#signed-envelope
    pub(crate) fn decode(s: &str) -> Result<Self, ParseCheckpointError> {
        // refer to: https://github.com/sigstore/rekor/blob/d702f84e6b8b127662c5e717ee550de1242a6aec/pkg/util/signed_note.go

        let checkpoint = s.trim_start_matches('"').trim_end_matches('"');

        let Some((note, sigs)) = checkpoint.split_once("\n\n") else {
            return Err(DecodeError("unexpected checkpoint format".to_string()));
        };

        let signatures: Vec<CheckpointSignature> = sigs
            .split("\n\n")
            .filter(|s| !s.trim().is_empty())
            .map(CheckpointSignature::decode)
            .collect::<Result<_, _>>()?;

        let note = Checkpoint::unmarshal(note)?;

        Ok(SignedCheckpoint { note, signatures })
    }

    // encode into format used by Rekor for envelopes (signed notes)
    // See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#signed-envelope
    pub(crate) fn encode(&self) -> String {
        let note = self.note.marshal() + "\n";
        let empty_line = "\n";
        let signatures = self
            .signatures
            .iter()
            .map(|s| s.encode())
            .collect::<Vec<_>>()
            .join("\n");
        format!("{note}{empty_line}{signatures}")
    }

    /// verify_signature checks that at least one of the signatures can be verified by the log
    /// with the public key `rekor_key`
    pub fn verify_signature(&self, rekor_key: &CosignVerificationKey) -> Result<(), SigstoreError> {
        for sig in &self.signatures {
            if rekor_key
                .verify_signature(Signature::Raw(&sig.raw), self.note.marshal().as_bytes())
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(SigstoreError::CheckpointSignatureVerificationError)
    }

    /// Checks if the checkpoint (root hash) matches the Merkle root and tree size claimed by an
    /// inclusion or consistency proof. This prevents accepting proofs that claim to be for a
    /// different tree than the one actually signed by the log, even if they are correctly signed.
    /// This ensures a cryptographic linkage between the log's signed state and the proof being
    /// verified.
    pub(crate) fn is_valid_for_proof(
        &self,
        proof_root_hash: &Output<Rfc6269Default>,
        proof_tree_size: u64,
    ) -> Result<(), SigstoreError> {
        // Delegate implementation as trivial consistency proof.
        // the checkpoint and the proof claim the same tree size. According to RFC-6962,
        // if two tree sizes are equal, the only valid consistency proof is that their roots are
        // equal and the proof is empty: one doesn't need any hashes to prove consistency between
        // two identical trees, just check that the roots match.
        Rfc6269Default::verify_consistency(
            self.note.size,         // checkpoint's tree size
            proof_tree_size,        // proof's tree size
            &[],                    // empty proof_hashes
            &self.note.hash.into(), // checkpoint's root hash
            proof_root_hash,        // proof's root hash
        )
        .map_err(ConsistencyProofError)
    }
}

impl Checkpoint {
    /// marshals the note
    /// See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#checkpoint-body
    fn marshal(&self) -> String {
        let hash_b64 = BASE64_STANDARD.encode(self.hash);
        let other_content: String = self.other_content.iter().fold(String::new(), |mut acc, c| {
            writeln!(acc, "{c}").expect("failed to write to string");
            acc
        });
        format!(
            "{}\n{}\n{hash_b64}\n{other_content}",
            self.origin, self.size
        )
    }

    /// unmarshal parses the common formatted note data and stores the result in a
    /// CheckpointNote
    fn unmarshal(s: &str) -> Result<Self, ParseCheckpointError> {
        // See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#checkpoint-body
        // The note is in the form:
        // <Origin string>
        // <Decimal log size>
        // <Base64 log root hash>
        // [other data]
        let split_note = s.split('\n').collect::<Vec<_>>();
        let [origin, size, hash_b64, other_content @ ..] = split_note.as_slice() else {
            return Err(DecodeError("note not in expected format".to_string()));
        };

        if origin.trim().is_empty() {
            return Err(DecodeError("origin string must not be empty".to_string()));
        }

        let size = size
            .parse::<u64>()
            .map_err(|_| DecodeError("expected decimal string for size".into()))?;

        let hash = BASE64_STANDARD
            .decode(hash_b64)
            .map_err(|_| DecodeError("failed to decode root hash".to_string()))
            .and_then(|v| {
                <[u8; 32]>::try_from(v)
                    .map_err(|_| DecodeError("expected 32-byte hash".to_string()))
            })?;

        let other_content = other_content
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split_once(": ")
                    .map(|(k, v)| OtherContent::KeyValue(k.to_string(), v.to_string()))
                    .unwrap_or(OtherContent::Value(s.to_string()))
            })
            .collect();

        Ok(Checkpoint {
            origin: origin.to_string(),
            size,
            hash,
            other_content,
        })
    }
}

impl Serialize for SignedCheckpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.encode().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedCheckpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <String>::deserialize(deserializer).and_then(|s| {
            SignedCheckpoint::decode(&s).map_err(|DecodeError(err)| serde::de::Error::custom(err))
        })
    }
}

impl CheckpointSignature {
    // encode into format used by Rekor for signed checkpoints (Signed Tree Heads)
    // in the sumdb note format `– <identity> <key_hint+signature_bytes>`
    // See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#signed-envelope
    fn encode(&self) -> String {
        let sig_b64 =
            BASE64_STANDARD.encode([self.key_fingerprint.as_slice(), self.raw.as_slice()].concat());
        // line starts with an em dash ( \u{2014})
        format!("\u{2014} {} {sig_b64}\n", self.name)
    }

    // decode from format used by Rekor for signed checkpoints (Signed Tree Heads)
    // in the sumdb note format `– <identity> <key_hint+signature_bytes>`
    // See https://github.com/transparency-dev/formats/blob/2de64aa755f08489bda36125786ced79688af872/log/README.md#signed-envelope
    fn decode(s: &str) -> Result<Self, ParseCheckpointError> {
        let s = s.trim_start_matches('\n').trim_end_matches('\n');
        if !s.starts_with('\u{2014}') {
            return Err(DecodeError("signature line missing em dash".to_string()));
        }
        let [_emdash, name, sig_b64] = s.split(' ').collect::<Vec<_>>()[..] else {
            return Err(DecodeError(format!("unexpected signature format {s:?}")));
        };
        let sig = BASE64_STANDARD
            .decode(sig_b64.trim_end())
            .map_err(|_| DecodeError("failed to decode signature".to_string()))?;

        // first four bytes of signature are fingerprint of key
        let (key_fingerprint, sig) = sig
            .split_at_checked(4)
            .ok_or_else(|| DecodeError("unexpected signature length in checkpoint".to_string()))?;
        let key_fingerprint = key_fingerprint
            .try_into()
            .map_err(|_| DecodeError("unexpected signature length in checkpoint".to_string()))?;

        Ok(CheckpointSignature {
            key_fingerprint,
            name: name.to_string(),
            raw: sig.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(test)]
    mod test_checkpoint_note {
        use crate::rekor::models::checkpoint::Checkpoint;
        use crate::rekor::models::checkpoint::OtherContent::{KeyValue, Value};

        #[test]
        fn test_marshal() {
            let test_cases = [
                (
                    "Log Checkpoint v0",
                    123,
                    [0; 32],
                    vec![],
                    "Log Checkpoint v0\n123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                ),
                (
                    "Banana Checkpoint v5",
                    9944,
                    [1; 32],
                    vec![],
                    "Banana Checkpoint v5\n9944\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
                ),
                (
                    "Banana Checkpoint v7",
                    9943,
                    [2; 32],
                    vec![Value("foo".to_string()), Value("bar".to_string())],
                    "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nfoo\nbar\n",
                ),
            ];

            for (origin, size, hash, other_content, expected) in test_cases {
                assert_eq!(
                    Checkpoint {
                        size,
                        origin: origin.to_string(),
                        hash,
                        other_content,
                    }
                    .marshal(),
                    expected
                );
            }
        }

        #[test]
        fn test_unmarshal_valid() {
            let test_cases = [
                (
                    "valid",
                    "Log Checkpoint v0",
                    123,
                    [0; 32],
                    vec![],
                    "Log Checkpoint v0\n123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                ),
                (
                    "valid",
                    "Banana Checkpoint v5",
                    9944,
                    [1; 32],
                    vec![],
                    "Banana Checkpoint v5\n9944\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
                ),
                (
                    "valid with multiple trailing data lines",
                    "Banana Checkpoint v7",
                    9943,
                    [2; 32],
                    vec![Value("foo".to_string()), Value("bar".to_string())],
                    "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nfoo\nbar\n",
                ),
                (
                    "valid with key-value data line",
                    "Banana Checkpoint v7",
                    9943,
                    [2; 32],
                    vec![KeyValue(
                        "Timestamp".to_string(),
                        "1689748607742585419".to_string(),
                    )],
                    "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nTimestamp: 1689748607742585419\n",
                ),
                (
                    "valid with trailing newlines",
                    "Banana Checkpoint v7",
                    9943,
                    [2; 32],
                    vec![],
                    "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\n\n\n",
                ),
            ];

            for (desc, origin, size, hash, other_content, input) in test_cases {
                let got = Checkpoint::unmarshal(input);

                let expected = Checkpoint {
                    size,
                    origin: origin.to_string(),
                    hash,
                    other_content,
                };
                assert_eq!(got, Ok(expected), "failed test case: {desc}");
            }
        }

        #[test]
        fn test_unmarshal_invalid() {
            let test_cases = [
                ("invalid - insufficient lines", "Head\n9944\n"),
                (
                    "invalid - empty header",
                    "\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
                ),
                (
                    "invalid - empty origin",
                    "123\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\nother data\n",
                ),
                (
                    "invalid - missing newline on roothash",
                    "Log Checkpoint v0\n123\nYmFuYW5hcw==",
                ),
                (
                    "invalid size - not a number",
                    "Log Checkpoint v0\nbananas\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
                ),
                (
                    "invalid size - negative",
                    "Log Checkpoint v0\n-34\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
                ),
                (
                    "invalid size - too large",
                    "Log Checkpoint v0\n3438945738945739845734895735\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
                ),
                (
                    "invalid roothash - not base64",
                    "Log Checkpoint v0\n123\nThisIsn'tBase64\n",
                ),
            ];
            for (desc, data) in test_cases {
                assert!(
                    Checkpoint::unmarshal(data).is_err(),
                    "accepted invalid note: {desc}"
                );
            }
        }
    }

    #[cfg(test)]
    mod test_checkpoint_signature {
        use crate::rekor::models::checkpoint::{Checkpoint, CheckpointSignature, SignedCheckpoint};

        #[test]
        fn test_to_string_valid_with_url_name() {
            let got = CheckpointSignature {
                name: "log.example.org".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            }
            .encode();
            let expected = "— log.example.org AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            assert_eq!(got, expected)
        }

        #[test]
        fn test_to_string_valid_with_id_name() {
            let got = CheckpointSignature {
                name: "815f6c60aab9".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            }
            .encode();
            let expected = "— 815f6c60aab9 AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            assert_eq!(got, expected)
        }

        #[test]
        fn test_from_str_valid_with_url_name() {
            let input = "— log.example.org AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            let expected = CheckpointSignature {
                name: "log.example.org".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            };
            let got = CheckpointSignature::decode(input);
            assert_eq!(got, Ok(expected))
        }

        #[test]
        fn test_from_str_valid_with_id_name() {
            let input = "— 815f6c60aab9 AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            let expected = CheckpointSignature {
                name: "815f6c60aab9".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            };
            let got = CheckpointSignature::decode(input);
            assert_eq!(got, Ok(expected))
        }

        #[test]
        fn test_from_str_valid_with_whitespace() {
            let input = "\n— log.example.org AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n\n";
            let expected = CheckpointSignature {
                name: "log.example.org".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            };
            let got = CheckpointSignature::decode(input);
            assert_eq!(got, Ok(expected))
        }

        #[test]
        fn test_from_str_invalid_with_spaces_in_name() {
            let input = "— Foo Bar AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            let got = CheckpointSignature::decode(input);
            assert!(got.is_err())
        }

        #[test]
        fn test_checkpoint_encode_decode_multiple_signatures() {
            let note = Checkpoint {
                origin: "Test Log".to_string(),
                size: 42,
                hash: [7; 32],
                other_content: vec![],
            };
            let sig1 = CheckpointSignature {
                name: "log1.example.org".to_string(),
                key_fingerprint: [1, 2, 3, 4],
                raw: vec![5; 32],
            };
            let sig2 = CheckpointSignature {
                name: "log2.example.org".to_string(),
                key_fingerprint: [9, 8, 7, 6],
                raw: vec![6; 32],
            };
            let checkpoint = SignedCheckpoint {
                note: note.clone(),
                signatures: vec![sig1.clone(), sig2.clone()],
            };
            let encoded = checkpoint.encode();
            let decoded = SignedCheckpoint::decode(&encoded).expect("decode should succeed");
            assert_eq!(decoded.note, note);
            assert_eq!(decoded.signatures.len(), 2);
            assert_eq!(decoded.signatures[0], sig1);
            assert_eq!(decoded.signatures[1], sig2);
        }
    }
}
