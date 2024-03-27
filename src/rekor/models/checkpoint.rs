use crate::crypto::merkle::{MerkleProofVerifier, Rfc6269Default};
use crate::crypto::{CosignVerificationKey, Signature};
use crate::errors::SigstoreError;
use crate::errors::SigstoreError::ConsistencyProofError;
use crate::rekor::models::checkpoint::ParseCheckpointError::*;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use digest::Output;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// A checkpoint (also known as a signed tree head) that served by the log.
/// It represents the log state at a point in time.
/// The `note` field stores this data,
/// and its authenticity can be verified with the data in `signature`.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct Checkpoint {
    pub note: CheckpointNote,
    pub signature: CheckpointSignature,
}

/// The metadata that is contained in a checkpoint.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct CheckpointNote {
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

impl FromStr for Checkpoint {
    type Err = ParseCheckpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // refer to: https://github.com/sigstore/rekor/blob/d702f84e6b8b127662c5e717ee550de1242a6aec/pkg/util/checkpoint.go

        let checkpoint = s.trim_start_matches('"').trim_end_matches('"');

        let Some((note, signature)) = checkpoint.split_once("\n\n") else {
            return Err(DecodeError("unexpected checkpoint format".to_string()));
        };

        let signature = signature.parse()?;
        let note = CheckpointNote::unmarshal(note)?;

        Ok(Checkpoint { note, signature })
    }
}

impl CheckpointNote {
    // Output is the part of the checkpoint that is signed.
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
    fn unmarshal(s: &str) -> Result<Self, ParseCheckpointError> {
        // refer to: https://github.com/sigstore/rekor/blob/d702f84e6b8b127662c5e717ee550de1242a6aec/pkg/util/checkpoint.go
        // note is separated by new lines
        let split_note = s.split('\n').collect::<Vec<_>>();
        let [origin, size, hash_b64, other_content @ ..] = split_note.as_slice() else {
            return Err(DecodeError("note not in expected format".to_string()));
        };

        let size = size
            .parse()
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

        Ok(CheckpointNote {
            origin: origin.to_string(),
            size,
            hash,
            other_content,
        })
    }
}

impl ToString for Checkpoint {
    fn to_string(&self) -> String {
        let note = self.note.marshal();
        let signature = self.signature.to_string();
        format!("{note}\n{signature}")
    }
}

impl Checkpoint {
    /// This method can be used to verify that the checkpoint was issued by the log with the
    /// public key `rekor_key`.
    pub fn verify_signature(&self, rekor_key: &CosignVerificationKey) -> Result<(), SigstoreError> {
        rekor_key.verify_signature(
            Signature::Raw(&self.signature.raw),
            self.note.marshal().as_bytes(),
        )
    }

    /// Checks if the checkpoint and inclusion proof are valid together.
    pub(crate) fn is_valid_for_proof(
        &self,
        proof_root_hash: &Output<Rfc6269Default>,
        proof_tree_size: u64,
    ) -> Result<(), SigstoreError> {
        // Delegate implementation as trivial consistency proof.
        Rfc6269Default::verify_consistency(
            self.note.size as usize,
            proof_tree_size as usize,
            &[],
            &self.note.hash.into(),
            proof_root_hash,
        )
        .map_err(ConsistencyProofError)
    }
}

impl Serialize for Checkpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Checkpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <String>::deserialize(deserializer).and_then(|s| {
            Checkpoint::from_str(&s).map_err(|DecodeError(err)| serde::de::Error::custom(err))
        })
    }
}

impl ToString for CheckpointSignature {
    fn to_string(&self) -> String {
        let sig_b64 =
            BASE64_STANDARD.encode([self.key_fingerprint.as_slice(), self.raw.as_slice()].concat());
        format!("— {} {sig_b64}\n", self.name)
    }
}

impl FromStr for CheckpointSignature {
    type Err = ParseCheckpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches('\n').trim_end_matches('\n');
        let [_, name, sig_b64] = s.split(' ').collect::<Vec<_>>()[..] else {
            return Err(DecodeError(format!("unexpected signature format {s:?}")));
        };
        let sig = BASE64_STANDARD
            .decode(sig_b64.trim_end())
            .map_err(|_| DecodeError("failed to decode signature".to_string()))?;

        // first four bytes of signature are fingerprint of key
        let (key_fingerprint, sig) = sig.split_at(4);
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
        use crate::rekor::models::checkpoint::CheckpointNote;
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
                    "Banana Checkpoint v5\n9944\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n", ),
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
                    CheckpointNote {
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
                    "Banana Checkpoint v5\n9944\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n", ),
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
                    vec![KeyValue("Timestamp".to_string(), "1689748607742585419".to_string())],
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
                let got = CheckpointNote::unmarshal(input);

                let expected = CheckpointNote {
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
            let test_cases = [(
                "invalid - insufficient lines",
                "Head\n9944\n",
            ), (
                "invalid - empty header",
                "\n9944\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
            ), (
                "invalid - missing newline on roothash",
                "Log Checkpoint v0\n123\nYmFuYW5hcw==",
            ), (
                "invalid size - not a number",
                "Log Checkpoint v0\nbananas\ndGhlIHZpZXcgZnJvbSB0aGUgdHJlZSB0b3BzIGlzIGdyZWF0IQ==\n",
            ), (
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
                    CheckpointNote::unmarshal(data).is_err(),
                    "accepted invalid note: {desc}"
                );
            }
        }
    }

    #[cfg(test)]
    mod test_checkpoint_signature {
        use crate::rekor::models::checkpoint::CheckpointSignature;
        use std::str::FromStr;

        #[test]
        fn test_to_string_valid_with_url_name() {
            let got = CheckpointSignature {
                name: "log.example.org".to_string(),
                key_fingerprint: [0; 4],
                raw: vec![1; 32],
            }
            .to_string();
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
            .to_string();
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
            let got = CheckpointSignature::from_str(input);
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
            let got = CheckpointSignature::from_str(input);
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
            let got = CheckpointSignature::from_str(input);
            assert_eq!(got, Ok(expected))
        }

        #[test]
        fn test_from_str_invalid_with_spaces_in_name() {
            let input = "— Foo Bar AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n";
            let got = CheckpointSignature::from_str(input);
            assert!(got.is_err())
        }
    }
}
