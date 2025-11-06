use std::fmt::Display;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use json_syntax::Print;

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::LogId,
    rekor::v1::{Checkpoint, InclusionPromise, InclusionProof, KindVersion, TransparencyLogEntry},
};

use crate::rekor::models::{
    LogEntry as RekorLogEntry, log_entry::InclusionProof as RekorInclusionProof,
};

// Known Sigstore bundle media types.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    Bundle0_1,
    Bundle0_2,
    Bundle0_3,
    Bundle0_3Alt,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Version::Bundle0_1 => "application/vnd.dev.sigstore.bundle+json;version=0.1",
            Version::Bundle0_2 => "application/vnd.dev.sigstore.bundle+json;version=0.2",
            Version::Bundle0_3 => "application/vnd.dev.sigstore.bundle.v0.3+json",
            Version::Bundle0_3Alt => "application/vnd.dev.sigstore.bundle+json;version=0.3",
        })
    }
}

impl FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "application/vnd.dev.sigstore.bundle+json;version=0.1" => Ok(Version::Bundle0_1),
            "application/vnd.dev.sigstore.bundle+json;version=0.2" => Ok(Version::Bundle0_2),
            "application/vnd.dev.sigstore.bundle.v0.3+json" => Ok(Version::Bundle0_3),
            "application/vnd.dev.sigstore.bundle+json;version=0.3" => Ok(Version::Bundle0_3Alt),
            _ => Err(()),
        }
    }
}

#[inline]
fn decode_hex<S: AsRef<str>>(hex: S) -> Result<Vec<u8>, ()> {
    hex::decode(hex.as_ref()).or(Err(()))
}

impl TryFrom<RekorInclusionProof> for InclusionProof {
    type Error = ();

    fn try_from(value: RekorInclusionProof) -> Result<Self, Self::Error> {
        let hashes = value
            .hashes
            .iter()
            .map(decode_hex)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(InclusionProof {
            checkpoint: Some(Checkpoint {
                envelope: value.checkpoint,
            }),
            hashes,
            log_index: value.log_index,
            root_hash: decode_hex(value.root_hash)?,
            tree_size: value.tree_size,
        })
    }
}

/// Convert log entries returned from Rekor into Sigstore Bundle format entries.
impl TryFrom<RekorLogEntry> for TransparencyLogEntry {
    type Error = ();

    fn try_from(value: RekorLogEntry) -> Result<Self, Self::Error> {
        let (canonicalized_body, kind, version) = {
            // First, serialize the body to JSON to extract kind and version
            let body_json = serde_json::to_value(&value.body).or(Err(()))?;

            // Extract kind and apiVersion
            let kind = body_json
                .get("kind")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned())
                .unwrap_or_else(|| "hashedrekord".to_owned());

            let version = body_json
                .get("apiVersion")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned())
                .unwrap_or_else(|| "0.0.1".to_owned());

            // Then canonicalize for the bundle
            let mut body = json_syntax::to_value(value.body).or(Err(()))?;
            body.canonicalize();
            (body.compact_print().to_string().into_bytes(), kind, version)
        };
        // V2 entries use checkpoints and don't have SETs (signed entry timestamps)
        // Only create an inclusion_promise if there's actually a SET
        let inclusion_promise = if value.verification.signed_entry_timestamp.is_empty() {
            None
        } else {
            Some(InclusionPromise {
                signed_entry_timestamp: base64
                    .decode(value.verification.signed_entry_timestamp)
                    .or(Err(()))?,
            })
        };
        let inclusion_proof = value
            .verification
            .inclusion_proof
            .map(|p| p.try_into())
            .transpose()?;

        Ok(TransparencyLogEntry {
            canonicalized_body,
            inclusion_promise,
            inclusion_proof,
            integrated_time: value.integrated_time,
            kind_version: Some(KindVersion { kind, version }),
            log_id: Some(LogId {
                key_id: decode_hex(value.log_i_d)?,
            }),
            log_index: value.log_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_version_parsing() {
        // Test Bundle 0.1
        assert!(matches!(
            Version::from_str("application/vnd.dev.sigstore.bundle+json;version=0.1"),
            Ok(Version::Bundle0_1)
        ));

        // Test Bundle 0.2
        assert!(matches!(
            Version::from_str("application/vnd.dev.sigstore.bundle+json;version=0.2"),
            Ok(Version::Bundle0_2)
        ));

        // Test Bundle 0.3 (canonical format)
        assert!(matches!(
            Version::from_str("application/vnd.dev.sigstore.bundle.v0.3+json"),
            Ok(Version::Bundle0_3)
        ));

        // Test Bundle 0.3 (alternate format)
        assert!(matches!(
            Version::from_str("application/vnd.dev.sigstore.bundle+json;version=0.3"),
            Ok(Version::Bundle0_3Alt)
        ));

        // Test unknown version
        assert!(Version::from_str("application/vnd.dev.sigstore.bundle+json;version=0.4").is_err());
    }

    #[test]
    fn test_bundle_version_display() {
        assert_eq!(
            Version::Bundle0_1.to_string(),
            "application/vnd.dev.sigstore.bundle+json;version=0.1"
        );
        assert_eq!(
            Version::Bundle0_2.to_string(),
            "application/vnd.dev.sigstore.bundle+json;version=0.2"
        );
        assert_eq!(
            Version::Bundle0_3.to_string(),
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
        assert_eq!(
            Version::Bundle0_3Alt.to_string(),
            "application/vnd.dev.sigstore.bundle+json;version=0.3"
        );
    }
}
