use std::fmt::Display;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use json_syntax::Print;

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::LogId,
    rekor::v1::{Checkpoint, InclusionPromise, InclusionProof, KindVersion, TransparencyLogEntry},
};

use crate::rekor::models::{
    log_entry::InclusionProof as RekorInclusionProof, LogEntry as RekorLogEntry,
};

// Known Sigstore bundle media types.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    Bundle0_1,
    Bundle0_2,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Version::Bundle0_1 => "application/vnd.dev.sigstore.bundle+json;version=0.1",
            Version::Bundle0_2 => "application/vnd.dev.sigstore.bundle+json;version=0.2",
        })
    }
}

impl FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "application/vnd.dev.sigstore.bundle+json;version=0.1" => Ok(Version::Bundle0_1),
            "application/vnd.dev.sigstore.bundle+json;version=0.2" => Ok(Version::Bundle0_2),
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
        let canonicalized_body = {
            let mut body = json_syntax::to_value(value.body).or(Err(()))?;
            body.canonicalize();
            body.compact_print().to_string().into_bytes()
        };
        let inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: base64
                .decode(value.verification.signed_entry_timestamp)
                .or(Err(()))?,
        });
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
            kind_version: Some(KindVersion {
                kind: "hashedrekord".to_owned(),
                version: "0.0.1".to_owned(),
            }),
            log_id: Some(LogId {
                key_id: decode_hex(value.log_i_d)?,
            }),
            log_index: value.log_index,
        })
    }
}
