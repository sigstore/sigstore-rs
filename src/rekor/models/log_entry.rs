use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use serde::{Deserialize, Serialize};

use crate::errors::SigstoreError;
use crate::rekor::models::hashedrekord::Spec;
use crate::rekor::TreeSize;

/// Stores the response returned by Rekor after making a new entry
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    pub body: String,
    pub integrated_time: i64,
    pub log_i_d: String,
    pub log_index: i64,
    pub verification: Verification,
}

impl LogEntry {
    pub fn decode_body(&self) -> Result<Body, SigstoreError> {
        let decoded = BASE64_STD_ENGINE.decode(&self.body)?;
        serde_json::from_slice(&decoded).map_err(SigstoreError::from)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "spec")]
    pub spec: Spec,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    // This field is just a place holder
    // Not sure what is stored inside the Attestation struct, it is empty for now
    #[serde(skip_serializing_if = "Option::is_none")]
    dummy: Option<String>,
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    #[serde(skip_serializing_if = "Option::is_none")]
    inclusion_proof: Option<InclusionProof>,
    signed_entry_timestamp: String,
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    hashes: Vec<String>,
    log_index: i64,
    root_hash: String,
    tree_size: TreeSize,
}
