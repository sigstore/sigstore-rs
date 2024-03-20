//
// Copyright 2023 The Sigstore Authors.
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

use crate::errors::SigstoreError;
use crate::rekor::TreeSize;
use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};

use crate::crypto::CosignVerificationKey;
use crate::errors::SigstoreError::UnexpectedError;
use crate::rekor::models::checkpoint::Checkpoint;
use crate::rekor::models::InclusionProof as InclusionProof2;
use json_syntax::Print;
use serde::{Deserialize, Serialize};
use serde_json::{json, Error, Value};
use std::collections::HashMap;
use std::str::FromStr;

use super::{
    AlpineAllOf, HashedrekordAllOf, HelmAllOf, IntotoAllOf, JarAllOf, RekordAllOf, Rfc3161AllOf,
    RpmAllOf, TufAllOf,
};

/// Stores the response returned by Rekor after making a new entry
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogEntry {
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    pub body: Body,
    pub integrated_time: i64,
    pub log_i_d: String,
    pub log_index: i64,
    pub verification: Verification,
}

impl FromStr for LogEntry {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut log_entry_map = serde_json::from_str::<HashMap<&str, Value>>(s)?;
        log_entry_map.entry("body").and_modify(|body| {
            let decoded_body = serde_json::to_value(
                decode_body(body.as_str().expect("Failed to parse Body"))
                    .expect("Failed to decode Body"),
            )
            .expect("Serialization failed");
            *body = json!(decoded_body);
        });
        let log_entry_str = serde_json::to_string(&log_entry_map)?;
        Ok(serde_json::from_str::<LogEntry>(&log_entry_str).expect("Serialization failed"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[allow(non_camel_case_types)]
pub enum Body {
    alpine(AlpineAllOf),
    helm(HelmAllOf),
    jar(JarAllOf),
    rfc3161(Rfc3161AllOf),
    rpm(RpmAllOf),
    tuf(TufAllOf),
    intoto(IntotoAllOf),
    hashedrekord(HashedrekordAllOf),
    rekord(RekordAllOf),
}

impl Default for Body {
    fn default() -> Self {
        Self::hashedrekord(Default::default())
    }
}

fn decode_body(s: &str) -> Result<Body, SigstoreError> {
    let decoded = BASE64_STD_ENGINE.decode(s)?;
    serde_json::from_slice(&decoded).map_err(SigstoreError::from)
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
    pub inclusion_proof: Option<InclusionProof>,
    pub signed_entry_timestamp: String,
}

impl LogEntry {
    /// Verifies that the log entry was included by a log in possession of `rekor_key`.
    ///
    /// Example:
    /// ```rust
    /// use sigstore::rekor::apis::configuration::Configuration;
    /// use sigstore::rekor::apis::pubkey_api::get_public_key;
    /// use sigstore::rekor::apis::tlog_api::get_log_info;
    /// use sigstore::crypto::{CosignVerificationKey, SigningScheme};
    /// #[tokio::main]
    /// async fn main() {
    ///     use sigstore::rekor::apis::entries_api::get_log_entry_by_index;
    ///     let rekor_config = Configuration::default();
    ///     // Important: in practice obtain the rekor key via TUF repo or another secure channel!
    ///     let rekor_key = get_public_key(&rekor_config, None)
    ///         .await
    ///         .expect("failed to fetch pubkey from remote log");
    ///     let rekor_key =  CosignVerificationKey::from_pem(
    ///         rekor_key.as_bytes(),
    ///         &SigningScheme::ECDSA_P256_SHA256_ASN1,
    ///     ).expect("failed to parse rekor key");
    ///
    ///     // fetch log info and then the most recent entry
    ///     let log_info = get_log_info(&rekor_config)
    ///         .await
    ///         .expect("failed to fetch log info");
    ///     let entry = get_log_entry_by_index(&rekor_config, (log_info.tree_size - 1) as i32)
    ///         .await.expect("failed to fetch log entry");
    ///     entry.verify_inclusion(&rekor_key)
    ///         .expect("failed to verify inclusion");
    /// }
    /// ```
    pub fn verify_inclusion(&self, rekor_key: &CosignVerificationKey) -> Result<(), SigstoreError> {
        self.verification
            .inclusion_proof
            .as_ref()
            .ok_or(UnexpectedError("missing inclusion proof".to_string()))
            .and_then(|proof| {
                Checkpoint::from_str(&proof.checkpoint)
                    .map_err(|_| UnexpectedError("failed to parse checkpoint".to_string()))
                    .map(|checkpoint| {
                        InclusionProof2::new(
                            proof.log_index,
                            proof.root_hash.clone(),
                            proof.tree_size,
                            proof.hashes.clone(),
                            Some(checkpoint),
                        )
                    })
            })
            .and_then(|proof| {
                // encode as canonical JSON
                let mut body = json_syntax::to_value(&self.body).map_err(|_| {
                    SigstoreError::UnexpectedError(
                        "failed to serialize with json_syntax".to_string(),
                    )
                })?;
                body.canonicalize();
                let encoded_entry = body.compact_print().to_string();
                proof.verify(encoded_entry.as_bytes(), rekor_key)
            })
    }
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    pub hashes: Vec<String>,
    pub log_index: i64,
    pub root_hash: String,
    pub tree_size: TreeSize,

    /// A snapshot of the transparency log's state at a specific point in time,
    /// in [Signed Note format].
    ///
    /// [Signed Note format]: https://github.com/transparency-dev/formats/blob/main/log/README.md
    pub checkpoint: String,
}
