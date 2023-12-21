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
