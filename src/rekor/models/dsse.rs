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

//! DSSE entry models for Rekor transparency log.
//!
//! This module was manually created based on the Rekor DSSE type specification.
//! The upstream JSON schema can be found at:
//! <https://github.com/sigstore/rekor/blob/main/pkg/types/dsse/v0.0.1/dsse_v0_0_1_schema.json>
//!
//! Note: The Rekor OpenAPI spec references external JSON schema files via `$ref`,
//! which are not well-supported by openapi-generator, so manual implementation
//! was chosen instead.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dsse {
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "spec")]
    pub spec: Spec,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Spec {
    #[serde(rename = "root", skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(rename = "proposedContent")]
    pub proposed_content: ProposedContent,
    #[serde(rename = "payloadHash", skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<Hash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposedContent {
    #[serde(rename = "envelope", skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
    #[serde(rename = "verifiers")]
    pub verifiers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hash {
    #[serde(rename = "algorithm")]
    pub algorithm: String,
    #[serde(rename = "value")]
    pub value: String,
}
