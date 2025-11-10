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

//! Rekor v1 API client implementation.

use async_trait::async_trait;

use super::apis::configuration::Configuration;
use super::apis::entries_api;
use super::client::RekorClient;
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::rekor::models::log_entry::LogEntry;
use crate::rekor::models::proposed_entry::ProposedEntry;

/// Rekor v1 API client.
///
/// This client uses the traditional Rekor v1 API (`/api/v1/log/entries`)
/// and creates hashedrekord v0.0.1 entries.
///
/// The v1 API uses JSON request/response format and has been the standard
/// for production Rekor instances.
pub struct RekorV1Client {
    config: Configuration,
    base_url: String,
}

impl RekorV1Client {
    /// Create a new Rekor v1 client for the given base URL.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Rekor instance (e.g., <https://rekor.sigstore.dev>)
    pub fn new(base_url: String) -> Self {
        let config = Configuration {
            // TODO(wolfv): base_path should perhaps be a URL type?
            base_path: base_url.clone(),
            ..Default::default()
        };

        Self { config, base_url }
    }
}

#[async_trait]
impl RekorClient for RekorV1Client {
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry> {
        // Use existing v1 API implementation
        entries_api::create_log_entry(&self.config, entry)
            .await
            .map_err(|e| SigstoreError::RekorClientError(e.to_string()))
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn api_version(&self) -> u32 {
        1
    }
}
