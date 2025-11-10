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

//! Rekor client trait and implementations for v1 and v2 APIs.

use async_trait::async_trait;

use crate::errors::Result as SigstoreResult;
use crate::rekor::models::log_entry::LogEntry;
use crate::rekor::models::proposed_entry::ProposedEntry;

/// Trait for Rekor transparency log clients.
///
/// This trait abstracts over the differences between Rekor v1 and v2 APIs,
/// allowing the signing context to work with either version transparently.
///
/// Implementations:
/// - [`RekorV1Client`](crate::rekor::client_v1::RekorV1Client): Uses the traditional `/api/v1/log/entries` endpoint
/// - [`RekorV2Client`](crate::rekor::client_v2::RekorV2Client): Uses the new `/api/v2/log/entries` endpoint with protobuf
#[async_trait]
pub trait RekorClient: Send + Sync {
    /// Submit a log entry to Rekor and return the integrated entry.
    ///
    /// This method submits the proposed entry to the transparency log and waits for
    /// the server to integrate it into the merkle tree, returning the complete log entry
    /// with inclusion proof.
    ///
    /// # Arguments
    ///
    /// * `entry` - The proposed log entry to submit
    ///
    /// # Returns
    ///
    /// The integrated log entry from Rekor, including the log index, body, and inclusion proof.
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry>;

    /// Get the base URL of this Rekor instance.
    fn base_url(&self) -> &str;

    /// Get the major API version (1 or 2) that this client uses.
    fn api_version(&self) -> u32;
}
