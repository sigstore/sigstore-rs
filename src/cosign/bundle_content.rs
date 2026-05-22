//
// Copyright 2026 The Sigstore Authors.
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

use serde::Serialize;

use crate::cosign::bundle::Bundle;

/// Evidence that a signature was recorded in a transparency log.
///
/// Cosign supports two provenance formats:
///
/// - [`BundleContent::RekorBundle`]: the legacy cosign-specific format,
///   consisting of a Signed Entry Timestamp (SET) and a payload with body,
///   integrated time, log index, and log ID.  Stored as OCI annotations on
///   tag-based cosign signature layers.
///
/// - [`BundleContent::SigstoreBundle`]: the protobuf-based Sigstore bundle
///   format (v0.1–v0.3), carrying a full [`TransparencyLogEntry`](sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry).
///   The entry is verified (SET / inclusion promise, Merkle inclusion proof, and body
///   consistency) during [`SignatureLayer`](super::signature_layers::SignatureLayer)
///   construction; the verified entry is retained here for downstream verifiers.
#[derive(Clone, Debug, Serialize)]
pub enum BundleContent {
    /// Legacy cosign-specific Rekor bundle stored as OCI annotations.
    /// Contains a Signed Entry Timestamp (SET) and a payload with body,
    /// integrated time, log index, and log ID.
    RekorBundle(Bundle),
    /// Protobuf-based Sigstore bundle transparency log entry (v0.1–v0.3).
    /// The entry has been fully verified (SET / inclusion promise, Merkle
    /// inclusion proof, and body consistency) prior to being stored here.
    SigstoreBundle(sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry),
}

impl BundleContent {
    /// Returns the UNIX timestamp from the transparency log when the entry
    /// was persisted.
    pub fn integrated_time(&self) -> i64 {
        match self {
            BundleContent::RekorBundle(b) => b.payload.integrated_time,
            BundleContent::SigstoreBundle(entry) => entry.integrated_time,
        }
    }
}
