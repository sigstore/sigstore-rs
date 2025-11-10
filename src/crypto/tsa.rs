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

//! Client for requesting RFC 3161 timestamps from a Timestamp Authority.

use reqwest::Client;
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};
use x509_tsp::{MessageImprint, TimeStampReq, TspVersion};

use crate::errors::{Result as SigstoreResult, SigstoreError};

/// Client for interacting with a Timestamp Authority (TSA).
///
/// This client implements RFC 3161 timestamp requests, allowing artifacts
/// to be timestamped by a trusted third-party timestamp service.
pub struct TimestampAuthorityClient {
    url: String,
    client: Client,
}

impl TimestampAuthorityClient {
    /// Creates a new TSA client for the given URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the TSA endpoint (e.g., "<https://timestamp.sigstore.dev/api/v1/timestamp>")
    pub fn new(url: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { url, client }
    }

    /// Requests a timestamp for the given signature bytes.
    ///
    /// This method:
    /// 1. Hashes the signature using SHA-256
    /// 2. Creates an RFC 3161 timestamp request
    /// 3. Sends it to the TSA
    /// 4. Returns the raw timestamp response bytes (DER-encoded)
    ///
    /// The response is not verified by this method - verification happens
    /// during bundle verification using the trust root.
    ///
    /// # Arguments
    ///
    /// * `signature_bytes` - The signature to timestamp
    ///
    /// # Returns
    ///
    /// The DER-encoded RFC 3161 TimeStampResp bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The timestamp request cannot be constructed
    /// - The HTTP request fails
    /// - The server returns a non-200 response
    pub async fn request_timestamp(&self, signature_bytes: &[u8]) -> SigstoreResult<Vec<u8>> {
        // Hash the signature using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(signature_bytes);
        let signature_hash = hasher.finalize();

        // Build the MessageImprint
        // According to RFC 4055, the parameters field for SHA-256 SHOULD be either
        // absent or NULL. We use None (absent) to match what other implementations do.
        let message_imprint = MessageImprint {
            hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: None,
            },
            hashed_message: x509_cert::der::asn1::OctetString::new(&signature_hash[..]).map_err(
                |e| {
                    SigstoreError::UnexpectedError(format!(
                        "failed to create OCTET STRING for hash: {}",
                        e
                    ))
                },
            )?,
        };

        // Generate a random nonce for replay protection
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 8] = rng.r#gen();
        let nonce = x509_cert::der::asn1::Int::new(&nonce_bytes).map_err(|e| {
            SigstoreError::UnexpectedError(format!("failed to create nonce: {}", e))
        })?;

        // Build the timestamp request
        let timestamp_request = TimeStampReq {
            version: TspVersion::V1,
            message_imprint,
            req_policy: None,
            nonce: Some(nonce),
            cert_req: true, // Request the TSA certificate to be included
            extensions: None,
        };

        // Encode the request to DER
        let request_der = timestamp_request.to_der().map_err(|e| {
            SigstoreError::UnexpectedError(format!("failed to encode timestamp request: {}", e))
        })?;

        tracing::debug!("Sending timestamp request to TSA: {}", self.url);
        tracing::debug!("Request size: {} bytes", request_der.len());

        // Send the request to the TSA
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .header("User-Agent", "sigstore-rs")
            .body(request_der)
            .send()
            .await
            .map_err(|e| SigstoreError::UnexpectedError(format!("TSA request failed: {}", e)))?;

        // Check the response status
        if !response.status().is_success() {
            return Err(SigstoreError::UnexpectedError(format!(
                "TSA returned error status: {}",
                response.status()
            )));
        }

        // Get the response bytes
        let response_bytes = response.bytes().await.map_err(|e| {
            SigstoreError::UnexpectedError(format!("failed to read TSA response: {}", e))
        })?;

        tracing::debug!(
            "Received timestamp response: {} bytes",
            response_bytes.len()
        );

        // Parse and validate the TimeStampResp to ensure it's well-formed
        use x509_tsp::TimeStampResp;
        let timestamp_resp = TimeStampResp::from_der(&response_bytes).map_err(|e| {
            SigstoreError::UnexpectedError(format!("TSA returned invalid TimeStampResp: {}", e))
        })?;

        // Check that the response status is successful
        use cmpv2::status::PkiStatus;
        match timestamp_resp.status.status {
            PkiStatus::Accepted | PkiStatus::GrantedWithMods => {
                // Response is successful, continue
            }
            _ => {
                return Err(SigstoreError::UnexpectedError(format!(
                    "TSA returned non-success status: {:?}",
                    timestamp_resp.status.status
                )));
            }
        }

        // Verify that the timestamp token is present
        if timestamp_resp.time_stamp_token.is_none() {
            return Err(SigstoreError::UnexpectedError(
                "TSA response missing TimeStampToken".to_string(),
            ));
        }

        tracing::debug!("TimeStampResp validation successful");

        Ok(response_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Only run manually as it requires network access
    async fn test_timestamp_request() {
        let client = TimestampAuthorityClient::new(
            "https://timestamp.sigstage.dev/api/v1/timestamp".to_string(),
        );

        let signature = b"test signature bytes";
        let result = client.request_timestamp(signature).await;

        assert!(result.is_ok(), "Timestamp request should succeed");
        let timestamp_bytes = result.unwrap();
        assert!(!timestamp_bytes.is_empty(), "Timestamp should not be empty");
    }
}
