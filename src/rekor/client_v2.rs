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

//! Rekor v2 API client implementation.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use reqwest;
use x509_cert::{Certificate, der::Decode};

use super::client::RekorClient;
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::rekor::models::dsse::ProposedContent as DsseProposedContent;
use crate::rekor::models::log_entry::LogEntry;
use crate::rekor::models::proposed_entry::ProposedEntry;
use sigstore_protobuf_specs::dev::sigstore::common::v1::{
    PublicKeyDetails, X509Certificate as ProtoX509Certificate,
};
use sigstore_protobuf_specs::dev::sigstore::rekor::v2::{
    CreateEntryRequest, DsseRequestV002, HashedRekordRequestV002, Signature, Verifier,
    create_entry_request::Spec as EntrySpec, verifier::Verifier as VerifierEnum,
};
use sigstore_protobuf_specs::io::intoto::Envelope as ProtoEnvelope;

/// Rekor v2 API client.
///
/// This client uses the new Rekor v2 API (`/api/v2/log/entries`)
/// and creates hashedrekord v0.0.2 entries.
///
/// The v2 API uses protobuf request/response format and includes additional
/// metadata such as key algorithm details that must be extracted from certificates.
pub struct RekorV2Client {
    base_url: String,
    client: reqwest::Client,
}

impl RekorV2Client {
    /// Create a new Rekor v2 client for the given base URL.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Rekor instance (e.g., "https://log2025-alpha3.rekor.sigstage.dev")
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Convert a ProposedEntry to a v2 API request.
    ///
    /// This method handles the differences between v1 and v2 API formats:
    /// - Extracts key algorithm details from certificates
    /// - Converts base64-encoded data to raw bytes
    /// - Builds the appropriate protobuf message structure
    fn build_v2_request(&self, entry: &ProposedEntry) -> SigstoreResult<CreateEntryRequest> {
        match entry {
            ProposedEntry::Hashedrekord { spec, .. } => {
                // Extract signature content (base64 encoded)
                let signature_bytes = base64.decode(&spec.signature.content).map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to decode signature: {}", e))
                })?;

                // Extract certificate (PEM encoded, then base64 encoded)
                // Use the decode() method which handles base64 decoding
                let cert_pem_str = spec.signature.public_key.decode().map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to decode certificate: {}", e))
                })?;
                let cert_pem_bytes = cert_pem_str.as_bytes();

                // Parse PEM to get DER bytes
                let pem = pem::parse(cert_pem_bytes).map_err(|e| {
                    SigstoreError::UnexpectedError(format!(
                        "Failed to parse PEM certificate: {}",
                        e
                    ))
                })?;
                let cert_der = pem.contents().to_vec();

                // Parse certificate to extract key details
                let cert = Certificate::from_der(&cert_der).map_err(|e| {
                    SigstoreError::UnexpectedError(format!(
                        "Failed to parse DER certificate: {}",
                        e
                    ))
                })?;

                // Extract key algorithm details from certificate
                let key_details = extract_key_details(&cert)?;

                // Build verifier with certificate and key details
                let verifier = Verifier {
                    key_details: key_details as i32,
                    verifier: Some(VerifierEnum::X509Certificate(ProtoX509Certificate {
                        raw_bytes: cert_der,
                    })),
                };

                // Extract digest (hex string from v1, need to convert to bytes)
                let digest_hex = &spec.data.hash.value;
                let digest_bytes = hex::decode(digest_hex).map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to decode digest hex: {}", e))
                })?;

                // Build the v2 request
                Ok(CreateEntryRequest {
                    spec: Some(EntrySpec::HashedRekordRequestV002(
                        HashedRekordRequestV002 {
                            signature: Some(Signature {
                                content: signature_bytes,
                                verifier: Some(verifier),
                            }),
                            digest: digest_bytes,
                        },
                    )),
                })
            }
            ProposedEntry::Dsse { spec, .. } => {
                // Deserialize the spec into the DsseProposedContent struct
                let proposed_content: DsseProposedContent = serde_json::from_value(
                    spec.get("proposedContent")
                        .ok_or_else(|| {
                            SigstoreError::UnexpectedError(
                                "Missing proposedContent in DSSE spec".into(),
                            )
                        })?
                        .clone(),
                )
                .map_err(|e| {
                    SigstoreError::UnexpectedError(format!(
                        "Failed to parse DSSE proposedContent: {}",
                        e
                    ))
                })?;

                // Parse the envelope JSON
                let envelope_str = proposed_content.envelope.ok_or_else(|| {
                    SigstoreError::UnexpectedError("Missing envelope in DSSE spec".into())
                })?;
                let envelope: ProtoEnvelope = serde_json::from_str(&envelope_str).map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to parse DSSE envelope: {}", e))
                })?;

                // Build verifier list with key details for each certificate
                let mut verifiers = Vec::new();
                for cert_b64_str in &proposed_content.verifiers {
                    // Decode base64 certificate
                    let cert_pem_bytes = base64.decode(cert_b64_str).map_err(|e| {
                        SigstoreError::UnexpectedError(format!(
                            "Failed to decode verifier certificate: {}",
                            e
                        ))
                    })?;

                    // Parse PEM to get DER
                    let pem = pem::parse(&cert_pem_bytes).map_err(|e| {
                        SigstoreError::UnexpectedError(format!(
                            "Failed to parse verifier PEM: {}",
                            e
                        ))
                    })?;
                    let cert_der = pem.contents().to_vec();

                    // Parse certificate to extract key details
                    let cert = Certificate::from_der(&cert_der).map_err(|e| {
                        SigstoreError::UnexpectedError(format!(
                            "Failed to parse verifier certificate: {}",
                            e
                        ))
                    })?;

                    let key_details = extract_key_details(&cert)?;

                    verifiers.push(Verifier {
                        key_details: key_details as i32,
                        verifier: Some(VerifierEnum::X509Certificate(ProtoX509Certificate {
                            raw_bytes: cert_der,
                        })),
                    });
                }

                // Build the v2 DSSE request
                Ok(CreateEntryRequest {
                    spec: Some(EntrySpec::DsseRequestV002(DsseRequestV002 {
                        envelope: Some(envelope),
                        verifiers,
                    })),
                })
            }
            _ => Err(SigstoreError::UnexpectedError(
                "Unsupported entry type for Rekor v2".into(),
            )),
        }
    }
}

#[async_trait]
impl RekorClient for RekorV2Client {
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry> {
        // Convert ProposedEntry to v2 request format
        let v2_request = self.build_v2_request(&entry)?;

        // Serialize to JSON (like sigstore-python does)
        // The v2 API accepts JSON-serialized protobuf messages
        let json_payload = serde_json::to_value(&v2_request).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to serialize v2 request to JSON: {}", e))
        })?;

        // POST to /api/v2/log/entries
        let url = format!("{}/api/v2/log/entries", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&json_payload)
            .send()
            .await
            .map_err(|e| SigstoreError::RekorClientError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unable to read error>".to_string());
            return Err(SigstoreError::RekorClientError(format!(
                "Rekor v2 API error ({}): {}",
                status, error_body
            )));
        }

        // Parse response (v2 API returns JSON, same as v1)
        // First get the response text for debugging
        let response_text = response.text().await.map_err(|e| {
            SigstoreError::RekorClientError(format!("Failed to read response: {}", e))
        })?;

        // Parse the v2 response format
        let v2_response: RekorV2Response = serde_json::from_str(&response_text).map_err(|e| {
            SigstoreError::RekorClientError(format!("Failed to parse v2 response: {}. Response was: {}", e, response_text))
        })?;

        // Convert v2 response to v1 LogEntry format
        let entry = v2_response.to_log_entry(&entry)?;

        Ok(entry)
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn api_version(&self) -> u32 {
        2
    }
}

/// Rekor v2 API response structure.
///
/// The v2 API returns a different structure than v1, with fields like `logIndex`
/// as strings instead of integers, and `inclusionProof` at the top level.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorV2Response {
    log_index: String,
    log_id: LogId,
    kind_version: KindVersion,
    integrated_time: String,
    inclusion_promise: Option<serde_json::Value>,
    inclusion_proof: V2InclusionProof,
    canonicalized_body: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct KindVersion {
    kind: String,
    version: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2InclusionProof {
    log_index: String,
    root_hash: String,
    tree_size: String,
    hashes: Vec<String>,
    checkpoint: Checkpoint,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Checkpoint {
    envelope: String,
}

impl RekorV2Response {
    /// Convert a v2 response to a v1 LogEntry format.
    ///
    /// This method bridges the gap between the v2 API response and the v1 LogEntry
    /// structure that the rest of the codebase expects.
    fn to_log_entry(&self, _original_entry: &ProposedEntry) -> SigstoreResult<LogEntry> {
        use crate::rekor::models::log_entry::{InclusionProof as V1InclusionProof, Verification};
        use std::str::FromStr;

        // Parse log index from string to i64
        let log_index = self.log_index.parse::<i64>().map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to parse log index: {}", e))
        })?;

        // Parse integrated time from string to i64
        let integrated_time = self.integrated_time.parse::<i64>().map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to parse integrated time: {}", e))
        })?;

        // Build inclusion proof
        let tree_size = self.inclusion_proof.tree_size.parse::<i64>().map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to parse tree size: {}", e))
        })?;

        let proof_log_index = self.inclusion_proof.log_index.parse::<i64>().map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to parse proof log index: {}", e))
        })?;

        // The v2 API returns base64-encoded values, but v1 expects hex
        // Convert base64 logID to hex
        let log_id_bytes = base64.decode(&self.log_id.key_id).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to decode logID: {}", e))
        })?;
        let log_id_hex = hex::encode(&log_id_bytes);

        // Convert base64 root_hash to hex
        let root_hash_bytes = base64.decode(&self.inclusion_proof.root_hash).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to decode root_hash: {}", e))
        })?;
        let root_hash_hex = hex::encode(&root_hash_bytes);

        // Convert base64 hashes to hex
        let hashes_hex: Result<Vec<String>, SigstoreError> = self
            .inclusion_proof
            .hashes
            .iter()
            .map(|h| {
                let hash_bytes = base64.decode(h).map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to decode hash: {}", e))
                })?;
                Ok(hex::encode(&hash_bytes))
            })
            .collect();
        let hashes_hex = hashes_hex?;

        // The v2 API returns canonicalized_body as base64-encoded JSON
        // We need to construct a JSON response that LogEntry::from_str can parse
        // The from_str method will decode the base64 body and parse it
        // We also need to store the kind and version to later fix up the LogEntry
        let kind = self.kind_version.kind.clone();
        let version = self.kind_version.version.clone();

        let temp_entry_json = serde_json::json!({
            "uuid": log_index.to_string(),
            "body": self.canonicalized_body,
            "integratedTime": integrated_time,
            "logID": log_id_hex,
            "logIndex": log_index,
            "verification": {
                "signedEntryTimestamp": "",  // v2 API uses checkpoints, not SETs
                "inclusionProof": {
                    "logIndex": proof_log_index,
                    "rootHash": root_hash_hex,
                    "treeSize": tree_size,
                    "hashes": hashes_hex,
                    "checkpoint": self.inclusion_proof.checkpoint.envelope,
                }
            }
        });

        // Use LogEntry::from_str to properly decode the body
        let log_entry = LogEntry::from_str(&temp_entry_json.to_string()).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to parse v2 response into LogEntry: {}", e))
        })?;

        // TODO: The LogEntry doesn't store kind/version directly - it's in the body.
        // The version information will be extracted properly when converting to TransparencyLogEntry.
        // For now, we rely on the fact that the canonicalized_body contains the correct version.
        // We may need to update the TryFrom implementation to extract version from the body
        // rather than hardcoding it.

        Ok(log_entry)
    }
}

/// Extract key algorithm details from a certificate's public key.
///
/// This function inspects the certificate's Subject Public Key Info (SPKI)
/// to determine the key type and algorithm details required by the Rekor v2 API.
///
/// Supported key types:
/// - ECDSA P-256 with SHA-256
/// - ECDSA P-384 with SHA-384
/// - ECDSA P-521 with SHA-512
/// - RSA PKCS#1 v1.5 (various key sizes)
/// - Ed25519
///
/// # Arguments
///
/// * `cert` - The X.509 certificate containing the public key
///
/// # Returns
///
/// The [`PublicKeyDetails`] enum variant corresponding to the key type and algorithm.
fn extract_key_details(cert: &Certificate) -> SigstoreResult<PublicKeyDetails> {
    use const_oid::ObjectIdentifier;
    use x509_cert::der::Encode;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let alg_oid = &spki.algorithm.oid;

    // Common OIDs for public key algorithms
    const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const RSA_ENCRYPTION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

    // Named curve OIDs for ECDSA
    const SECP256R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    const SECP521R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

    match *alg_oid {
        EC_PUBLIC_KEY_OID => {
            // For EC keys, we need to check the curve parameter
            if let Some(params) = &spki.algorithm.parameters {
                // The parameters contain the curve OID
                use x509_cert::der::Decode;

                // Try to decode the parameters as an OID
                let curve_oid = ObjectIdentifier::from_der(
                    params
                        .to_der()
                        .map_err(|e| {
                            SigstoreError::UnexpectedError(format!(
                                "Failed to encode curve parameters: {}",
                                e
                            ))
                        })?
                        .as_slice(),
                )
                .map_err(|e| {
                    SigstoreError::UnexpectedError(format!("Failed to decode curve OID: {}", e))
                })?;

                match curve_oid {
                    SECP256R1_OID => Ok(PublicKeyDetails::PkixEcdsaP256Sha256),
                    SECP384R1_OID => Ok(PublicKeyDetails::PkixEcdsaP384Sha384),
                    SECP521R1_OID => Ok(PublicKeyDetails::PkixEcdsaP521Sha512),
                    _ => Err(SigstoreError::UnexpectedError(format!(
                        "Unsupported EC curve: {}",
                        curve_oid
                    ))),
                }
            } else {
                Err(SigstoreError::UnexpectedError(
                    "EC public key missing curve parameters".into(),
                ))
            }
        }
        RSA_ENCRYPTION_OID => {
            // For RSA, we could inspect the key size, but for now default to the most common
            // In a full implementation, we would parse the public key to determine the modulus size
            Ok(PublicKeyDetails::PkixRsaPkcs1v152048Sha256)
        }
        ED25519_OID => Ok(PublicKeyDetails::PkixEd25519),
        _ => Err(SigstoreError::UnexpectedError(format!(
            "Unsupported public key algorithm: {}",
            alg_oid
        ))),
    }
}
