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

//! RFC 3161 timestamp verification support.

use chrono::{DateTime, Utc};
use cryptographic_message_syntax::asn1::rfc3161::{TimeStampResp, TstInfo};
use cryptographic_message_syntax::TimeStampResponse;
use pki_types::CertificateDer;
use sha2::{Digest, Sha256};

/// Errors that can occur during timestamp verification.
#[derive(Debug, thiserror::Error)]
pub enum TimestampError {
    #[error("failed to parse timestamp response: {0}")]
    ParseError(String),

    #[error("failed to verify timestamp signature: {0}")]
    SignatureVerificationError(String),

    #[error("timestamp message hash does not match signature: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("timestamp response indicates failure status")]
    ResponseFailure,

    #[error("no timestamp token in response")]
    NoToken,

    #[error("no TSTInfo in timestamp token")]
    NoTstInfo,

    #[error("leaf certificate does not have TimeStamping EKU")]
    InvalidEKU,

    #[error("timestamp is outside validity period")]
    OutsideValidityPeriod,
}

/// Verification options for RFC 3161 timestamps.
#[allow(dead_code)]
pub struct VerifyOpts<'a> {
    /// Root certificates for chain verification
    pub roots: Vec<CertificateDer<'a>>,

    /// Intermediate certificates for chain building
    pub intermediates: Vec<CertificateDer<'a>>,

    /// TSA certificate (optional if embedded in timestamp)
    pub tsa_certificate: Option<CertificateDer<'a>>,
}

/// Result of timestamp verification.
pub struct TimestampResult {
    /// The timestamp from the TSA
    pub time: DateTime<Utc>,
}

/// Verify an RFC 3161 timestamp response.
///
/// This function:
/// 1. Parses the timestamp response (DER encoded)
/// 2. Extracts the TSTInfo to get the timestamp
/// 3. Verifies the message imprint (hash) matches the signature bytes
/// 4. TODO: Verifies the CMS signature using the certificate chain
///
/// # Arguments
///
/// * `timestamp_response_bytes` - The RFC 3161 timestamp response bytes (DER encoded)
/// * `signature_bytes` - The signature that was timestamped
/// * `_opts` - Verification options (currently unused, for future certificate chain verification)
///
/// # Returns
///
/// Returns `Ok(TimestampResult)` if verification succeeds, otherwise returns an error.
pub fn verify_timestamp_response(
    timestamp_response_bytes: &[u8],
    signature_bytes: &[u8],
    _opts: VerifyOpts<'_>,
) -> Result<TimestampResult, TimestampError> {
    use cryptographic_message_syntax::asn1::rfc3161::OID_CONTENT_TYPE_TST_INFO;

    // Parse the TimeStampResponse using bcder
    let tsr = bcder::decode::Constructed::decode(
        timestamp_response_bytes,
        bcder::Mode::Der,
        TimeStampResp::take_from,
    )
    .map_err(|e| TimestampError::ParseError(format!("failed to decode TimeStampResp: {}", e)))?;

    let response = TimeStampResponse::from(tsr);

    // Check that the response was successful
    if !response.is_success() {
        return Err(TimestampError::ResponseFailure);
    }

    // Get the SignedData from the timestamp token
    let signed_data = response
        .signed_data()
        .map_err(|e| TimestampError::ParseError(format!("failed to get signed data: {}", e)))?
        .ok_or(TimestampError::NoToken)?;

    // Verify the content type is TSTInfo
    if signed_data.content_info.content_type != OID_CONTENT_TYPE_TST_INFO {
        return Err(TimestampError::ParseError(
            "content type is not TSTInfo".to_string(),
        ));
    }

    // Extract the TSTInfo
    let tst_info = response
        .tst_info()
        .map_err(|e| TimestampError::ParseError(format!("failed to get TSTInfo: {}", e)))?
        .ok_or(TimestampError::NoTstInfo)?;

    // Verify the message imprint (hash of the signature) matches
    verify_message_imprint(&tst_info, signature_bytes)?;

    // Extract the timestamp from TSTInfo
    // The gen_time field is a GeneralizedTime which has a From impl for DateTime<Utc>
    let timestamp: DateTime<Utc> = tst_info.gen_time.into();

    // TODO: Implement full CMS signature verification including:
    // - Verifying the CMS signature matches the SignedData
    // - Checking TSA certificate has TimeStamping EKU
    // - Validating TSA certificate chains to trusted root
    // - Checking timestamp is within TSA cert validity period
    // For now, we just validate the message imprint and extract the timestamp

    Ok(TimestampResult { time: timestamp })
}

/// Verify that the message imprint in TSTInfo matches the hash of the signature.
fn verify_message_imprint(tst_info: &TstInfo, signature_bytes: &[u8]) -> Result<(), TimestampError> {
    // Hash the signature bytes
    let mut hasher = Sha256::new();
    hasher.update(signature_bytes);
    let signature_hash = hasher.finalize();

    // Get the hash from the message imprint
    let imprint_hash = tst_info.message_imprint.hashed_message.as_slice()
        .ok_or_else(|| TimestampError::ParseError("hashed_message is not primitive encoded".to_string()))?;

    // Compare the hashes
    if signature_hash.as_slice() != imprint_hash {
        return Err(TimestampError::HashMismatch {
            expected: hex::encode(imprint_hash),
            actual: hex::encode(signature_hash),
        });
    }

    Ok(())
}
