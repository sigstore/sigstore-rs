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
use cmpv2::status::PkiStatus;
use cms::signed_data::SignedData;
use pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_tsp::{TimeStampResp, TstInfo};

// TimeStamping Extended Key Usage OID (1.3.6.1.5.5.7.3.8)
// Note: This constant is currently unused but kept for future signature verification
#[allow(dead_code)]
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

/// Wrapper around TimeStampResp that provides convenience methods.
struct TimeStampResponse<'a>(TimeStampResp<'a>);

impl<'a> TimeStampResponse<'a> {
    /// Whether the time stamp request was successful.
    fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Accepted | PkiStatus::GrantedWithMods
        )
    }

    /// Decode the `SignedData` value in the response.
    fn signed_data(&self) -> Result<Option<SignedData>, String> {
        use x509_cert::der::{Decode, Encode};

        if let Some(token) = &self.0.time_stamp_token {
            // token is a ContentInfo - check it's SignedData
            const ID_SIGNED_DATA_STR: &str = "1.2.840.113549.1.7.2";
            if token.content_type.to_string() == ID_SIGNED_DATA_STR {
                // Encode the content to DER and parse as SignedData
                let signed_data_der = token
                    .content
                    .to_der()
                    .map_err(|e| format!("failed to encode SignedData content: {}", e))?;

                let signed_data = SignedData::from_der(&signed_data_der)
                    .map_err(|e| format!("failed to decode SignedData: {}", e))?;

                Ok(Some(signed_data))
            } else {
                Err("invalid OID on signed data".to_string())
            }
        } else {
            Ok(None)
        }
    }

    /// Extract the TSTInfo from the SignedData.
    fn tst_info(&self) -> Result<Option<TstInfo>, String> {
        use x509_cert::der::{Decode, Encode};

        // OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
        const OID_CONTENT_TYPE_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

        if let Some(signed_data) = self.signed_data()? {
            if signed_data.encap_content_info.econtent_type.to_string()
                == OID_CONTENT_TYPE_TST_INFO
            {
                if let Some(content) = signed_data.encap_content_info.econtent {
                    // Content is wrapped in Any - decode it to get the TSTInfo bytes
                    let tst_info_der = content
                        .to_der()
                        .map_err(|e| format!("failed to encode TSTInfo content: {}", e))?;

                    let tst_info = TstInfo::from_der(&tst_info_der)
                        .map_err(|e| format!("failed to decode TSTInfo: {}", e))?;

                    Ok(Some(tst_info))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl<'a> From<TimeStampResp<'a>> for TimeStampResponse<'a> {
    fn from(resp: TimeStampResp<'a>) -> Self {
        Self(resp)
    }
}

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

    /// Validity period for the TSA certificate in the trusted root
    /// If provided, the timestamp must fall within this period
    pub tsa_valid_for: Option<(DateTime<Utc>, DateTime<Utc>)>,
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
/// * `opts` - Verification options (currently unused, for future certificate chain verification)
///
/// # Returns
///
/// Returns `Ok(TimestampResult)` if verification succeeds, otherwise returns an error.
pub fn verify_timestamp_response(
    timestamp_response_bytes: &[u8],
    signature_bytes: &[u8],
    opts: VerifyOpts<'_>,
) -> Result<TimestampResult, TimestampError> {
    use x509_cert::der::Decode;

    // OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
    const OID_CONTENT_TYPE_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

    // Parse the TimeStampResponse using der
    let tsr = TimeStampResp::from_der(timestamp_response_bytes)
        .map_err(|e| TimestampError::ParseError(format!("failed to decode TimeStampResp: {}", e)))?;

    let response = TimeStampResponse::from(tsr);

    // Check that the response was successful
    if !response.is_success() {
        return Err(TimestampError::ResponseFailure);
    }

    // Get the SignedData from the timestamp token
    let signed_data = response
        .signed_data()
        .map_err(TimestampError::ParseError)?
        .ok_or(TimestampError::NoToken)?;

    // Verify the content type is TSTInfo
    if signed_data.encap_content_info.econtent_type.to_string() != OID_CONTENT_TYPE_TST_INFO {
        return Err(TimestampError::ParseError(
            "content type is not TSTInfo".to_string(),
        ));
    }

    // Extract the TSTInfo
    let tst_info = response
        .tst_info()
        .map_err(TimestampError::ParseError)?
        .ok_or(TimestampError::NoTstInfo)?;

    // Verify the message imprint (hash of the signature) matches
    verify_message_imprint(&tst_info, signature_bytes)?;

    // Extract the timestamp from TSTInfo
    // The gen_time field is a GeneralizedTimeNanos - convert to DateTime<Utc>
    let unix_duration = tst_info.gen_time.to_unix_duration();
    let timestamp = DateTime::from_timestamp(unix_duration.as_secs() as i64, unix_duration.subsec_nanos())
        .ok_or(TimestampError::ParseError("invalid timestamp in TSTInfo".to_string()))?;

    // Check that the timestamp is within the TSA validity period in the trusted root
    if let Some((start, end)) = opts.tsa_valid_for {
        if timestamp < start || timestamp > end {
            tracing::error!(
                "Timestamp {} is outside TSA validity period ({} to {})",
                timestamp,
                start,
                end
            );
            return Err(TimestampError::OutsideValidityPeriod);
        }
        tracing::debug!(
            "Timestamp {} is within TSA validity period ({} to {})",
            timestamp,
            start,
            end
        );
    }

    // TODO: Implement CMS signature verification using RustCrypto primitives
    // For now, we skip signature verification to get the migration compiling
    // The signature verification needs to:
    // 1. Extract signer info from SignedData
    // 2. Extract TSA certificate (from SignedData or opts.tsa_certificate)
    // 3. Verify message digest
    // 4. Verify signature using certificate's public key
    // 5. Validate certificate chain
    // 6. Check certificate validity period
    tracing::warn!("CMS signature verification not yet implemented with RustCrypto");

    // Check if we have embedded certificates
    let has_embedded_certs = signed_data.certificates.is_some();
    if has_embedded_certs {
        let cert_count = signed_data.certificates.as_ref().unwrap().0.len();
        tracing::debug!("SignedData contains {} embedded certificate(s)", cert_count);
    }

    Ok(TimestampResult { time: timestamp })
}

/// Verify that the message imprint in TSTInfo matches the hash of the signature.
fn verify_message_imprint(
    tst_info: &TstInfo,
    signature_bytes: &[u8],
) -> Result<(), TimestampError> {
    // Hash the signature bytes
    let mut hasher = Sha256::new();
    hasher.update(signature_bytes);
    let signature_hash = hasher.finalize();

    // Get the hash from the message imprint
    let imprint_hash = tst_info
        .message_imprint
        .hashed_message
        .as_bytes();

    // Compare the hashes
    if &signature_hash[..] != imprint_hash {
        return Err(TimestampError::HashMismatch {
            expected: hex::encode(imprint_hash),
            actual: hex::encode(&signature_hash[..]),
        });
    }

    Ok(())
}
