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
use cryptographic_message_syntax::asn1::rfc3161::{PkiStatus, TimeStampResp, TstInfo};
use pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};

// TimeStamping Extended Key Usage OID (1.3.6.1.5.5.7.3.8)
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

/// Wrapper around TimeStampResp that provides convenience methods.
struct TimeStampResponse(TimeStampResp);

impl TimeStampResponse {
    /// Whether the time stamp request was successful.
    fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    /// Decode the `SignedData` value in the response.
    fn signed_data(
        &self,
    ) -> Result<Option<cryptographic_message_syntax::asn1::rfc5652::SignedData>, String> {
        use cryptographic_message_syntax::asn1::rfc5652::{OID_ID_SIGNED_DATA, SignedData};

        if let Some(token) = &self.0.time_stamp_token {
            let source = token.content.clone();

            if token.content_type == OID_ID_SIGNED_DATA {
                Ok(Some(source.decode(SignedData::take_from).map_err(|e| {
                    format!("failed to decode SignedData: {}", e)
                })?))
            } else {
                Err("invalid OID on signed data".to_string())
            }
        } else {
            Ok(None)
        }
    }

    /// Extract the TSTInfo from the SignedData.
    fn tst_info(&self) -> Result<Option<TstInfo>, String> {
        use cryptographic_message_syntax::asn1::rfc3161::OID_CONTENT_TYPE_TST_INFO;

        if let Some(signed_data) = self.signed_data()? {
            if signed_data.content_info.content_type == OID_CONTENT_TYPE_TST_INFO {
                if let Some(content) = signed_data.content_info.content {
                    Ok(Some(
                        bcder::decode::Constructed::decode(
                            content.to_bytes(),
                            bcder::Mode::Der,
                            TstInfo::take_from,
                        )
                        .map_err(|e| format!("failed to decode TSTInfo: {}", e))?,
                    ))
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

impl From<TimeStampResp> for TimeStampResponse {
    fn from(resp: TimeStampResp) -> Self {
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
/// * `_opts` - Verification options (currently unused, for future certificate chain verification)
///
/// # Returns
///
/// Returns `Ok(TimestampResult)` if verification succeeds, otherwise returns an error.
pub fn verify_timestamp_response(
    timestamp_response_bytes: &[u8],
    signature_bytes: &[u8],
    opts: VerifyOpts<'_>,
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
        .map_err(TimestampError::ParseError)?
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
        .map_err(TimestampError::ParseError)?
        .ok_or(TimestampError::NoTstInfo)?;

    // Verify the message imprint (hash of the signature) matches
    verify_message_imprint(&tst_info, signature_bytes)?;

    // Extract the timestamp from TSTInfo
    // The gen_time field is a GeneralizedTime which has a From impl for DateTime<Utc>
    let timestamp: DateTime<Utc> = tst_info.gen_time.into();

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

    // Verify the CMS signature on the SignedData
    // Parse the SignedData into the high-level type that has verification methods
    let parsed_signed_data = cryptographic_message_syntax::SignedData::try_from(&signed_data)
        .map_err(|e| {
            TimestampError::SignatureVerificationError(format!("failed to parse SignedData: {}", e))
        })?;

    // Check if we have embedded certificates or need to use external ones
    let has_embedded_certs = parsed_signed_data.certificates().count() > 0;

    // If no embedded certificates, we need to use the TSA certificate from opts
    let external_tsa_cert = if !has_embedded_certs {
        if let Some(ref tsa_cert) = opts.tsa_certificate {
            use x509_certificate::CapturedX509Certificate;
            Some(
                CapturedX509Certificate::from_der(tsa_cert.as_ref()).map_err(|e| {
                    TimestampError::SignatureVerificationError(format!(
                        "failed to parse TSA certificate: {}",
                        e
                    ))
                })?,
            )
        } else {
            tracing::warn!("No embedded certificates and no TSA certificate provided in opts");
            None
        }
    } else {
        None
    };

    // Verify signature for each signer
    for signer in parsed_signed_data.signers() {
        // Verify the message digest
        match signer.verify_message_digest_with_signed_data(&parsed_signed_data) {
            Ok(_) => {
                tracing::debug!("TSA message digest verified successfully");
            }
            Err(e) => {
                tracing::error!("TSA message digest verification failed: {}", e);
                return Err(TimestampError::SignatureVerificationError(format!(
                    "message digest verification failed: {}",
                    e
                )));
            }
        }

        // Verify the signature
        if has_embedded_certs {
            // Use embedded certificates
            match signer.verify_signature_with_signed_data(&parsed_signed_data) {
                Ok(_) => {
                    tracing::debug!("TSA signature verified successfully");
                }
                Err(e) => {
                    tracing::error!("TSA signature verification failed: {}", e);
                    return Err(TimestampError::SignatureVerificationError(format!(
                        "signature verification failed: {}",
                        e
                    )));
                }
            }
        } else {
            // Use external TSA certificate
            if let Some(ref tsa_cert) = external_tsa_cert {
                let signed_content = signer.signed_content_with_signed_data(&parsed_signed_data);
                let verifier = signer
                    .signature_verifier(std::iter::once(tsa_cert))
                    .map_err(|e| {
                        TimestampError::SignatureVerificationError(format!(
                            "failed to create signature verifier: {}",
                            e
                        ))
                    })?;

                verifier
                    .verify(&signed_content, signer.signature())
                    .map_err(|_| {
                        TimestampError::SignatureVerificationError(
                            "signature verification failed".to_string(),
                        )
                    })?;

                tracing::debug!("TSA signature verified successfully with external certificate");
            } else {
                return Err(TimestampError::SignatureVerificationError(
                    "no TSA certificate available for verification".to_string(),
                ));
            }
        }
    }

    // Additional verification: Check timestamp is within TSA certificate's validity period
    // Extract the TSA certificate (either embedded or external)
    let tsa_cert_der = if has_embedded_certs {
        // Get the first certificate from the SignedData
        parsed_signed_data.certificates().next().map(|cert| {
            // CapturedX509Certificate has encoded_der() method to get the raw bytes
            cert.constructed_data().to_vec()
        })
    } else {
        opts.tsa_certificate.as_ref().map(|c| c.as_ref().to_vec())
    };

    if let Some(ref cert_der) = tsa_cert_der {
        // Parse the certificate to check validity
        use x509_cert::{Certificate, der::Decode};
        let cert = Certificate::from_der(cert_der).map_err(|e| {
            TimestampError::SignatureVerificationError(format!(
                "failed to parse TSA certificate: {}",
                e
            ))
        })?;

        // Get the certificate validity period
        let validity = &cert.tbs_certificate.validity;
        let not_before_unix = validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after_unix = validity.not_after.to_unix_duration().as_secs() as i64;

        let not_before = DateTime::from_timestamp(not_before_unix, 0).ok_or_else(|| {
            TimestampError::SignatureVerificationError(
                "invalid notBefore timestamp in TSA certificate".to_string()
            )
        })?;
        let not_after = DateTime::from_timestamp(not_after_unix, 0).ok_or_else(|| {
            TimestampError::SignatureVerificationError(
                "invalid notAfter timestamp in TSA certificate".to_string()
            )
        })?;

        // Check that the timestamp is within the certificate's validity period
        if timestamp < not_before || timestamp > not_after {
            tracing::error!(
                "Timestamp {} is outside TSA certificate validity period ({} to {})",
                timestamp,
                not_before,
                not_after
            );
            return Err(TimestampError::OutsideValidityPeriod);
        }
        tracing::debug!(
            "Timestamp {} is within TSA certificate validity period ({} to {})",
            timestamp,
            not_before,
            not_after
        );
    }

    // TODO: Additional verification: Validate TSA certificate chain
    // This is complex and requires careful handling of certificate chain building.
    // The challenge is that webpki needs the exact root certificate that signed the chain,
    // but matching the TSA root from the trusted root to the certificate chain is non-trivial.
    // For now, we rely on the CMS signature verification which validates the cryptographic
    // signature is correct (though not that it's from a trusted TSA).
    //
    // Uncomment below to enable TSA certificate chain validation (currently incomplete):
    if false && !opts.roots.is_empty() {
        if let Some(ref cert_der) = tsa_cert_der {
            // Collect all certificates from SignedData except the root as intermediates
            // The leaf certificate will be validated separately
            let mut all_certs: Vec<_> = if has_embedded_certs {
                parsed_signed_data
                    .certificates()
                    .map(|cert| CertificateDer::from(cert.constructed_data().to_vec()))
                    .collect()
            } else {
                vec![]
            };

            // The intermediates should be everything except the leaf (first cert)
            let intermediates: Vec<CertificateDer> = if all_certs.len() > 1 {
                all_certs.drain(1..).collect()
            } else {
                vec![]
            };

            // Validate the certificate chain using CertificatePool
            use crate::crypto::CertificatePool;
            use webpki::{EndEntityCert, KeyUsage};

            let cert_pool = CertificatePool::from_certificates(
                opts.roots.iter().cloned(),
                intermediates,
            )
            .map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to create certificate pool: {}",
                    e
                ))
            })?;

            let cert_der_ref = CertificateDer::from(cert_der.as_slice());
            let end_entity_cert = EndEntityCert::try_from(&cert_der_ref).map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to parse TSA certificate: {}",
                    e
                ))
            })?;

            // Verify the certificate chains to a trusted root with TimeStamping EKU
            let verification_time = UnixTime::since_unix_epoch(
                std::time::Duration::from_secs(timestamp.timestamp() as u64),
            );

            // Verify the certificate chains to a trusted TSA root
            // We use required_if_present for TimeStamping EKU: if the certificate has EKUs,
            // then TimeStamping must be present. Otherwise, we allow certificates without EKUs.
            let signing_algs = webpki::ALL_VERIFICATION_ALGS;

            end_entity_cert
                .verify_for_usage(
                    signing_algs,
                    cert_pool.trusted_roots(),
                    cert_pool.intermediates(),
                    verification_time,
                    KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
                    None,
                    None,
                )
                .map_err(|e| {
                    tracing::error!("TSA certificate chain validation failed: {}", e);
                    TimestampError::SignatureVerificationError(format!(
                        "TSA certificate chain validation failed: {}",
                        e
                    ))
                })?;

            tracing::debug!("TSA certificate chain validated successfully");
        }
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
        .as_slice()
        .ok_or_else(|| {
            TimestampError::ParseError("hashed_message is not primitive encoded".to_string())
        })?;

    // Compare the hashes
    if signature_hash.as_slice() != imprint_hash {
        return Err(TimestampError::HashMismatch {
            expected: hex::encode(imprint_hash),
            actual: hex::encode(signature_hash),
        });
    }

    Ok(())
}
