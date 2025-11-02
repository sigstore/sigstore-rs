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
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;
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
        use x509_cert::der::{Decode};

        // OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
        const OID_CONTENT_TYPE_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

        if let Some(signed_data) = self.signed_data()? {
            if signed_data.encap_content_info.econtent_type.to_string()
                == OID_CONTENT_TYPE_TST_INFO
            {
                if let Some(content) = signed_data.encap_content_info.econtent {
                    // The content is an Any wrapping an OCTET STRING that contains the TSTInfo
                    // We need to get the value bytes from the Any, which gives us the OCTET STRING content
                    let tst_info_bytes = content.value();

                    let tst_info = TstInfo::from_der(tst_info_bytes)
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

    // Verify the CMS signature
    // We need the DER-encoded TSTInfo for signature verification
    // The econtent is an Any wrapping an OCTET STRING that contains the TSTInfo bytes
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(TimestampError::NoTstInfo)?
        .value();  // Get the value bytes from the Any (OCTET STRING content)

    tracing::debug!("Starting CMS signature verification");
    verify_cms_signature(&signed_data, tst_info_der)?;
    tracing::debug!("CMS signature verification completed successfully");

    // TODO: Validate certificate chain using webpki
    // This will require:
    // 1. Building a certificate chain from the signer cert to a trusted root
    // 2. Verifying the chain is valid at the timestamp
    // 3. Checking the TimeStamping EKU (1.3.6.1.5.5.7.3.8) is present
    tracing::debug!("Certificate chain validation not yet implemented");

    Ok(TimestampResult { time: timestamp })
}

/// Extract certificates from SignedData.
fn extract_certificates(signed_data: &SignedData) -> Result<Vec<Certificate>, TimestampError> {
    let mut certificates = Vec::new();

    if let Some(cert_set) = &signed_data.certificates {
        for cert_choice in cert_set.0.iter() {
            // Each element is already a CertificateChoices - just match on it
            match cert_choice {
                CertificateChoices::Certificate(cert) => {
                    certificates.push(cert.clone());
                }
                CertificateChoices::Other(_) => {
                    // Skip other certificate formats
                    tracing::debug!("Skipping non-standard certificate format");
                }
            }
        }
    }

    if certificates.is_empty() {
        return Err(TimestampError::SignatureVerificationError(
            "no certificates found in SignedData".to_string(),
        ));
    }

    Ok(certificates)
}

/// Find the signer certificate that matches the SignerIdentifier.
fn find_signer_certificate<'a>(
    signer_id: &SignerIdentifier,
    certificates: &'a [Certificate],
) -> Result<&'a Certificate, TimestampError> {
    use cms::cert::IssuerAndSerialNumber;

    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
            // Match by issuer and serial number
            for cert in certificates {
                if cert.tbs_certificate.issuer == issuer_serial.issuer
                    && cert.tbs_certificate.serial_number == issuer_serial.serial_number
                {
                    return Ok(cert);
                }
            }
            Err(TimestampError::SignatureVerificationError(
                "no certificate matches issuer and serial number".to_string(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Match by subject key identifier extension
            for cert in certificates {
                if let Some(extensions) = &cert.tbs_certificate.extensions {
                    for ext in extensions.iter() {
                        // OID for SubjectKeyIdentifier: 2.5.29.14
                        if ext.extn_id.to_string() == "2.5.29.14" {
                            // Decode the extension value as SubjectKeyIdentifier
                            if let Ok(cert_ski) = x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                                if &cert_ski == ski {
                                    return Ok(cert);
                                }
                            }
                        }
                    }
                }
            }
            Err(TimestampError::SignatureVerificationError(
                "no certificate matches subject key identifier".to_string(),
            ))
        }
    }
}

/// Verify the message-digest attribute in signed_attrs matches the TSTInfo content.
fn verify_message_digest_attribute(
    signed_attrs: &x509_cert::attr::Attributes,
    tst_info_der: &[u8],
) -> Result<(), TimestampError> {
    use x509_cert::der::asn1::OctetStringRef;

    // OID for message-digest attribute: 1.2.840.113549.1.9.4
    const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

    // Find the message-digest attribute
    let message_digest_attr = signed_attrs
        .iter()
        .find(|attr| attr.oid.to_string() == OID_MESSAGE_DIGEST)
        .ok_or_else(|| {
            TimestampError::SignatureVerificationError(
                "message-digest attribute not found in signed_attrs".to_string(),
            )
        })?;

    // The attribute values should contain exactly one OCTET STRING
    if message_digest_attr.values.len() != 1 {
        return Err(TimestampError::SignatureVerificationError(
            "message-digest attribute should have exactly one value".to_string(),
        ));
    }

    // Decode the attribute value as OCTET STRING
    let message_digest_any = message_digest_attr.values.get(0).ok_or_else(|| {
        TimestampError::SignatureVerificationError(
            "failed to get message-digest attribute value".to_string(),
        )
    })?;
    let message_digest_der = message_digest_any.to_der().map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to encode message-digest attribute value: {}",
            e
        ))
    })?;
    let message_digest_octets = OctetStringRef::from_der(&message_digest_der)
    .map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode message-digest as OCTET STRING: {}",
            e
        ))
    })?;

    let message_digest = message_digest_octets.as_bytes();

    // Hash the TSTInfo content
    let mut hasher = Sha256::new();
    hasher.update(tst_info_der);
    let content_hash = hasher.finalize();

    // Compare the hashes
    if &content_hash[..] != message_digest {
        return Err(TimestampError::HashMismatch {
            expected: hex::encode(message_digest),
            actual: hex::encode(&content_hash[..]),
        });
    }

    Ok(())
}

/// Verify ECDSA signature using the certificate's public key.
fn verify_ecdsa_signature(
    signature: &[u8],
    message: &[u8],
    certificate: &Certificate,
) -> Result<(), TimestampError> {
    use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
    use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
    use signature::Verifier;

    // Get the public key from the certificate
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
        TimestampError::SignatureVerificationError("invalid public key encoding".to_string())
    })?;

    // Determine the algorithm from the AlgorithmIdentifier
    let alg_oid = spki.algorithm.oid.to_string();

    match alg_oid.as_str() {
        "1.2.840.10045.2.1" => {
            // id-ecPublicKey - need to check the curve parameter
            if let Some(params) = &spki.algorithm.parameters {
                use x509_cert::der::asn1::ObjectIdentifier;
                // For EC public keys, the parameter is an OID identifying the curve
                // Decode the Any as an ObjectIdentifier
                let curve_oid = params.decode_as::<ObjectIdentifier>().map_err(|e| {
                    TimestampError::SignatureVerificationError(format!(
                        "failed to decode curve OID: {}",
                        e
                    ))
                })?;

                match curve_oid.to_string().as_str() {
                    "1.2.840.10045.3.1.7" => {
                        // secp256r1 (P-256)
                        let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
                            .map_err(|e| {
                                TimestampError::SignatureVerificationError(format!(
                                    "failed to parse P-256 public key: {}",
                                    e
                                ))
                            })?;

                        // Try DER-encoded signature first
                        let sig_result = P256Signature::from_der(signature);
                        let sig = match sig_result {
                            Ok(s) => s,
                            Err(_) => {
                                // If DER parsing fails, try raw signature bytes (64 bytes for P-256)
                                tracing::debug!("DER signature parsing failed, trying raw signature format");
                                P256Signature::from_bytes(signature.into()).map_err(|e| {
                                    TimestampError::SignatureVerificationError(format!(
                                        "failed to parse P-256 signature (raw): {}",
                                        e
                                    ))
                                })?
                            }
                        };

                        verifying_key.verify(message, &sig).map_err(|e| {
                            TimestampError::SignatureVerificationError(format!(
                                "P-256 signature verification failed: {}",
                                e
                            ))
                        })?;
                    }
                    "1.3.132.0.34" => {
                        // secp384r1 (P-384)
                        let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_bytes)
                            .map_err(|e| {
                                TimestampError::SignatureVerificationError(format!(
                                    "failed to parse P-384 public key: {}",
                                    e
                                ))
                            })?;

                        // Try DER-encoded signature first
                        let sig_result = P384Signature::from_der(signature);
                        let sig = match sig_result {
                            Ok(s) => s,
                            Err(_) => {
                                // If DER parsing fails, try raw signature bytes (96 bytes for P-384)
                                tracing::debug!("DER signature parsing failed, trying raw signature format");
                                P384Signature::from_bytes(signature.into()).map_err(|e| {
                                    TimestampError::SignatureVerificationError(format!(
                                        "failed to parse P-384 signature (raw): {}",
                                        e
                                    ))
                                })?
                            }
                        };

                        verifying_key.verify(message, &sig).map_err(|e| {
                            TimestampError::SignatureVerificationError(format!(
                                "P-384 signature verification failed: {}",
                                e
                            ))
                        })?;
                    }
                    _ => {
                        return Err(TimestampError::SignatureVerificationError(format!(
                            "unsupported elliptic curve: {}",
                            curve_oid
                        )));
                    }
                }
            } else {
                return Err(TimestampError::SignatureVerificationError(
                    "missing curve parameters for EC public key".to_string(),
                ));
            }
        }
        _ => {
            return Err(TimestampError::SignatureVerificationError(format!(
                "unsupported signature algorithm: {}",
                alg_oid
            )));
        }
    }

    Ok(())
}

/// Verify the CMS signature in the SignedData.
fn verify_cms_signature(
    signed_data: &SignedData,
    tst_info_der: &[u8],
) -> Result<(), TimestampError> {
    // Extract certificates from the SignedData
    let certificates = extract_certificates(signed_data)?;

    tracing::debug!("Extracted {} certificate(s) from SignedData", certificates.len());

    // Get the first (and should be only) SignerInfo
    if signed_data.signer_infos.0.is_empty() {
        return Err(TimestampError::SignatureVerificationError(
            "no SignerInfo found in SignedData".to_string(),
        ));
    }

    if signed_data.signer_infos.0.len() > 1 {
        tracing::warn!(
            "Multiple SignerInfo entries found ({}), using the first one",
            signed_data.signer_infos.0.len()
        );
    }

    let signer_info = signed_data.signer_infos.0.get(0).ok_or_else(|| {
        TimestampError::SignatureVerificationError(
            "failed to get first SignerInfo".to_string(),
        )
    })?;

    // Find the certificate that matches the SignerIdentifier
    let signer_cert = find_signer_certificate(&signer_info.sid, &certificates)?;

    tracing::debug!("Found signer certificate matching SignerIdentifier");

    // Verify the signature based on whether signed_attrs are present
    if let Some(signed_attrs) = &signer_info.signed_attrs {
        // With signed_attrs: signature is over DER-encoded signed_attrs
        tracing::debug!("Verifying signature with signed_attrs");

        // Verify the message-digest attribute matches the TSTInfo content
        verify_message_digest_attribute(signed_attrs, tst_info_der)?;

        // The signature is over the DER encoding of signed_attrs with tag 0x31 (SET OF)
        // When encoding for signature verification, we need to use SET OF tag
        let mut signed_attrs_der = signed_attrs.to_der().map_err(|e| {
            TimestampError::SignatureVerificationError(format!(
                "failed to encode signed_attrs: {}",
                e
            ))
        })?;

        tracing::debug!("signed_attrs DER length: {}, first bytes: {}",
            signed_attrs_der.len(),
            hex::encode(&signed_attrs_der[..signed_attrs_der.len().min(32)]));

        // RFC 5652 Section 5.4: The message digest is computed on the DER encoding of the
        // signedAttrs field, including the tag and length octets. For the purpose of computing
        // the digest, the DER encoding uses the tag value 0x31 (SET OF) rather than the
        // context-specific tag (0xA0) that appears in the actual encoding.
        if !signed_attrs_der.is_empty() && signed_attrs_der[0] == 0xa0 {
            tracing::debug!("Replacing tag 0xA0 with 0x31 for signature verification");
            signed_attrs_der[0] = 0x31;
        }

        // Determine hash algorithm from digest_alg
        let digest_alg_oid = signer_info.digest_alg.oid.to_string();
        tracing::debug!("Digest algorithm OID: {}", digest_alg_oid);

        // Hash the signed_attrs using the appropriate algorithm
        let signed_attrs_hash = match digest_alg_oid.as_str() {
            "2.16.840.1.101.3.4.2.1" => {
                // SHA-256
                tracing::debug!("Using SHA-256 for signed_attrs hash");
                let mut hasher = Sha256::new();
                hasher.update(&signed_attrs_der);
                hasher.finalize().to_vec()
            }
            "2.16.840.1.101.3.4.2.2" => {
                // SHA-384
                tracing::debug!("Using SHA-384 for signed_attrs hash");
                use sha2::Sha384;
                let mut hasher = Sha384::new();
                hasher.update(&signed_attrs_der);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(TimestampError::SignatureVerificationError(format!(
                    "unsupported digest algorithm: {}",
                    digest_alg_oid
                )));
            }
        };

        // Verify the signature
        verify_ecdsa_signature(
            signer_info.signature.as_bytes(),
            &signed_attrs_hash,
            signer_cert,
        )?;
    } else {
        // Without signed_attrs: signature is directly over content hash
        tracing::debug!("Verifying signature without signed_attrs (direct content)");

        // Hash the content
        let mut hasher = Sha256::new();
        hasher.update(tst_info_der);
        let content_hash = hasher.finalize();

        // Verify the signature
        verify_ecdsa_signature(signer_info.signature.as_bytes(), &content_hash, signer_cert)?;
    }

    tracing::debug!("CMS signature verification succeeded");

    Ok(())
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
