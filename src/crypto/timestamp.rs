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
use cms::signed_data::{SignedData, SignerIdentifier};
use pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
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
        use x509_cert::der::Decode;

        // OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
        const OID_CONTENT_TYPE_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

        if let Some(signed_data) = self.signed_data()? {
            if signed_data.encap_content_info.econtent_type.to_string() == OID_CONTENT_TYPE_TST_INFO
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

    #[error("TSA certificate validation failed: {0}")]
    CertificateValidationError(String),
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
    let tsr = TimeStampResp::from_der(timestamp_response_bytes).map_err(|e| {
        TimestampError::ParseError(format!("failed to decode TimeStampResp: {}", e))
    })?;

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
    let timestamp =
        DateTime::from_timestamp(unix_duration.as_secs() as i64, unix_duration.subsec_nanos())
            .ok_or(TimestampError::ParseError(
                "invalid timestamp in TSTInfo".to_string(),
            ))?;

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
        .value(); // Get the value bytes from the Any (OCTET STRING content)

    tracing::debug!("Starting CMS signature verification");
    let signer_cert =
        verify_cms_signature(&signed_data, tst_info_der, timestamp_response_bytes, &opts)?;
    tracing::debug!("CMS signature verification completed successfully");

    // Extract intermediate certificates from the SignedData for chain validation
    let embedded_certs = extract_certificates(&signed_data);

    // Validate certificate chain using webpki
    tracing::debug!("Starting TSA certificate chain validation");
    validate_tsa_certificate_chain(&signer_cert, timestamp, &opts, &embedded_certs)?;
    tracing::debug!("TSA certificate chain validation completed successfully");

    Ok(TimestampResult { time: timestamp })
}

/// Validate the TSA certificate chain.
/// Verifies that:
/// 1. The certificate chains to a trusted root
/// 2. The certificate was valid at the timestamp time
/// 3. The certificate has the TimeStamping Extended Key Usage
fn validate_tsa_certificate_chain(
    signer_cert: &Certificate,
    timestamp: DateTime<Utc>,
    opts: &VerifyOpts,
    embedded_certs: &[Certificate],
) -> Result<(), TimestampError> {
    use pki_types::{CertificateDer, UnixTime};
    use webpki::{EndEntityCert, KeyUsage};

    // If no roots are provided, skip certificate chain validation
    if opts.roots.is_empty() {
        tracing::debug!("No trusted roots provided, skipping certificate chain validation");
        return Ok(());
    }

    // Convert the signer certificate to DER format for webpki
    let signer_cert_der = signer_cert.to_der().map_err(|e| {
        TimestampError::CertificateValidationError(format!(
            "failed to encode signer certificate to DER: {}",
            e
        ))
    })?;

    let signer_cert_der = CertificateDer::from(signer_cert_der);
    let end_entity_cert = EndEntityCert::try_from(&signer_cert_der).map_err(|e| {
        TimestampError::CertificateValidationError(format!(
            "failed to parse end-entity certificate: {}",
            e
        ))
    })?;

    // Build trust anchors from the provided roots
    let trust_anchors: Vec<_> = opts
        .roots
        .iter()
        .map(|cert| {
            webpki::anchor_from_trusted_cert(cert)
                .map(|anchor| anchor.to_owned())
                .map_err(|e| {
                    TimestampError::CertificateValidationError(format!(
                        "failed to create trust anchor: {}",
                        e
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Convert embedded certificates to DER format for use as intermediates
    // Filter out the signer cert itself - we only want intermediate CAs
    let mut intermediate_ders: Vec<CertificateDer<'static>> = Vec::new();

    for cert in embedded_certs {
        // Skip the signer certificate itself
        if cert == signer_cert {
            continue;
        }

        let cert_der = cert.to_der().map_err(|e| {
            TimestampError::CertificateValidationError(format!(
                "failed to encode embedded certificate to DER: {}",
                e
            ))
        })?;
        intermediate_ders.push(CertificateDer::from(cert_der).into_owned());
    }

    // Add intermediates from opts
    intermediate_ders.extend(opts.intermediates.iter().map(|c| c.clone().into_owned()));

    tracing::debug!(
        "Using {} embedded intermediate cert(s) + {} provided intermediate cert(s)",
        embedded_certs.len().saturating_sub(1), // -1 for signer cert
        opts.intermediates.len()
    );

    // Convert timestamp to UnixTime for webpki
    let verification_time =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(timestamp.timestamp() as u64));

    tracing::debug!(
        "Verifying certificate chain at timestamp: {} (unix: {})",
        timestamp,
        timestamp.timestamp()
    );

    // Verify the certificate chain with TimeStamping EKU
    let signing_algs = webpki::ALL_VERIFICATION_ALGS;

    end_entity_cert
        .verify_for_usage(
            signing_algs,
            &trust_anchors,
            &intermediate_ders,
            verification_time,
            KeyUsage::required(ID_KP_TIME_STAMPING),
            None,
            None,
        )
        .map_err(|e| {
            TimestampError::CertificateValidationError(format!(
                "TSA certificate chain validation failed: {}",
                e
            ))
        })?;

    tracing::debug!("TSA certificate chain validated successfully");

    Ok(())
}

/// Extract certificates from SignedData.
/// Returns an empty Vec if no certificates are embedded (caller should handle this).
fn extract_certificates(signed_data: &SignedData) -> Vec<Certificate> {
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

    certificates
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
                            if let Ok(cert_ski) =
                                x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                                    ext.extn_value.as_bytes(),
                                )
                            {
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
    let message_digest_octets = OctetStringRef::from_der(&message_digest_der).map_err(|e| {
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
    use signature::hazmat::PrehashVerifier;

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
                                tracing::debug!(
                                    "DER signature parsing failed, trying raw signature format"
                                );
                                P256Signature::from_bytes(signature.into()).map_err(|e| {
                                    TimestampError::SignatureVerificationError(format!(
                                        "failed to parse P-256 signature (raw): {}",
                                        e
                                    ))
                                })?
                            }
                        };

                        // Convert message (hash) to FieldBytes for P-256 (32 bytes)
                        if message.len() != 32 {
                            return Err(TimestampError::SignatureVerificationError(format!(
                                "P-256 requires 32-byte hash, got {}",
                                message.len()
                            )));
                        }
                        let mut field_bytes = p256::FieldBytes::default();
                        field_bytes.copy_from_slice(message);

                        verifying_key
                            .verify_prehash(&field_bytes, &sig)
                            .map_err(|e| {
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
                                tracing::debug!(
                                    "DER signature parsing failed, trying raw signature format"
                                );
                                P384Signature::from_bytes(signature.into()).map_err(|e| {
                                    TimestampError::SignatureVerificationError(format!(
                                        "failed to parse P-384 signature (raw): {}",
                                        e
                                    ))
                                })?
                            }
                        };

                        // Convert message (hash) to FieldBytes for P-384 (48 bytes for SHA-384, but can be 32 for SHA-256)
                        // P-384 can verify hashes of different sizes, so we need to handle both SHA-256 (32) and SHA-384 (48)
                        let mut field_bytes = p384::FieldBytes::default();
                        if message.len() <= field_bytes.len() {
                            // Pad with zeros on the left if needed (standard practice for shorter hashes)
                            let offset = field_bytes.len() - message.len();
                            field_bytes[offset..].copy_from_slice(message);
                        } else {
                            return Err(TimestampError::SignatureVerificationError(format!(
                                "P-384 hash too long: {} bytes",
                                message.len()
                            )));
                        }

                        verifying_key
                            .verify_prehash(&field_bytes, &sig)
                            .map_err(|e| {
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

/// Extract the raw signed_attrs bytes from the timestamp DER encoding.
/// This function manually parses the DER structure to get the original bytes
/// without re-encoding, which is critical for signature verification.
///
/// The signed_attrs field is stored with context-specific tag 0xA0 in the SignerInfo,
/// but for signature verification it needs to be replaced with SET tag 0x31.
fn extract_signed_attrs_bytes(timestamp_der: &[u8]) -> Result<Vec<u8>, TimestampError> {
    use x509_cert::der::{Reader, SliceReader};

    // TimeStampResp is a SEQUENCE
    let mut reader = SliceReader::new(timestamp_der).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to create reader: {}", e))
    })?;

    // Parse outer TimeStampResp structure to find the ContentInfo (time_stamp_token)
    // We need to manually navigate through:
    // TimeStampResp ::= SEQUENCE {
    //   status PKIStatusInfo,
    //   timeStampToken TimeStampToken OPTIONAL }
    // where TimeStampToken ::= ContentInfo

    // Read the SEQUENCE header
    let _header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode header: {}", e))
    })?;

    // First field is PKIStatusInfo (SEQUENCE)
    let status_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode status header: {}", e))
    })?;

    // Skip the status bytes
    reader.read_slice(status_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to skip status: {}", e))
    })?;

    // Now we should be at the ContentInfo (SignedData wrapper)
    // ContentInfo ::= SEQUENCE {
    //   contentType OBJECT IDENTIFIER,
    //   content [0] EXPLICIT ANY DEFINED BY contentType }

    let content_info_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode ContentInfo header: {}",
            e
        ))
    })?;

    // Read the OID
    let oid_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode OID header: {}", e))
    })?;
    reader.read_slice(oid_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to skip OID: {}", e))
    })?;

    // Read the [0] EXPLICIT tag
    let explicit_tag_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode explicit tag: {}", e))
    })?;

    // Now we're at the SignedData SEQUENCE
    let _signed_data_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode SignedData header: {}",
            e
        ))
    })?;

    // SignedData ::= SEQUENCE {
    //   version CMSVersion,
    //   digestAlgorithms SET OF DigestAlgorithmIdentifier,
    //   encapContentInfo EncapsulatedContentInfo,
    //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    //   signerInfos SignerInfos }

    // Skip version (INTEGER)
    let version_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode version: {}", e))
    })?;
    reader.read_slice(version_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to skip version: {}", e))
    })?;

    // Skip digestAlgorithms (SET OF)
    let digest_algs_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode digestAlgorithms: {}",
            e
        ))
    })?;
    reader.read_slice(digest_algs_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to skip digestAlgorithms: {}",
            e
        ))
    })?;

    // Skip encapContentInfo (SEQUENCE)
    let encap_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode encapContentInfo: {}",
            e
        ))
    })?;
    reader.read_slice(encap_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to skip encapContentInfo: {}",
            e
        ))
    })?;

    // Check for optional certificates [0]
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA0 {
            let cert_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to decode certificates: {}",
                    e
                ))
            })?;
            reader.read_slice(cert_header.length).map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to skip certificates: {}",
                    e
                ))
            })?;
        }
    }

    // Check for optional crls [1]
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA1 {
            let crl_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                TimestampError::SignatureVerificationError(format!("failed to decode CRLs: {}", e))
            })?;
            reader.read_slice(crl_header.length).map_err(|e| {
                TimestampError::SignatureVerificationError(format!("failed to skip CRLs: {}", e))
            })?;
        }
    }

    // Now we're at signerInfos (SET OF SignerInfo)
    let _signer_infos_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode signerInfos: {}", e))
    })?;

    // Read the first SignerInfo SEQUENCE
    let _signer_info_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode SignerInfo: {}", e))
    })?;

    // SignerInfo ::= SEQUENCE {
    //   version CMSVersion,
    //   sid SignerIdentifier,
    //   digestAlgorithm DigestAlgorithmIdentifier,
    //   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    //   ...

    // Skip version
    let si_version_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode SignerInfo version: {}",
            e
        ))
    })?;
    reader.read_slice(si_version_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to skip SignerInfo version: {}",
            e
        ))
    })?;

    // Skip sid (SignerIdentifier - either SEQUENCE or [0] IMPLICIT)
    let sid_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to decode sid: {}", e))
    })?;
    reader.read_slice(sid_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to skip sid: {}", e))
    })?;

    // Skip digestAlgorithm (SEQUENCE)
    let digest_alg_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
        TimestampError::SignatureVerificationError(format!(
            "failed to decode digestAlgorithm: {}",
            e
        ))
    })?;
    reader.read_slice(digest_alg_header.length).map_err(|e| {
        TimestampError::SignatureVerificationError(format!("failed to skip digestAlgorithm: {}", e))
    })?;

    // Now we should be at signedAttrs [0] IMPLICIT
    if let Some(byte) = reader.peek_byte() {
        if byte == 0xA0 {
            // Found signed_attrs!
            // We need to capture this INCLUDING the tag and length, but then replace 0xA0 with 0x31
            let start_offset_len = reader.position();
            let start_offset: u32 = start_offset_len.into();
            let start_offset = start_offset as usize;

            let signed_attrs_header = x509_cert::der::Header::decode(&mut reader).map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to decode signedAttrs: {}",
                    e
                ))
            })?;

            // Calculate total length including tag and length bytes
            let current_pos_len = reader.position();
            let current_pos: u32 = current_pos_len.into();
            let current_pos = current_pos as usize;
            let header_len = current_pos - start_offset;

            // Convert Length to usize for indexing
            let content_len: u32 = signed_attrs_header.length.into();
            let content_len = content_len as usize;

            // Get the actual signed_attrs bytes directly from the timestamp_der slice
            // We know the start_offset and the total length (header + content)
            let total_len = header_len + content_len;

            if start_offset + total_len > timestamp_der.len() {
                return Err(TimestampError::SignatureVerificationError(
                    "signed_attrs extends beyond timestamp data".to_string(),
                ));
            }

            // Extract the signed_attrs bytes directly from the slice
            let mut signed_attrs_bytes =
                timestamp_der[start_offset..start_offset + total_len].to_vec();

            // Replace the context-specific tag 0xA0 with SET tag 0x31
            // RFC 5652 Section 5.4: For signature verification, use SET tag
            if !signed_attrs_bytes.is_empty() && signed_attrs_bytes[0] == 0xA0 {
                signed_attrs_bytes[0] = 0x31;
            }

            return Ok(signed_attrs_bytes);
        }
    }

    Err(TimestampError::SignatureVerificationError(
        "signed_attrs not found in SignerInfo".to_string(),
    ))
}

/// Verify the CMS signature in the SignedData.
/// Returns the signer certificate for further validation.
fn verify_cms_signature(
    signed_data: &SignedData,
    tst_info_der: &[u8],
    timestamp_der: &[u8],
    opts: &VerifyOpts,
) -> Result<Certificate, TimestampError> {
    // Extract certificates from the SignedData
    let mut certificates = extract_certificates(signed_data);

    // If no certificates are embedded and a TSA certificate is provided, use it
    if certificates.is_empty() {
        if let Some(tsa_cert) = &opts.tsa_certificate {
            tracing::debug!(
                "No certificates embedded in SignedData, using TSA certificate from VerifyOpts"
            );
            // Convert CertificateDer to Certificate
            let cert = Certificate::from_der(tsa_cert.as_ref()).map_err(|e| {
                TimestampError::SignatureVerificationError(format!(
                    "failed to parse TSA certificate: {}",
                    e
                ))
            })?;
            certificates.push(cert);
        } else {
            return Err(TimestampError::SignatureVerificationError(
                "no certificates found in SignedData and no TSA certificate provided in VerifyOpts"
                    .to_string(),
            ));
        }
    }

    tracing::debug!(
        "Using {} certificate(s) for verification",
        certificates.len()
    );

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
        TimestampError::SignatureVerificationError("failed to get first SignerInfo".to_string())
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

        // CRITICAL: We need to use the ORIGINAL bytes from the SignedData structure,
        // not re-encode the parsed structure. Re-encoding can introduce subtle differences.
        // We need to extract the raw signed_attrs bytes from the original DER encoding.

        // Parse the SignedData structure manually to extract raw signed_attrs bytes
        let signed_attrs_der = extract_signed_attrs_bytes(timestamp_der)?;

        tracing::debug!(
            "Extracted signed_attrs DER length: {}, first bytes: {}",
            signed_attrs_der.len(),
            hex::encode(&signed_attrs_der[..signed_attrs_der.len().min(32)])
        );

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

    Ok(signer_cert.clone())
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
    let imprint_hash = tst_info.message_imprint.hashed_message.as_bytes();

    // Compare the hashes
    if &signature_hash[..] != imprint_hash {
        return Err(TimestampError::HashMismatch {
            expected: hex::encode(imprint_hash),
            actual: hex::encode(&signature_hash[..]),
        });
    }

    Ok(())
}
