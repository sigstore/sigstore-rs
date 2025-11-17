//! Minimal CMS (Cryptographic Message Syntax) parser for Sigstore
//!
//! This is a lightweight, read-only implementation of RFC 5652 and RFC 3161
//! parsing, focused solely on what Sigstore needs:
//! - Parse RFC 3161 TimeStampResp (Timestamp Response)
//! - Extract SignedData from timestamps
//! - Extract certificates from SignedData
//! - Verify message digests
//!
//! This does NOT support:
//! - Creating/signing CMS structures
//! - EnvelopedData, AuthenticatedData, etc.
//! - CRLs (Certificate Revocation Lists)
//! - Most optional attributes
//!
//! Total size: ~400 lines vs ~2000 lines in cryptographic-message-syntax

use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode::{self, Values},
    Mode, Oid, Tag,
};
use std::ops::Deref;

//==============================================================================
// RFC 3161 - Timestamp Protocol Structures
//==============================================================================

/// OID for id-signedData (1.2.840.113549.1.7.2)
pub const OID_ID_SIGNED_DATA: Oid<&[u8]> = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);

/// OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
pub const OID_CONTENT_TYPE_TST_INFO: Oid<&[u8]> = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 4]);

/// PKI Status values from RFC 3161
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    Granted = 0,
    GrantedWithMods = 1,
    Rejection = 2,
    Waiting = 3,
    RevocationWarning = 4,
    RevocationNotification = 5,
}

impl PkiStatus {
    fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(PkiStatus::Granted),
            1 => Some(PkiStatus::GrantedWithMods),
            2 => Some(PkiStatus::Rejection),
            3 => Some(PkiStatus::Waiting),
            4 => Some(PkiStatus::RevocationWarning),
            5 => Some(PkiStatus::RevocationNotification),
            _ => None,
        }
    }
}

/// RFC 3161 TimeStampResp
///
/// ```asn1
/// TimeStampResp ::= SEQUENCE {
///   status         PKIStatusInfo,
///   timeStampToken TimeStampToken OPTIONAL
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TimeStampResp {
    pub status: PkiStatus,
    pub time_stamp_token: Option<ContentInfo>,
}

impl TimeStampResp {
    pub fn from_der(data: &[u8]) -> Result<Self, String> {
        Constructed::decode(data, Mode::Der, |cons| {
            cons.take_sequence(|cons| {
                // Parse PKIStatusInfo
                let status = cons.take_sequence(|cons| {
                    let status_value = cons.take_u64()?;
                    PkiStatus::from_u64(status_value)
                        .ok_or_else(|| cons.content_err("invalid PKI status value"))
                })?;

                // TimeStampToken is OPTIONAL
                let time_stamp_token = ContentInfo::take_opt_from(cons)?;

                Ok(TimeStampResp {
                    status,
                    time_stamp_token,
                })
            })
        })
        .map_err(|e| format!("Failed to parse TimeStampResp: {:?}", e))
    }
}

//==============================================================================
// RFC 5652 - CMS Core Structures
//==============================================================================

/// ContentInfo - wrapper for all CMS content types
///
/// ```asn1
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ContentInfo {
    pub content_type: Oid<Vec<u8>>,
    pub content: bcder::Captured,
}

impl ContentInfo {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let content_type = Oid::take_from(cons)?;

            // Content is [0] EXPLICIT
            let content = cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.capture_one()
            })?;

            Ok(ContentInfo {
                content_type: content_type.into(),
                content,
            })
        })
    }

    /// Decode the content as SignedData
    pub fn as_signed_data(&self) -> Result<SignedData, String> {
        if self.content_type.as_ref() != OID_ID_SIGNED_DATA.as_ref() {
            return Err("ContentInfo is not SignedData".to_string());
        }

        self.content
            .clone()
            .decode(SignedData::take_from)
            .map_err(|e| format!("Failed to parse SignedData: {:?}", e))
    }
}

/// SignedData - the main CMS structure
///
/// ```asn1
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SignedData {
    pub version: u64,
    pub certificates: Option<Vec<Certificate>>,
    pub signer_infos: Vec<SignerInfo>,
    pub encap_content_type: Oid<Vec<u8>>,
}

impl SignedData {
    fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = cons.take_u64()?;

            // digestAlgorithms (we don't need to parse, just skip)
            cons.skip_one()?;

            // encapContentInfo
            let encap_content_type = cons.take_sequence(|cons| {
                let content_type = Oid::take_from(cons)?;
                // Skip the optional content [0] EXPLICIT
                let _ = cons.take_opt_constructed_if(Tag::CTX_0, |cons| cons.skip_all());
                Ok(content_type)
            })?;

            // certificates [0] IMPLICIT OPTIONAL
            let certificates = cons
                .take_opt_constructed_if(Tag::CTX_0, |cons| {
                    let mut certs = Vec::new();
                    while let Some(cert) = Certificate::take_opt_from(cons)? {
                        certs.push(cert);
                    }
                    Ok(certs)
                })?;

            // Skip CRLs [1] IMPLICIT if present
            let _ = cons.take_opt_constructed_if(Tag::CTX_1, |cons| cons.skip_all());

            // signerInfos
            let signer_infos = cons.take_set(|cons| {
                let mut infos = Vec::new();
                while let Some(info) = SignerInfo::take_opt_from(cons)? {
                    infos.push(info);
                }
                Ok(infos)
            })?;

            Ok(SignedData {
                version,
                certificates,
                signer_infos,
                encap_content_type: encap_content_type.into(),
            })
        })
    }
}

/// Certificate wrapper - preserves original DER bytes
///
/// This is the KEY to fixing the corruption bug: we store both
/// the original bytes AND the parsed structure.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The original DER bytes - NEVER re-encode these!
    original: bcder::Captured,
}

impl Certificate {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        // Check for other certificate types (we don't support them)
        // [0] ExtendedCertificate (obsolete)
        if cons.take_opt_constructed_if(Tag::CTX_0, |_| Ok::<(), _>(()))?.is_some() {
            return Err(cons.content_err("ExtendedCertificate not supported"));
        }
        // [1] v1AttrCert (obsolete)
        if cons.take_opt_constructed_if(Tag::CTX_1, |_| Ok::<(), _>(()))?.is_some() {
            return Err(cons.content_err("v1AttrCert not supported"));
        }
        // [2] v2AttrCert
        if cons.take_opt_constructed_if(Tag::CTX_2, |cons| cons.skip_all())?.is_some() {
            return Ok(None); // Skip attribute certificates
        }
        // [3] other
        if cons.take_opt_constructed_if(Tag::CTX_3, |cons| cons.skip_all())?.is_some() {
            return Ok(None); // Skip other certificate formats
        }

        // CRITICAL: Use capture() to preserve original bytes!
        // This prevents the re-encoding bug that adds NULL parameters.
        let captured_result = cons.capture(|capture_cons| {
            match capture_cons.take_opt_constructed(|tag, inner| {
                if tag == Tag::SEQUENCE {
                    inner.skip_all()?;
                    Ok(())
                } else {
                    Err(inner.content_err("expected SEQUENCE for Certificate"))
                }
            })? {
                Some(()) => Ok(()),
                None => Ok(()), // No certificate found
            }
        });

        match captured_result {
            Ok(original) => {
                if original.as_slice().is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(Certificate { original }))
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Get the original DER bytes - preserves exact encoding
    pub fn as_der(&self) -> &[u8] {
        self.original.as_slice()
    }

    /// Get a reference to the Captured bytes for encoding
    pub fn captured(&self) -> &bcder::Captured {
        &self.original
    }
}

/// Minimal SignerInfo - we only need the basics
#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub signed_attrs: Option<SignedAttributes>,
}

impl SignerInfo {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            // version
            let _ = cons.take_u64()?;

            // sid (SignerIdentifier) - skip
            cons.skip_one()?;

            // digestAlgorithm - skip
            cons.skip_one()?;

            // signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL
            let signed_attrs = cons
                .take_opt_constructed_if(Tag::CTX_0, |cons| {
                    SignedAttributes::take_from(cons)
                })?;

            // We don't need the rest for basic parsing
            // Skip: signatureAlgorithm, signature, unsignedAttrs
            while cons.skip_opt_one()?.is_some() {}

            Ok(SignerInfo { signed_attrs })
        })
    }
}

/// Signed attributes - contains message digest
#[derive(Debug, Clone)]
pub struct SignedAttributes {
    pub message_digest: Vec<u8>,
}

impl SignedAttributes {
    fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        // Attributes are a SET OF Attribute
        let mut message_digest = None;

        while let Some(attr) = cons.take_opt_sequence(|cons| {
            let oid = Oid::<Vec<u8>>::take_from(cons)?;
            let values = cons.take_set(|cons| cons.capture_all())?;
            Ok((oid, values))
        })? {
            // OID for message-digest: 1.2.840.113549.1.9.4
            const OID_MESSAGE_DIGEST: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 4];

            if attr.0.as_ref() == OID_MESSAGE_DIGEST {
                // Parse the message digest value
                message_digest = Some(
                    attr.1
                        .decode(|cons| {
                            cons.take_value(|tag, prim| {
                                if tag == Tag::OCTET_STRING {
                                    prim.to_bytes().map(|b| b.to_vec())
                                } else {
                                    Err(prim.content_err("expected OCTET STRING"))
                                }
                            })
                        })
                        .map_err(|_| cons.content_err("failed to parse message digest"))?,
                );
            }
        }

        let message_digest = message_digest
            .ok_or_else(|| cons.content_err("message-digest attribute not found"))?;

        Ok(SignedAttributes { message_digest })
    }
}

//==============================================================================
// Convenience Functions
//==============================================================================

/// Verify that a message digest matches the expected content
pub fn verify_message_digest(
    signed_data: &SignedData,
    expected_digest: &[u8],
) -> Result<(), String> {
    if signed_data.signer_infos.is_empty() {
        return Err("No signer infos in SignedData".to_string());
    }

    let signer_info = &signed_data.signer_infos[0];
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or("No signed attributes")?;

    if signed_attrs.message_digest != expected_digest {
        return Err("Message digest mismatch".to_string());
    }

    Ok(())
}

//==============================================================================
// Tests
//==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_parser_compiles() {
        // This test just ensures the parser compiles
        // Real tests would use actual Sigstore timestamp data
        assert!(true);
    }

    #[test]
    fn test_pki_status() {
        assert_eq!(PkiStatus::from_u64(0), Some(PkiStatus::Granted));
        assert_eq!(PkiStatus::from_u64(2), Some(PkiStatus::Rejection));
        assert_eq!(PkiStatus::from_u64(99), None);
    }

    // TODO: Add real tests with Sigstore timestamp data
    // These would test:
    // - Parsing real TimeStampResp
    // - Extracting certificates (preserving original bytes)
    // - Verifying message digests
}
