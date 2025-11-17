//! Test RustCrypto CMS certificate preservation
//!
//! This test verifies that the RustCrypto `cms` crate does NOT have the certificate
//! corruption bug that we found in `cryptographic-message-syntax`.
//!
//! The bug manifests as:
//! - Original certificate: 531 bytes (ECDSA without NULL parameters)
//! - Re-encoded certificate: 535 bytes (ECDSA with NULL parameters added)
//!
//! This test uses real Sigstore TSA timestamp data to verify byte-perfect preservation.

use cms::cert::x509::der::{self, Decode, Encode};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

/// Test data: Sigstore TSA timestamp response
const TIMESTAMP_DER: &[u8] = include_bytes!("../tests/data/sigstore_timestamp.der");

/// Test data: Expected TSA certificate (531 bytes, no NULL parameters)
const EXPECTED_CERT_DER: &[u8] = include_bytes!("../tests/data/sigstore_tsa_cert.der");

#[test]
fn test_rustcrypto_cms_preserves_certificate_bytes() {
    println!("\n=== RustCrypto CMS Certificate Preservation Test ===");
    println!("This test verifies that certificates are NOT corrupted during parsing/re-encoding\n");

    // Parse the timestamp response as ContentInfo
    let content_info = ContentInfo::from_der(TIMESTAMP_DER).expect("Failed to parse ContentInfo");

    println!("✓ Parsed ContentInfo");

    // Extract and parse SignedData
    let signed_data_bytes = content_info
        .content
        .to_der()
        .expect("Failed to encode content");

    let signed_data = SignedData::from_der(&signed_data_bytes).expect("Failed to parse SignedData");

    println!("✓ Parsed SignedData");

    // Get certificates
    let certificates = signed_data
        .certificates
        .as_ref()
        .expect("No certificates in SignedData");

    println!("✓ Found {} certificate(s)", certificates.0.len());

    // Get the first certificate
    let cert_choice = certificates.0.iter().next().expect("No certificates found");

    // Extract the Certificate from CertificateChoices
    let cert = match cert_choice {
        cms::cert::CertificateChoices::Certificate(c) => c,
        _ => panic!("Expected Certificate, got other choice"),
    };

    println!("✓ Extracted certificate");

    // Re-encode the certificate
    let re_encoded = cert.to_der().expect("Failed to re-encode certificate");

    println!("\nCertificate size comparison:");
    println!("  Expected (original):  {} bytes", EXPECTED_CERT_DER.len());
    println!("  Re-encoded:           {} bytes", re_encoded.len());

    // CRITICAL TEST: Check if size matches
    if re_encoded.len() == EXPECTED_CERT_DER.len() {
        println!("  ✓ Size matches (no NULL parameters added)");
    } else {
        println!("  ✗ Size mismatch!");
        println!("\nByte difference analysis:");
        println!("  Expected: {} bytes", EXPECTED_CERT_DER.len());
        println!("  Got:      {} bytes", re_encoded.len());
        println!(
            "  Diff:     {} bytes",
            re_encoded.len() as i32 - EXPECTED_CERT_DER.len() as i32
        );

        if re_encoded.len() == 535 && EXPECTED_CERT_DER.len() == 531 {
            println!("\n⚠️  SIGNATURE BUG DETECTED:");
            println!("  This is the SAME bug we found in cryptographic-message-syntax!");
            println!("  NULL parameters (05 00) are being added to ECDSA signature algorithm.");
        }

        panic!("Certificate size mismatch - re-encoding corrupted the certificate");
    }

    // CRITICAL TEST: Check if bytes match exactly
    assert_eq!(
        &re_encoded[..],
        EXPECTED_CERT_DER,
        "\n\nCertificate bytes differ!\n\
         The certificate was corrupted during re-encoding.\n\
         This means RustCrypto cms has the SAME bug as cryptographic-message-syntax.\n\
         \n\
         Likely cause: Re-encoding adds NULL parameters to ECDSA signature algorithm.\n\
         Impact: Invalid certificate signatures, verification failures.\n"
    );

    println!("  ✓ Bytes match exactly (byte-perfect preservation)");
    println!("\n✅ SUCCESS: RustCrypto cms preserves certificate bytes correctly!");
    println!("   Safe to use for Sigstore timestamp validation.");
}

#[test]
fn test_roundtrip_signed_data_with_certificates() {
    println!("\n=== Full SignedData Roundtrip Test ===");

    // Parse original
    let content_info = ContentInfo::from_der(TIMESTAMP_DER).expect("Failed to parse ContentInfo");

    let signed_data_bytes = content_info
        .content
        .to_der()
        .expect("Failed to encode content");

    let signed_data = SignedData::from_der(&signed_data_bytes).expect("Failed to parse SignedData");

    // Re-encode SignedData
    let re_encoded_signed_data = signed_data
        .to_der()
        .expect("Failed to re-encode SignedData");

    println!("SignedData size: {} bytes", re_encoded_signed_data.len());

    // Re-encode full ContentInfo
    let new_content_info = ContentInfo {
        content_type: content_info.content_type,
        content: der::AnyRef::try_from(re_encoded_signed_data.as_slice())
            .expect("Failed to create AnyRef")
            .into(),
    };

    let re_encoded_content_info = new_content_info
        .to_der()
        .expect("Failed to re-encode ContentInfo");

    // Check if roundtrip is byte-perfect
    if re_encoded_content_info == TIMESTAMP_DER {
        println!("✅ Byte-perfect roundtrip (identical to original)");
    } else {
        println!("⚠️  Roundtrip produced different bytes");
        println!("  Original:    {} bytes", TIMESTAMP_DER.len());
        println!("  Re-encoded:  {} bytes", re_encoded_content_info.len());
        println!(
            "  Difference:  {} bytes",
            re_encoded_content_info.len() as i32 - TIMESTAMP_DER.len() as i32
        );

        // This might be okay if only encoding differences (e.g., optional fields, ordering)
        // But we should still verify the certificate itself wasn't corrupted
        println!("  Note: This may be due to encoding differences (e.g., optional fields)");
        println!("        The certificate preservation test is the critical one.");
    }
}

#[test]
fn test_certificate_parses_correctly() {
    println!("\n=== Certificate Parsing Verification ===");

    // Verify the expected certificate parses correctly
    use cms::cert::x509::Certificate;

    let cert = Certificate::from_der(EXPECTED_CERT_DER).expect("Failed to parse certificate");

    println!("✓ Certificate parsed successfully");
    println!("  Subject: {:?}", cert.tbs_certificate().subject());
    println!("  Issuer:  {:?}", cert.tbs_certificate().issuer());

    // Verify re-encoding produces same bytes
    let re_encoded = cert.to_der().expect("Failed to re-encode certificate");

    println!("  Original size:   {} bytes", EXPECTED_CERT_DER.len());
    println!("  Re-encoded size: {} bytes", re_encoded.len());

    assert_eq!(
        &re_encoded[..],
        EXPECTED_CERT_DER,
        "Direct certificate parsing/re-encoding should preserve bytes"
    );

    println!("✓ Direct certificate roundtrip is byte-perfect");
}
