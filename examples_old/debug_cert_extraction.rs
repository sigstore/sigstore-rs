/// Debug certificate extraction from CMS SignedData
///
/// This investigates why our Rust extraction differs from Go extraction
use base64::Engine;
use bcder::encode::Values;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Debugging Certificate Extraction ===\n");

    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";
    let bundle_json = std::fs::read_to_string(format!("{}/bundle.sigstore.json", test_dir))?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]
        ["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .ok_or("No timestamp")?;

    let timestamp_der = base64::engine::general_purpose::STANDARD.decode(timestamp_b64)?;
    println!("Timestamp DER: {} bytes\n", timestamp_der.len());

    // Parse using bcder directly to see the raw structure
    use cryptographic_message_syntax::asn1::rfc3161::TimeStampResp;
    use cryptographic_message_syntax::asn1::rfc5652::{OID_ID_SIGNED_DATA, SignedData};

    let tsr = bcder::decode::Constructed::decode(
        timestamp_der.as_ref(),
        bcder::Mode::Der,
        TimeStampResp::take_from,
    )?;

    let tst_token = tsr.time_stamp_token.ok_or("No timestamp token")?;

    if tst_token.content_type != OID_ID_SIGNED_DATA {
        return Err("Invalid content type".into());
    }

    let asn1_signed_data = tst_token.content.clone().decode(SignedData::take_from)?;

    println!("SignedData structure:");
    println!("  Version: {:?}", asn1_signed_data.version);
    println!(
        "  Certificates count: {:?}",
        asn1_signed_data.certificates.as_ref().map(|c| c.len())
    );

    // Extract certificate using the high-level API
    let signed_data = cryptographic_message_syntax::SignedData::try_from(&asn1_signed_data)?;

    println!("\nExtracting certificate using high-level API:");
    for (i, cert) in signed_data.certificates().enumerate() {
        let cert_data = cert.constructed_data();
        println!("  Certificate {}: {} bytes", i, cert_data.len());

        // Save it
        std::fs::write(format!("/tmp/cert_{}_constructed.der", i), cert_data)?;
        println!("  Saved to: /tmp/cert_{}_constructed.der", i);

        // Parse and check signature algorithm
        use x509_cert::{Certificate, der::Decode};
        let cert_from_constructed = Certificate::from_der(cert_data)?;

        println!(
            "  Signature algorithm: {:?}",
            cert_from_constructed.signature_algorithm
        );
        println!(
            "  Public key: {} bytes",
            cert_from_constructed
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
                .len()
        );
    }

    // Now extract directly from the ASN.1 using bcder to see raw bytes
    println!("\n\nDirect ASN.1 extraction:");
    if let Some(ref certs) = asn1_signed_data.certificates {
        println!("Found {} certificates in ASN.1 structure", certs.len());

        for (i, cert_info) in certs.iter().enumerate() {
            // The cert_info is a CertificateChoices which wraps the certificate
            // Let's see if we can get the raw bytes
            println!(
                "  Certificate {}: type = {:?}",
                i,
                std::mem::discriminant(cert_info)
            );

            // Try to extract raw DER by re-encoding the ASN.1
            let mut cert_der = Vec::new();
            cert_info
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut cert_der)?;
            println!("    Raw DER: {} bytes", cert_der.len());

            std::fs::write(format!("/tmp/cert_{}_raw_asn1.der", i), &cert_der)?;
            println!("    Saved to: /tmp/cert_{}_raw_asn1.der", i);
        }
    }

    println!("\n\nComparison:");
    println!("Run: diff /tmp/cert_0_constructed.der /tmp/cert_0_encoded.der");
    println!("And: diff /tmp/cert_0_constructed.der /tmp/cert_0_raw_asn1.der");
    println!("Also compare with: /tmp/sigstore_go_cert.der (from Go extraction)");

    Ok(())
}
