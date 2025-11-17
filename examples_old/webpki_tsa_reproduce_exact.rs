/// Exact reproducer for webpki TSA certificate chain validation issue
///
/// This example replicates EXACTLY how the production code validates TSA certificates,
/// including extracting the embedded certificate from the CMS SignedData structure.
///
/// Usage:
///   cargo run --example webpki_tsa_reproduce_exact --features verify -- \
///     --bundle sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
///     --trusted-root sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json
///
/// This should reproduce the UnsupportedSignatureAlgorithmContext error we see in production.
use pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage};

// TimeStamping EKU OID: 1.3.6.1.5.5.7.3.8
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse command line arguments
    let mut bundle_path = None;
    let mut trusted_root_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                bundle_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--trusted-root" => {
                trusted_root_path = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let bundle_path = bundle_path.expect("--bundle required");
    let trusted_root_path = trusted_root_path.expect("--trusted-root required");

    println!("=== Exact TSA Certificate Chain Validation Reproducer ===\n");
    println!("Bundle: {}", bundle_path);
    println!("Trusted Root: {}\n", trusted_root_path);

    // Step 1: Load the bundle and extract the timestamp
    println!("Step 1: Loading bundle and extracting timestamp...");
    let bundle_json = std::fs::read_to_string(&bundle_path)?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .expect("Failed to find timestamp in bundle");

    use base64::Engine;
    let timestamp_der = base64::engine::general_purpose::STANDARD.decode(timestamp_b64)?;
    println!("  ✓ Extracted timestamp: {} bytes", timestamp_der.len());

    // Step 2: Parse the TimeStampResponse first (exactly like production code)
    println!("\nStep 2: Parsing RFC 3161 TimeStampResponse...");
    use cryptographic_message_syntax::asn1::rfc3161::TimeStampResp;

    let tsr = bcder::decode::Constructed::decode(
        timestamp_der.as_ref(),
        bcder::Mode::Der,
        TimeStampResp::take_from,
    )
    .map_err(|e| format!("Failed to decode TimeStampResp: {}", e))?;
    println!("  ✓ Parsed TimeStampResp");

    // Step 3: Extract SignedData from the timestamp token
    println!("\nStep 3: Extracting SignedData from timestamp token...");
    let tst_token = tsr
        .time_stamp_token
        .ok_or("No time stamp token in response")?;

    // First decode the ASN.1 structure
    use cryptographic_message_syntax::asn1::rfc5652::{OID_ID_SIGNED_DATA, SignedData};
    if tst_token.content_type != OID_ID_SIGNED_DATA {
        return Err("Invalid OID on signed data".into());
    }
    let asn1_signed_data = tst_token
        .content
        .clone()
        .decode(SignedData::take_from)
        .map_err(|e| format!("Failed to decode SignedData: {}", e))?;

    // Then convert to high-level type
    let signed_data = cryptographic_message_syntax::SignedData::try_from(&asn1_signed_data)
        .map_err(|e| format!("Failed to parse SignedData: {}", e))?;
    println!("  ✓ Parsed SignedData");

    // Step 4: Extract embedded certificates (exactly like production code)
    println!("\nStep 4: Extracting embedded certificate from SignedData...");
    let cert_count = signed_data.certificates().count();
    println!("  Found {} embedded certificate(s)", cert_count);

    let embedded_cert_der = if cert_count > 0 {
        let cert = signed_data.certificates().next().unwrap();
        let cert_der = cert.constructed_data().to_vec();
        println!(
            "  ✓ Extracted embedded certificate: {} bytes",
            cert_der.len()
        );

        // Show certificate info
        use x509_cert::{Certificate, der::Decode};
        if let Ok(cert_parsed) = Certificate::from_der(&cert_der) {
            println!("    Subject: {:?}", cert_parsed.tbs_certificate.subject);
            println!("    Issuer: {:?}", cert_parsed.tbs_certificate.issuer);
            println!(
                "    Signature Algorithm: {:?}",
                cert_parsed.signature_algorithm.oid
            );
        }

        Some(cert_der)
    } else {
        println!("  (No embedded certificates - would use external TSA cert)");
        None
    };

    // Step 5: Load trusted root and extract TSA root certificates
    println!("\nStep 5: Loading trusted root and extracting TSA root certificates...");
    let trusted_root_json = std::fs::read_to_string(&trusted_root_path)?;
    let trusted_root: serde_json::Value = serde_json::from_str(&trusted_root_json)?;

    let tsa = &trusted_root["timestampAuthorities"][0];
    let certs = &tsa["certChain"]["certificates"];

    println!(
        "  Found {} certificates in TSA cert chain",
        certs.as_array().unwrap().len()
    );

    // Extract the ROOT certificate (last in chain) - this is what production code does
    let root_b64 = certs[certs.as_array().unwrap().len() - 1]["rawBytes"]
        .as_str()
        .expect("Failed to get root cert");
    let root_der = base64::engine::general_purpose::STANDARD.decode(root_b64)?;
    println!(
        "  ✓ Extracted TSA root certificate: {} bytes",
        root_der.len()
    );

    use x509_cert::{Certificate, der::Decode};
    let root_cert = Certificate::from_der(&root_der)?;
    println!("    Subject: {:?}", root_cert.tbs_certificate.subject);
    println!(
        "    Signature Algorithm: {:?}",
        root_cert.signature_algorithm.oid
    );

    // Step 6: Create trust anchor from root certificate
    println!("\nStep 6: Creating trust anchor from TSA root certificate...");
    let root_cert_der = CertificateDer::from(root_der);
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert_der)
        .map_err(|e| format!("Failed to create trust anchor: {:?}", e))?;
    let trust_anchors = vec![trust_anchor.to_owned()];
    println!("  ✓ Created trust anchor");

    // Step 7: Validate the embedded certificate (if present)
    if let Some(cert_der) = embedded_cert_der {
        println!("\nStep 7: Validating embedded certificate against trust anchor...");

        let cert_der_ref = CertificateDer::from(cert_der.as_slice());
        let end_entity_cert = EndEntityCert::try_from(&cert_der_ref)
            .map_err(|e| format!("Failed to create EndEntityCert: {:?}", e))?;
        println!("  ✓ Created EndEntityCert");

        // Use a verification time from 2025
        let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(1749024860));
        println!("  Using verification time: {:?}", verification_time);

        println!("\n  Attempting webpki validation...");
        let result = end_entity_cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[], // No intermediates for this test
            verification_time,
            KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
            None,
            None,
        );

        match result {
            Ok(_) => {
                println!("  ✓ Certificate chain validation SUCCEEDED!");
                println!("\n=== SUCCESS ===");
                println!("The embedded certificate validates correctly.");
            }
            Err(e) => {
                println!("  ✗ Certificate chain validation FAILED!");
                println!("\n=== ERROR ===");
                println!("Error: {:?}", e);
                println!("\nThis is the error we need to fix.");
                println!("\nDetails:");
                println!("- Embedded certificate: extracted from CMS SignedData");
                println!("- Trust anchor: extracted from trusted root (last cert in chain)");
                println!("- Algorithm: ECDSA-with-SHA384");

                if let webpki::Error::UnsupportedSignatureAlgorithmContext(_) = e {
                    println!("\nThe error is UnsupportedSignatureAlgorithm.");
                    println!("This suggests an encoding issue with the signature algorithm.");
                }

                return Err(format!("Validation failed: {:?}", e).into());
            }
        }
    } else {
        println!("\nStep 7: Skipped (no embedded certificate)");
    }

    Ok(())
}
