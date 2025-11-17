/// Demonstration of the webpki NULL parameter issue with TSA certificates
///
/// This test extracts certificates from both the CMS SignedData (embedded)
/// and the trusted root, then compares their DER encoding to identify the
/// exact difference that causes webpki to reject the embedded certificate.
///
/// Usage: cargo run --example webpki_issue_demo --features verify
use pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage};

// TimeStamping EKU OID: 1.3.6.1.5.5.7.3.8
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== webpki NULL Parameter Issue Demonstration ===\n");

    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";

    // Part 1: Extract embedded certificate from CMS SignedData
    println!("Part 1: Extracting embedded certificate from CMS SignedData");
    println!("------------------------------------------------------------");

    let bundle_json = std::fs::read_to_string(format!("{}/bundle.sigstore.json", test_dir))?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .expect("Failed to find timestamp");

    use base64::Engine;
    let timestamp_der = base64::engine::general_purpose::STANDARD.decode(timestamp_b64)?;

    // Parse the timestamp response
    use cryptographic_message_syntax::asn1::rfc3161::TimeStampResp;
    let tsr = bcder::decode::Constructed::decode(
        timestamp_der.as_ref(),
        bcder::Mode::Der,
        TimeStampResp::take_from,
    )
    .map_err(|e| format!("Failed to decode TimeStampResp: {}", e))?;

    // Extract SignedData
    use cryptographic_message_syntax::asn1::rfc5652::{OID_ID_SIGNED_DATA, SignedData};
    let tst_token = tsr.time_stamp_token.ok_or("No timestamp token")?;

    if tst_token.content_type != OID_ID_SIGNED_DATA {
        return Err("Invalid OID on signed data".into());
    }

    let asn1_signed_data = tst_token
        .content
        .clone()
        .decode(SignedData::take_from)
        .map_err(|e| format!("Failed to decode SignedData: {}", e))?;

    let signed_data = cryptographic_message_syntax::SignedData::try_from(&asn1_signed_data)
        .map_err(|e| format!("Failed to parse SignedData: {}", e))?;

    let embedded_cert_der = signed_data
        .certificates()
        .next()
        .map(|cert| cert.constructed_data().to_vec())
        .ok_or("No embedded certificate")?;

    println!(
        "✓ Extracted embedded certificate: {} bytes",
        embedded_cert_der.len()
    );

    // Write to file for inspection
    std::fs::write("/tmp/embedded_cert.der", &embedded_cert_der)?;
    println!("  Saved to: /tmp/embedded_cert.der");

    // Part 2: Extract certificate from trusted root
    println!("\nPart 2: Extracting certificate from trusted root");
    println!("------------------------------------------------------------");

    let trusted_root_json = std::fs::read_to_string(format!("{}/trusted_root.json", test_dir))?;
    let trusted_root: serde_json::Value = serde_json::from_str(&trusted_root_json)?;

    let tsa = &trusted_root["timestampAuthorities"][0];
    let certs = &tsa["certChain"]["certificates"];

    // Get the leaf certificate (index 0)
    let leaf_b64 = certs[0]["rawBytes"].as_str().unwrap();
    let trusted_leaf_der = base64::engine::general_purpose::STANDARD.decode(leaf_b64)?;

    // Get the root certificate (index 1)
    let root_b64 = certs[1]["rawBytes"].as_str().unwrap();
    let root_der = base64::engine::general_purpose::STANDARD.decode(root_b64)?;

    println!(
        "✓ Extracted leaf from trusted root: {} bytes",
        trusted_leaf_der.len()
    );
    println!("✓ Extracted root certificate: {} bytes", root_der.len());

    std::fs::write("/tmp/trusted_leaf_cert.der", &trusted_leaf_der)?;
    std::fs::write("/tmp/trusted_root_cert.der", &root_der)?;
    println!("  Saved leaf to: /tmp/trusted_leaf_cert.der");
    println!("  Saved root to: /tmp/trusted_root_cert.der");

    // Part 3: Compare the certificates
    println!("\nPart 3: Comparing certificates");
    println!("------------------------------------------------------------");

    use x509_cert::{Certificate, der::Decode};
    let embedded_cert = Certificate::from_der(&embedded_cert_der)?;
    let trusted_leaf = Certificate::from_der(&trusted_leaf_der)?;

    println!("Embedded cert signature algorithm:");
    println!("  OID: {:?}", embedded_cert.signature_algorithm.oid);
    println!(
        "  Parameters: {:?}",
        embedded_cert.signature_algorithm.parameters
    );

    println!("\nTrusted leaf cert signature algorithm:");
    println!("  OID: {:?}", trusted_leaf.signature_algorithm.oid);
    println!(
        "  Parameters: {:?}",
        trusted_leaf.signature_algorithm.parameters
    );

    // Compare exact bytes
    if embedded_cert_der == trusted_leaf_der {
        println!("\n✓ Certificates are byte-for-byte identical!");
    } else {
        println!("\n✗ Certificates differ!");
        println!(
            "  Size difference: {} vs {} bytes",
            embedded_cert_der.len(),
            trusted_leaf_der.len()
        );

        // Find where they differ
        let min_len = embedded_cert_der.len().min(trusted_leaf_der.len());
        for i in 0..min_len {
            if embedded_cert_der[i] != trusted_leaf_der[i] {
                println!(
                    "  First difference at byte {}: 0x{:02x} vs 0x{:02x}",
                    i, embedded_cert_der[i], trusted_leaf_der[i]
                );
                println!(
                    "  Context (embedded): {:02x?}",
                    &embedded_cert_der
                        [i.saturating_sub(5)..=(i + 5).min(embedded_cert_der.len() - 1)]
                );
                println!(
                    "  Context (trusted):  {:02x?}",
                    &trusted_leaf_der
                        [i.saturating_sub(5)..=(i + 5).min(trusted_leaf_der.len() - 1)]
                );
                break;
            }
        }
    }

    // Part 4: Test webpki validation with both certificates
    println!("\nPart 4: Testing webpki validation");
    println!("------------------------------------------------------------");

    let root_cert_der = CertificateDer::from(root_der);
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert_der)?;
    let trust_anchors = vec![trust_anchor.to_owned()];
    let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(1749024860));

    // Test 1: Validate trusted leaf (from trusted root JSON)
    println!("\nTest 1: Validating certificate from trusted root JSON");
    let trusted_cert_der_ref = CertificateDer::from(trusted_leaf_der.as_slice());
    let trusted_end_entity = EndEntityCert::try_from(&trusted_cert_der_ref)?;

    match trusted_end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &trust_anchors,
        &[],
        verification_time,
        KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
        None,
        None,
    ) {
        Ok(_) => println!("  ✓ SUCCESS - Certificate from trusted root validates"),
        Err(e) => println!("  ✗ FAILED - {:?}", e),
    }

    // Test 2: Validate embedded certificate (from CMS SignedData)
    println!("\nTest 2: Validating embedded certificate from CMS SignedData");
    let embedded_cert_der_ref = CertificateDer::from(embedded_cert_der.as_slice());
    let embedded_end_entity = EndEntityCert::try_from(&embedded_cert_der_ref)?;

    match embedded_end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &trust_anchors,
        &[],
        verification_time,
        KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
        None,
        None,
    ) {
        Ok(_) => println!("  ✓ SUCCESS - Embedded certificate validates"),
        Err(webpki::Error::UnsupportedSignatureAlgorithmContext(ctx)) => {
            println!("  ✗ FAILED - UnsupportedSignatureAlgorithmContext");
            println!(
                "\n  The embedded certificate has a NULL parameter in its signature algorithm:"
            );
            println!("  Raw bytes: {:02x?}", ctx.signature_algorithm_id);
            println!("\n  Breaking down the encoding:");
            println!("    06 08 2a 86 48 ce 3d 04 03 03  <- OID for ECDSA-with-SHA384");
            println!("    05 00                          <- NULL parameter (THIS IS THE PROBLEM!)");
            println!("\n  webpki expects ECDSA algorithms WITHOUT the NULL parameter.");
            println!(
                "  The supported algorithms list contains: 0x06082a8648ce3d040303 (without NULL)"
            );
            println!("\n  This is technically valid ASN.1 (RFC 5480 allows NULL parameters),");
            println!("  but webpki's implementation requires strict encoding without NULL.");
        }
        Err(e) => println!("  ✗ FAILED - {:?}", e),
    }

    // Part 5: Analysis and recommendations
    println!("\n\n=== ANALYSIS ===");
    println!("------------------------------------------------------------");
    println!("\n1. THE ISSUE:");
    println!("   - The embedded certificate in the CMS SignedData has ECDSA-SHA384");
    println!("     encoded with NULL parameters (05 00)");
    println!("   - webpki expects ECDSA algorithms without NULL parameters");
    println!("   - This causes UnsupportedSignatureAlgorithmContext error");
    println!("\n2. WHY IT HAPPENS:");
    println!("   - RFC 5480 says ECDSA parameters 'SHOULD be absent' but allows NULL");
    println!("   - Some certificate generation tools include the NULL parameter");
    println!("   - webpki enforces strict encoding (no NULL allowed)");
    println!("\n3. SECURITY IMPLICATIONS OF CURRENT WORKAROUND:");
    println!("   - Current code validates embedded cert identity (subject/issuer/serial)");
    println!("     against trusted TSA certificate - this prevents untrusted TSAs");
    println!("   - CMS signature verification ensures cryptographic integrity");
    println!("   - Validity period checks ensure cert and timestamp are not expired");
    println!("   - MISSING: Full X.509 chain validation to root CA");
    println!("   - RISK: If embedded cert is revoked, we won't detect it");
    println!("   - RISK: If intermediate CAs have constraints, we don't check them");
    println!("\n4. RECOMMENDED SOLUTIONS:");
    println!("   A. Fix webpki upstream:");
    println!("      - Submit PR to webpki to accept both encodings");
    println!("      - This is the most secure long-term solution");
    println!("   B. Use OpenSSL for chain validation (feature flag):");
    println!("      - Add openssl-sys dependency behind feature flag");
    println!("      - More permissive with encoding, full chain validation");
    println!("      - Downside: Adds C dependency");
    println!("   C. Use rustls-native-certs or similar:");
    println!("      - Other Rust TLS libraries might be more permissive");
    println!("   D. Accept current risk:");
    println!("      - If conformance suite passes, other implementations may have same limitation");
    println!("      - Document the limitation clearly");
    println!("      - Add tracking issue to re-enable when webpki fixed");

    println!("\n\nRun 'openssl x509 -in /tmp/embedded_cert.der -inform DER -text -noout'");
    println!("to inspect the certificate details.");

    Ok(())
}
