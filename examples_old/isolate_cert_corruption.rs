/// Minimal test case to isolate the certificate corruption bug
///
/// This demonstrates that x509-certificate or cryptographic-message-syntax
/// is adding NULL parameters when extracting certificates from CMS.
///
/// Usage: cargo run --example isolate_cert_corruption --features verify
use base64::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Isolating Certificate Corruption Bug ===\n");

    // Load the test bundle
    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";
    let bundle_json = std::fs::read_to_string(format!("{}/bundle.sigstore.json", test_dir))?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]
        ["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .ok_or("No timestamp")?;

    let timestamp_der = base64::engine::general_purpose::STANDARD.decode(timestamp_b64)?;

    // Parse the timestamp to get to SignedData
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

    println!("Test 1: Direct ASN.1 access (should be correct)");
    println!("================================================");

    if let Some(ref certs) = asn1_signed_data.certificates {
        use bcder::encode::Values;

        for (i, cert_choice) in certs.iter().enumerate() {
            // Encode directly from ASN.1 without going through x509-certificate
            let mut raw_der = Vec::new();
            cert_choice
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut raw_der)?;

            println!("Certificate {} (raw ASN.1):", i);
            println!("  Size: {} bytes", raw_der.len());

            std::fs::write("/tmp/cert_raw_asn1.der", &raw_der)?;

            // Check if this has NULL parameter
            let hex: String = raw_der
                .iter()
                .take(48)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  First 48 bytes: {}", hex);

            // Look for the signature algorithm (bytes around offset 0x20)
            if raw_der.len() > 0x30 {
                let sig_alg_area = &raw_der[0x20..0x30];
                let has_null = sig_alg_area.windows(2).any(|w| w == [0x05, 0x00]);
                println!("  Has NULL parameter: {}", has_null);
            }
        }
    }

    println!("\nTest 2: Via x509-certificate crate (may be corrupted)");
    println!("======================================================");

    let signed_data = cryptographic_message_syntax::SignedData::try_from(&asn1_signed_data)?;

    for (i, cert) in signed_data.certificates().enumerate() {
        let cert_data = cert.constructed_data();

        println!("Certificate {} (via x509-certificate):", i);
        println!("  Size: {} bytes", cert_data.len());

        std::fs::write("/tmp/cert_via_x509.der", cert_data)?;

        let hex: String = cert_data
            .iter()
            .take(48)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  First 48 bytes: {}", hex);

        if cert_data.len() > 0x30 {
            let sig_alg_area = &cert_data[0x20..0x30];
            let has_null = sig_alg_area.windows(2).any(|w| w == [0x05, 0x00]);
            println!("  Has NULL parameter: {}", has_null);
        }
    }

    println!("\nTest 3: Comparing the two extractions");
    println!("======================================");

    let raw_asn1 = std::fs::read("/tmp/cert_raw_asn1.der")?;
    let via_x509 = std::fs::read("/tmp/cert_via_x509.der")?;

    if raw_asn1 == via_x509 {
        println!("✓ IDENTICAL - No corruption");
    } else {
        println!("✗ DIFFERENT - Corruption detected!");
        println!("  Raw ASN.1: {} bytes", raw_asn1.len());
        println!("  Via x509:  {} bytes", via_x509.len());
        println!(
            "  Difference: {} bytes",
            (via_x509.len() as i32 - raw_asn1.len() as i32).abs()
        );

        // Find first difference
        let min_len = raw_asn1.len().min(via_x509.len());
        for i in 0..min_len {
            if raw_asn1[i] != via_x509[i] {
                println!("\n  First difference at byte {:#x}:", i);
                println!("    Raw ASN.1: {:02x}", raw_asn1[i]);
                println!("    Via x509:  {:02x}", via_x509[i]);

                // Show context
                let start = i.saturating_sub(8);
                let end = (i + 8).min(min_len);
                print!("    Context (raw):  ");
                for j in start..end {
                    print!("{:02x} ", raw_asn1[j]);
                    if j == i {
                        print!("| ");
                    }
                }
                println!();

                print!("    Context (x509): ");
                for j in start..end {
                    print!("{:02x} ", via_x509[j]);
                    if j == i {
                        print!("| ");
                    }
                }
                println!("\n");
                break;
            }
        }
    }

    println!("\nTest 4: What does CapturedX509Certificate do?");
    println!("==============================================");

    // Try creating a CapturedX509Certificate directly from raw DER
    use x509_certificate::CapturedX509Certificate;

    let raw_asn1 = std::fs::read("/tmp/cert_raw_asn1.der")?;

    // Parse it
    let captured = CapturedX509Certificate::from_der(raw_asn1.clone())?;
    let reconstructed = captured.constructed_data();

    println!("Original size:     {} bytes", raw_asn1.len());
    println!("Reconstructed size: {} bytes", reconstructed.len());

    if raw_asn1 == reconstructed {
        println!("✓ CapturedX509Certificate preserves original bytes");
    } else {
        println!("✗ CapturedX509Certificate modifies the certificate!");
        println!("  This is where the corruption happens!");

        // Find the difference
        let min_len = raw_asn1.len().min(reconstructed.len());
        for i in 0..min_len {
            if raw_asn1[i] != reconstructed[i] {
                println!("\n  First modification at byte {:#x}:", i);
                println!("    Original:      {:02x}", raw_asn1[i]);
                println!("    Reconstructed: {:02x}", reconstructed[i]);
                break;
            }
        }
    }

    println!("\n=== CONCLUSION ===");
    println!("Check the output above to see where corruption occurs:");
    println!("1. If Test 1 shows NO NULL but Test 2 shows NULL:");
    println!("   → Bug is in cryptographic-message-syntax SignedData conversion");
    println!("2. If both Tests 1 and 2 show NULL:");
    println!("   → Check Test 4 - if CapturedX509Certificate modifies it,");
    println!("     the bug is in x509-certificate crate");
    println!("3. If all tests show NO NULL:");
    println!("   → The corruption happens elsewhere in our code");

    Ok(())
}
