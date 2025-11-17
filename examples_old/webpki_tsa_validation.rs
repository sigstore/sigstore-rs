/// Standalone reproducer for webpki TSA certificate chain validation issue
///
/// This demonstrates the UnsupportedSignatureAlgorithmContext error when trying
/// to validate a TSA certificate chain using rustls-webpki 0.103.8.
///
/// The certificates use ECDSA-with-SHA384 and appear to be encoded correctly,
/// but webpki fails with an algorithm encoding error.
///
/// To run: cargo run --example webpki_tsa_validation --features verify
use pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage};

// TimeStamping EKU OID: 1.3.6.1.5.5.7.3.8
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

fn main() {
    println!("=== webpki TSA Certificate Chain Validation Reproducer ===\n");

    // Load test certificates from the conformance test bundle
    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";

    println!("Loading trusted root from: {}/trusted_root.json", test_dir);
    println!("Loading bundle from: {}/bundle.sigstore.json\n", test_dir);

    let trusted_root_json = std::fs::read_to_string(format!("{}/trusted_root.json", test_dir))
        .expect("Failed to read trusted_root.json");

    let bundle_json = std::fs::read_to_string(format!("{}/bundle.sigstore.json", test_dir))
        .expect("Failed to read bundle.sigstore.json");

    let trusted_root: serde_json::Value =
        serde_json::from_str(&trusted_root_json).expect("Failed to parse trusted_root.json");

    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).expect("Failed to parse bundle.sigstore.json");

    // Extract TSA certificates from trusted root
    let tsa = &trusted_root["timestampAuthorities"][0];
    let certs = &tsa["certChain"]["certificates"];

    println!(
        "Found {} certificates in TSA cert chain\n",
        certs.as_array().unwrap().len()
    );

    // Certificate 0 is the leaf (sigstore-tsa)
    // Certificate 1 is the root (sigstore-tsa-selfsigned)
    let leaf_b64 = certs[0]["rawBytes"].as_str().unwrap();
    let root_b64 = certs[1]["rawBytes"].as_str().unwrap();

    use base64::Engine;
    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(leaf_b64)
        .expect("Failed to decode leaf cert");
    let root_der = base64::engine::general_purpose::STANDARD
        .decode(root_b64)
        .expect("Failed to decode root cert");

    println!("Leaf certificate: {} bytes", leaf_der.len());
    println!("Root certificate: {} bytes", root_der.len());

    // Parse certificates to show subject/issuer
    use x509_cert::{Certificate, der::Decode};

    let leaf_cert = Certificate::from_der(&leaf_der).expect("Failed to parse leaf cert");
    let root_cert = Certificate::from_der(&root_der).expect("Failed to parse root cert");

    println!("\n--- Leaf Certificate ---");
    println!("Subject: {:?}", leaf_cert.tbs_certificate.subject);
    println!("Issuer: {:?}", leaf_cert.tbs_certificate.issuer);
    println!(
        "Signature Algorithm: {:?}",
        leaf_cert.signature_algorithm.oid
    );

    println!("\n--- Root Certificate ---");
    println!("Subject: {:?}", root_cert.tbs_certificate.subject);
    println!("Issuer: {:?}", root_cert.tbs_certificate.issuer);
    println!(
        "Signature Algorithm: {:?}",
        root_cert.signature_algorithm.oid
    );

    // Also extract the embedded certificate from the bundle's timestamp
    println!("\n--- Extracting Embedded Certificate from Bundle ---");
    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .unwrap();
    let timestamp_der = base64::engine::general_purpose::STANDARD
        .decode(timestamp_b64)
        .expect("Failed to decode timestamp");

    // Parse the CMS SignedData to extract embedded certificate
    use cryptographic_message_syntax::SignedData;
    let signed_data = SignedData::parse_ber(&timestamp_der).expect("Failed to parse SignedData");

    let embedded_certs: Vec<_> = signed_data.certificates().collect();
    println!(
        "Found {} embedded certificate(s) in timestamp",
        embedded_certs.len()
    );

    if !embedded_certs.is_empty() {
        let embedded_cert = &embedded_certs[0];
        let embedded_subject = embedded_cert.subject_name();
        let embedded_issuer = embedded_cert.issuer_name();
        println!("Embedded cert subject: {:?}", embedded_subject);
        println!("Embedded cert issuer: {:?}", embedded_issuer);

        // Extract DER bytes for webpki validation
        let embedded_der = embedded_cert.constructed_data().to_vec();
        println!("Embedded cert size: {} bytes", embedded_der.len());

        // Compare with trusted root leaf cert
        if embedded_der == leaf_der {
            println!("✓ Embedded certificate matches trusted root leaf certificate");
        } else {
            println!("✗ Embedded certificate differs from trusted root leaf certificate");
            println!("  This will be used for validation instead of trusted root leaf");
        }
    }

    println!("\n=== Attempting webpki validation ===\n");

    // Convert to webpki types
    let root_cert_der = CertificateDer::from(root_der.clone());
    let leaf_cert_der = CertificateDer::from(leaf_der.clone());

    // Create trust anchor from root certificate
    println!("Creating trust anchor from root certificate...");
    let trust_anchor = match webpki::anchor_from_trusted_cert(&root_cert_der) {
        Ok(anchor) => {
            println!("✓ Trust anchor created successfully");
            anchor
        }
        Err(e) => {
            println!("✗ Failed to create trust anchor: {:?}", e);
            return;
        }
    };

    // Create EndEntityCert from leaf certificate
    println!("Creating EndEntityCert from leaf certificate...");
    let end_entity_cert = match EndEntityCert::try_from(&leaf_cert_der) {
        Ok(cert) => {
            println!("✓ EndEntityCert created successfully");
            cert
        }
        Err(e) => {
            println!("✗ Failed to create EndEntityCert: {:?}", e);
            return;
        }
    };

    // Attempt to verify the certificate chain
    println!("\nVerifying certificate chain...");
    // Use a time when the certificate is valid (certificate notBefore: 2025-03-28 09:14:06 UTC)
    let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(1749024860)); // 2025-06-12 12:02:20 UTC (corrected)
    let trust_anchors = vec![trust_anchor.to_owned()];

    let result = end_entity_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &trust_anchors,
        &[], // No intermediates - leaf is directly signed by root
        verification_time,
        KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
        None,
        None,
    );

    match result {
        Ok(_) => {
            println!("✓ Certificate chain validation succeeded!");
        }
        Err(e) => {
            println!("✗ Certificate chain validation failed: {:?}", e);
            println!("\nThis is the error we're investigating.");
            println!("Expected: Validation should succeed since the leaf is signed by the root.");
            println!("Actual: {:?}", e);

            // Print additional debug info
            println!("\nDEBUG INFO:");
            println!("- Both certificates use ECDSA-with-SHA384 (OID 1.2.840.10045.4.3.3)");
            println!("- The algorithm is in webpki::ALL_VERIFICATION_ALGS");
            println!("- OpenSSL parses these certificates without issues");
            println!("- The error may be UnsupportedSignatureAlgorithmContext");
            println!("- However, inspection with openssl asn1parse shows standard encoding");
        }
    }

    println!("\n=== Additional Information ===");
    println!("rustls-webpki version: 0.103.8");
    println!("The certificates are from Sigstore's staging TSA");
    println!("They can be inspected with: openssl x509 -inform DER -in <file> -text -noout");
}
