/// Simple standalone reproducer for webpki TSA certificate chain validation
///
/// This demonstrates validating a TSA certificate chain using rustls-webpki 0.103.8.
///
/// The test shows that basic validation WORKS with the current setup, which means
/// the UnsupportedSignatureAlgorithmContext error we saw earlier was likely due to
/// a different issue (possibly related to how CertificatePool was being used).
///
/// To run: cargo run --example webpki_tsa_simple --features verify
use pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage};

// TimeStamping EKU OID: 1.3.6.1.5.5.7.3.8
const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

fn main() {
    println!("=== webpki TSA Certificate Chain Validation Test ===\n");

    // Load test certificates from the conformance test bundle
    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";

    let trusted_root_json = std::fs::read_to_string(format!("{}/trusted_root.json", test_dir))
        .expect("Failed to read trusted_root.json");

    let trusted_root: serde_json::Value =
        serde_json::from_str(&trusted_root_json).expect("Failed to parse trusted_root.json");

    // Extract TSA certificates from trusted root
    let tsa = &trusted_root["timestampAuthorities"][0];
    let certs = &tsa["certChain"]["certificates"];

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

    println!("Loaded leaf certificate: {} bytes", leaf_der.len());
    println!("Loaded root certificate: {} bytes", root_der.len());

    // Convert to webpki types
    let root_cert_der = CertificateDer::from(root_der);
    let leaf_cert_der = CertificateDer::from(leaf_der);

    // Create trust anchor from root certificate
    println!("\nCreating trust anchor from root certificate...");
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_cert_der).expect("Failed to create trust anchor");

    // Create EndEntityCert from leaf certificate
    println!("Creating EndEntityCert from leaf certificate...");
    let end_entity_cert =
        EndEntityCert::try_from(&leaf_cert_der).expect("Failed to create EndEntityCert");

    // Verify the certificate chain
    println!("\nAttempting webpki validation...");
    // Use a time when the certificate is valid (2025-06-12 12:02:20 UTC)
    let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(1749024860));
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
            println!("✓ Certificate chain validation SUCCEEDED!");
            println!("\nThis shows that webpki CAN validate the TSA certificate chain.");
            println!("The UnsupportedSignatureAlgorithmContext error seen earlier was likely");
            println!("caused by a different issue, possibly in how we were using CertificatePool.");
        }
        Err(e) => {
            println!("✗ Certificate chain validation FAILED: {:?}", e);
            println!("\nPlease share this error with your expert friend:");
            println!("- rustls-webpki version: 0.103.8");
            println!("- Certificate algorithm: ECDSA-with-SHA384 (OID 1.2.840.10045.4.3.3)");
            println!("- Test files: {}/", test_dir);
        }
    }
}
