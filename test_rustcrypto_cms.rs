// Test if RustCrypto's cms crate preserves certificate bytes correctly
//
// This test uses the SAME Sigstore TSA timestamp that exposed the bug in
// cryptographic-message-syntax to verify that RustCrypto's implementation
// doesn't have the same issue.
//
// Run with: cargo run --bin test_rustcrypto_cms

use std::path::Path;

fn main() {
    println!("=== Testing RustCrypto CMS Certificate Preservation ===\n");

    // Path to the RustCrypto formats directory
    let formats_path = Path::new("/Users/wolfv/Programs/sigstore-rs/formats");

    if !formats_path.exists() {
        eprintln!("ERROR: RustCrypto formats directory not found at {:?}", formats_path);
        eprintln!("Please clone it to /Users/wolfv/Programs/sigstore-rs/formats");
        std::process::exit(1);
    }

    println!("Found RustCrypto formats at: {:?}", formats_path);

    // Load test data
    let timestamp_path = Path::new("/tmp/cms-fork/cryptographic-message-syntax/test_data/sigstore_timestamp.der");
    let cert_path = Path::new("/tmp/cms-fork/cryptographic-message-syntax/test_data/sigstore_tsa_cert.der");

    if !timestamp_path.exists() || !cert_path.exists() {
        eprintln!("ERROR: Test data not found");
        eprintln!("Need: {:?}", timestamp_path);
        eprintln!("Need: {:?}", cert_path);
        std::process::exit(1);
    }

    let timestamp_der = std::fs::read(timestamp_path).expect("Failed to read timestamp");
    let expected_cert = std::fs::read(cert_path).expect("Failed to read certificate");

    println!("Loaded test data:");
    println!("  Timestamp: {} bytes", timestamp_der.len());
    println!("  Expected certificate: {} bytes", expected_cert.len());
    println!();

    // TODO: Add actual test using RustCrypto cms crate
    // This requires adding the cms crate as a dependency first

    println!("⚠️  Test not yet implemented");
    println!();
    println!("To implement this test:");
    println!("1. Add to Cargo.toml:");
    println!("   cms = {{ path = \"formats/cms\" }}");
    println!("2. Parse timestamp using cms::content_info::ContentInfo");
    println!("3. Extract SignedData");
    println!("4. Get certificates");
    println!("5. Re-encode first certificate");
    println!("6. Compare with expected_cert");
    println!();
    println!("Expected result:");
    println!("  ✓ If re-encoded cert == expected_cert (531 bytes): SAFE TO USE");
    println!("  ✗ If re-encoded cert != expected_cert (535 bytes): HAS THE BUG");
}
