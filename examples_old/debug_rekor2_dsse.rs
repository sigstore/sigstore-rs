// Debug test for rekor2-dsse-happy-path conformance test

use serde_json::Value;
use std::fs;

#[test]
fn test_rekor2_dsse_happy_path() {
    // Load the bundle
    let bundle_path = "sigstore-conformance/test/assets/bundle-verify/rekor2-dsse-happy-path/bundle.sigstore.json";
    let bundle_json = fs::read_to_string(bundle_path).expect("Failed to read bundle");

    println!("Bundle loaded successfully");

    // Parse the JSON
    let bundle: Value = serde_json::from_str(&bundle_json).expect("Failed to parse bundle JSON");

    // Check the DSSE envelope
    if let Some(dsse) = bundle.get("dsseEnvelope") {
        println!("Found DSSE envelope");

        // Decode the payload
        if let Some(payload_b64) = dsse.get("payload").and_then(|v| v.as_str()) {
            use base64::prelude::*;
            let payload_bytes = BASE64_STANDARD
                .decode(payload_b64)
                .expect("Failed to decode payload");
            let payload_json: Value =
                serde_json::from_slice(&payload_bytes).expect("Failed to parse payload JSON");

            println!(
                "Payload: {}",
                serde_json::to_string_pretty(&payload_json).unwrap()
            );

            // Check the subject digest
            if let Some(subject) = payload_json
                .get("subject")
                .and_then(|s| s.as_array())
                .and_then(|a| a.get(0))
            {
                if let Some(digest) = subject
                    .get("digest")
                    .and_then(|d| d.get("sha256"))
                    .and_then(|v| v.as_str())
                {
                    println!("Subject digest: {}", digest);

                    // The conformance test expects this digest
                    let expected_digest =
                        "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf";
                    assert_eq!(digest, expected_digest, "Digest mismatch!");
                    println!("✅ Digest matches expected value");
                }
            }
        }
    }

    // Check if there's a timestamp
    if let Some(timestamp_data) = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("timestampVerificationData"))
        .and_then(|tvd| tvd.get("rfc3161Timestamps"))
    {
        if let Some(timestamps) = timestamp_data.as_array() {
            println!("Found {} RFC 3161 timestamp(s)", timestamps.len());
        }
    }
}
