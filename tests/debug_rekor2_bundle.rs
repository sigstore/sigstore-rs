// Test to debug rekor2 bundle verification issues

use std::fs;

#[test]
fn test_rekor2_timestamp_with_embedded_cert() {
    // Load the bundle
    let bundle_path = "sigstore-conformance/test/assets/bundle-verify/rekor2-timestamp-with-embedded-cert/bundle.sigstore.json";
    let bundle_json = fs::read_to_string(bundle_path).expect("Failed to read bundle");

    println!("Bundle loaded successfully");
    println!("Bundle length: {}", bundle_json.len());

    // Parse the JSON
    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).expect("Failed to parse bundle JSON");

    println!("Bundle parsed successfully");

    // Check if it has RFC 3161 timestamps
    if let Some(timestamp_data) = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("timestampVerificationData"))
        .and_then(|tvd| tvd.get("rfc3161Timestamps"))
    {
        if let Some(timestamps) = timestamp_data.as_array() {
            println!("Found {} RFC 3161 timestamp(s)", timestamps.len());

            if let Some(first_ts) = timestamps.get(0) {
                if let Some(signed_ts_b64) =
                    first_ts.get("signedTimestamp").and_then(|v| v.as_str())
                {
                    println!("Found signedTimestamp field");

                    // Decode the timestamp
                    use base64::prelude::*;
                    let timestamp_der = BASE64_STANDARD
                        .decode(signed_ts_b64)
                        .expect("Failed to decode timestamp");

                    println!("Timestamp DER length: {}", timestamp_der.len());
                    println!(
                        "First 32 bytes: {}",
                        hex::encode(&timestamp_der[..32.min(timestamp_der.len())])
                    );

                    // Try to verify it
                    use sigstore::crypto::timestamp::{VerifyOpts, verify_timestamp_response};

                    // We need a signature to verify against - get it from the bundle
                    let signature_b64 = bundle
                        .get("messageSignature")
                        .and_then(|ms| ms.get("signature"))
                        .and_then(|s| s.as_str())
                        .or_else(|| {
                            bundle
                                .get("dsseEnvelope")
                                .and_then(|de| de.get("signatures"))
                                .and_then(|sigs| sigs.as_array())
                                .and_then(|arr| arr.get(0))
                                .and_then(|sig| sig.get("sig"))
                                .and_then(|s| s.as_str())
                        })
                        .expect("Failed to find signature in bundle");

                    let signature_bytes = BASE64_STANDARD
                        .decode(signature_b64)
                        .expect("Failed to decode signature");

                    println!("Signature length: {}", signature_bytes.len());
                    println!("Signature (hex): {}", hex::encode(&signature_bytes));

                    let opts = VerifyOpts {
                        roots: vec![],
                        intermediates: vec![],
                        tsa_certificate: None,
                        tsa_valid_for: None,
                    };

                    println!("\n=== About to verify timestamp ===");
                    println!("Timestamp DER (hex): {}", hex::encode(&timestamp_der));
                    println!("Signature bytes (hex): {}", hex::encode(&signature_bytes));

                    match verify_timestamp_response(&timestamp_der, &signature_bytes, opts) {
                        Ok(result) => {
                            println!("✅ Timestamp verification PASSED!");
                            println!("Timestamp: {:?}", result.time);
                        }
                        Err(e) => {
                            println!("❌ Timestamp verification FAILED: {:?}", e);
                            panic!("Timestamp verification failed: {:?}", e);
                        }
                    }
                }
            }
        }
    } else {
        println!("No RFC 3161 timestamps found in bundle");
    }
}
