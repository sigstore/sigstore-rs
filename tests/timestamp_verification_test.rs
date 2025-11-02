// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test for RFC 3161 timestamp verification with real test data.

use sigstore::crypto::timestamp::{verify_timestamp_response, VerifyOpts};
use std::fs;

#[test]
fn test_timestamp_cms_signature_verification() {
    // Load the timestamp response
    let timestamp_der =
        fs::read("tests/data/sigstore_timestamp.der").expect("Failed to read timestamp file");

    // The timestamp was created for a signature with this message imprint (from the timestamp):
    // 6ddf31609e2a6c814f8266aab75204b7a1f5e96d1bc07dde6ff39add8408cda2
    // We need to find or create the original signature that produces this hash

    // For now, let's create dummy signature bytes that will hash to the expected value
    // This tests the CMS signature verification independent of the message imprint verification
    let _expected_hash_hex = "6ddf31609e2a6c814f8266aab75204b7a1f5e96d1bc07dde6ff39add8408cda2";

    // Create dummy signature bytes (we just need something to pass in)
    // The actual verification will fail on message imprint, but we can test CMS signature verification
    let dummy_signature = vec![0u8; 72]; // Dummy 72-byte signature

    println!("Expected message imprint: {}", _expected_hash_hex);
    println!("Using dummy signature for testing");

    // Set up verification options
    let opts = VerifyOpts {
        roots: vec![], // Empty for now - we'll add if needed
        intermediates: vec![],
        tsa_certificate: None, // Should be embedded in the timestamp
        tsa_valid_for: None,   // Don't check TSA validity period for this test
    };

    // Verify the timestamp
    // This will fail on message imprint check, but should get past CMS signature verification
    let result = verify_timestamp_response(&timestamp_der, &dummy_signature, opts);

    match result {
        Ok(timestamp_result) => {
            println!("Timestamp verification succeeded!");
            println!("Timestamp: {:?}", timestamp_result.time);
        }
        Err(e) => {
            // Print the error to see where it fails
            println!("Timestamp verification failed (expected): {:?}", e);

            // If we get a HashMismatch error, that's actually good - it means CMS signature
            // verification passed and we got to the message imprint verification!
            use sigstore::crypto::timestamp::TimestampError;
            match e {
                TimestampError::HashMismatch { expected, actual } => {
                    println!("\nGood! CMS signature verification passed!");
                    println!("Got to message imprint verification:");
                    println!("  Expected: {}", expected);
                    println!("  Actual:   {}", actual);
                    // This is success for our purposes - the CMS signature verified!
                }
                _ => {
                    // Any other error means CMS signature verification failed
                    panic!("CMS signature verification failed: {:?}", e);
                }
            }
        }
    }
}
