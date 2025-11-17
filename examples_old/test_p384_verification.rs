// Standalone test to verify P-384 ECDSA signature verification

use p384::ecdsa::{
    Signature as P384Signature, VerifyingKey as P384VerifyingKey, signature::Verifier,
};

#[test]
fn test_p384_signature_verification_standalone() {
    // Public key bytes (uncompressed format, 97 bytes)
    let public_key_hex = "04c75bf91771e90fd7a01ee927a41165473ed00510c9bb869e573b7dcc92d163496f9b1d6517b58133673d00df1918f42c983a8794937647fefe4712e4be52f391cd7d20ec77f2dee618611c07b6a050374217f2b2dd14cb48ad17a3fd0080741d";
    let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode public key");

    // Signature (DER-encoded, 102 bytes)
    let signature_hex = "3064022f24d3d3a6ee17bc2a9bf5366498cb7087a5ae607973c9a651f8bd385d0ef006ae952e4a761bccfdd5e24d3a5ad9de1b023100bca2dfcf9f5a80d3d2211fd7dc493a718df133342b0e310e06ae9302608f317bc724371f3c7be32b5f2268fc0864e286";
    let signature_bytes = hex::decode(signature_hex).expect("Failed to decode signature");

    // Message hash (SHA-256 hash of signed_attrs, 32 bytes)
    let message_hex = "308869576321914bb87e9d7c65ff161e59af90bf314e11c68001e449f7e8cbad";
    let message_bytes = hex::decode(message_hex).expect("Failed to decode message");

    println!("Public key len: {}", public_key_bytes.len());
    println!("Signature len: {}", signature_bytes.len());
    println!("Message len: {}", message_bytes.len());

    // Parse the public key
    let verifying_key = P384VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .expect("Failed to parse P-384 public key");

    println!("Successfully parsed P-384 verifying key");

    // Parse the signature
    let signature =
        P384Signature::from_der(&signature_bytes).expect("Failed to parse P-384 signature");

    println!("Successfully parsed P-384 signature");

    // Verify the signature
    let result = verifying_key.verify(&message_bytes, &signature);

    match result {
        Ok(_) => println!("✅ Signature verification SUCCEEDED!"),
        Err(e) => {
            println!("❌ Signature verification FAILED: {:?}", e);
            panic!("Signature verification failed");
        }
    }
}
