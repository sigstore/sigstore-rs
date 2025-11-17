/// Minimal test case for webpki upstream issue/PR
///
/// This demonstrates the NULL parameter issue with real-world certificates
/// from the Sigstore ecosystem. Can be used as a test case for a webpki PR.
///
/// Usage: cargo run --example webpki_upstream_test --features verify
use pki_types::{CertificateDer, UnixTime};
use std::time::Duration;

const ID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== webpki NULL Parameter Test Case ===\n");
    println!("Issue: webpki rejects ECDSA certificates with NULL parameters");
    println!("       even though RFC 5480 allows them (though discourages)\n");

    // These are real certificates from the Sigstore staging ecosystem
    let test_dir = "sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path";

    // Load bundle and extract embedded certificate
    let bundle_json = std::fs::read_to_string(format!("{}/bundle.sigstore.json", test_dir))?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json)?;

    let timestamp_b64 = bundle["verificationMaterial"]["timestampVerificationData"]
        ["rfc3161Timestamps"][0]["signedTimestamp"]
        .as_str()
        .ok_or("No timestamp in bundle")?;

    use base64::Engine;
    let timestamp_der = base64::engine::general_purpose::STANDARD.decode(timestamp_b64)?;

    // Extract the embedded certificate from CMS SignedData
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
    let signed_data = cryptographic_message_syntax::SignedData::try_from(&asn1_signed_data)?;

    let cert_with_null = signed_data
        .certificates()
        .next()
        .map(|c| c.constructed_data().to_vec())
        .ok_or("No embedded cert")?;

    // Load the root certificate
    let trusted_root_json = std::fs::read_to_string(format!("{}/trusted_root.json", test_dir))?;
    let trusted_root: serde_json::Value = serde_json::from_str(&trusted_root_json)?;

    let root_b64 =
        trusted_root["timestampAuthorities"][0]["certChain"]["certificates"][1]["rawBytes"]
            .as_str()
            .ok_or("No root cert")?;
    let root_der = base64::engine::general_purpose::STANDARD.decode(root_b64)?;

    println!("Test Setup:");
    println!("  Root cert: {} bytes", root_der.len());
    println!(
        "  Leaf cert: {} bytes (has NULL parameter in signature algorithm)",
        cert_with_null.len()
    );

    // Parse both certs to show the encoding difference
    use x509_cert::{Certificate, der::Decode};
    let leaf_cert = Certificate::from_der(&cert_with_null)?;

    println!("\nLeaf Certificate Details:");
    println!("  Subject: {:?}", leaf_cert.tbs_certificate.subject);
    println!(
        "  Signature Algorithm OID: {}",
        leaf_cert.signature_algorithm.oid
    );
    println!(
        "  Parameters: {:?}",
        leaf_cert.signature_algorithm.parameters
    );
    println!("  ^ This 'Some(NULL)' is the problem!");

    // Attempt validation
    println!("\nAttempting webpki validation...");

    let root_cert_der = CertificateDer::from(root_der);
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert_der)?;

    let leaf_cert_der = CertificateDer::from(cert_with_null.as_slice());
    let end_entity_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)?;

    let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(1749024860));

    let result = end_entity_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor.to_owned()],
        &[],
        verification_time,
        webpki::KeyUsage::required_if_present(ID_KP_TIME_STAMPING),
        None,
        None,
    );

    match result {
        Ok(_) => {
            println!("\n✓ SUCCESS!");
            println!("\nIf this succeeds, the NULL parameter issue has been fixed in webpki!");
        }
        Err(webpki::Error::UnsupportedSignatureAlgorithmContext(ctx)) => {
            println!("\n✗ FAILED as expected");
            println!("\nError Details:");
            println!("  {:#?}", ctx);

            println!("\nSignature Algorithm Encoding:");
            println!("  {:02x?}", ctx.signature_algorithm_id);
            println!("\nBreakdown:");
            println!(
                "  06 08 2a 86 48 ce 3d 04 03 03  <- OID: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)"
            );
            println!("  05 00                          <- NULL parameter");

            println!("\nRFC 5480 Section 2.1.1 says:");
            println!("  \"The parameters field is OPTIONAL and SHOULD be absent\"");
            println!("  However, it does NOT forbid NULL - it's valid ASN.1");

            println!("\nReal-world impact:");
            println!("  - Prevents validation of Sigstore TSA certificates");
            println!("  - Blocks full X.509 chain validation in sigstore-rs");
            println!("  - Other implementations (OpenSSL, Go crypto/x509) accept this");

            println!("\nProposed fix:");
            println!("  Accept both encodings: with and without NULL parameter");
            println!("  - Without NULL: 06 08 2a 86 48 ce 3d 04 03 03");
            println!("  - With NULL:    06 08 2a 86 48 ce 3d 04 03 03 05 00");

            return Err("webpki rejects NULL parameter in ECDSA signature algorithm".into());
        }
        Err(e) => {
            println!("\n✗ FAILED with unexpected error: {:?}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
