// Test to parse the failing timestamp with x509-tsp crate
use std::path::Path;
use std::fs;

fn main() {
    // Load the failing timestamp
    let failing_path = Path::new("/tmp/failing_bundles/timestamp_20251110_074233.der");
    let working_path = Path::new("/tmp/failing_bundles/working_timestamp.der");

    println!("=== Testing with x509-tsp crate ===\n");

    if failing_path.exists() {
        println!("Testing FAILING timestamp:");
        let bytes = fs::read(failing_path).unwrap();
        println!("  Size: {} bytes", bytes.len());

        match x509_tsp::TimeStampResp::from_der(&bytes) {
            Ok(tsr) => {
                println!("  ✓ Parsed TimeStampResp");
                println!("    Status: {:?}", tsr.status.status);

                if let Some(ref token) = tsr.time_stamp_token {
                    println!("    ✓ Has TimeStampToken");

                    // Try to extract the TSTInfo
                    // This is where Python might be failing
                    match extract_tst_info(token) {
                        Ok(()) => println!("    ✓ Successfully extracted TSTInfo"),
                        Err(e) => println!("    ✗ Failed to extract TSTInfo: {}", e),
                    }
                } else {
                    println!("    ✗ No TimeStampToken");
                }
            }
            Err(e) => {
                println!("  ✗ Failed to parse: {:?}", e);
            }
        }
    } else {
        println!("Failing timestamp not found at {:?}", failing_path);
    }

    println!();

    if working_path.exists() {
        println!("Testing WORKING timestamp:");
        let bytes = fs::read(working_path).unwrap();
        println!("  Size: {} bytes", bytes.len());

        match x509_tsp::TimeStampResp::from_der(&bytes) {
            Ok(tsr) => {
                println!("  ✓ Parsed TimeStampResp");
                println!("    Status: {:?}", tsr.status.status);

                if let Some(ref token) = tsr.time_stamp_token {
                    println!("    ✓ Has TimeStampToken");

                    match extract_tst_info(token) {
                        Ok(()) => println!("    ✓ Successfully extracted TSTInfo"),
                        Err(e) => println!("    ✗ Failed to extract TSTInfo: {}", e),
                    }
                } else {
                    println!("    ✗ No TimeStampToken");
                }
            }
            Err(e) => {
                println!("  ✗ Failed to parse: {:?}", e);
            }
        }
    } else {
        println!("Working timestamp not found at {:?}", working_path);
    }
}

fn extract_tst_info(token: &x509_cert::der::asn1::OctetString) -> Result<(), Box<dyn std::error::Error>> {
    // The token is the ContentInfo containing SignedData
    use x509_cert::der::Decode;

    let content_info = cms::content_info::ContentInfo::from_der(token.as_bytes())?;

    // Verify it's SignedData
    if content_info.content_type != cms::content_info::ID_SIGNED_DATA {
        return Err("Not SignedData".into());
    }

    // Parse the SignedData
    let signed_data = cms::signed_data::SignedData::from_der(content_info.content.to_der()?.as_slice())?;

    println!("      SignedData version: {:?}", signed_data.version);
    println!("      Digest algorithms: {}", signed_data.digest_algorithms.len());
    println!("      Encap content type: {}", signed_data.encap_content_info.econtent_type);

    // Try to extract the TSTInfo from encapsulated content
    if let Some(ref content) = signed_data.encap_content_info.econtent {
        println!("      Encap content size: {} bytes", content.as_bytes().len());

        // Parse as TSTInfo
        match x509_tsp::TstInfo::from_der(content.as_bytes()) {
            Ok(tst_info) => {
                println!("      ✓ Parsed TSTInfo");
                println!("        Version: {:?}", tst_info.version);
                println!("        Serial: {} bytes", tst_info.serial_number.as_bytes().len());
            }
            Err(e) => {
                println!("      ✗ Failed to parse TSTInfo: {:?}", e);
                return Err(Box::new(e));
            }
        }
    }

    Ok(())
}
