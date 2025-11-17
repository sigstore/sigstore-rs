use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig;

fn main() {
    let config_data = std::fs::read("../../tests/data/signing_config.v0.2.json")
        .expect("failed to read");
    let config: SigningConfig = serde_json::from_slice(&config_data)
        .expect("failed to parse");
    
    println!("media_type: {}", config.media_type);
    println!("ca_urls count: {}", config.ca_urls.len());
    println!("oidc_urls count: {}", config.oidc_urls.len());
    
    // Try to print all fields
    println!("Debug: {:?}", config);
}
