use clap::Parser;
use sigstore::crypto::CosignVerificationKey;
use sigstore::rekor::apis::configuration::Configuration;
use sigstore::rekor::apis::entries_api::get_log_entry_by_index;
use std::fs::read_to_string;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, value_name = "INDEX")]
    log_index: usize,
    #[arg(long, value_name = "REKOR PUBLIC KEY")]
    rekor_key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // read verification key
    let rekor_key = read_to_string(&args.rekor_key)
        .map_err(Into::into)
        .and_then(|k| CosignVerificationKey::from_pem(k.as_bytes(), &Default::default()))?;

    // fetch entry from log
    let rekor_config = Configuration::default();
    let log_entry = get_log_entry_by_index(&rekor_config, args.log_index as i32).await?;

    // verify inclusion with key
    log_entry
        .verify_inclusion(&rekor_key)
        .expect("failed to verify log inclusion");
    println!("Successfully verified inclusion.");
    Ok(())
}
