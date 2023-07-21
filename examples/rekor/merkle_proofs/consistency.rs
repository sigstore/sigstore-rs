use clap::Parser;
use sigstore::crypto::CosignVerificationKey;
use sigstore::rekor::apis::configuration::Configuration;
use sigstore::rekor::apis::tlog_api::{get_log_info, get_log_proof};
use std::fs::read_to_string;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, value_name = "REKOR PUBLIC KEY")]
    rekor_key: PathBuf,
    #[arg(long, value_name = "HEX ENCODED HASH")]
    old_root: String,
    #[arg(long)]
    old_size: usize,
    #[arg(long, value_name = "TREE ID")]
    tree_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let tree_id = args.tree_id.as_ref().map(|s| s.as_str());
    // read verification key
    let rekor_key = read_to_string(&args.rekor_key)
        .map_err(Into::into)
        .and_then(|k| CosignVerificationKey::from_pem(k.as_bytes(), &Default::default()))?;

    // fetch log info
    let rekor_config = Configuration::default();
    let log_info = get_log_info(&rekor_config).await?;

    let proof = get_log_proof(
        &rekor_config,
        log_info.tree_size as _,
        Some(&args.old_size.to_string()),
        tree_id,
    )
    .await?;

    log_info
        .verify_consistency(args.old_size, &args.old_root, &proof, &rekor_key)
        .expect("failed to verify log consistency");
    println!("Successfully verified consistency");
    Ok(())
}
