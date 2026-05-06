use anyhow::Result;
use sigstore::trust::{TrustRoot, sigstore::SigstoreTrustRoot};

#[tokio::main]
pub async fn main() -> Result<()> {
    let root = SigstoreTrustRoot::new(None).await?;

    let fulcio_certs = root.fulcio_certs()?;
    println!("Fulcio Certificates found: {}", fulcio_certs.len());

    let rekor_keys = root.rekor_keys()?;
    println!("Rekor Public Keys found: {}", rekor_keys.len());

    Ok(())
}
