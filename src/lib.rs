//! This is an experimental crate to interact with [sigstore](https://sigstore.dev/).
//!
//! This is under high development, many features and probably checks are still missing.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use oci_distribution::{secrets::RegistryAuth, Reference};

mod mock_client;

#[cfg(test)]
use mock_client::test::MockOciClient as Client;
#[cfg(not(test))]
use oci_distribution::client::Client;

mod crypto;
use crate::crypto::{new_verification_key, verify_layers};

mod distribution;
use distribution::{image_signature_layers, image_signatures};

pub mod simple_signing;
use simple_signing::SimpleSigning;

/// Calculate the cosign image reference.
/// This is the location cosign stores signatures.
pub async fn triangulate(
    client: &mut Client,
    image: Reference,
    auth: &RegistryAuth,
) -> Result<(Reference, String)> {
    let manifest_digest = client.fetch_manifest_digest(&image, auth).await?;
    let sign = format!(
        "{}/{}:{}.sig",
        image.registry(),
        image.repository(),
        manifest_digest.replace(":", "-")
    );
    let reference = sign
        .parse()
        .map_err(|e| anyhow!("Cannot calculate signature object reference {:?}", e))?;
    Ok((reference, manifest_digest))
}

/// Ensure the provided key is used to sign at least one of the layers of the
/// signature image produced by cosign.
///
/// Returns the list of SimpleSigning objects that have been signed by the given
/// key.
pub async fn verify(
    client: &mut Client,
    auth: &RegistryAuth,
    source_image_digest: String,
    cosign_image: Reference,
    public_key: &str,
    annotations: Option<HashMap<String, String>>,
) -> Result<Vec<SimpleSigning>> {
    let verification_key = new_verification_key(public_key)?;
    let signatures = image_signatures(client, &cosign_image, auth).await?;
    let layers = image_signature_layers(client, &cosign_image, auth).await?;
    verify_layers(
        source_image_digest,
        layers,
        signatures,
        annotations,
        &verification_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock_client::test::MockOciClient;

    #[tokio::test]
    async fn triangulate_sigstore_object() {
        let image: Reference = "docker.io/busybox:latest".parse().unwrap();
        let image_digest =
            String::from("sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b");
        let expected_image = "docker.io/busybox:sha256-f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b.sig".parse().unwrap();
        let mut mock_client = MockOciClient {
            fetch_manifest_digest_response: Some(Ok(image_digest.clone())),
            pull_response: None,
            pull_manifest_response: None,
        };

        let reference = triangulate(
            &mut mock_client,
            image,
            &oci_distribution::secrets::RegistryAuth::Anonymous,
        )
        .await;

        assert!(reference.is_ok());
        assert_eq!(reference.unwrap(), (expected_image, image_digest));
    }
}
