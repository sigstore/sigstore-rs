use anyhow::Result;
use oci_distribution::{client::ImageLayer, secrets::RegistryAuth, Reference};
use std::collections::HashMap;

#[cfg(test)]
use crate::mock_client::test::MockOciClient as Client;
#[cfg(not(test))]
use oci_distribution::client::Client;

pub(crate) static SIGSTORE_OCI_MEDIA_TYPE: &str =
    "application/vnd.dev.cosign.simplesigning.v1+json";
pub(crate) static SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";

/// Produce a Hash that has the following contents:
/// * key: the sha256 sum of the layer containing the signature object
/// * value: the expected signature
///
/// The values are extracted from the manifest of the image containing
/// the cosign data. They are part of the annotations.
///
/// See [the official spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)
pub(crate) async fn image_signatures(
    client: &mut Client,
    image: &Reference,
    auth: &RegistryAuth,
) -> Result<HashMap<String, String>> {
    let (manifest, _) = client.pull_manifest(image, auth).await?;

    let mut signatures: HashMap<String, String> = HashMap::new();

    for layer in &manifest.layers {
        if layer.media_type != SIGSTORE_OCI_MEDIA_TYPE {
            continue;
        }
        if let Some(signature) = layer
            .annotations
            .as_ref()
            .and_then(|a| a.get(&String::from(SIGSTORE_SIGNATURE_ANNOTATION)).cloned())
        {
            signatures.insert(layer.digest.clone(), signature);
        }
    }
    Ok(signatures)
}

/// Fetch the signature layers that are part of the image produced
/// by cosign
pub(crate) async fn image_signature_layers(
    client: &mut Client,
    image: &Reference,
    auth: &RegistryAuth,
) -> Result<Vec<ImageLayer>> {
    let image_data = client
        .pull(image, auth, vec![SIGSTORE_OCI_MEDIA_TYPE])
        .await?;
    Ok(image_data.layers)
}
