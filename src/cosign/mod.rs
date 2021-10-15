//! Strucs providing cosign capabilities

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;

use crate::registry::{Auth, ClientConfig};
use crate::simple_signing::SimpleSigning;

pub(crate) static SIGSTORE_OCI_MEDIA_TYPE: &str =
    "application/vnd.dev.cosign.simplesigning.v1+json";
pub(crate) static SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";

#[async_trait]
/// Cosign Abilities that have to be implemented by a
/// Cosign client
pub trait CosignCapabilities {
    /// Calculate the cosign image reference.
    /// This is the location cosign stores signatures.
    async fn triangulate(&mut self, image: &str, auth: &Auth) -> Result<(String, String)>;

    /// Ensure the provided key is used to sign at least one of the layers of the
    /// signature image produced by cosign.
    ///
    /// Returns the list of SimpleSigning objects that have been signed by the given
    /// key.
    async fn verify(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &str,
        public_key: &str,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<Vec<SimpleSigning>>;
}

/// Cosign Client
///
/// Given a container image/oci artifact, calculate the location of
/// its cosign signature inside of a registry:
///
/// ```rust,no_run
/// use crate::sigstore::cosign::CosignCapabilities;
///
/// #[tokio::main]
/// pub async fn main() {
///   let auth = &sigstore::registry::Auth::Anonymous;
///   let mut client = sigstore::cosign::Client::default();
///   let image = "registry-testing.svc.lan/kubewarden/disallow-service-nodeport:v0.1.0";
///   let (cosign_signature_image, source_image_digest) = client.triangulate(
///     image,
///     auth
///   ).await.unwrap();
/// }
/// ```
///
/// Verify the signature of a container image/oci artifact:
///
/// ```rust,no_run
/// use crate::sigstore::cosign::CosignCapabilities;
/// use std::collections::HashMap;
///
/// #[tokio::main]
/// pub async fn main() {
///   let auth = &sigstore::registry::Auth::Anonymous;
///   let mut client = sigstore::cosign::Client::default();
///
///   // Obtained via `triangulate`
///   let cosign_image = "registry-testing.svc.lan/kubewarden/disallow-service-nodeport:sha256-5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e.sig";
///   // Obtained via `triangulate`
///   let source_image_digest = "sha256-5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e";
///
///   let mut annotations: HashMap<String, String> = HashMap::new();
///   annotations.insert("env".to_string(), "prod".to_string());
///
///   let verification_key = "contents of a `cosign.pub` key read from the disk";
///   let signatures_matching_requirements = client.verify(
///     auth,
///     cosign_image,
///     source_image_digest,
///     verification_key,
///     Some(annotations)
///   ).await.unwrap();
///
///   if signatures_matching_requirements.is_empty() {
///     panic!("no signature is matching the requirments");
///   } else {
///     println!("signatures matching the requirements: {:?}",
///         signatures_matching_requirements);
///   }
/// }
/// ```
pub struct Client {
    registry_client: Box<dyn crate::registry::ClientCapabilities>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        let oci_client = oci_distribution::client::Client::new(config.into());
        Client {
            registry_client: Box::new(crate::registry::OciClient {
                registry_client: oci_client,
            }),
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        let oci_client = oci_distribution::client::Client::default();
        Client {
            registry_client: Box::new(crate::registry::OciClient {
                registry_client: oci_client,
            }),
        }
    }
}

#[async_trait]
impl CosignCapabilities for Client {
    async fn triangulate(&mut self, image: &str, auth: &Auth) -> Result<(String, String)> {
        let image_reference: oci_distribution::Reference = image
            .parse()
            .map_err(|e| anyhow!("Cannot parse image reference '{}': {:?}", image, e))?;

        let manifest_digest = self
            .registry_client
            .fetch_manifest_digest(&image_reference, &auth.into())
            .await
            .map_err(|e| {
                anyhow!(
                    "Cannot fetch manifest digest for {:?}: {:?}",
                    image_reference,
                    e
                )
            })?;

        let sign = format!(
            "{}/{}:{}.sig",
            image_reference.registry(),
            image_reference.repository(),
            manifest_digest.replace(":", "-")
        );
        let reference = sign
            .parse()
            .map_err(|e| anyhow!("Cannot calculate signature object reference {:?}", e))?;

        Ok((reference, manifest_digest))
    }

    async fn verify(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &str,
        public_key: &str,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<Vec<SimpleSigning>> {
        let cosign_image_reference: oci_distribution::Reference = cosign_image
            .parse()
            .map_err(|e| anyhow!("Cannot parse image reference '{}': {:?}", cosign_image, e))?;
        let oci_auth: oci_distribution::secrets::RegistryAuth = auth.into();

        let verification_key = crate::crypto::new_verification_key(public_key)?;

        let (manifest, _) = self
            .registry_client
            .pull_manifest(&cosign_image_reference, &oci_auth)
            .await
            .map_err(|e| {
                anyhow!(
                    "Cannot pull manifest for image {:?}: {:?}",
                    cosign_image_reference,
                    e
                )
            })?;

        let signatures = image_signatures(manifest);
        let layers = self
            .registry_client
            .pull(
                &cosign_image_reference,
                &oci_auth,
                vec![SIGSTORE_OCI_MEDIA_TYPE],
            )
            .await
            .map_err(|e| {
                anyhow!(
                    "Cannot pull data for image {:?}: {:?}",
                    cosign_image_reference,
                    e
                )
            })?
            .layers;

        crate::crypto::verify_layers(
            String::from(source_image_digest),
            layers,
            signatures,
            annotations,
            &verification_key,
        )
    }
}

// Return all the signatures stored inside of the given image manifest
fn image_signatures(manifest: oci_distribution::manifest::OciManifest) -> HashMap<String, String> {
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
    signatures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::test::MockOciClient;

    #[tokio::test]
    async fn triangulate_sigstore_object() {
        let image = "docker.io/busybox:latest";
        let image_digest =
            String::from("sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b");
        let expected_image = "docker.io/busybox:sha256-f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b.sig".parse().unwrap();
        let mock_client = MockOciClient {
            fetch_manifest_digest_response: Some(Ok(image_digest.clone())),
            pull_response: None,
            pull_manifest_response: None,
        };

        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let reference = cosign_client
            .triangulate(image, &crate::registry::Auth::Anonymous)
            .await;

        assert!(reference.is_ok());
        assert_eq!(reference.unwrap(), (expected_image, image_digest));
    }
}
