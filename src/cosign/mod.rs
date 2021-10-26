//! Strucs providing cosign capabilities

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};

use crate::crypto::CosignVerificationKey;
use crate::registry::{Auth, ClientConfig};
use crate::simple_signing::SimpleSigning;

mod signature_layers;
use self::signature_layers::{build_signature_layers, SignatureLayer};

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
        let (manifest, layers) = self.fetch_manifest_and_layers(auth, cosign_image).await?;
        let signature_layers = build_signature_layers(&manifest, &layers);

        let verification_key = crate::crypto::new_verification_key(public_key)?;
        let annotations = annotations.unwrap_or_default();
        let verified_signatures = self.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            source_image_digest,
            &verification_key,
            &annotations,
        );
        Ok(verified_signatures)
    }
}

impl Client {
    /// Internal helper method used to fetch data from an OCI registry
    async fn fetch_manifest_and_layers(
        &mut self,
        auth: &Auth,
        cosign_image: &str,
    ) -> Result<(
        oci_distribution::manifest::OciManifest,
        Vec<oci_distribution::client::ImageLayer>,
    )> {
        let cosign_image_reference: oci_distribution::Reference = cosign_image
            .parse()
            .map_err(|e| anyhow!("Cannot parse image reference '{}': {:?}", cosign_image, e))?;
        let oci_auth: oci_distribution::secrets::RegistryAuth = auth.into();

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
        let image_data = self
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
            })?;

        Ok((manifest, image_data.layers))
    }

    /// The heart of the verification code. This is where all the checks are done
    /// against the SignatureLayer objects found inside of the OCI registry.
    ///
    /// The method returns a list of SimpleSigning object satisfying the requirements.
    /// The list is empty if no SimpleSigning object satisfied the requirements.
    fn find_simple_signing_objects_satisfying_constraints(
        &mut self,
        signature_layers: &HashSet<SignatureLayer>,
        source_image_digest: &str,
        verification_key: &CosignVerificationKey,
        annotations: &HashMap<String, String>,
    ) -> Vec<SimpleSigning> {
        let verified_signatures: Vec<SimpleSigning> = signature_layers
            .iter()
            .filter_map(|sl| match sl.is_signed_by_key(verification_key) {
                // filter by the layers that have been signed with the given key,
                // then convert them into SimpleSigning objects
                Ok(true) => Some(sl.simple_signing.clone()),
                _ => None,
            })
            .filter(|ss| {
                // ensure given annotations are respected
                ss.satisfies_annotations(annotations)
            })
            .filter(|ss| {
                // ensure the manifest digest mentioned by the signed SimpleSigning
                // object matches the value of the OCI object we're verifying
                ss.satisfies_manifest_digest(source_image_digest)
            })
            .collect();
        verified_signatures
    }
}

#[cfg(test)]
mod tests {
    use self::signature_layers::tests::build_correct_signature_layer;
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

    #[test]
    fn find_simple_signing_object_when_verification_key_and_no_annotations_are_provided() {
        let (signature_layer, verification_key) = build_correct_signature_layer();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let mut signature_layers: HashSet<SignatureLayer> = HashSet::new();
        signature_layers.insert(signature_layer);

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            &verification_key,
            &annotations,
        );
        assert!(!actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_no_signature_matches_the_given_key() {
        let (signature_layer, _) = build_correct_signature_layer();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let mut signature_layers: HashSet<SignatureLayer> = HashSet::new();
        signature_layers.insert(signature_layer);

        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            &verification_key,
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_annotations_are_not_satisfied() {
        let (signature_layer, verification_key) = build_correct_signature_layer();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let mut signature_layers: HashSet<SignatureLayer> = HashSet::new();
        signature_layers.insert(signature_layer);

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("env".into(), "prod".into());

        let mock_client = MockOciClient::default();
        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            &verification_key,
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_simple_signing_digest_does_not_match_the_expected_one(
    ) {
        let (signature_layer, verification_key) = build_correct_signature_layer();
        let source_image_digest = "this is a different value";
        let mut signature_layers: HashSet<SignatureLayer> = HashSet::new();
        signature_layers.insert(signature_layer);

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            &verification_key,
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_no_signature_layer_exists() {
        let source_image_digest = "something";
        let signature_layers: HashSet<SignatureLayer> = HashSet::new();

        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let mut cosign_client = crate::cosign::Client {
            registry_client: Box::new(mock_client),
        };

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            &verification_key,
            &annotations,
        );
        assert!(actual.is_empty());
    }
}
