//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;
use std::ops::Add;

use async_trait::async_trait;
use oci_client::manifest::OCI_IMAGE_MEDIA_TYPE;
use tracing::{debug, warn};

use super::constants::{
    SIGSTORE_BUNDLE_V03_MEDIA_TYPE, SIGSTORE_OCI_MEDIA_TYPE, SIGSTORE_SIGNATURE_ANNOTATION,
};
use super::{CosignCapabilities, SignatureLayer};
use crate::cosign::signature_layers::build_signature_layers;
use crate::crypto::CosignVerificationKey;
use crate::registry::{Auth, OciReference, PushResponse};
use crate::{
    crypto::certificate_pool::CertificatePool,
    errors::{Result, SigstoreError},
};

/// Used to generate an empty [OCI Configuration](https://github.com/opencontainers/image-spec/blob/v1.0.0/config.md).
pub const CONFIG_DATA: &str = "{}";

/// Cosign Client
///
/// Instances of `Client` can be built via [`sigstore::cosign::ClientBuilder`](crate::cosign::ClientBuilder).
pub struct Client {
    pub(crate) registry_client: Box<dyn crate::registry::ClientCapabilities>,
    pub(crate) rekor_pub_keys: Option<BTreeMap<String, CosignVerificationKey>>,
    pub(crate) fulcio_cert_pool: Option<CertificatePool>,
}

#[async_trait]
impl CosignCapabilities for Client {
    async fn triangulate(
        &mut self,
        image: &OciReference,
        auth: &Auth,
    ) -> Result<(OciReference, String)> {
        let manifest_digest = self
            .registry_client
            .fetch_manifest_digest(&image.oci_reference, &auth.into())
            .await?;

        let reference = OciReference::with_tag(
            image.registry().to_string(),
            image.repository().to_string(),
            manifest_digest.replace(':', "-").add(".sig"),
        );

        Ok((reference, manifest_digest))
    }

    async fn trusted_signature_layers(
        &mut self,
        auth: &Auth,
        source_image: &OciReference,
    ) -> Result<Vec<SignatureLayer>> {
        let (cosign_image, source_image_digest) = self.triangulate(source_image, auth).await?;

        let mut all_layers: Vec<SignatureLayer> = Vec::new();

        // --- SimpleSigning path: .sig tag ------------------------------------
        match self
            .fetch_signature_layers_from_tag(auth, &source_image_digest, &cosign_image)
            .await
        {
            Ok(mut layers) => {
                debug!(
                    count = layers.len(),
                    "fetched SimpleSigning (.sig tag) signature layers"
                );
                all_layers.append(&mut layers);
            }
            Err(e) => {
                warn!(error = ?e, "Could not fetch SimpleSigning (.sig tag) signature layers");
            }
        }

        // --- Sigstore Bundle path: OCI referrers -----------------------------
        #[cfg(any(feature = "verify", feature = "sign"))]
        match self
            .fetch_signature_layers_from_referrers(auth, source_image, &source_image_digest)
            .await
        {
            Ok(mut layers) => {
                debug!(
                    count = layers.len(),
                    "fetched Sigstore Bundle (OCI referrers) signature layers"
                );
                all_layers.append(&mut layers);
            }
            Err(e) => {
                warn!(error = ?e, "Could not fetch Sigstore Bundle (OCI referrers) signature layers");
            }
        }

        Ok(all_layers)
    }

    async fn push_signature(
        &mut self,
        annotations: Option<BTreeMap<String, String>>,
        auth: &Auth,
        target_reference: &OciReference,
        signature_layers: Vec<SignatureLayer>,
    ) -> Result<PushResponse> {
        let layers: Vec<oci_client::client::ImageLayer> = signature_layers
            .iter()
            .filter_map(|sl| {
                match serde_json::to_vec(&sl.simple_signing) {
                    Ok(data) => {
                        let annotations = match &sl.signature {
                            Some(sig) => [(SIGSTORE_SIGNATURE_ANNOTATION.into(), sig.clone())].into(),
                            None => BTreeMap::new(),
                        };
                        let image_layer = oci_client::client::ImageLayer::new(data, SIGSTORE_OCI_MEDIA_TYPE.into(), Some(annotations));
                        Some(image_layer)
                    }
                    Err(e) => {
                        warn!(error = ?e, signaturelayer = ?sl, "Skipping SignatureLayer because serialization failed");
                        None
                    }
                }
            })
            .collect();

        // TODO: Do we need to support OCI Image Configuration?
        let config = oci_client::client::Config::oci_v1(CONFIG_DATA.as_bytes().to_vec(), None);
        let mut manifest =
            oci_client::manifest::OciImageManifest::build(&layers[..], &config, annotations);
        manifest.media_type = Some(OCI_IMAGE_MEDIA_TYPE.to_string());
        self.registry_client
            .push(
                &target_reference.oci_reference,
                &layers[..],
                config,
                &auth.into(),
                Some(manifest),
            )
            .await
            .map(|r| r.into())
    }
}

impl Client {
    /// Internal helper method used to fetch data from an OCI registry
    async fn fetch_manifest_and_layers(
        &mut self,
        auth: &Auth,
        cosign_image: &OciReference,
    ) -> Result<(
        oci_client::manifest::OciManifest,
        Vec<oci_client::client::ImageLayer>,
    )> {
        let oci_auth: oci_client::secrets::RegistryAuth = auth.into();

        let (manifest, _) = self
            .registry_client
            .pull_manifest(&cosign_image.oci_reference, &oci_auth)
            .await?;
        let image_data = self
            .registry_client
            .pull(
                &cosign_image.oci_reference,
                &oci_auth,
                vec![SIGSTORE_OCI_MEDIA_TYPE],
            )
            .await?;

        Ok((manifest, image_data.layers))
    }

    /// Fetch SimpleSigning signature layers via the cosign `.sig` tag.
    async fn fetch_signature_layers_from_tag(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &OciReference,
    ) -> Result<Vec<SignatureLayer>> {
        let (manifest, layers) = self.fetch_manifest_and_layers(auth, cosign_image).await?;
        let image_manifest = match manifest {
            oci_client::manifest::OciManifest::Image(im) => im,
            oci_client::manifest::OciManifest::ImageIndex(_) => {
                return Err(SigstoreError::RegistryPullManifestError {
                    image: cosign_image.to_string(),
                    error: "Found a OciImageIndex instead of a OciImageManifest".to_string(),
                });
            }
        };

        let sl = build_signature_layers(
            &image_manifest,
            source_image_digest,
            &layers,
            self.rekor_pub_keys.as_ref(),
            self.fulcio_cert_pool.as_ref(),
        )?;

        debug!(signature_layers=?sl, ?cosign_image, "SimpleSigning (.sig tag) signature layers");
        Ok(sl)
    }

    /// Fetch Sigstore Bundle signature layers via the OCI referrers API.
    #[cfg(any(feature = "verify", feature = "sign"))]
    async fn fetch_signature_layers_from_referrers(
        &mut self,
        auth: &Auth,
        source_image: &OciReference,
        source_image_digest: &str,
    ) -> Result<Vec<SignatureLayer>> {
        let oci_auth: oci_client::secrets::RegistryAuth = auth.into();

        let digest_ref = OciReference::with_digest(
            source_image.registry().to_string(),
            source_image.repository().to_string(),
            source_image_digest.to_string(),
        );

        let referrers = self
            .registry_client
            .pull_referrers(
                &digest_ref.oci_reference,
                &oci_auth,
                None, // do not filter by artifact_type here: the index entry's artifactType
                      // may differ from the layer media type (e.g. ghcr.io stores the bundle
                      // manifest with artifactType "application/vnd.oci.empty.v1+json" in the
                      // referrers index, not "application/vnd.dev.sigstore.bundle.v0.3+json").
                      // We filter downstream by layer media type instead (see below).
            )
            .await
            .map_err(|e| SigstoreError::RegistryPullManifestError {
                image: digest_ref.to_string(),
                error: e.to_string(),
            })?;

        let mut layers: Vec<SignatureLayer> = Vec::new();

        for entry in &referrers.manifests {
            // Build a reference for the referrer manifest using its digest.
            let referrer_ref = OciReference::with_digest(
                source_image.registry().to_string(),
                source_image.repository().to_string(),
                entry.digest.clone(),
            );

            // Pull the bundle layer data.
            let image_data = match self
                .registry_client
                .pull(
                    &referrer_ref.oci_reference,
                    &oci_auth,
                    vec![SIGSTORE_BUNDLE_V03_MEDIA_TYPE],
                )
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    warn!(referrer = ?entry.digest, error = ?e, "Failed to pull Sigstore Bundle referrer layer");
                    continue;
                }
            };

            for layer in &image_data.layers {
                if layer.media_type != SIGSTORE_BUNDLE_V03_MEDIA_TYPE {
                    continue;
                }
                let layer_digest = layer.sha256_digest();
                match SignatureLayer::from_sigstore_bundle(
                    &layer.data,
                    &layer_digest,
                    source_image_digest,
                    source_image,
                    self.fulcio_cert_pool.as_ref(),
                    self.rekor_pub_keys.as_ref(),
                ) {
                    Ok(sl) => layers.push(sl),
                    Err(e) => {
                        warn!(error = ?e, "Skipping Sigstore Bundle layer due to error");
                    }
                }
            }
        }

        Ok(layers)
    }
}

#[cfg(feature = "mock-client")]
#[cfg(test)]
mod tests {
    use oci_client::client::{Config, ImageData, ImageLayer};
    use oci_client::manifest::{ImageIndexEntry, OciImageIndex, OciManifest};
    use rstest::rstest;

    use super::*;

    use crate::{
        cosign::tests::{get_fulcio_cert_pool, get_rekor_public_key},
        mock_client::test::MockOciClient,
    };

    fn build_test_client(mock_client: MockOciClient) -> Client {
        let (key_id, key) = get_rekor_public_key();
        let rekor_pub_keys = BTreeMap::from([(key_id, key)]);

        Client {
            registry_client: Box::new(mock_client),
            rekor_pub_keys: Some(rekor_pub_keys),
            fulcio_cert_pool: Some(get_fulcio_cert_pool()),
        }
    }

    /// Build a minimal single-entry OciImageIndex whose one manifest has the
    /// given media type.  Used by several test helpers below.
    fn index_with_one_entry(media_type: &str) -> OciImageIndex {
        OciImageIndex {
            schema_version: 2,
            media_type: None,
            artifact_type: None,
            manifests: vec![ImageIndexEntry {
                media_type: media_type.to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size: 0,
                artifact_type: None,
                platform: None,
                annotations: None,
            }],
            annotations: None,
        }
    }

    #[tokio::test]
    async fn triangulate_sigstore_object() {
        let image = "docker.io/busybox:latest".parse().unwrap();
        let image_digest =
            String::from("sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b");
        let expected_image = "docker.io/library/busybox:sha256-f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b.sig".parse().unwrap();
        let mock_client = MockOciClient {
            fetch_manifest_digest_response: Some(Ok(image_digest.clone())),
            pull_response: None,
            pull_manifest_response: None,
            push_response: None,
            pull_referrers_response: None,
        };
        let mut cosign_client = build_test_client(mock_client);

        let reference = cosign_client
            .triangulate(&image, &crate::registry::Auth::Anonymous)
            .await;

        assert!(reference.is_ok());
        assert_eq!(reference.unwrap(), (expected_image, image_digest));
    }

    // -------------------------------------------------------------------------
    // fetch_signature_layers_from_tag
    // -------------------------------------------------------------------------

    /// Registry errors and unsupported manifest types must be propagated as
    /// Err, not silently swallowed.
    #[rstest]
    #[case::registry_error_is_propagated(
        MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: Some(Err(anyhow::anyhow!("registry unavailable"))),
            pull_response: None,
            push_response: None,
            pull_referrers_response: None,
        }
    )]
    #[case::image_index_instead_of_manifest_is_rejected(
        MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: Some(Ok((
                OciManifest::ImageIndex(OciImageIndex {
                    schema_version: 2,
                    media_type: None,
                    artifact_type: None,
                    manifests: vec![],
                    annotations: None,
                }),
                String::new(),
            ))),
            pull_response: Some(Ok(ImageData {
                layers: vec![],
                digest: None,
                config: Config::new(vec![], String::new(), None),
                manifest: None,
            })),
            push_response: None,
            pull_referrers_response: None,
        }
    )]
    #[tokio::test]
    async fn fetch_from_tag_returns_err(#[case] mock_client: MockOciClient) {
        let mut client = build_test_client(mock_client);
        let cosign_image = "docker.io/library/busybox:sha256-abc.sig"
            .parse()
            .unwrap();

        let result = client
            .fetch_signature_layers_from_tag(&Auth::Anonymous, "sha256:abc", &cosign_image)
            .await;

        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // fetch_signature_layers_from_referrers
    // -------------------------------------------------------------------------

    /// A registry error from pull_referrers must be propagated as an Err, not
    /// silently swallowed.
    #[cfg(any(feature = "verify", feature = "sign"))]
    #[tokio::test]
    async fn fetch_from_referrers_propagates_registry_error() {
        let mock_client = MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: None,
            pull_response: None,
            push_response: None,
            pull_referrers_response: Some(Err(anyhow::anyhow!("registry unavailable"))),
        };
        let mut client = build_test_client(mock_client);
        let source_image = "docker.io/library/busybox:latest".parse().unwrap();

        let result = client
            .fetch_signature_layers_from_referrers(
                &Auth::Anonymous,
                &source_image,
                "sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b",
            )
            .await;

        assert!(result.is_err());
    }

    /// Conditions that must all produce Ok(vec![]) — i.e. partial or total
    /// absence of valid bundle layers must never abort the whole call.
    ///
    /// Note: MockOciClient has a single pull_response field, so only
    /// single-referrer scenarios can be exercised here without extending the
    /// mock.
    #[cfg(any(feature = "verify", feature = "sign"))]
    #[rstest]
    #[case::empty_referrers_index_yields_no_layers(
        MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: None,
            pull_response: None,
            push_response: None,
            pull_referrers_response: Some(Ok(OciImageIndex {
                schema_version: 2,
                media_type: None,
                artifact_type: None,
                manifests: vec![],
                annotations: None,
            })),
        }
    )]
    #[case::failed_referrer_pull_is_skipped_not_propagated(
        MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: None,
            pull_response: Some(Err(anyhow::anyhow!("pull failed"))),
            push_response: None,
            pull_referrers_response: Some(Ok(index_with_one_entry(
                SIGSTORE_BUNDLE_V03_MEDIA_TYPE,
            ))),
        }
    )]
    #[case::layers_with_non_bundle_media_type_are_skipped(
        MockOciClient {
            fetch_manifest_digest_response: None,
            pull_manifest_response: None,
            pull_response: Some(Ok(ImageData {
                layers: vec![ImageLayer {
                    data: b"not a bundle".as_ref().into(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    annotations: None,
                }],
                digest: None,
                config: Config::new(vec![], String::new(), None),
                manifest: None,
            })),
            push_response: None,
            pull_referrers_response: Some(Ok(index_with_one_entry(
                "application/vnd.oci.image.manifest.v1+json",
            ))),
        }
    )]
    #[tokio::test]
    async fn fetch_from_referrers_returns_empty(#[case] mock_client: MockOciClient) {
        let mut client = build_test_client(mock_client);
        let source_image = "docker.io/library/busybox:latest".parse().unwrap();

        let result = client
            .fetch_signature_layers_from_referrers(
                &Auth::Anonymous,
                &source_image,
                "sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b",
            )
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
