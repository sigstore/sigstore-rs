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
    async fn fetch_signature_layers_from_referrers(
        &mut self,
        auth: &Auth,
        source_image: &OciReference,
        source_image_digest: &str,
    ) -> Result<Vec<SignatureLayer>> {
        let oci_auth: oci_client::secrets::RegistryAuth = auth.into();

        // Build a reference using the digest so we can query referrers.
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
                Some(SIGSTORE_BUNDLE_V03_MEDIA_TYPE),
            )
            .await?;

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
}
