//
// Copyright 2021 The Sigstore Authors.
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

use super::{ClientCapabilities, ClientCapabilitiesDeps};
use crate::errors::{Result, SigstoreError};

use async_trait::async_trait;

/// Internal client for an OCI Registry. This performs actual
/// calls against the remote registry.OciClient
///
/// For testing purposes, use instead the client inside of the
/// `mock_client` module.
pub(crate) struct OciClient {
    pub registry_client: oci_client::Client,
}

impl ClientCapabilitiesDeps for OciClient {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl ClientCapabilities for OciClient {
    async fn fetch_manifest_digest(
        &mut self,
        image: &oci_client::Reference,
        auth: &oci_client::secrets::RegistryAuth,
    ) -> Result<String> {
        self.registry_client
            .fetch_manifest_digest(image, auth)
            .await
            .map_err(|e| SigstoreError::RegistryFetchManifestError {
                image: image.whole(),
                error: e.to_string(),
            })
    }

    async fn pull(
        &mut self,
        image: &oci_client::Reference,
        auth: &oci_client::secrets::RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<oci_client::client::ImageData> {
        self.registry_client
            .pull(image, auth, accepted_media_types)
            .await
            .map_err(|e| SigstoreError::RegistryPullError {
                image: image.whole(),
                error: e.to_string(),
            })
    }

    async fn pull_manifest(
        &mut self,
        image: &oci_client::Reference,
        auth: &oci_client::secrets::RegistryAuth,
    ) -> Result<(oci_client::manifest::OciManifest, String)> {
        self.registry_client
            .pull_manifest(image, auth)
            .await
            .map_err(|e| SigstoreError::RegistryPullManifestError {
                image: image.whole(),
                error: e.to_string(),
            })
    }

    async fn push(
        &mut self,
        image_ref: &oci_client::Reference,
        layers: &[oci_client::client::ImageLayer],
        config: oci_client::client::Config,
        auth: &oci_client::secrets::RegistryAuth,
        manifest: Option<oci_client::manifest::OciImageManifest>,
    ) -> Result<oci_client::client::PushResponse> {
        self.registry_client
            .push(image_ref, layers, config, auth, manifest)
            .await
            .map_err(|e| SigstoreError::RegistryPushError {
                image: image_ref.whole(),
                error: e.to_string(),
            })
    }
}
