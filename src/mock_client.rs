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

#[cfg(test)]
pub(crate) mod test {
    use crate::errors::{Result, SigstoreError};

    use async_trait::async_trait;
    use oci_distribution::{
        client::{ImageData, PushResponse},
        manifest::OciManifest,
        secrets::RegistryAuth,
        Reference,
    };
    use std::sync::Arc;

    #[derive(Default, Clone)]
    pub struct MockOciClient {
        // Note: all the `Result` objects have to be wrapped inside of an `Arc` to be able to clone them
        pub fetch_manifest_digest_response: Option<Arc<anyhow::Result<String>>>,
        pub pull_response: Option<Arc<anyhow::Result<ImageData>>>,
        pub pull_manifest_response: Option<Arc<anyhow::Result<(OciManifest, String)>>>,
        pub push_response: Option<Arc<anyhow::Result<PushResponse>>>,
    }

    impl crate::registry::ClientCapabilitiesDeps for MockOciClient {}

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl crate::registry::ClientCapabilities for MockOciClient {
        async fn fetch_manifest_digest(
            &mut self,
            image: &Reference,
            _auth: &RegistryAuth,
        ) -> Result<String> {
            let mock_response = self
                .fetch_manifest_digest_response
                .as_ref()
                .ok_or_else(|| SigstoreError::RegistryFetchManifestError {
                    image: image.whole(),
                    error: String::from("No fetch_manifest_digest_response provided!"),
                })?;

            match mock_response.as_ref() {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(SigstoreError::RegistryFetchManifestError {
                    image: image.whole(),
                    error: e.to_string(),
                }),
            }
        }

        async fn pull(
            &mut self,
            image: &Reference,
            _auth: &RegistryAuth,
            _accepted_media_types: Vec<&str>,
        ) -> Result<ImageData> {
            let mock_response =
                self.pull_response
                    .as_ref()
                    .ok_or_else(|| SigstoreError::RegistryPullError {
                        image: image.whole(),
                        error: String::from("No pull_response provided!"),
                    })?;

            match mock_response.as_ref() {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(SigstoreError::RegistryPullError {
                    image: image.whole(),
                    error: e.to_string(),
                }),
            }
        }

        async fn pull_manifest(
            &mut self,
            image: &Reference,
            _auth: &RegistryAuth,
        ) -> Result<(OciManifest, String)> {
            let mock_response = self.pull_manifest_response.as_ref().ok_or_else(|| {
                SigstoreError::RegistryPullError {
                    image: image.whole(),
                    error: String::from("No pull_manifest_response provided!"),
                }
            })?;

            match mock_response.as_ref() {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(SigstoreError::RegistryPullError {
                    image: image.whole(),
                    error: e.to_string(),
                }),
            }
        }

        async fn push(
            &mut self,
            image_ref: &oci_distribution::Reference,
            _layers: &[oci_distribution::client::ImageLayer],
            _config: oci_distribution::client::Config,
            _auth: &oci_distribution::secrets::RegistryAuth,
            _manifest: Option<oci_distribution::manifest::OciImageManifest>,
        ) -> Result<PushResponse> {
            let mock_response =
                self.push_response
                    .as_ref()
                    .ok_or_else(|| SigstoreError::RegistryPushError {
                        image: image_ref.whole(),
                        error: String::from("No push_response provided!"),
                    })?;

            match mock_response.as_ref() {
                Ok(r) => Ok(PushResponse {
                    config_url: r.config_url.clone(),
                    manifest_url: r.manifest_url.clone(),
                }),
                Err(e) => Err(SigstoreError::RegistryPushError {
                    image: image_ref.whole(),
                    error: e.to_string(),
                }),
            }
        }
    }
}
