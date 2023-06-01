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

pub mod config;
pub use config::*;

#[cfg(feature = "cosign")]
pub(crate) mod oci_client;
#[cfg(feature = "cosign")]
pub(crate) use oci_client::*;

#[cfg(feature = "cosign")]
pub mod oci_reference;
#[cfg(feature = "cosign")]
pub use oci_reference::OciReference;

#[cfg(all(feature = "cosign", feature = "cached-client"))]
pub(crate) mod oci_caching_client;
#[cfg(all(feature = "cosign", feature = "cached-client"))]
pub(crate) use oci_caching_client::*;

use crate::errors::Result;

use async_trait::async_trait;

/// Workaround to ensure the `Send + Sync` supertraits are
/// required by ClientCapabilities only when the target
/// architecture is NOT wasm32.
///
/// This intermediate trait has been created to avoid
/// to define ClientCapabilities twice (one with `#[cfg(target_arch = "wasm32")]`,
/// the other with `#[cfg(not(target_arch = "wasm32"))]`
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait ClientCapabilitiesDeps: Send + Sync {}

/// Workaround to ensure the `Send + Sync` supertraits are
/// required by ClientCapabilities only when the target
/// architecture is NOT wasm32.
///
/// This intermediate trait has been created to avoid
/// to define ClientCapabilities twice (one with `#[cfg(target_arch = "wasm32")]`,
/// the other with `#[cfg(not(target_arch = "wasm32"))]`
#[cfg(target_arch = "wasm32")]
pub(crate) trait ClientCapabilitiesDeps {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
/// Capabilities that are expected to be provided by a registry client
pub(crate) trait ClientCapabilities: ClientCapabilitiesDeps {
    async fn fetch_manifest_digest(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
    ) -> Result<String>;

    async fn pull(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<oci_distribution::client::ImageData>;

    async fn pull_manifest(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
    ) -> Result<(oci_distribution::manifest::OciManifest, String)>;

    async fn push(
        &mut self,
        image_ref: &oci_distribution::Reference,
        layers: &[oci_distribution::client::ImageLayer],
        config: oci_distribution::client::Config,
        auth: &oci_distribution::secrets::RegistryAuth,
        manifest: Option<oci_distribution::manifest::OciImageManifest>,
    ) -> Result<oci_distribution::client::PushResponse>;
}
