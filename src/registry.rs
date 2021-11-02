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

//! Set of structs and enums used to define how to interact with OCI registries

use anyhow::Result;
use async_trait::async_trait;
use std::convert::From;

/// A method for authenticating to a registry
pub enum Auth {
    /// Access the registry anonymously
    Anonymous,
    /// Access the registry using HTTP Basic authentication
    Basic(String, String),
}

impl From<&Auth> for oci_distribution::secrets::RegistryAuth {
    fn from(auth: &Auth) -> Self {
        match auth {
            Auth::Anonymous => oci_distribution::secrets::RegistryAuth::Anonymous,
            Auth::Basic(username, pass) => {
                oci_distribution::secrets::RegistryAuth::Basic(username.clone(), pass.clone())
            }
        }
    }
}

/// The protocol that the client should use to connect
#[derive(Debug, Clone, PartialEq)]
pub enum ClientProtocol {
    #[allow(missing_docs)]
    Http,
    #[allow(missing_docs)]
    Https,
    #[allow(missing_docs)]
    HttpsExcept(Vec<String>),
}

impl Default for ClientProtocol {
    fn default() -> Self {
        ClientProtocol::Https
    }
}

impl From<ClientProtocol> for oci_distribution::client::ClientProtocol {
    fn from(cp: ClientProtocol) -> Self {
        match cp {
            ClientProtocol::Http => oci_distribution::client::ClientProtocol::Http,
            ClientProtocol::Https => oci_distribution::client::ClientProtocol::Https,
            ClientProtocol::HttpsExcept(exceptions) => {
                oci_distribution::client::ClientProtocol::HttpsExcept(exceptions)
            }
        }
    }
}

/// The encoding of the certificate
#[derive(Debug, Clone)]
pub enum CertificateEncoding {
    #[allow(missing_docs)]
    Der,
    #[allow(missing_docs)]
    Pem,
}

impl From<CertificateEncoding> for oci_distribution::client::CertificateEncoding {
    fn from(ce: CertificateEncoding) -> Self {
        match ce {
            CertificateEncoding::Der => oci_distribution::client::CertificateEncoding::Der,
            CertificateEncoding::Pem => oci_distribution::client::CertificateEncoding::Pem,
        }
    }
}

/// A x509 certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Which encoding is used by the certificate
    pub encoding: CertificateEncoding,

    /// Actual certificate
    pub data: Vec<u8>,
}

impl From<&Certificate> for oci_distribution::client::Certificate {
    fn from(cert: &Certificate) -> Self {
        oci_distribution::client::Certificate {
            encoding: cert.encoding.clone().into(),
            data: cert.data.clone(),
        }
    }
}

/// A client configuration
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// Which protocol the client should use
    pub protocol: ClientProtocol,

    /// Accept invalid hostname. Defaults to false
    pub accept_invalid_hostnames: bool,

    /// Accept invalid certificates. Defaults to false
    pub accept_invalid_certificates: bool,

    /// A list of extra root certificate to trust. This can be used to connect
    /// to servers using self-signed certificates
    pub extra_root_certificates: Vec<Certificate>,
}

impl From<ClientConfig> for oci_distribution::client::ClientConfig {
    fn from(config: ClientConfig) -> Self {
        oci_distribution::client::ClientConfig {
            protocol: oci_distribution::client::ClientProtocol::Https,
            accept_invalid_certificates: config.accept_invalid_certificates,
            accept_invalid_hostnames: config.accept_invalid_hostnames,
            extra_root_certificates: config
                .extra_root_certificates
                .iter()
                .map(|c| c.into())
                .collect(),
        }
    }
}

#[async_trait]
/// Capabilities that are expected to be provided by a registry client
pub(crate) trait ClientCapabilities: Send + Sync {
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
}

/// Internal client for an OCI Registry. This performs actual
/// calls against the remote registry.OciClient
///
/// For testing purposes, use instead the client inside of the
/// `mock_client` module.
pub(crate) struct OciClient {
    pub registry_client: oci_distribution::Client,
}

#[async_trait]
impl ClientCapabilities for OciClient {
    async fn fetch_manifest_digest(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
    ) -> Result<String> {
        self.registry_client
            .fetch_manifest_digest(image, auth)
            .await
    }

    async fn pull(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<oci_distribution::client::ImageData> {
        self.registry_client
            .pull(image, auth, accepted_media_types)
            .await
    }

    async fn pull_manifest(
        &mut self,
        image: &oci_distribution::Reference,
        auth: &oci_distribution::secrets::RegistryAuth,
    ) -> Result<(oci_distribution::manifest::OciManifest, String)> {
        self.registry_client.pull_manifest(image, auth).await
    }
}
