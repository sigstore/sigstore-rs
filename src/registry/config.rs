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

use pki_types::CertificateDer;
use serde::Serialize;
use std::cmp::Ordering;

use crate::errors;

/// A method for authenticating to a registry
#[derive(Serialize, Debug)]
pub enum Auth {
    /// Access the registry anonymously
    Anonymous,
    /// Access the registry using HTTP Basic authentication
    Basic(String, String),
    /// Access the registry using a bearer token
    Bearer(String),
}

impl From<&Auth> for oci_client::secrets::RegistryAuth {
    fn from(auth: &Auth) -> Self {
        match auth {
            Auth::Anonymous => oci_client::secrets::RegistryAuth::Anonymous,
            Auth::Basic(username, pass) => {
                oci_client::secrets::RegistryAuth::Basic(username.clone(), pass.clone())
            }
            Auth::Bearer(token) => oci_client::secrets::RegistryAuth::Bearer(token.clone()),
        }
    }
}

impl From<&oci_client::secrets::RegistryAuth> for Auth {
    fn from(auth: &oci_client::secrets::RegistryAuth) -> Self {
        match auth {
            oci_client::secrets::RegistryAuth::Anonymous => Auth::Anonymous,
            oci_client::secrets::RegistryAuth::Basic(username, pass) => {
                Auth::Basic(username.clone(), pass.clone())
            }
            oci_client::secrets::RegistryAuth::Bearer(token) => Auth::Bearer(token.clone()),
        }
    }
}

/// The protocol that the client should use to connect
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientProtocol {
    #[allow(missing_docs)]
    Http,
    #[allow(missing_docs)]
    #[default]
    Https,
    #[allow(missing_docs)]
    HttpsExcept(Vec<String>),
}

impl From<ClientProtocol> for oci_client::client::ClientProtocol {
    fn from(cp: ClientProtocol) -> Self {
        match cp {
            ClientProtocol::Http => oci_client::client::ClientProtocol::Http,
            ClientProtocol::Https => oci_client::client::ClientProtocol::Https,
            ClientProtocol::HttpsExcept(exceptions) => {
                oci_client::client::ClientProtocol::HttpsExcept(exceptions)
            }
        }
    }
}

/// The encoding of the certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateEncoding {
    #[allow(missing_docs)]
    Der,
    #[allow(missing_docs)]
    Pem,
}

impl From<CertificateEncoding> for oci_client::client::CertificateEncoding {
    fn from(ce: CertificateEncoding) -> Self {
        match ce {
            CertificateEncoding::Der => oci_client::client::CertificateEncoding::Der,
            CertificateEncoding::Pem => oci_client::client::CertificateEncoding::Pem,
        }
    }
}

/// A x509 certificate
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate {
    /// Which encoding is used by the certificate
    pub encoding: CertificateEncoding,

    /// Actual certificate
    pub data: Vec<u8>,
}

impl Ord for Certificate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.cmp(&other.data)
    }
}

impl PartialOrd for Certificate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<&Certificate> for oci_client::client::Certificate {
    fn from(cert: &Certificate) -> Self {
        oci_client::client::Certificate {
            encoding: cert.encoding.clone().into(),
            data: cert.data.clone(),
        }
    }
}

impl<'a> TryFrom<Certificate> for CertificateDer<'a> {
    type Error = errors::SigstoreError;
    fn try_from(value: Certificate) -> errors::Result<CertificateDer<'a>> {
        #[inline]
        fn to_der(pem: &[u8]) -> errors::Result<Vec<u8>> {
            Ok(pem::parse(pem)?.into_contents())
        }

        match &value.encoding {
            CertificateEncoding::Der => Ok(CertificateDer::from(value.data)),
            CertificateEncoding::Pem => Ok(CertificateDer::from(to_der(&value.data)?)),
        }
    }
}

/// A client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Which protocol the client should use
    pub protocol: ClientProtocol,

    /// Accept invalid hostname. Defaults to false
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
    #[cfg(feature = "native-tls")]
    pub accept_invalid_hostnames: bool,

    /// Accept invalid certificates. Defaults to false
    pub accept_invalid_certificates: bool,

    /// A list of extra root certificate to trust. This can be used to connect
    /// to servers using self-signed certificates
    pub extra_root_certificates: Vec<Certificate>,

    /// Set the `HTTPS PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub https_proxy: Option<String>,

    /// Set the `HTTP PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub http_proxy: Option<String>,

    /// Set the `NO PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub no_proxy: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            protocol: ClientProtocol::Https,
            #[cfg(feature = "native-tls")]
            accept_invalid_hostnames: false,
            accept_invalid_certificates: false,
            extra_root_certificates: Vec::new(),
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
        }
    }
}

impl From<ClientConfig> for oci_client::client::ClientConfig {
    fn from(config: ClientConfig) -> Self {
        oci_client::client::ClientConfig {
            protocol: config.protocol.into(),
            accept_invalid_certificates: config.accept_invalid_certificates,
            #[cfg(feature = "native-tls")]
            accept_invalid_hostnames: config.accept_invalid_hostnames,
            extra_root_certificates: config
                .extra_root_certificates
                .iter()
                .map(|c| c.into())
                .collect(),
            https_proxy: config.https_proxy,
            http_proxy: config.http_proxy,
            no_proxy: config.no_proxy,
            ..Default::default()
        }
    }
}

/// A client configuration
#[derive(Debug, Clone)]
pub struct PushResponse {
    /// Pullable url for the config.
    pub config_url: String,
    /// Pullable url for the manifest.
    pub manifest_url: String,
}

impl From<PushResponse> for oci_client::client::PushResponse {
    fn from(pr: PushResponse) -> Self {
        oci_client::client::PushResponse {
            config_url: pr.config_url,
            manifest_url: pr.manifest_url,
        }
    }
}

impl From<oci_client::client::PushResponse> for PushResponse {
    fn from(pr: oci_client::client::PushResponse) -> Self {
        PushResponse {
            config_url: pr.config_url,
            manifest_url: pr.manifest_url,
        }
    }
}
