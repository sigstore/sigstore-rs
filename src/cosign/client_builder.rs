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

use tracing::info;

use super::client::Client;
use crate::crypto::SigningScheme;
use crate::crypto::{certificate_pool::CertificatePool, CosignVerificationKey};
use crate::errors::Result;
use crate::registry::ClientConfig;
use crate::trust::{RawTrustRoot, TrustRoot};

/// A builder that generates Client objects.
///
/// ## Rekor integration
///
/// Rekor integration can be enabled by specifying Rekor's public key.
/// This can be provided via a [`crate::trust::ManualTrustRoot`].
///
/// > Note well: the [`sigstore`](crate::sigstore) module provides helper structs and methods
/// > to obtain this data from the official TUF repository of the Sigstore project.
///
/// ## Fulcio integration
///
/// Fulcio integration can be enabled by specifying Fulcio's certificate.
/// This can be provided via a [`crate::sigstore::ManualTrustRoot`].
///
/// > Note well: the [`sigstore`](crate::sigstore) module provides helper structs and methods
/// > to obtain this data from the official TUF repository of the Sigstore project.
///
/// ## Registry caching
///
/// The [`cosign::Client`](crate::cosign::Client) interacts with remote container registries to obtain
/// the data needed to perform Sigstore verification.
///
/// By default, the client will always reach out to the remote registry. However,
/// it's possible to enable an in-memory cache. This behaviour can be enabled via
/// the [`ClientBuilder::enable_registry_caching`] method.
///
/// Each cached entry will automatically expire after 60 seconds.
#[derive(Default)]
pub struct ClientBuilder {
    oci_client_config: ClientConfig,
    rekor_pub_key: Option<CosignVerificationKey>,
    fulcio_cert_pool: CertificatePool,
    #[cfg(feature = "cached-client")]
    enable_registry_caching: bool,
}

impl ClientBuilder {
    /// Enable caching of data returned from remote OCI registries
    #[cfg(feature = "cached-client")]
    pub fn enable_registry_caching(mut self) -> Self {
        self.enable_registry_caching = true;
        self
    }

    /// Optional - Configures the roots of trust.
    ///
    /// Enables Fulcio and Rekor integration with the given trust repository.
    /// See [`TrustRoot`] for more details on trust repositories.
    pub fn with_trust_repository<R: TrustRoot + RawTrustRoot + ?Sized>(
        mut self,
        repo: &R,
    ) -> Result<Self> {
        self.rekor_pub_key = Some(CosignVerificationKey::from_der(
            &repo.raw_tlog_keys()[0],
            &SigningScheme::default(),
        )?);
        self.fulcio_cert_pool = repo.ca_certs()?;

        Ok(self)
    }

    /// Optional - the configuration to be used by the OCI client.
    ///
    /// This can be used when dealing with registries that are not using
    /// TLS termination, or are using self-signed certificates.
    pub fn with_oci_client_config(mut self, config: ClientConfig) -> Self {
        self.oci_client_config = config;
        self
    }

    pub fn build(self) -> Result<Client> {
        if self.rekor_pub_key.is_none() {
            info!("Rekor public key not provided. Rekor integration disabled");
        }

        let oci_client =
            oci_distribution::client::Client::new(self.oci_client_config.clone().into());

        let registry_client: Box<dyn crate::registry::ClientCapabilities> = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "cached-client")] {
                    if self.enable_registry_caching {
                        Box::new(crate::registry::OciCachingClient {
                            registry_client: oci_client,
                        }) as Box<dyn crate::registry::ClientCapabilities>
                    } else {
                        Box::new(crate::registry::OciClient {
                            registry_client: oci_client,
                        }) as Box<dyn crate::registry::ClientCapabilities>
                    }
                } else {
                    Box::new(crate::registry::OciClient {
                        registry_client: oci_client,
                    }) as Box<dyn crate::registry::ClientCapabilities>
                }
            }
        };

        Ok(Client {
            registry_client,
            rekor_pub_key: self.rekor_pub_key,
            fulcio_cert_pool: Some(self.fulcio_cert_pool),
        })
    }
}
