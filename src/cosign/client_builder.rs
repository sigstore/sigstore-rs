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

use pki_types::CertificateDer;
use tracing::info;

use crate::{
    cosign::client::Client,
    crypto::{CosignVerificationKey, certificate_pool::CertificatePool},
    errors::Result,
    registry::ClientConfig,
    trust::TrustRoot,
};

/// A builder that generates Client objects.
///
/// ## Rekor integration
///
/// Rekor integration can be enabled by specifying Rekor's public key.
/// This can be provided via a [`crate::trust::ManualTrustRoot`].
///
/// > Note well: the [`trust::sigstore`](crate::trust::sigstore) module provides helper structs and methods
/// > to obtain this data from the official TUF repository of the Sigstore project.
///
/// ## Fulcio integration
///
/// Fulcio integration can be enabled by specifying Fulcio's certificate.
/// This can be provided via a [`crate::trust::sigstore::ManualTrustRoot`].
///
/// > Note well: the [`trust::sigstore`](crate::trust::sigstore) module provides helper structs and methods
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
pub struct ClientBuilder<'a> {
    oci_client_config: ClientConfig,
    rekor_pub_keys: Option<BTreeMap<String, &'a [u8]>>,
    fulcio_certs: Vec<CertificateDer<'a>>,
    #[cfg(feature = "cached-client")]
    enable_registry_caching: bool,
}

impl<'a> ClientBuilder<'a> {
    /// Enable caching of data returned from remote OCI registries
    #[cfg(feature = "cached-client")]
    #[cfg_attr(docsrs, doc(cfg(feature = "cached-client")))]
    pub fn enable_registry_caching(mut self) -> Self {
        self.enable_registry_caching = true;
        self
    }

    /// Optional - Configures the roots of trust.
    ///
    /// Enables Fulcio and Rekor integration with the given trust repository.
    /// See [crate::trust::sigstore::TrustRoot] for more details on trust repositories.
    pub fn with_trust_repository<R: TrustRoot + ?Sized>(mut self, repo: &'a R) -> Result<Self> {
        let rekor_keys = repo.rekor_keys()?;
        if !rekor_keys.is_empty() {
            self.rekor_pub_keys = Some(rekor_keys);
        }
        self.fulcio_certs = repo.fulcio_certs()?;

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
        let rekor_pub_keys: Option<BTreeMap<String, CosignVerificationKey>> = self
            .rekor_pub_keys
            .map(|keys| {
                keys.iter()
                    .filter_map(
                        |(key_id, data)| match CosignVerificationKey::try_from_der(data) {
                            Ok(key) => Some((key_id.clone(), key)),
                            Err(e) => {
                                info!("Cannot parse Rekor public key with id {key_id}: {e}");
                                None
                            }
                        },
                    )
                    .collect::<BTreeMap<String, CosignVerificationKey>>()
            })
            .filter(|m| !m.is_empty());

        let fulcio_cert_pool = if self.fulcio_certs.is_empty() {
            info!("No Fulcio cert has been provided. Fulcio integration disabled");
            None
        } else {
            let cert_pool = CertificatePool::from_certificates(self.fulcio_certs, [])?;
            Some(cert_pool)
        };

        let oci_client = oci_client::client::Client::new(self.oci_client_config.clone().into());

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
            rekor_pub_keys,
            fulcio_cert_pool,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::ManualTrustRoot;

    const OLD_REKOR_ED25519_KEY_DER: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xb7, 0xca, 0xe5,
        0xa7, 0x59, 0x27, 0x1b, 0x08, 0xdf, 0x6d, 0xc5, 0xc0, 0x60, 0xf6, 0x00, 0x92, 0x7d, 0x17,
        0x88, 0xbc, 0xf5, 0xc7, 0xc3, 0xb8, 0xb7, 0x46, 0x24, 0x12, 0x18, 0x9e, 0xdb, 0x8e,
    ];

    const OLD_REKOR_ED25519_KEY_ID: &str =
        "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0";

    // Regression test for the ClientBuilder bug:
    // https://github.com/sigstore/sigstore-rs/issues/508. When the TUF trust root contains an
    // Ed25519 Rekor key, the resulting Client must have that key in its rekor_pub_keys map.
    #[test]
    fn client_builder_parses_ed25519_rekor_key() {
        let mut trust_root = ManualTrustRoot::default();
        trust_root.rekor_keys.insert(
            OLD_REKOR_ED25519_KEY_ID.to_string(),
            OLD_REKOR_ED25519_KEY_DER.to_vec(),
        );

        let client = ClientBuilder::default()
            .with_trust_repository(&trust_root)
            .expect("with_trust_repository failed")
            .build()
            .expect("build failed");

        assert!(
            client.rekor_pub_keys.is_some(),
            "Expected rekor_pub_keys to be Some after providing an Ed25519 Rekor key, \
             but it was None — the key was silently dropped. \
             Fix: use CosignVerificationKey::try_from_der(data) instead of \
             from_der(data, &SigningScheme::default()) in client_builder.rs"
        );

        let keys = client.rekor_pub_keys.unwrap();
        assert_eq!(
            keys.len(),
            1,
            "Expected exactly 1 parsed Rekor key, got {}",
            keys.len()
        );
        assert!(
            keys.contains_key(OLD_REKOR_ED25519_KEY_ID),
            "Expected parsed key to have the correct key ID"
        );
    }
}
