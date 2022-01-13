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

use anyhow::Result;
use tracing::info;

use super::client::Client;
use crate::crypto;
use crate::registry::ClientConfig;

/// A builder that generates Client objects.
///
/// ## Rekor integration
///
/// Rekor integration can be enabled by specifying Rekor's public key.
/// This can be provided via the [`ClientBuilder::with_rekor_pub_key`] method.
///
/// > Note well: currently this library is not able to retrieve the key from Sigstore's
/// > TUF repository like `cosign` does. This will be done in the near future.
///
/// ## Fulcio integration
///
/// Fulcio integration can be enabled by specifying Fulcio's certificate.
/// This can be provided via the [`ClientBuilder::with_fulcio_cert`] method.
///
/// > Note well: currently this library is not able to retrieve the certificate from Sigstore's
/// > TUF repository like `cosign` does. This will be done in the near future.
#[derive(Default)]
pub struct ClientBuilder {
    client_config: ClientConfig,
    rekor_pub_key: Option<String>,
    fulcio_cert: Option<Vec<u8>>,
    cert_email: Option<String>,
}

impl ClientBuilder {
    /// Specify the public key used by Rekor.
    ///
    /// Currently this library is not able to retrieve the key from Sigstore's
    /// TUF repository like `cosign` does. This will be done in the near future.
    ///
    /// In the meantime, end users of the library can fetch the key in a secure
    /// way by using `cosign initialize`.
    /// This will place the key under `~/.sigstore/root/targets/rekor.pub`.
    pub fn with_rekor_pub_key(mut self, key: &str) -> Self {
        self.rekor_pub_key = Some(key.to_string());
        self
    }

    /// Specify the certificate used by Fulcio.
    ///
    /// Currently this library is not able to retrieve the certificate from Sigstore's
    /// TUF repository like `cosign` does. This will be done in the near future.
    ///
    /// In the meantime, end users of the library can fetch the certificate in a secure
    /// way by using `cosign initialize`.
    /// This will place the key under `~/.sigstore/root/targets/fulcio.crt.pem`.
    pub fn with_fulcio_cert(mut self, cert: &[u8]) -> Self {
        self.fulcio_cert = Some(cert.to_owned());
        self
    }

    pub fn with_client_config(mut self, config: ClientConfig) -> Self {
        self.client_config = config;
        self
    }

    /// Optional: the email expected in a valid fulcio cert
    pub fn with_cert_email(mut self, cert_email: Option<&str>) -> Self {
        self.cert_email = cert_email.map(String::from);
        self
    }

    pub fn build(self) -> Result<Client> {
        let rekor_pub_key = match self.rekor_pub_key {
            None => {
                info!("rekor public key not provided");
                None
            }
            Some(der) => Some(crypto::new_verification_key(&der)?),
        };

        let fulcio_pub_key_der = match self.fulcio_cert {
            None => {
                info!("The fulcio cert has not been provided");
                None
            }
            Some(cert) => Some(crypto::extract_public_key_from_pem_cert(&cert)?),
        };

        let cert_email = self.cert_email.clone();

        let oci_client = oci_distribution::client::Client::new(self.client_config.clone().into());
        Ok(Client {
            registry_client: Box::new(crate::registry::OciClient {
                registry_client: oci_client,
            }),
            rekor_pub_key,
            fulcio_pub_key_der,
            cert_email,
        })
    }
}
