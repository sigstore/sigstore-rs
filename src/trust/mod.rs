//
// Copyright 2024 The Sigstore Authors.
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

use async_trait::async_trait;
use webpki::types::CertificateDer;

#[cfg(feature = "sigstore-trust-root")]
pub mod sigstore;

/// A `TrustRoot` owns all key material necessary for establishing a root of trust.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait TrustRoot: Send + Sync {
    async fn fulcio_certs(&self) -> crate::errors::Result<Vec<CertificateDer>>;
    async fn rekor_keys(&self) -> crate::errors::Result<Vec<&[u8]>>;
}

/// A `ManualTrustRoot` is a [TrustRoot] with out-of-band trust materials.
/// As it does not establish a trust root with TUF, users must initialize its materials themselves.
#[derive(Debug, Default)]
pub struct ManualTrustRoot<'a> {
    pub fulcio_certs: Option<Vec<CertificateDer<'a>>>,
    pub rekor_keys: Option<Vec<Vec<u8>>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl TrustRoot for ManualTrustRoot<'_> {
    #[cfg(not(target_arch = "wasm32"))]
    async fn fulcio_certs(&self) -> crate::errors::Result<Vec<CertificateDer>> {
        Ok(match &self.fulcio_certs {
            Some(certs) => certs.clone(),
            None => Vec::new(),
        })
    }

    async fn rekor_keys(&self) -> crate::errors::Result<Vec<&[u8]>> {
        Ok(match &self.rekor_keys {
            Some(keys) => keys.iter().map(|k| k.as_slice()).collect(),
            None => Vec::new(),
        })
    }
}
