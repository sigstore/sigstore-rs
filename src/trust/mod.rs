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

use std::collections::BTreeMap;

use pki_types::CertificateDer;

#[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
#[cfg(feature = "sigstore-trust-root")]
pub mod sigstore;

/// A `TrustRoot` owns all key material necessary for establishing a root of trust.
pub trait TrustRoot {
    fn fulcio_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'_>>>;
    fn rekor_keys(&self) -> crate::errors::Result<BTreeMap<String, &[u8]>>;
    fn ctfe_keys(&self) -> crate::errors::Result<BTreeMap<String, &[u8]>>;
    fn tsa_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'_>>>;

    /// Get TSA certificates with their validity periods.
    /// Returns tuples of (certificate, valid_from, valid_to).
    /// Default implementation returns None for validity periods.
    #[allow(clippy::type_complexity)] // TODO fix return type
    fn tsa_certs_with_validity(
        &self,
    ) -> crate::errors::Result<
        Vec<(
            CertificateDer<'_>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        )>,
    > {
        // Default implementation: just return certs without validity info
        let certs = self.tsa_certs()?;
        Ok(certs.into_iter().map(|c| (c, None, None)).collect())
    }

    /// Get TSA root certificates for chain validation.
    /// Returns the root certificates (last cert in each chain) that should be used
    /// as trust anchors when validating TSA certificate chains.
    /// Default implementation returns empty vector.
    fn tsa_root_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'_>>> {
        Ok(vec![])
    }

    /// Get TSA intermediate certificates (all certs between leaf and root).
    /// These should be passed as untrusted intermediates when validating TSA certificate chains.
    /// Default implementation returns empty vector.
    fn tsa_intermediate_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'_>>> {
        Ok(vec![])
    }
}

/// A `ManualTrustRoot` is a [TrustRoot] with out-of-band trust materials.
/// As it does not establish a trust root with TUF, users must initialize its materials themselves.
#[derive(Debug, Default)]
pub struct ManualTrustRoot<'a> {
    pub fulcio_certs: Vec<CertificateDer<'a>>,
    pub rekor_keys: BTreeMap<String, Vec<u8>>,
    pub ctfe_keys: BTreeMap<String, Vec<u8>>,
    pub tsa_certs: Vec<CertificateDer<'a>>,
}

impl<'a> TrustRoot for ManualTrustRoot<'a> {
    fn fulcio_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'a>>> {
        Ok(self.fulcio_certs.clone())
    }

    fn rekor_keys(&self) -> crate::errors::Result<BTreeMap<String, &[u8]>> {
        Ok(self
            .rekor_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.as_slice()))
            .collect())
    }

    fn ctfe_keys(&self) -> crate::errors::Result<BTreeMap<String, &[u8]>> {
        Ok(self
            .ctfe_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.as_slice()))
            .collect())
    }

    fn tsa_certs(&self) -> crate::errors::Result<Vec<CertificateDer<'a>>> {
        Ok(self.tsa_certs.clone())
    }
}
