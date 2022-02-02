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

//! Strucs providing cosign verification capabilities
//!
//! The focus of this crate is to provide the verification capabilities of cosign,
//! not the signing one.
//!
//! Sigstore verification can be done using [`sigstore::cosign::Client`](crate::cosign::client::Client).
//! Instances of this struct can be created via the [`sigstore::cosign::ClientBuilder`](crate::cosign::client_builder::ClientBuilder).
//!
//! ## What is currently supported
//!
//! The crate implements the following verification mechanisms:
//!
//!   * Verify using a given key
//!   * Verify bundle produced by transparency log (Rekor)
//!   * Verify signature produced in keyless mode, using Fulcio Web-PKI
//!
//! Signature annotations and certificate email can be provided at verification time.
//!
//! ## Current limitations
//!
//! Fulcio integration requires the developer to provide Fulcio's certificate to
//! work.
//! The same applies to Rekor integratiom, which relies on the developer to provide
//! Rekor's public key.
//!
//! Currently the library is not capable of downloading this data from Sigstore's TUF
//! repository, like the `cosign` client does.
//!
//! This limitation is going to be addressed in the near future.
//!
//! ## Unit testing inside of our own libraries
//!
//! In case you want to mock sigstore interactions inside of your own code, you
//! can implement the [`CosignCapabilities`] trait inside of your test suite.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::errors::Result;
use crate::registry::Auth;
use crate::simple_signing::SimpleSigning;

mod bundle;
mod constants;
mod signature_layers;

pub mod client;
pub use self::client::Client;

pub mod client_builder;
pub use self::client_builder::ClientBuilder;

#[async_trait]
/// Cosign Abilities that have to be implemented by a
/// Cosign client
pub trait CosignCapabilities {
    /// Calculate the cosign image reference.
    /// This is the location cosign stores signatures.
    async fn triangulate(&mut self, image: &str, auth: &Auth) -> Result<(String, String)>;

    /// Verifies the layers of signature image produced by cosign and returns a list
    /// of [`SimpleSigning`] objects that are satisfying the constrains.
    ///
    /// When Fulcio's integration has been enabled, the returned [`SimpleSigning`]
    /// objects have been verified using the certificates bundled inside of the
    /// signature image. All these certificates have been issues by Fulcio's CA.
    ///
    /// When `public_key` is not `None`, the returned [`SimpleSigning`]
    /// objects have been signed using the specified key.
    ///
    /// When Rekor's integration is enabled, the [`SimpleSigning`] objects have
    /// been successfully verified using the Bundle object found inside of the
    /// signature image. All the Bundled objects have been verified using Rekor's
    /// signature.
    async fn verify(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &str,
        public_key: &Option<String>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<Vec<SimpleSigning>>;
}

#[cfg(test)]
mod tests {
    use crate::crypto::{self, extract_public_key_from_pem_cert, CosignVerificationKey};

    pub(crate) const REKOR_PUB_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----"#;

    pub(crate) const FULCIO_CRT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu
ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy
A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas
taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm
MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u
Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx
Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup
Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==
-----END CERTIFICATE-----"#;

    pub(crate) fn get_fulcio_public_key() -> Vec<u8> {
        extract_public_key_from_pem_cert(FULCIO_CRT_PEM.as_bytes())
            .expect("Cannot extract public key from Fulcio hard-coded cert")
    }

    pub(crate) fn get_rekor_public_key() -> CosignVerificationKey {
        crypto::new_verification_key(REKOR_PUB_KEY).expect("Cannot create test REKOR_PUB_KEY")
    }
}
