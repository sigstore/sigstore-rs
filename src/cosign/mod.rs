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
//! ## Unit testing inside of our own libraries
//!
//! In case you want to mock sigstore interactions inside of your own code, you
//! can implement the [`CosignCapabilities`] trait inside of your test suite.

use async_trait::async_trait;
use tracing::warn;

use crate::errors::{Result, SigstoreError};
use crate::registry::Auth;

mod bundle;
pub(crate) mod constants;
pub mod signature_layers;
pub use signature_layers::SignatureLayer;

pub mod client;
pub use self::client::Client;

pub mod client_builder;
pub use self::client_builder::ClientBuilder;

pub mod verification_constraint;
use verification_constraint::VerificationConstraintVec;

#[async_trait]
/// Cosign Abilities that have to be implemented by a
/// Cosign client
pub trait CosignCapabilities {
    /// Calculate the cosign image reference.
    /// This is the location cosign stores signatures.
    async fn triangulate(&mut self, image: &str, auth: &Auth) -> Result<(String, String)>;

    /// Returns the list of [`SignatureLayer`](crate::cosign::signature_layers::SignatureLayer)
    /// objects that are associated with the given signature object.
    ///
    /// When Fulcio's integration has been enabled, the returned `SignatureLayer`
    /// objects have been verified using the certificates bundled inside of the
    /// signature image. All these certificates have been issued by Fulcio's CA.
    ///
    /// When Rekor's integration is enabled, the [`SignatureLayer`] objects have
    /// been successfully verified using the Bundle object found inside of the
    /// signature image. All the Bundled objects have been verified using Rekor's
    /// signature.
    ///
    /// These returned objects can then be filtered using the [`filter_signature_layers`]
    /// function.
    async fn trusted_signature_layers(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &str,
    ) -> Result<Vec<SignatureLayer>>;
}

/// Given a list of trusted `SignatureLayer`, find all the layers that satisfy
/// the given constraints.
///
/// See the documentation of the [`cosign::verification_constraint`](crate::cosign::verification_constraint) module for more
/// details about how to define verification constraints.
pub fn filter_signature_layers(
    signature_layers: &[SignatureLayer],
    constraints: VerificationConstraintVec,
) -> Result<Vec<SignatureLayer>> {
    let layers: Vec<SignatureLayer> = signature_layers
            .iter()
            .filter(|sl| {
                let is_a_match = if constraints.is_empty() {
                    true
                } else {
                    !constraints.iter().any(|c| {
                        match c.verify(sl) {
                            Ok(verification_passed) => !verification_passed,
                            Err(e) => {
                                warn!(error = ?e, constraint = ?c, "Skipping layer because constraint verification returned an error");
                                // handle errors as verification failures
                                false
                            }
                        }
                    })
                };
                is_a_match
            })
            .cloned()
            .collect();

    if layers.is_empty() {
        Err(SigstoreError::SigstoreNoVerifiedLayer)
    } else {
        Ok(layers)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;

    use super::*;
    use crate::cosign::signature_layers::tests::build_correct_signature_layer_with_certificate;
    use crate::cosign::signature_layers::CertificateSubject;
    use crate::cosign::verification_constraint::{AnnotationVerifier, CertSubjectEmailVerifier};
    use crate::crypto::{self, extract_public_key_from_pem_cert, CosignVerificationKey};
    use crate::simple_signing::Optional;

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

    #[test]
    fn filter_signature_layers_matches() {
        let email = "alice@example.com".to_string();
        let issuer = "an issuer".to_string();

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("key1".into(), "value1".into());
        annotations.insert("key2".into(), "value2".into());

        let mut layers: Vec<SignatureLayer> = Vec::new();
        let expected_matches = 5;
        for _ in 0..expected_matches {
            let mut sl = build_correct_signature_layer_with_certificate();
            let mut cert_signature = sl.certificate_signature.unwrap();
            let cert_subj = CertificateSubject::Email(email.clone());
            cert_signature.issuer = Some(issuer.clone());
            cert_signature.subject = cert_subj;
            sl.certificate_signature = Some(cert_signature);

            let mut extra: HashMap<String, serde_json::Value> = annotations
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect();
            extra.insert("something extra".into(), json!("value extra"));

            let mut simple_signing = sl.simple_signing;
            let optional = Optional {
                creator: Some("test".into()),
                timestamp: None,
                extra,
            };
            simple_signing.optional = Some(optional);
            sl.simple_signing = simple_signing;

            layers.push(sl);
        }

        let mut constraints: VerificationConstraintVec = Vec::new();
        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: Some(issuer.clone()),
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: None,
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let vc = AnnotationVerifier {
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let matches = filter_signature_layers(&layers, constraints)
            .expect("Should not have returned an error");
        assert_eq!(matches.len(), expected_matches);
    }

    #[test]
    fn filter_signature_layers_no_matches() {
        let email = "alice@example.com".to_string();
        let issuer = "an issuer".to_string();

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("key1".into(), "value1".into());
        annotations.insert("key2".into(), "value2".into());

        let mut layers: Vec<SignatureLayer> = Vec::new();
        let expected_matches = 5;
        for _ in 0..expected_matches {
            let mut sl = build_correct_signature_layer_with_certificate();
            let mut cert_signature = sl.certificate_signature.unwrap();
            let cert_subj = CertificateSubject::Email(email.clone());
            cert_signature.issuer = Some(issuer.clone());
            cert_signature.subject = cert_subj;
            sl.certificate_signature = Some(cert_signature);

            let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
            extra.insert("something extra".into(), json!("value extra"));

            let mut simple_signing = sl.simple_signing;
            let optional = Optional {
                creator: Some("test".into()),
                timestamp: None,
                extra,
            };
            simple_signing.optional = Some(optional);
            sl.simple_signing = simple_signing;

            layers.push(sl);
        }

        let mut constraints: VerificationConstraintVec = Vec::new();
        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: Some(issuer.clone()),
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: None,
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let vc = AnnotationVerifier {
            annotations: annotations.clone(),
        };
        constraints.push(Box::new(vc));

        let error =
            filter_signature_layers(&layers, constraints).expect_err("Should have god an error");
        let found = match error {
            SigstoreError::SigstoreNoVerifiedLayer => true,
            _ => false,
        };
        assert!(found, "Didn't get the expected error, got {}", error);
    }
}
