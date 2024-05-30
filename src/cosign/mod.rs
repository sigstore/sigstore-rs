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

//! Structs providing cosign verification capabilities
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

use std::collections::HashMap;

use async_trait::async_trait;
use tracing::warn;

use crate::errors::{Result, SigstoreApplicationConstraintsError, SigstoreVerifyConstraintsError};
use crate::registry::{Auth, PushResponse};

use crate::crypto::{CosignVerificationKey, Signature};
use crate::errors::SigstoreError;
use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use pkcs8::der::Decode;
use x509_cert::Certificate;

pub mod bundle;
pub(crate) mod constants;
pub mod signature_layers;
pub use signature_layers::SignatureLayer;

pub mod client;
pub use self::client::Client;

pub mod client_builder;
pub use self::client_builder::ClientBuilder;

pub mod verification_constraint;
pub use self::constraint::{Constraint, SignConstraintRefVec};
use self::verification_constraint::{VerificationConstraint, VerificationConstraintRefVec};

pub mod payload;
use crate::registry::oci_reference::OciReference;
pub use payload::simple_signing;

pub mod constraint;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
/// Cosign Abilities that have to be implemented by a
/// Cosign client
pub trait CosignCapabilities {
    /// Calculate the cosign image reference.
    /// This is the location cosign stores signatures.
    async fn triangulate(
        &mut self,
        image: &OciReference,
        auth: &Auth,
    ) -> Result<(OciReference, String)>;

    /// Returns the list of [`SignatureLayer`](crate::cosign::signature_layers::SignatureLayer)
    /// objects that are associated with the given signature object.
    ///
    /// Each layer is verified, to ensure it contains legitimate data.
    ///
    /// ## Layers with embedded certificate
    ///
    /// A signature can contain a certificate, this happens when signatures
    /// are produced in keyless mode or when a PKCS11 tokens are used.
    ///
    /// The certificate is added to [`SignatureLayer::certificate_signature`]
    /// only when it can be trusted.
    ///
    /// In order to trust an embedded certificate, the following prerequisites
    /// must be satisfied:
    ///
    /// * The [`sigstore::cosign::Client`](crate::cosign::client::Client) must
    ///   have been created with Rekor integration enabled (see [`crate::trust::sigstore::ManualTrustRoot`])
    /// * The [`sigstore::cosign::Client`](crate::cosign::client::Client) must
    ///   have been created with Fulcio integration enabled (see [`crate::trust::sigstore::ManualTrustRoot])
    /// * The layer must include a bundle produced by Rekor
    ///
    /// > Note well: the [`trust::sigstore`](crate::trust::sigstore) module provides helper structs and methods
    /// > to obtain this data from the official TUF repository of the Sigstore project.
    ///
    /// When the embedded certificate cannot be verified, [`SignatureLayer::certificate_signature`]
    /// is going to be `None`.
    ///
    /// ## Usage
    ///
    /// These returned objects can then be verified against
    /// [`VerificationConstraints`](crate::cosign::verification_constraint::VerificationConstraint)
    /// using the [`verify_constraints`] function.
    async fn trusted_signature_layers(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &OciReference,
    ) -> Result<Vec<SignatureLayer>>;

    /// Push [`SignatureLayer`] objects to the registry. This function will do
    /// the following steps:
    /// * Generate a series of [`oci_distribution::client::ImageLayer`]s due to
    /// the given [`Vec<SignatureLayer>`].
    /// * Generate a `OciImageManifest` of [`oci_distribution::manifest::OciManifest`]
    /// due to the given `source_image_digest` and `signature_layers`. It supports
    /// to be extended when newly published
    /// [Referrers API of OCI Registry v1.1.0](https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#listing-referrers),
    /// is prepared. At that time,
    /// [an artifact manifest](https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/artifact.md)
    /// will be created instead of [an image manifest](https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/manifest.md).
    /// * Push the generated manifest together with the layers
    /// to the `target_reference`. `target_reference` contains information
    /// about the registry, repository and tag.
    ///
    /// The parameters:
    /// - `annotations`: annotations of the generated manifest
    /// - `auth`: Credential used to access the registry
    /// - `target_reference`: target reference to push the manifest
    /// - `signature_layers`: [`SignatureLayer`] objects containing signature information
    async fn push_signature(
        &mut self,
        annotations: Option<HashMap<String, String>>,
        auth: &Auth,
        target_reference: &OciReference,
        signature_layers: Vec<SignatureLayer>,
    ) -> Result<PushResponse>;

    /// Verifies the signature produced by cosign when signing the given blob via the `cosign sign-blob` command
    ///
    /// The parameters:
    /// * `cert`: a PEM encoded x509 certificate that contains the public key used to verify the signature
    /// * `signature`: the base64 encoded signature of the blob that has to be verified
    /// * `blob`: the contents of the blob
    ///
    /// This function returns `Ok())` when the given signature has been verified, otherwise returns an `Err`.
    fn verify_blob(cert: &str, signature: &str, blob: &[u8]) -> Result<()> {
        let cert = BASE64_STD_ENGINE.decode(cert)?;
        let pem = pem::parse(cert)?;
        let cert = Certificate::from_der(pem.contents()).map_err(|e| {
            SigstoreError::PKCS8SpkiError(format!("parse der into cert failed: {e}"))
        })?;
        let spki = cert.tbs_certificate.subject_public_key_info;
        let ver_key = CosignVerificationKey::try_from(&spki)?;
        let signature = Signature::Base64Encoded(signature.as_bytes());
        ver_key.verify_signature(signature, blob)?;
        Ok(())
    }

    ///
    /// Verifies the signature produced by cosign when signing the given blob via the `cosign sign-blob` command
    ///
    /// The parameters:
    /// * `public_key`: the public key used to verify the signature, PEM encoded
    /// * `signature`: the base64 encoded signature of the blob that has to be verified
    /// * `blob`: the contents of the blob
    ///
    /// This function returns `Ok())` when the given signature has been verified, otherwise returns an `Err`.
    fn verify_blob_with_public_key(public_key: &str, signature: &str, blob: &[u8]) -> Result<()> {
        let ver_key = CosignVerificationKey::try_from_pem(public_key.as_bytes())?;
        let signature = Signature::Base64Encoded(signature.as_bytes());
        ver_key.verify_signature(signature, blob)?;
        Ok(())
    }
}

/// Given a list of trusted `SignatureLayer`, find all the constraints that
/// aren't satisfied by the layers.
///
/// If there's any unsatisfied constraints it means that the image failed
/// verification.
/// If there's no unsatisfied constraints it means that the image passed
/// verification.
///
/// Returns a `Result` with either `Ok()` for passed verification or
/// [`SigstoreVerifyConstraintsError`]
/// which contains a vector of references to unsatisfied constraints.
///
/// See the documentation of the [`cosign::verification_constraint`](crate::cosign::verification_constraint) module for more
/// details about how to define verification constraints.
pub fn verify_constraints<'a, 'b, I>(
    signature_layers: &'a [SignatureLayer],
    constraints: I,
) -> std::result::Result<(), SigstoreVerifyConstraintsError<'b>>
where
    I: Iterator<Item = &'b Box<dyn VerificationConstraint>>,
{
    let unsatisfied_constraints: VerificationConstraintRefVec = constraints.filter(|c| {
        let mut is_c_unsatisfied = true;
        signature_layers.iter().any( | sl | {
            // iterate through all layers and find if at least one layer
            // satisfies constraint. If so, we stop iterating
            match c.verify(sl) {
                Ok(is_sl_verified) => {
                    is_c_unsatisfied = !is_sl_verified;
                    is_sl_verified // if true, stop searching
                }
                Err(e) => {
                    warn!(error = ?e, constraint = ?c, "Skipping layer because constraint verification returned an error");
                    // handle errors as verification failures
                    is_c_unsatisfied = true;
                    false // keep searching to see if other layer satisfies
                }
            }
        });
        is_c_unsatisfied // if true, constraint gets filtered into result
    }).collect();

    if unsatisfied_constraints.is_empty() {
        Ok(())
    } else {
        Err(SigstoreVerifyConstraintsError {
            unsatisfied_constraints,
        })
    }
}

/// Given a [`SignatureLayer`], apply all the constraints to that.
///
/// If there's any constraints that fails to apply, it means the
/// application process fails.
/// If all constraints succeed applying, it means that this layer
/// passes applying constraints process.
///
/// Returns a `Result` with either `Ok()` for success or
/// [`SigstoreApplicationConstraintsError`]
/// which contains a vector of references to unapplied constraints.
///
/// See the documentation of the [`cosign::constraint`](crate::cosign::constraint) module for more
/// details about how to define constraints.
pub fn apply_constraints<'a, 'b, I>(
    signature_layer: &'a mut SignatureLayer,
    constraints: I,
) -> std::result::Result<(), SigstoreApplicationConstraintsError<'b>>
where
    I: Iterator<Item = &'b Box<dyn Constraint>>,
{
    let unapplied_constraints: SignConstraintRefVec = constraints
        .filter(|c| match c.add_constraint(signature_layer) {
            Ok(is_applied) => !is_applied,
            Err(e) => {
                warn!(error = ?e, constraint = ?c, "Applying constraint failed due to error");
                true
            }
        })
        .collect();

    if unapplied_constraints.is_empty() {
        Ok(())
    } else {
        Err(SigstoreApplicationConstraintsError {
            unapplied_constraints,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use webpki::types::CertificateDer;

    use super::constraint::{AnnotationMarker, PrivateKeySigner};
    use super::*;
    use crate::cosign::signature_layers::tests::build_correct_signature_layer_with_certificate;
    use crate::cosign::signature_layers::CertificateSubject;
    use crate::cosign::simple_signing::Optional;
    use crate::cosign::verification_constraint::{
        AnnotationVerifier, CertSubjectEmailVerifier, VerificationConstraintVec,
    };
    use crate::crypto::certificate_pool::CertificatePool;
    use crate::crypto::SigningScheme;

    #[cfg(feature = "test-registry")]
    use testcontainers::{core::WaitFor, runners::AsyncRunner};

    pub(crate) const REKOR_PUB_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----"#;

    const FULCIO_CRT_1_PEM: &str = r#"-----BEGIN CERTIFICATE-----
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

    const FULCIO_CRT_2_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----"#;

    #[cfg(feature = "test-registry")]
    const SIGNED_IMAGE: &str = "busybox:1.34";

    pub(crate) fn get_fulcio_cert_pool() -> CertificatePool {
        fn pem_to_der<'a>(input: &'a str) -> CertificateDer<'a> {
            let pem_cert = pem::parse(input).unwrap();
            assert_eq!(pem_cert.tag(), "CERTIFICATE");
            CertificateDer::from(pem_cert.into_contents())
        }
        let certificates = vec![pem_to_der(FULCIO_CRT_1_PEM), pem_to_der(FULCIO_CRT_2_PEM)];

        CertificatePool::from_certificates(certificates, []).unwrap()
    }

    pub(crate) fn get_rekor_public_key() -> CosignVerificationKey {
        CosignVerificationKey::from_pem(REKOR_PUB_KEY.as_bytes(), &SigningScheme::default())
            .expect("Cannot create test REKOR_PUB_KEY")
    }

    #[test]
    fn verify_constraints_all_satisfied() {
        let email = "alice@example.com".to_string();
        let issuer = "an issuer".to_string();

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("key1".into(), "value1".into());
        annotations.insert("key2".into(), "value2".into());

        let mut layers: Vec<SignatureLayer> = Vec::new();
        for _ in 0..5 {
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
            issuer: Some(issuer),
        };
        constraints.push(Box::new(vc));

        let vc = CertSubjectEmailVerifier {
            email,
            issuer: None,
        };
        constraints.push(Box::new(vc));

        let vc = AnnotationVerifier { annotations };
        constraints.push(Box::new(vc));

        verify_constraints(&layers, constraints.iter()).expect("should not return an error");
    }

    #[test]
    fn verify_constraints_none_satisfied() {
        let email = "alice@example.com".to_string();
        let issuer = "an issuer".to_string();
        let wrong_email = "bob@example.com".to_string();

        let mut layers: Vec<SignatureLayer> = Vec::new();
        for _ in 0..5 {
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
            email: wrong_email.clone(),
            issuer: Some(issuer), // correct issuer
        };
        constraints.push(Box::new(vc));

        let vc = CertSubjectEmailVerifier {
            email: wrong_email,
            issuer: None, // missing issuer, more relaxed
        };
        constraints.push(Box::new(vc));

        let err =
            verify_constraints(&layers, constraints.iter()).expect_err("we should have an err");
        assert_eq!(err.unsatisfied_constraints.len(), 2);
    }

    #[test]
    fn verify_constraints_some_unsatisfied() {
        let email = "alice@example.com".to_string();
        let issuer = "an issuer".to_string();
        let email_incorrect = "bob@example.com".to_string();

        let mut layers: Vec<SignatureLayer> = Vec::new();
        for _ in 0..5 {
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
        let satisfied_constraint = CertSubjectEmailVerifier {
            email,
            issuer: Some(issuer),
        };
        constraints.push(Box::new(satisfied_constraint));

        let unsatisfied_constraint = CertSubjectEmailVerifier {
            email: email_incorrect,
            issuer: None,
        };
        constraints.push(Box::new(unsatisfied_constraint));

        let err =
            verify_constraints(&layers, constraints.iter()).expect_err("we should have an err");
        assert_eq!(err.unsatisfied_constraints.len(), 1);
    }

    #[test]
    fn add_constrains_all_succeed() {
        let mut signature_layer = SignatureLayer::new_unsigned(
            &"test_image".parse().unwrap(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("create SignatureLayer failed");

        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .expect("create signer failed");
        let signer = PrivateKeySigner::new_with_signer(signer);

        let annotations = [(String::from("key"), String::from("value"))].into();
        let annotations = AnnotationMarker::new(annotations);

        let constrains: Vec<Box<dyn Constraint>> = vec![Box::new(signer), Box::new(annotations)];
        apply_constraints(&mut signature_layer, constrains.iter()).expect("no error should occur");
    }

    #[test]
    fn add_constrain_some_failed() {
        let mut signature_layer = SignatureLayer::new_unsigned(
            &"test_image".parse().unwrap(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("create SignatureLayer failed");

        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .expect("create signer failed");
        let signer = PrivateKeySigner::new_with_signer(signer);
        let another_signer_of_same_layer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .expect("create signer failed");
        let another_signer_of_same_layer =
            PrivateKeySigner::new_with_signer(another_signer_of_same_layer);

        let annotations = [(String::from("key"), String::from("value"))].into();
        let annotations = AnnotationMarker::new(annotations);

        let constrains: Vec<Box<dyn Constraint>> = vec![
            Box::new(signer),
            Box::new(annotations),
            Box::new(another_signer_of_same_layer),
        ];
        apply_constraints(&mut signature_layer, constrains.iter())
            .expect_err("no error should occur");
    }

    #[cfg(feature = "test-registry")]
    #[rstest::rstest]
    #[case(SigningScheme::RSA_PSS_SHA256(2048))]
    #[case(SigningScheme::RSA_PSS_SHA384(2048))]
    #[case(SigningScheme::RSA_PSS_SHA512(2048))]
    #[case(SigningScheme::RSA_PKCS1_SHA256(2048))]
    #[case(SigningScheme::RSA_PKCS1_SHA384(2048))]
    #[case(SigningScheme::RSA_PKCS1_SHA512(2048))]
    #[case(SigningScheme::ECDSA_P256_SHA256_ASN1)]
    #[case(SigningScheme::ECDSA_P384_SHA384_ASN1)]
    #[case(SigningScheme::ED25519)]
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_verify_image(#[case] signing_scheme: SigningScheme) {
        let test_container = registry_image()
            .start()
            .await
            .expect("failed to start registry");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("failed to get port");

        let mut client = ClientBuilder::default()
            .enable_registry_caching()
            .with_oci_client_config(crate::registry::ClientConfig {
                protocol: crate::registry::ClientProtocol::HttpsExcept(vec![format!(
                    "localhost:{}",
                    port
                )]),
                ..Default::default()
            })
            .build()
            .expect("failed to create oci client");

        let image_ref = format!("localhost:{}/{}", port, SIGNED_IMAGE)
            .parse::<OciReference>()
            .expect("failed to parse reference");
        prepare_image_to_be_signed(&mut client, &image_ref).await;

        let (cosign_signature_image, source_image_digest) = client
            .triangulate(&image_ref, &crate::registry::Auth::Anonymous)
            .await
            .expect("get manifest failed");
        let mut signature_layer = SignatureLayer::new_unsigned(&image_ref, &source_image_digest)
            .expect("create SignatureLayer failed");
        let signer = signing_scheme
            .create_signer()
            .expect("create signer failed");
        let pubkey = signer
            .to_sigstore_keypair()
            .expect("to keypair failed")
            .public_key_to_pem()
            .expect("derive public key failed");

        let signer = PrivateKeySigner::new_with_signer(signer);
        if !signer
            .add_constraint(&mut signature_layer)
            .expect("sign SignatureLayer failed")
        {
            panic!("failed to sign SignatureLayer");
        };

        client
            .push_signature(
                None,
                &Auth::Anonymous,
                &cosign_signature_image,
                vec![signature_layer],
            )
            .await
            .expect("push signature failed");

        dbg!("start to verify");

        let (cosign_image, manifest_digest) = client
            .triangulate(&image_ref, &Auth::Anonymous)
            .await
            .expect("triangulate failed");
        let signature_layers = client
            .trusted_signature_layers(&Auth::Anonymous, &manifest_digest, &cosign_image)
            .await
            .expect("get trusted signature layers failed");
        let pk_verifier =
            verification_constraint::PublicKeyVerifier::new(pubkey.as_bytes(), &signing_scheme)
                .expect("create PublicKeyVerifier failed");
        assert_eq!(signature_layers.len(), 1);
        let res = pk_verifier
            .verify(&signature_layers[0])
            .expect("failed to verify");
        assert!(res);
    }

    #[cfg(feature = "test-registry")]
    async fn prepare_image_to_be_signed(client: &mut Client, image_ref: &OciReference) {
        let data = client
            .registry_client
            .pull(
                &SIGNED_IMAGE.parse().expect("failed to parse image ref"),
                &oci_distribution::secrets::RegistryAuth::Anonymous,
                vec![oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE],
            )
            .await
            .expect("pull test image failed");

        client
            .registry_client
            .push(
                &image_ref.oci_reference,
                &data.layers[..],
                data.config.clone(),
                &oci_distribution::secrets::RegistryAuth::Anonymous,
                None,
            )
            .await
            .expect("push test image failed");
    }

    #[cfg(feature = "test-registry")]
    fn registry_image() -> testcontainers::GenericImage {
        testcontainers::GenericImage::new("docker.io/library/registry", "2")
            .with_wait_for(WaitFor::message_on_stderr("listening on "))
    }
}
