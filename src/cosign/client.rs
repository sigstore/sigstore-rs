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

use async_trait::async_trait;
use std::collections::HashMap;
use x509_parser::{traits::FromDer, x509::SubjectPublicKeyInfo};

use super::{
    constants::SIGSTORE_OCI_MEDIA_TYPE,
    signature_layers::{build_signature_layers, SignatureLayer},
    CosignCapabilities,
};
use crate::crypto::CosignVerificationKey;
use crate::errors::{Result, SigstoreError};
use crate::registry::Auth;
use crate::simple_signing::SimpleSigning;

/// Cosign Client
///
/// Instances of `Client` can be built via [`sigstore::cosign::ClientBuilder`](crate::cosign::ClientBuilder).
pub struct Client {
    pub(crate) registry_client: Box<dyn crate::registry::ClientCapabilities>,
    pub(crate) rekor_pub_key: Option<CosignVerificationKey>,
    pub(crate) fulcio_pub_key_der: Option<Vec<u8>>,
    pub(crate) cert_email: Option<String>,
}

#[async_trait]
impl CosignCapabilities for Client {
    async fn triangulate(&mut self, image: &str, auth: &Auth) -> Result<(String, String)> {
        let image_reference: oci_distribution::Reference =
            image
                .parse()
                .map_err(|_| SigstoreError::OciReferenceNotValidError {
                    reference: image.to_string(),
                })?;

        let manifest_digest = self
            .registry_client
            .fetch_manifest_digest(&image_reference, &auth.into())
            .await?;

        let sign = format!(
            "{}/{}:{}.sig",
            image_reference.registry(),
            image_reference.repository(),
            manifest_digest.replace(":", "-")
        );
        let reference = sign
            .parse()
            .map_err(|_| SigstoreError::OciReferenceNotValidError {
                reference: image.to_string(),
            })?;

        Ok((reference, manifest_digest))
    }

    async fn verify(
        &mut self,
        auth: &Auth,
        source_image_digest: &str,
        cosign_image: &str,
        public_key: &Option<String>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<Vec<SimpleSigning>> {
        let (manifest, layers) = self.fetch_manifest_and_layers(auth, cosign_image).await?;

        let fulcio_pub_key = match &self.fulcio_pub_key_der {
            None => None,
            Some(der) => {
                let (_, key) = SubjectPublicKeyInfo::from_der(der)?;
                Some(key)
            }
        };

        let verification_key: Option<CosignVerificationKey> = match public_key {
            Some(key) => Some(crate::crypto::new_verification_key(key)?),
            None => None,
        };

        let signature_layers = build_signature_layers(
            &manifest,
            &layers,
            self.rekor_pub_key.as_ref(),
            fulcio_pub_key.as_ref(),
            self.cert_email.as_ref(),
        );

        let verified_signatures = self.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            source_image_digest,
            verification_key.as_ref(),
            &annotations.unwrap_or_default(),
        );
        Ok(verified_signatures)
    }
}

impl Client {
    /// Internal helper method used to fetch data from an OCI registry
    async fn fetch_manifest_and_layers(
        &mut self,
        auth: &Auth,
        cosign_image: &str,
    ) -> Result<(
        oci_distribution::manifest::OciManifest,
        Vec<oci_distribution::client::ImageLayer>,
    )> {
        let cosign_image_reference: oci_distribution::Reference =
            cosign_image
                .parse()
                .map_err(|_| SigstoreError::OciReferenceNotValidError {
                    reference: cosign_image.to_string(),
                })?;

        let oci_auth: oci_distribution::secrets::RegistryAuth = auth.into();

        let (manifest, _) = self
            .registry_client
            .pull_manifest(&cosign_image_reference, &oci_auth)
            .await?;
        let image_data = self
            .registry_client
            .pull(
                &cosign_image_reference,
                &oci_auth,
                vec![SIGSTORE_OCI_MEDIA_TYPE],
            )
            .await?;

        Ok((manifest, image_data.layers))
    }

    /// The heart of the verification code. This is where all the checks are done
    /// against the SignatureLayer objects found inside of the OCI registry.
    ///
    /// The method returns a list of SimpleSigning object satisfying the requirements.
    /// The list is empty if no SimpleSigning object satisfied the requirements.
    fn find_simple_signing_objects_satisfying_constraints(
        &self,
        signature_layers: &[SignatureLayer],
        source_image_digest: &str,
        verification_key: Option<&CosignVerificationKey>,
        annotations: &HashMap<String, String>,
    ) -> Vec<SimpleSigning> {
        let verified_signatures: Vec<SimpleSigning> = signature_layers
            .iter()
            .filter_map(|sl| {
                // find all the layers that have a signature that
                // can be either verified with the supplied verification_key
                // or with of the trusted bundled certificates.
                // Then convert them into SimpleSigning objects
                if sl.verified(verification_key) {
                    Some(sl.simple_signing.clone())
                } else {
                    None
                }
            })
            .filter(|ss| {
                // ensure given annotations are respected
                ss.satisfies_annotations(annotations)
            })
            .filter(|ss| {
                // ensure the manifest digest mentioned by the signed SimpleSigning
                // object matches the value of the OCI object we're verifying
                ss.satisfies_manifest_digest(source_image_digest)
            })
            .collect();
        verified_signatures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosign::signature_layers::tests::build_correct_signature_layer_without_bundle;
    use crate::cosign::tests::{FULCIO_CRT_PEM, REKOR_PUB_KEY};
    use crate::{
        crypto::{self},
        mock_client::test::MockOciClient,
    };

    fn build_test_client(mock_client: MockOciClient) -> Client {
        let rekor_pub_key = crypto::new_verification_key(REKOR_PUB_KEY).unwrap();

        Client {
            registry_client: Box::new(mock_client),
            rekor_pub_key: Some(rekor_pub_key),
            fulcio_pub_key_der: Some(FULCIO_CRT_PEM.as_bytes().to_vec()),
            cert_email: None,
        }
    }

    #[tokio::test]
    async fn triangulate_sigstore_object() {
        let image = "docker.io/busybox:latest";
        let image_digest =
            String::from("sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b");
        let expected_image = "docker.io/library/busybox:sha256-f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b.sig".parse().unwrap();
        let mock_client = MockOciClient {
            fetch_manifest_digest_response: Some(Ok(image_digest.clone())),
            pull_response: None,
            pull_manifest_response: None,
        };
        let mut cosign_client = build_test_client(mock_client);

        let reference = cosign_client
            .triangulate(image, &crate::registry::Auth::Anonymous)
            .await;

        assert!(reference.is_ok());
        assert_eq!(reference.unwrap(), (expected_image, image_digest));
    }

    #[test]
    fn find_simple_signing_object_when_verification_key_and_no_annotations_are_provided() {
        let (signature_layer, verification_key) = build_correct_signature_layer_without_bundle();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let signature_layers = vec![signature_layer];

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let cosign_client = build_test_client(mock_client);

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            Some(&verification_key),
            &annotations,
        );
        assert!(!actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_no_signature_matches_the_given_key() {
        let (signature_layer, _) = build_correct_signature_layer_without_bundle();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let signature_layers = vec![signature_layer];

        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let cosign_client = build_test_client(mock_client);

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            Some(&verification_key),
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_annotations_are_not_satisfied() {
        let (signature_layer, verification_key) = build_correct_signature_layer_without_bundle();
        let source_image_digest = signature_layer
            .simple_signing
            .critical
            .image
            .docker_manifest_digest
            .clone();
        let signature_layers = vec![signature_layer];

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert("env".into(), "prod".into());

        let mock_client = MockOciClient::default();
        let cosign_client = build_test_client(mock_client);

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            Some(&verification_key),
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_simple_signing_digest_does_not_match_the_expected_one(
    ) {
        let (signature_layer, verification_key) = build_correct_signature_layer_without_bundle();
        let source_image_digest = "this is a different value";
        let signature_layers = vec![signature_layer];

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let cosign_client = build_test_client(mock_client);

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            Some(&verification_key),
            &annotations,
        );
        assert!(actual.is_empty());
    }

    #[test]
    fn find_simple_signing_object_no_matches_when_no_signature_layer_exists() {
        let source_image_digest = "something";
        let signature_layers: Vec<SignatureLayer> = Vec::new();

        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKhD7F5OKy77Z582Y6h0u1J3GNA+
kvUsh4eKpd1lwkDAzfFDs7yXEExsEkPPuiQJBelDT68n7PDIWB/QEY7mrA==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let annotations: HashMap<String, String> = HashMap::new();

        let mock_client = MockOciClient::default();
        let cosign_client = build_test_client(mock_client);

        let actual = cosign_client.find_simple_signing_objects_satisfying_constraints(
            &signature_layers,
            &source_image_digest,
            Some(&verification_key),
            &annotations,
        );
        assert!(actual.is_empty());
    }
}
