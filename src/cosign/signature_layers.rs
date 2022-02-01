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

use oci_distribution::client::ImageLayer;
use std::{collections::HashMap, fmt};
use tracing::{debug, info, warn};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem, x509::SubjectPublicKeyInfo};

use super::bundle::Bundle;
use super::constants::{
    SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION,
};
use crate::{
    crypto::{verify_certificate_can_be_trusted, CosignVerificationKey},
    errors::{Result, SigstoreError},
    simple_signing::SimpleSigning,
};

/// This is an internal object that contains all the data about a
/// SimpleSigning object.
///
/// The struct provides some helper methods that can be used at verification
/// time.
///
/// Note well, the information needed to build a SignatureLayer are spread over
/// two places:
///   * The manifest of the signature object created by cosign
///   * One or more SIGSTORE_OCI_MEDIA_TYPE layers
#[derive(Clone)]
pub(crate) struct SignatureLayer {
    pub simple_signing: SimpleSigning,
    pub oci_digest: String,
    certificate_key: Option<CosignVerificationKey>,
    signature: String,
    bundle: Option<Bundle>,
    raw_data: Vec<u8>,
}

impl fmt::Display for SignatureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = format!(
            r#"SignatureLayer
- digest: {}
- signature: {:?}
- bundle: {:?},
- certificate key: {:?}
- Simple Signing:
  {}
---"#,
            self.oci_digest, self.signature, self.bundle, self.certificate_key, self.simple_signing,
        );

        write!(f, "{}", msg)
    }
}

impl SignatureLayer {
    /// Create a SignatureLayer that can be considered trusted.
    ///
    /// Params:
    ///   * `descriptor`: the metatada of the layer, taken from the OCI manifest associated
    ///     with the Sigstore object
    ///   * `layer`: the data referenced by the descriptor
    ///   * `rekor_pub_key`: the public key of Rekor, used to verify `bundle`
    ///     entries
    ///   * `fulcio_pub_key`: the public key provided by Fulcio's certificate.
    ///     Used to verify the `certificate` entries
    ///   * `cert_email`: optional, the SAN to look for inside of trusted
    ///     certificates issued by Fulcio
    ///
    /// **Note well:** the certificate and bundle added to the final SignatureLayer
    /// object are to be considered **trusted** and **verified**, according to
    /// the parameters provided to this method.
    pub(crate) fn new(
        descriptor: &oci_distribution::manifest::OciDescriptor,
        layer: &oci_distribution::client::ImageLayer,
        rekor_pub_key: Option<&CosignVerificationKey>,
        fulcio_pub_key: Option<&SubjectPublicKeyInfo>,
        cert_email: Option<&String>,
    ) -> Result<SignatureLayer> {
        if descriptor.media_type != SIGSTORE_OCI_MEDIA_TYPE {
            return Err(SigstoreError::SigstoreMediaTypeNotFoundError);
        }

        if layer.media_type != SIGSTORE_OCI_MEDIA_TYPE {
            return Err(SigstoreError::SigstoreMediaTypeNotFoundError);
        }

        let layer_digest = layer.clone().sha256_digest();
        if descriptor.digest != layer_digest {
            return Err(SigstoreError::SigstoreLayerDigestMismatchError);
        }

        let simple_signing: SimpleSigning = serde_json::from_slice(&layer.data).map_err(|e| {
            SigstoreError::UnexpectedError(format!(
                "Cannot convert layer data into SimpleSigning object: {:?}",
                e
            ))
        })?;

        let annotations = descriptor.annotations.clone().unwrap_or_default();

        let signature = Self::get_signature_from_annotations(&annotations)?;
        let bundle = Self::get_bundle_from_annotations(&annotations, rekor_pub_key)?;
        let certificate_key = Self::get_certificate_from_annotations(
            &annotations,
            fulcio_pub_key,
            bundle.as_ref(),
            cert_email,
        )?;

        Ok(SignatureLayer {
            oci_digest: descriptor.digest.clone(),
            raw_data: layer.data.clone(),
            simple_signing,
            signature,
            bundle,
            certificate_key,
        })
    }

    fn get_signature_from_annotations(annotations: &HashMap<String, String>) -> Result<String> {
        let signature: String = annotations
            .get(SIGSTORE_SIGNATURE_ANNOTATION)
            .cloned()
            .ok_or(SigstoreError::SigstoreAnnotationNotFoundError)?;
        Ok(signature)
    }

    fn get_bundle_from_annotations(
        annotations: &HashMap<String, String>,
        rekor_pub_key: Option<&CosignVerificationKey>,
    ) -> Result<Option<Bundle>> {
        let bundle = match annotations.get(SIGSTORE_BUNDLE_ANNOTATION) {
            Some(value) => match rekor_pub_key {
                Some(key) => Some(Bundle::new_verified(value, key)?),
                None => {
                    info!(bundle = ?value, "Ignoring bundle, rekor public key not provided to verification client");
                    None
                }
            },
            None => None,
        };
        Ok(bundle)
    }

    fn get_certificate_from_annotations(
        annotations: &HashMap<String, String>,
        fulcio_pub_key: Option<&SubjectPublicKeyInfo>,
        bundle: Option<&Bundle>,
        cert_email: Option<&String>,
    ) -> Result<Option<CosignVerificationKey>> {
        let certificate_key = match annotations.get(SIGSTORE_CERT_ANNOTATION) {
            Some(value) => match fulcio_pub_key {
                Some(key) => Some(verify_certificate_and_extract_public_key(
                    value.as_bytes(),
                    key,
                    cert_email,
                    bundle,
                )?),
                None => {
                    info!(bundle = ?value, "Ignoring certificate signature, fulcio certificate not provided to verification client");
                    None
                }
            },
            None => None,
        };
        Ok(certificate_key)
    }

    /// Checks whether the SignatureLayer's can be verified using the given `verification_key`.
    ///
    /// When no `verification_key` is given, the verification will be done using the Certificate
    /// and the Bundle that are eventually part of the SignatureLayer. If none of them is available,
    /// the verification will fail.
    ///
    /// The given `verification_key` has precedence over the eventually available Certificate and
    /// Bundle.
    pub fn verified(&self, verification_key: Option<&CosignVerificationKey>) -> bool {
        if verification_key.is_none() && self.certificate_key.is_none() {
            warn!(digest=self.oci_digest.as_str(), "Layer cannot be verified: no verification key provided and no trusted certificate key associated found");
            return false;
        }

        if let Some(vk) = verification_key {
            return self.is_signed_by_key(vk);
        }

        if let Some(vk) = self.certificate_key {
            return self.is_signed_by_key(&vk);
        }

        false
    }

    /// Given a Cosign public key, check whether one of the signatures embedded into
    /// the SignatureLayer has been produced by the given key
    fn is_signed_by_key(&self, verification_key: &CosignVerificationKey) -> bool {
        match crate::crypto::verify_signature(verification_key, &self.signature, &self.raw_data) {
            Ok(_) => true,
            Err(e) => {
                debug!(signature=self.signature.as_str(), reason=?e, "Cannot verify signature with the given key");
                false
            }
        }
    }
}

/// Creates a list of [`SignatureLayer`] objects by inspecting
/// the given OCI manifest and its associated layers.
///
/// **Note well:** when Rekor and Fulcio data has been provided, the
/// returned `SignatureLayer` is guaranteed to be
/// verified using the given Rekor and Fulcio keys.
/// When a certificate email is given, this is used to ensure
/// the bundled certificate issued by Fulcio has this identity
/// associated.
pub(crate) fn build_signature_layers(
    manifest: &oci_distribution::manifest::OciManifest,
    layers: &[oci_distribution::client::ImageLayer],
    rekor_pub_key: Option<&CosignVerificationKey>,
    fulcio_pub_key: Option<&SubjectPublicKeyInfo>,
    cert_email: Option<&String>,
) -> Vec<SignatureLayer> {
    let mut signature_layers: Vec<SignatureLayer> = Vec::new();

    for manifest_layer in &manifest.layers {
        let matching_layer: Option<&oci_distribution::client::ImageLayer> =
            layers.iter().find(|l| {
                let tmp: ImageLayer = (*l).clone();
                tmp.sha256_digest() == manifest_layer.digest
            });
        if let Some(layer) = matching_layer {
            match SignatureLayer::new(
                manifest_layer,
                layer,
                rekor_pub_key,
                fulcio_pub_key,
                cert_email,
            ) {
                Ok(sl) => signature_layers.push(sl),
                Err(e) => {
                    info!(error = ?e, "Skipping OCI layer because of error");
                }
            }
        }
    }

    signature_layers
}

/// Ensure the given certificate can be trusted, then extracts
/// its public key
fn verify_certificate_and_extract_public_key(
    cert_raw: &[u8],
    fulcio_pub_key: &SubjectPublicKeyInfo,
    cert_email: Option<&String>,
    trusted_bundle: Option<&Bundle>,
) -> Result<CosignVerificationKey> {
    if trusted_bundle.is_none() {
        return Err(SigstoreError::SigstoreRekorBundleNotFoundError);
    }
    let (_, pem) = parse_x509_pem(cert_raw)?;
    let (_, cert) = parse_x509_certificate(&pem.contents)?;
    let integrated_time = trusted_bundle.unwrap().payload.integrated_time;
    verify_certificate_can_be_trusted(&cert, fulcio_pub_key, integrated_time, cert_email)?;

    let key = crate::crypto::new_verification_key_from_public_key_der(cert.public_key().raw)?;
    Ok(key)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use x509_parser::traits::FromDer;

    use crate::{
        cosign::tests::{get_fulcio_public_key, get_rekor_public_key},
        crypto::{extract_public_key_from_pem_cert, new_verification_key_from_public_key_der},
    };

    pub(crate) fn build_correct_signature_layer_without_bundle(
    ) -> (SignatureLayer, CosignVerificationKey) {
        let public_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENptdY/l3nB0yqkXLBWkZWQwo6+cu
OSWS1X9vPavpiQOoTTGC0xX57OojUadxF1cdQmrsiReWg2Wn4FneJfa8xw==
-----END PUBLIC KEY-----"#;

        let signature = String::from("MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key = crate::crypto::new_verification_key(public_key).unwrap();
        let ss_value = json!({
            "critical": {
                "identity": {
                    "docker-reference":"registry-testing.svc.lan/busybox"
                },
                "image":{
                    "docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"
                },
                "type":"cosign container image signature"
            },
            "optional":null
        });

        (
            SignatureLayer {
                simple_signing: serde_json::from_value(ss_value.clone()).unwrap(),
                oci_digest: String::from("digest"),
                signature,
                bundle: None,
                certificate_key: None,
                raw_data: serde_json::to_vec(&ss_value).unwrap(),
            },
            verification_key,
        )
    }

    pub(crate) fn build_correct_signature_layer_with_certificate() -> SignatureLayer {
        let ss_value = json!({
            "critical": {
              "identity": {
                "docker-reference": "registry-testing.svc.lan/kubewarden/disallow-service-nodeport"
              },
              "image": {
                "docker-manifest-digest": "sha256:5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e"
              },
              "type": "cosign container image signature"
            },
            "optional": null
        });

        let bundle_value = json!({
          "SignedEntryTimestamp": "MEUCIDBGJijj2FqU25yRWzlEWHqE64XKwUvychBs1bSM1PaKAiEAwcR2u81c42TLBk3lWJqhtB7SnM7Lh0OYEl6Bfa7ZA4s=",
          "Payload": {
            "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlNzgwMWRlOTM1NTEyZTIyYjIzN2M3YjU3ZTQyY2E0ZDIwZTIxMzRiZGYxYjk4Zjk3NmM4ZjU1ZDljZmU0MDY3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJR3FXU2N6N3M5YVAyc0dYTkZLZXFpdnczQjZrUFJzNTZBSVRJSG52ZDVpZ0FpRUExa3piYVYyWTV5UEU4MUVOOTJOVUZPbDMxTExKU3Z3c2pGUTA3bTJYcWFBPSIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENrMUpTVU5rZWtORFFXWjVaMEYzU1VKQlowbFVRU3RRYzJGTGFtRkZXbkZ1TjBsWk9UUmlNV1V2YWtwdWFYcEJTMEpuWjNGb2EycFBVRkZSUkVGNlFYRUtUVkpWZDBWM1dVUldVVkZMUlhkNGVtRlhaSHBrUnpsNVdsTTFhMXBZV1hoRlZFRlFRbWRPVmtKQlRWUkRTRTV3V2pOT01HSXpTbXhOUWpSWVJGUkplQXBOVkVGNVRVUkJNMDFxVlhoT2JHOVlSRlJKZUUxVVFYbE5SRUV6VGtSVmVFNVdiM2RCUkVKYVRVSk5SMEo1Y1VkVFRUUTVRV2RGUjBORGNVZFRUVFE1Q2tGM1JVaEJNRWxCUWtsT1pYZFJRbE14WmpSQmJVNUpSVTVrVEN0VkwwaEtiM1JOVTAwM1drNXVhMVJ1V1dWbWVIZFdPVlJGY25CMmJrRmFNQ3RFZWt3S2VXWkJRVlpoWlVwMFMycEdkbUpQVkdJNFJqRjVhRXBHVlRCWVdTdFNhV3BuWjBWd1RVbEpRa3BVUVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUWpSQmR3cEZkMWxFVmxJd2JFSkJkM2REWjFsSlMzZFpRa0pSVlVoQmQwMTNSRUZaUkZaU01GUkJVVWd2UWtGSmQwRkVRV1JDWjA1V1NGRTBSVVpuVVZWTlpqRlNDazFOYzNGT1JrSnlWMko0T0cxU1RtUjRUMnRGUlZsemQwaDNXVVJXVWpCcVFrSm5kMFp2UVZWNVRWVmtRVVZIWVVwRGEzbFZVMVJ5UkdFMVN6ZFZiMGNLTUN0M2QyZFpNRWREUTNOSFFWRlZSa0ozUlVKQ1NVZEJUVWcwZDJaQldVbExkMWxDUWxGVlNFMUJTMGRqUjJnd1pFaEJOa3g1T1hkamJXd3lXVmhTYkFwWk1rVjBXVEk1ZFdSSFZuVmtRekF5VFVST2JWcFVaR3hPZVRCM1RVUkJkMHhVU1hsTmFtTjBXVzFaTTA1VE1XMU9SMWt4V2xSbmQxcEVTVFZPVkZGMUNtTXpVblpqYlVadVdsTTFibUl5T1c1aVIxWm9ZMGRzZWt4dFRuWmlVemxxV1ZSTk1sbFVSbXhQVkZsNVRrUkthVTlYV21wWmFrVXdUbWs1YWxsVE5Xb0tZMjVSZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFdtMTRhR1J0YkhaUlIwNW9Zek5TYkdKSGVIQk1iVEZzVFVGdlIwTkRjVWRUVFRRNVFrRk5SQXBCTW10QlRVZFpRMDFSUXpOWk1uVnNVRlJ6VUcxT1V6UmplbUZMWldwbE1FSnVUMUZJZWpWbE5rNUNXREJDY1hnNVdHTmhLM1F5YTA5cE1UZHpiM0JqQ2k5MkwzaElNWGhNZFZCdlEwMVJSRXRPUkRSWGFraG1TM0ZZV0U5bFZYWmFPVUU1TmtSeGNrVjNSMkZ4UjAxMGJrbDFUalJLZWxwWllWVk1Xbko0T1djS2IxaHhjVzh2UXpsUmJrOUlWSFJ2UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19",
            "integratedTime": 1634714717,
            "logIndex": 783607,
            "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
          }
        });
        let bundle: Bundle = serde_json::from_value(bundle_value).expect("Cannot parse bundle");

        let cert_raw = r#"-----BEGIN CERTIFICATE-----
MIICdzCCAfygAwIBAgITA+PsaKjaEZqn7IY94b1e/jJnizAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MTAyMDA3MjUxNloXDTIxMTAyMDA3NDUxNVowADBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABINewQBS1f4AmNIENdL+U/HJotMSM7ZNnkTnYefxwV9TErpvnAZ0+DzL
yfAAVaeJtKjFvbOTb8F1yhJFU0XY+RijggEpMIIBJTAOBgNVHQ8BAf8EBAMCB4Aw
EwYDVR0lBAwwCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUMf1R
MMsqNFBrWbx8mRNdxOkEEYswHwYDVR0jBBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG
0+wwgY0GCCsGAQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRl
Y2EtY29udGVudC02MDNmZTdlNy0wMDAwLTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQu
c3RvcmFnZS5nb29nbGVhcGlzLmNvbS9jYTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5j
cnQwIAYDVR0RAQH/BBYwFIESZmxhdmlvQGNhc3RlbGxpLm1lMAoGCCqGSM49BAMD
A2kAMGYCMQC3Y2ulPTsPmNS4czaKeje0BnOQHz5e6NBX0Bqx9Xca+t2kOi17sopc
/v/xH1xLuPoCMQDKND4WjHfKqXXOeUvZ9A96DqrEwGaqGMtnIuN4JzZYaULZrx9g
oXqqo/C9QnOHTto=
-----END CERTIFICATE-----"#;
        let cert_key = extract_public_key_from_pem_cert(cert_raw.as_bytes())
            .expect("Cannot extract public key from cert");
        let cert_key =
            new_verification_key_from_public_key_der(&cert_key).expect("Cannot build public key");

        SignatureLayer {
            simple_signing: serde_json::from_value(ss_value.clone()).unwrap(),
            oci_digest: String::from("sha256:5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e"),
            signature: String::from("MEUCIGqWScz7s9aP2sGXNFKeqivw3B6kPRs56AITIHnvd5igAiEA1kzbaV2Y5yPE81EN92NUFOl31LLJSvwsjFQ07m2XqaA="),
            bundle: Some(bundle),
            certificate_key: Some(cert_key),
            raw_data: serde_json::to_vec(&ss_value).unwrap(),
        }
    }

    #[test]
    fn is_signed_by_key_fails_when_signature_is_not_valid() {
        let (signature_layer, _) = build_correct_signature_layer_without_bundle();
        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(!actual, "expected false, got true");
    }

    #[test]
    fn new_signature_layer_fails_because_bad_descriptor() {
        let descriptor = oci_distribution::manifest::OciDescriptor {
            media_type: "not what you would expected".into(),
            ..Default::default()
        };
        let layer = oci_distribution::client::ImageLayer {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            data: Vec::new(),
        };

        let rekor_pub_key = get_rekor_public_key();

        let fulcio_key_raw = get_fulcio_public_key();
        let (_, fulcio_pub_key) = SubjectPublicKeyInfo::from_der(&fulcio_key_raw)
            .expect("Cannot parse fulcio public key");

        let actual = SignatureLayer::new(
            &descriptor,
            &layer,
            Some(&rekor_pub_key),
            Some(&fulcio_pub_key),
            None,
        );
        assert!(actual.is_err());
    }

    #[test]
    fn new_signature_layer_fails_because_bad_layer() {
        let descriptor = oci_distribution::manifest::OciDescriptor {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            ..Default::default()
        };
        let layer = oci_distribution::client::ImageLayer {
            media_type: "not what you would expect".into(),
            data: Vec::new(),
        };

        let rekor_pub_key = get_rekor_public_key();

        let fulcio_key_raw = get_fulcio_public_key();
        let (_, fulcio_pub_key) = SubjectPublicKeyInfo::from_der(&fulcio_key_raw)
            .expect("Cannot parse fulcio public key");

        let actual = SignatureLayer::new(
            &descriptor,
            &layer,
            Some(&rekor_pub_key),
            Some(&fulcio_pub_key),
            None,
        );
        assert!(actual.is_err());
    }

    #[test]
    fn new_signature_layer_fails_because_checksum_mismatch() {
        let descriptor = oci_distribution::manifest::OciDescriptor {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            digest: "some digest".into(),
            ..Default::default()
        };
        let layer = oci_distribution::client::ImageLayer {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            data: "some other contents".into(),
        };

        let rekor_pub_key = get_rekor_public_key();

        let fulcio_key_raw = get_fulcio_public_key();
        let (_, fulcio_pub_key) = SubjectPublicKeyInfo::from_der(&fulcio_key_raw)
            .expect("Cannot parse fulcio public key");

        let actual = SignatureLayer::new(
            &descriptor,
            &layer,
            Some(&rekor_pub_key),
            Some(&fulcio_pub_key),
            None,
        );
        assert!(actual.is_err());
    }

    #[test]
    fn get_signature_from_annotations_success() {
        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert(SIGSTORE_SIGNATURE_ANNOTATION.into(), "foo".into());

        let actual = SignatureLayer::get_signature_from_annotations(&annotations);
        assert!(actual.is_ok());
    }

    #[test]
    fn get_signature_from_annotations_failure() {
        let annotations: HashMap<String, String> = HashMap::new();

        let actual = SignatureLayer::get_signature_from_annotations(&annotations);
        assert!(actual.is_err());
    }

    #[test]
    fn get_bundle_from_annotations_works() {
        // we are **not** going to test neither the creation from a valid bundle
        // nor the fauilure because the bundle cannot be verified. These cases
        // are already covered by Bundle's test suite
        //
        // We care only about the only case not tested: to not
        // fail when no bundle is specified.
        let annotations: HashMap<String, String> = HashMap::new();
        let rekor_pub_key = get_rekor_public_key();

        let actual =
            SignatureLayer::get_bundle_from_annotations(&annotations, Some(&rekor_pub_key));
        assert!(actual.is_ok());
        assert!(actual.unwrap().is_none());
    }

    #[test]
    fn get_certificate_from_annotations_returns_none() {
        let annotations: HashMap<String, String> = HashMap::new();
        let fulcio_key_raw = get_fulcio_public_key();
        let (_, fulcio_pub_key) = SubjectPublicKeyInfo::from_der(&fulcio_key_raw)
            .expect("Cannot parse fulcio public key");

        let actual = SignatureLayer::get_certificate_from_annotations(
            &annotations,
            Some(&fulcio_pub_key),
            None,
            None,
        );

        assert!(actual.is_ok());
        assert!(actual.unwrap().is_none());
    }

    #[test]
    fn verify_certificate_and_extract_public_key_fails_when_no_bundle_is_found() {
        let fulcio_key_raw = get_fulcio_public_key();
        let (_, fulcio_pub_key) = SubjectPublicKeyInfo::from_der(&fulcio_key_raw)
            .expect("Cannot parse fulcio public key");

        // the actual contents of the certificate do not matter
        let cert: Vec<u8> = Vec::new();

        let actual = verify_certificate_and_extract_public_key(&cert, &fulcio_pub_key, None, None);

        let found = match actual.expect_err("It was supposed to fail") {
            SigstoreError::SigstoreRekorBundleNotFoundError => true,
            _ => false,
        };
        assert!(
            found,
            "Was supposed to get SigstoreRekorBundleNotFoundError"
        );
    }

    #[test]
    fn verify_with_key() {
        let (sl, key) = build_correct_signature_layer_without_bundle();
        assert!(sl.verified(Some(&key)));
    }

    #[test]
    fn verify_without_key_and_layer_does_not_have_certificate() {
        let (sl, _) = build_correct_signature_layer_without_bundle();
        assert!(!sl.verified(None));
    }

    #[test]
    fn verify_layer_signed_only_in_keyless_mode() {
        let sl = build_correct_signature_layer_with_certificate();
        assert!(sl.verified(None));

        // fail because the signature layer wasn't signed with the given key
        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();
        assert!(!sl.verified(Some(&verification_key)));
    }
}
