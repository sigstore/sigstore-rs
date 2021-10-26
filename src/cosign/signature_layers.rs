use anyhow::{anyhow, Result};
use std::{
    cmp::Eq,
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt,
    hash::{Hash, Hasher},
};
use tracing::{info, warn};

use crate::cosign::SIGSTORE_OCI_MEDIA_TYPE;
use crate::{crypto::CosignVerificationKey, simple_signing::SimpleSigning};

/// This is an internal object that contains all the data about a
/// SimpleSigning object.
/// This includes also a list of cosign signatures associated with the
/// SimpleSigning object.SimpleSigning
///
/// The struct provides some helper methods that can be used at verification
/// time.
///
/// Note well, the information needed to build a SignatureLayer are spread over
/// two places:
///   * The manifest of the signature object created by cosign
///   * One or more SIGSTORE_OCI_MEDIA_TYPE layers
///
/// Because of that, the object has to be built in two steps, this
/// is done inside of the `build_signature_layers` function declared below
pub(crate) struct SignatureLayer {
    pub simple_signing: SimpleSigning,
    pub oci_digest: String,
    cosign_signatures: Vec<String>,
    raw_data: Vec<u8>,
}

impl PartialEq for SignatureLayer {
    fn eq(&self, other: &Self) -> bool {
        self.oci_digest == other.oci_digest
    }
}
impl Eq for SignatureLayer {}

impl Hash for SignatureLayer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.oci_digest.hash(state);
    }
}

impl fmt::Display for SignatureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signatures: Vec<String> = self
            .cosign_signatures
            .iter()
            .map(|s| format!("  - {}", s))
            .collect();
        let msg = format!(
            "SignatureLayer\n- digest: {}\n- SimpleSigning: {}\n- signatures:\n{}\n---",
            self.oci_digest,
            self.simple_signing,
            signatures.join("\n"),
        );

        write!(f, "{}", msg)
    }
}

impl TryFrom<&oci_distribution::client::ImageLayer> for SignatureLayer {
    type Error = anyhow::Error;

    fn try_from(layer: &oci_distribution::client::ImageLayer) -> Result<Self, Self::Error> {
        if layer.media_type != super::SIGSTORE_OCI_MEDIA_TYPE {
            return Err(anyhow!("Not a simple signing layer"));
        }
        let simple_signing: SimpleSigning =
            serde_json::from_slice(&layer.data.clone()).map_err(|e| {
                anyhow!(
                    "Cannot convert layer data into SimpleSigning object: {:?}",
                    e
                )
            })?;

        Ok(SignatureLayer {
            oci_digest: layer.clone().sha256_digest(),
            cosign_signatures: Vec::<String>::new(),
            simple_signing,
            raw_data: layer.data.clone(),
        })
    }
}

impl SignatureLayer {
    /// Given a map containing all the oci annotations defined inside of an OCI Layer,
    /// add all the cosign signatures found
    pub fn add_signatures(&mut self, oci_annotations: Option<HashMap<String, String>>) {
        if oci_annotations.is_none() {
            return;
        }
        for (annotation_type, value) in oci_annotations.unwrap() {
            if annotation_type == super::SIGSTORE_SIGNATURE_ANNOTATION {
                self.cosign_signatures.push(value);
            }
        }
    }

    /// Given a Cosign public key, check whether the signature embedded into
    /// the SignatureLayer has been produced by the given key
    pub fn is_signed_by_key(&self, verification_key: &CosignVerificationKey) -> Result<bool> {
        for signature in &self.cosign_signatures {
            match crate::crypto::verify_signature(verification_key, signature, &self.raw_data) {
                Ok(_) => return Ok(true),
                Err(e) => {
                    info!(signature=signature.as_str(), reason=?e, "Cannot verify signature with the given key");
                }
            }
        }

        Ok(false)
    }
}

/// Create a list of unique SignatureLayer objects starting from the
/// data fetched from an OCI registry
pub(crate) fn build_signature_layers(
    manifest: &oci_distribution::manifest::OciManifest,
    layers: &[oci_distribution::client::ImageLayer],
) -> HashSet<SignatureLayer> {
    // Given the OCI manifest of the signature object,
    // this hash has:
    // * keys: the digest of the layer
    // * value: the OciDescriptor(s) of that layer
    //
    // Only layers of type "application/vnd.dev.cosign.simplesigning.v1+json"
    // are considered.
    //
    // Note well: signatures made by different users can have the same digest,
    // that's why the value of the HashMap is a list.
    let mut signature_layers_manifest_metadata: HashMap<
        String,
        Vec<oci_distribution::manifest::OciDescriptor>,
    > = HashMap::new();

    for l in manifest.clone().layers {
        if l.media_type != SIGSTORE_OCI_MEDIA_TYPE {
            continue;
        }
        match signature_layers_manifest_metadata.get_mut(&l.digest) {
            Some(descriptors) => descriptors.push(l),
            None => {
                let descriptors = vec![l.clone()];
                signature_layers_manifest_metadata.insert(l.digest, descriptors);
            }
        }
    }

    let signature_layers: HashSet<SignatureLayer> = layers
        .iter()
        .filter_map(|image_layer| {
            let sl: Result<SignatureLayer> = image_layer.try_into();
            match sl {
                Ok(mut sl) => match signature_layers_manifest_metadata.get(&sl.oci_digest) {
                    Some(oci_descriptions) => {
                        for description in oci_descriptions {
                            sl.add_signatures(description.annotations.clone());
                        }
                        Some(sl)
                    }
                    None => None,
                },
                Err(e) => {
                    warn!(error = ?e, "Ignoring layer");
                    None
                }
            }
        })
        .collect();

    signature_layers
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn build_correct_signature_layer() -> (SignatureLayer, CosignVerificationKey) {
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
                cosign_signatures: vec![signature],
                raw_data: serde_json::to_vec(&ss_value).unwrap(),
            },
            verification_key,
        )
    }

    #[test]
    fn is_signed_by_key_success() {
        let (signature_layer, verification_key) = build_correct_signature_layer();

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(actual.is_ok(), "unexpected error: {:?}", actual);
        assert!(actual.unwrap(), "expected true, got false");
    }

    #[test]
    fn is_signed_by_key_success_even_when_multiple_signatures_are_available() {
        let (mut signature_layer, verification_key) = build_correct_signature_layer();
        signature_layer.cosign_signatures.push(
            String::from("MEUCIQDcb5mP/PmZhB5ywI01N/R1T5hqyIjgwebdIA4DA6Gp7QIgIVEq/Wr7aajgwP9c7MJFIlScfW035TrdnNAwoOQsEcw="));

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(actual.is_ok(), "unexpected error: {:?}", actual);
        assert!(actual.unwrap(), "expected true, got false");
    }

    #[test]
    fn is_signed_by_key_fails_when_no_signatures_are_available() {
        let (mut signature_layer, verification_key) = build_correct_signature_layer();
        signature_layer.cosign_signatures = vec![];

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(actual.is_ok(), "unexpected error: {:?}", actual);
        assert!(!actual.unwrap(), "expected false, got true");
    }

    #[test]
    fn is_signed_by_key_fails_when_no_signatures_is_valid() {
        let (signature_layer, _) = build_correct_signature_layer();
        let verification_key = crate::crypto::new_verification_key(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#,
        )
        .unwrap();

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(actual.is_ok(), "unexpected error: {:?}", actual);
        assert!(!actual.unwrap(), "expected false, got true");
    }

    #[test]
    fn add_signatures_considers_only_sigstore_annotations() {
        let (mut signature_layer, _) = build_correct_signature_layer();
        signature_layer.cosign_signatures = vec![];

        let expected_signature = String::from("this is the exepected signature");
        let mut oci_annotations: HashMap<String, String> = HashMap::new();
        oci_annotations.insert(
            crate::cosign::SIGSTORE_SIGNATURE_ANNOTATION.into(),
            expected_signature.clone(),
        );
        oci_annotations.insert("something-else".into(), "not a signature".into());
        signature_layer.add_signatures(Some(oci_annotations));

        assert_eq!(signature_layer.cosign_signatures.len(), 1);
        assert_eq!(
            signature_layer.cosign_signatures.iter().next(),
            Some(&expected_signature)
        );
    }

    #[test]
    fn add_signatures_handles_oci_manifests_without_annotations() {
        let (mut signature_layer, _) = build_correct_signature_layer();
        signature_layer.cosign_signatures = vec![];
        signature_layer.add_signatures(None);

        assert!(signature_layer.cosign_signatures.is_empty());
    }

    #[test]
    fn build_signature_layers_when_multiple_signatures_are_available() {
        let signatures = vec![
            "MEQCIHES47aY6xcCSH/Q8FC8v8qQmqWx5Tq8rHskzmfp4fM2AiBsXDgGMgW5I68DsqoCSdobPr282UXHv/iM3ABBkIGBYA==",
            "MEUCIQDcb5mP/PmZhB5ywI01N/R1T5hqyIjgwebdIA4DA6Gp7QIgIVEq/Wr7aajgwP9c7MJFIlScfW035TrdnNAwoOQsEcw=",
        ];
        let manifest_json = json!({
              "schemaVersion": 2,
              "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 342,
                "digest": "sha256:44f7cbc918de5e174ac682fa0c83b35122482b9900ff312340709ac95a3d5372"
              },
              "layers": [
                {
                  "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                  "size": 247,
                  "digest": "sha256:3b135f3a4b97f77a80e332f3bd09737b449c627fbca957cb464a3322d35ec13f",
                  "annotations": {
                    "dev.cosignproject.cosign/signature": signatures[0]
                  }
                },
                {
                  "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                  "size": 247,
                  "digest": "sha256:3b135f3a4b97f77a80e332f3bd09737b449c627fbca957cb464a3322d35ec13f",
                  "annotations": {
                    "dev.cosignproject.cosign/signature": signatures[1]
                  }
                }
              ]
        });

        let manifest: oci_distribution::manifest::OciManifest =
            serde_json::from_value(manifest_json).unwrap();

        let layer = oci_distribution::client::ImageLayer{
            media_type: SIGSTORE_OCI_MEDIA_TYPE.into(),
            data: r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/alpine"},"image":{"docker-manifest-digest":"sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a"},"type":"cosign container image signature"},"optional":null}"#.into(),
        };

        // adding the same layer more than once, this happens when multiple people sign the
        // artifact
        let layers = vec![layer.clone(), layer];

        let actual = build_signature_layers(&manifest, &layers);

        assert_eq!(actual.len(), 1);
        let signature_layer = actual.iter().next().unwrap();
        assert_eq!(
            signature_layer.cosign_signatures.clone().sort(),
            signatures.clone().sort()
        );
    }
}
