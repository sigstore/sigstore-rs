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

use const_oid::ObjectIdentifier;
use digest::Digest;
use oci_client::client::ImageLayer;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use tracing::{debug, info, warn};
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use super::bundle::Bundle;
use super::constants::{
    DSSE_PAYLOAD_TYPE_IN_TOTO_JSON, SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION,
    SIGSTORE_GITHUB_WORKFLOW_NAME_OID, SIGSTORE_GITHUB_WORKFLOW_REF_OID,
    SIGSTORE_GITHUB_WORKFLOW_REPOSITORY_OID, SIGSTORE_GITHUB_WORKFLOW_SHA_OID,
    SIGSTORE_GITHUB_WORKFLOW_TRIGGER_OID, SIGSTORE_ISSUER_OID, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION,
};
use super::intoto::InTotoStatementV1;
use crate::crypto::certificate_pool::CertificatePool;
use crate::registry::oci_reference::OciReference;
use crate::{
    cosign::payload::simple_signing::{Critical, Identity, Image, SimpleSigning},
    crypto::{self, CosignVerificationKey, Signature},
    errors::{Result, SigstoreError},
};

/// Describe the details of a certificate produced when signing artifacts
/// using the keyless mode.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateSignature {
    /// The verification key embedded into the Certificate
    #[serde(skip_serializing)]
    pub verification_key: CosignVerificationKey,
    /// The unique ID associated to the identity
    pub subject: CertificateSubject,
    /// The issuer used by the signer to authenticate. (e.g. GitHub, GitHub Action, Microsoft, Google,...)
    pub issuer: Option<String>,
    /// The trigger of the GitHub workflow (e.g. `push`)
    pub github_workflow_trigger: Option<String>,
    /// The commit ID that triggered the GitHub workflow
    pub github_workflow_sha: Option<String>,
    /// The name of the GitHub workflow (e.g. `release artifact`)
    pub github_workflow_name: Option<String>,
    /// The repository that owns the GitHub workflow (e.g. `octocat/example-repo`)
    pub github_workflow_repository: Option<String>,
    /// The Git ref of the commit that triggered the GitHub workflow (e.g. `refs/tags/v0.9.9`)
    pub github_workflow_ref: Option<String>,
}

impl fmt::Display for CertificateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = format!(
            r#"CertificateSignature
- issuer: {:?}
- subject: {:?}
- GitHub Workflow trigger: {:?}
- GitHub Workflow SHA: {:?}
- GitHub Workflow name: {:?}
- GitHub Workflow repository: {:?}
- GitHub Workflow ref: {:?}
---"#,
            self.issuer,
            self.subject,
            self.github_workflow_trigger,
            self.github_workflow_sha,
            self.github_workflow_name,
            self.github_workflow_repository,
            self.github_workflow_ref,
        );

        write!(f, "{msg}")
    }
}

/// Types of identities associated with the signer.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum CertificateSubject {
    /// An email address. This is what is used when the signer authenticated himself using something like his GitHub/Google account
    Email(String),
    /// A URL. This is used for example by the OIDC token issued by GitHub Actions
    Uri(String),
}

/// Object that contains all the data about a `SimpleSigning` object.
///
/// The struct provides some helper methods that can be used at verification
/// time.
///
/// Note well, the information needed to build a SignatureLayer are spread over
/// two places:
///   * The manifest of the signature object created by cosign
///   * One or more SIGSTORE_OCI_MEDIA_TYPE layers
///
/// End users of this library are not supposed to create this object directly.
/// `SignatureLayer` objects are instead obtained by using the
/// [`sigstore::cosign::Client::trusted_signature_layers`](crate::cosign::client::Client)
/// method.
#[derive(Clone, Debug, Serialize)]
pub struct SignatureLayer {
    /// The Simple Signing object associated with this layer
    pub simple_signing: SimpleSigning,
    /// The digest of the layer
    pub oci_digest: String,
    /// The certificate holding the identity of the signer, plus his
    /// verification key. This exists for signature done with keyless mode or
    /// when a PKCS11 token was used.
    ///
    /// The value of `CertificateSignature` is `None`
    /// when no certificate was embedded into the
    /// layer, or when the embedded certificate could not be verified.
    ///
    /// Having a `None` value will rightfully cause the
    /// keyless verifiers like
    /// [`CertSubjectEmailVerifier`](crate::cosign::verification_constraint::CertSubjectEmailVerifier)
    /// or
    /// [`CertSubjectUrlVerifier`](crate::cosign::verification_constraint::CertSubjectUrlVerifier)
    /// to fail verification.
    /// However, it will still be possible to use the
    /// [`PublicKeyVerifier`](crate::cosign::verification_constraint::PublicKeyVerifier)
    /// to verify the layer. This can be useful to verify signatures produced
    /// with a PKCS11 token, but with Rekor's integration disabled at
    /// signature time.
    pub certificate_signature: Option<CertificateSignature>,
    /// The bundle produced by Rekor.
    pub bundle: Option<Bundle>,
    #[serde(skip_serializing)]
    pub signature: Option<String>,
    #[serde(skip_serializing)]
    pub raw_data: Vec<u8>,
}

impl fmt::Display for SignatureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = format!(
            r#"---
# SignatureLayer
## digest
{}

## signature
{:?}

## bundle:
{:?}

## certificate signature
{}

## Simple Signing
{}
---"#,
            self.oci_digest,
            self.signature,
            self.bundle,
            self.certificate_signature
                .clone()
                .map(|cs| cs.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.simple_signing,
        );

        write!(f, "{msg}")
    }
}

impl SignatureLayer {
    /// Create a [`SignatureLayer`], this function will generate a [`SimpleSigning`]
    /// payload due to the given reference of image and the digest of the manifest.
    /// However, the resulted [`SignatureLayer`] does not have a signature, and it
    /// should be manually generated.
    ///
    /// ## Usage
    /// ```rust,no_run
    /// use sigstore::cosign::{SignatureLayer, constraint::PrivateKeySigner, Constraint};
    /// use sigstore::crypto::SigningScheme;
    ///
    /// async fn func() {
    ///     let mut signature_layer = SignatureLayer::new_unsigned(
    ///         &"example/test".parse().unwrap(),
    ///         "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").expect("create SignatureLayer failed");
    ///     // Now the SignatureLayer does not have a signature, we need
    ///     // to generate one
    ///     let signer = SigningScheme::ECDSA_P256_SHA256_ASN1.create_signer().expect("create signer failed");
    ///     let pk_signer = PrivateKeySigner::new_with_signer(signer);
    ///     if pk_signer.add_constraint(&mut signature_layer).expect("unexpected error") {
    ///         println!("sign succeed!");
    ///     } else {
    ///         println!("sign failed!");
    ///     }
    /// }
    ///
    /// ```
    pub fn new_unsigned(image_ref: &OciReference, manifest_digest: &str) -> Result<Self> {
        let simple_signing = SimpleSigning::new(image_ref, manifest_digest);

        let payload = serde_json::to_vec(&simple_signing)?;
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(&payload));
        Ok(SignatureLayer {
            simple_signing,
            oci_digest: digest,
            certificate_signature: None,
            bundle: None,
            signature: None,
            raw_data: payload,
        })
    }

    /// Create a SignatureLayer that can be considered trusted.
    ///
    /// Params:
    ///   * `descriptor`: the metadata of the layer, taken from the OCI manifest associated
    ///     with the Sigstore object
    ///   * `layer`: the data referenced by the descriptor
    ///   * `source_image_digest`: the digest of the object that we're trying
    ///     to verify. This is **not** the digest of the signature itself.
    ///   * `rekor_pub_key`: the public key of Rekor, used to verify `bundle`
    ///     entries
    ///   * `fulcio_pub_key`: the public key provided by Fulcio's certificate.
    ///     Used to verify the `certificate` entries
    ///
    /// **Note well:** the certificate and bundle added to the final SignatureLayer
    /// object are to be considered **trusted** and **verified**, according to
    /// the parameters provided to this method.
    pub(crate) fn new(
        descriptor: &oci_client::manifest::OciDescriptor,
        layer: &oci_client::client::ImageLayer,
        source_image_digest: &str,
        rekor_pub_keys: Option<&BTreeMap<String, CosignVerificationKey>>,
        fulcio_cert_pool: Option<&CertificatePool>,
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
                "Cannot convert layer data into SimpleSigning object: {e:?}"
            ))
        })?;

        if !simple_signing.satisfies_manifest_digest(source_image_digest) {
            return Err(SigstoreError::UnexpectedError(
                "Simple signing image digest mismatch".to_string(),
            ));
        }

        let annotations = descriptor.annotations.clone().unwrap_or_default();

        let signature = Self::get_signature_from_annotations(&annotations)?;
        let bundle = Self::get_bundle_from_annotations(&annotations, rekor_pub_keys)?;
        let certificate_signature = Self::get_certificate_signature_from_annotations(
            &annotations,
            fulcio_cert_pool,
            bundle.as_ref(),
        );

        Ok(SignatureLayer {
            oci_digest: descriptor.digest.clone(),
            raw_data: layer.data.to_vec(),
            simple_signing,
            signature: Some(signature),
            bundle,
            certificate_signature,
        })
    }

    fn get_signature_from_annotations(annotations: &BTreeMap<String, String>) -> Result<String> {
        let signature: String = annotations
            .get(SIGSTORE_SIGNATURE_ANNOTATION)
            .cloned()
            .ok_or(SigstoreError::SigstoreAnnotationNotFoundError)?;
        Ok(signature)
    }

    fn get_bundle_from_annotations(
        annotations: &BTreeMap<String, String>,
        rekor_pub_keys: Option<&BTreeMap<String, CosignVerificationKey>>,
    ) -> Result<Option<Bundle>> {
        let bundle = match annotations.get(SIGSTORE_BUNDLE_ANNOTATION) {
            Some(value) => match rekor_pub_keys {
                Some(keys) => Some(Bundle::new_verified(value, keys)?),
                None => {
                    info!(bundle = ?value, "Ignoring bundle, rekor public key not provided to verification client");
                    None
                }
            },
            None => None,
        };
        Ok(bundle)
    }

    fn get_certificate_signature_from_annotations(
        annotations: &BTreeMap<String, String>,
        fulcio_cert_pool: Option<&CertificatePool>,
        bundle: Option<&Bundle>,
    ) -> Option<CertificateSignature> {
        let cert_raw = annotations.get(SIGSTORE_CERT_ANNOTATION)?;

        let fulcio_cert_pool = match fulcio_cert_pool {
            Some(cp) => cp,
            None => {
                info!(
                    reason = "fulcio certificates not provided",
                    "Ignoring certificate annotation"
                );
                return None;
            }
        };

        let bundle = match bundle {
            Some(b) => b,
            None => {
                info!(
                    reason = "rekor bundle not found",
                    "Ignoring certificate annotation"
                );
                return None;
            }
        };

        match CertificateSignature::from_certificate(cert_raw.as_bytes(), fulcio_cert_pool, bundle)
        {
            Ok(certificate_signature) => Some(certificate_signature),
            Err(e) => {
                info!(reason=?e, "Ignoring certificate annotation");
                None
            }
        }
    }

    /// Create a `SignatureLayer` from a Sigstore Bundle stored as an OCI referrer.
    ///
    /// Cosign (new bundle format) stores the bundle as an OCI referrer layer with media type
    /// `application/vnd.dev.sigstore.bundle.v0.3+json`. The bundle contains:
    ///   - a DSSE envelope whose payload is an in-toto Statement v1;
    ///   - verification material (DER certificate, tlog entries).
    ///
    /// The bundle is parsed directly into the protobuf-derived
    /// [`sigstore_protobuf_specs`] `Bundle` type (the same type used by
    /// `src/bundle/`), so no hand-rolled JSON structs are needed.
    ///
    /// The constructed `SignatureLayer` is compatible with the existing
    /// verification constraint infrastructure:
    ///   - `raw_data` holds the DSSE PAE bytes (what was actually signed);
    ///   - `signature` holds the base64-encoded DSSE signature;
    ///   - `simple_signing` is synthesised from the in-toto statement subject;
    ///   - `certificate_signature` is populated from the embedded certificate.
    ///
    /// The tlog entry's Signed Entry Timestamp (SET / inclusion promise) is
    /// verified against the corresponding Rekor public key and the inclusion
    /// proof (Merkle path + checkpoint) is verified offline.
    ///
    /// Rekor public keys are required for v0.3 verification. Missing keys,
    /// missing inclusion promise/proof, or failed transparency verification all
    /// cause the layer to be rejected.
    #[cfg(any(feature = "verify", feature = "sign"))]
    pub(crate) fn from_sigstore_bundle(
        bundle_data: &[u8],
        layer_digest: &str,
        source_image_digest: &str,
        source_image_ref: &OciReference,
        fulcio_cert_pool: Option<&CertificatePool>,
        rekor_pub_keys: Option<&BTreeMap<String, CosignVerificationKey>>,
    ) -> Result<SignatureLayer> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
        use sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle as ProtoBundle;
        use sigstore_protobuf_specs::dev::sigstore::bundle::v1::{
            bundle::Content as BundleContent, verification_material::Content as VmContent,
        };

        let proto_bundle: ProtoBundle = serde_json::from_slice(bundle_data).map_err(|e| {
            SigstoreError::UnexpectedError(format!("cannot parse Sigstore Bundle v0.3: {e}"))
        })?;

        // Extract the DSSE envelope from the bundle content
        // The proto Bundle.content oneof is DsseEnvelope for v0.3 bundles.
        // io::intoto::Envelope.payload is Vec<u8> (base64-decoded by serde).
        let dsse_env = match proto_bundle.content {
            Some(BundleContent::DsseEnvelope(env)) => env,
            _ => {
                return Err(SigstoreError::UnexpectedError(
                    "Sigstore Bundle v0.3: expected DsseEnvelope content".to_string(),
                ));
            }
        };

        if dsse_env.payload_type != DSSE_PAYLOAD_TYPE_IN_TOTO_JSON {
            return Err(SigstoreError::UnexpectedError(format!(
                "unsupported DSSE payloadType: expected {DSSE_PAYLOAD_TYPE_IN_TOTO_JSON}, got {}",
                dsse_env.payload_type
            )));
        }

        // Serialize the DSSE envelope to canonical JSON for envelopeHash verification.
        // Must happen before we consume dsse_env.signatures below.
        // prost_reflect serialises bytes as base64, omits default (empty) fields like
        // keyid, and uses camelCase field names — exactly what Rekor hashed.
        let envelope_json = serde_json::to_vec(&dsse_env).map_err(|e| {
            SigstoreError::UnexpectedError(format!("cannot serialize DSSE envelope to JSON: {e}"))
        })?;

        // Decode the in-toto Statement v1 from the envelope payload
        // dsse_env.payload is already raw bytes (proto bytes field).
        let statement = InTotoStatementV1::from_json(&dsse_env.payload)?;
        statement.validate_cosign_v1()?;

        // Verify that the in-toto statement covers the expected image digest.
        let subject_digest = statement.subject_sha256_digest()?;
        let expected_digest = source_image_digest
            .strip_prefix("sha256:")
            .unwrap_or(source_image_digest);
        if subject_digest != expected_digest {
            return Err(SigstoreError::UnexpectedError(format!(
                "Sigstore bundle subject digest {subject_digest} does not match source image digest {source_image_digest}"
            )));
        }

        // Build the DSSE PAE bytes (what was actually signed)
        let pae_bytes =
            crate::bundle::verify::models::compute_pae(&dsse_env.payload_type, &dsse_env.payload);

        // Extract the DSSE signature — spec requires exactly one signature.
        let sig_count = dsse_env.signatures.len();
        if sig_count != 1 {
            return Err(SigstoreError::UnexpectedError(format!(
                "Sigstore Bundle v0.3 DSSE envelope must have exactly 1 signature, got {sig_count}"
            )));
        }
        // io::intoto::Signature.sig is Vec<u8>; SignatureLayer.signature holds
        // a base64 String (the contract established by the signature-tag path).
        let raw_sig = dsse_env
            .signatures
            .into_iter()
            .next()
            .map(|s| s.sig)
            .ok_or_else(|| {
                SigstoreError::UnexpectedError(
                    "Sigstore Bundle v0.3 DSSE envelope has no signatures".to_string(),
                )
            })?;
        let dsse_sig = base64.encode(&raw_sig);

        // Extract verification material
        let vm = proto_bundle.verification_material.ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "Sigstore Bundle v0.3: missing verificationMaterial".to_string(),
            )
        })?;

        // v0.3 uses a single leaf Certificate (not X509CertificateChain).
        let cert_der = match vm.content {
            Some(VmContent::Certificate(c)) => c.raw_bytes,
            _ => {
                return Err(SigstoreError::UnexpectedError(
                    "Sigstore Bundle v0.3: expected Certificate in verificationMaterial"
                        .to_string(),
                ));
            }
        };

        // tlog_entries must contain exactly one entry per the v0.3 spec
        let entry_count = vm.tlog_entries.len();
        if entry_count != 1 {
            return Err(SigstoreError::UnexpectedError(format!(
                "Sigstore Bundle v0.3 must have exactly 1 tlog entry, got {entry_count}"
            )));
        }
        let tlog_entry = vm
            .tlog_entries
            .into_iter()
            .next()
            .expect("tlog_entries len already checked to be 1");
        let integrated_time = tlog_entry.integrated_time;

        // Verify the Signed Entry Timestamp (SET / inclusion promise) and the
        // Merkle inclusion proof. Rekor keys are mandatory for Sigstore bundle verification.
        let keys = rekor_pub_keys.ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "Sigstore bundle verification requires Rekor public keys".to_string(),
            )
        })?;
        verify_bundle_tlog_entry(
            &tlog_entry,
            keys,
            &envelope_json,
            &dsse_env.payload,
            &raw_sig,
            &cert_der,
        )?;

        // Synthesise a SimpleSigning for compatibility with constraints
        let simple_signing = SimpleSigning {
            critical: Critical {
                type_name: statement.predicate_type.clone(),
                image: Image {
                    docker_manifest_digest: format!("sha256:{subject_digest}"),
                },
                identity: Identity {
                    docker_reference: source_image_ref.to_string(),
                },
            },
            optional: None,
        };

        // Attempt to validate the signing certificate against the Fulcio cert
        // pool.  A failure here means `certificate_signature` is `None`, so
        // any downstream `CertificateVerifier` constraint will reject this
        // layer.
        let certificate_signature = if let Some(pool) = fulcio_cert_pool {
            match CertificateSignature::from_der_certificate(&cert_der, pool, integrated_time) {
                Ok(cs) => Some(cs),
                Err(e) => {
                    info!(reason=?e, "Sigstore bundle certificate did not validate against Fulcio pool; layer will have no certificate_signature");
                    None
                }
            }
        } else {
            info!("Ignoring certificate in Sigstore bundle: fulcio cert pool not provided");
            None
        };

        Ok(SignatureLayer {
            simple_signing,
            oci_digest: layer_digest.to_string(),
            certificate_signature,
            bundle: None,
            signature: Some(dsse_sig),
            raw_data: pae_bytes,
        })
    }

    /// Given a Cosign public key, check whether this Signature Layer has been
    /// signed by it
    pub(crate) fn is_signed_by_key(&self, verification_key: &CosignVerificationKey) -> bool {
        let signature = match &self.signature {
            Some(sig) => sig,
            None => {
                warn!(signature_layer = ?self, "signature not found in the SignatureLayer");
                return false;
            }
        };
        match verification_key.verify_signature(
            Signature::Base64Encoded(signature.as_bytes()),
            &self.raw_data,
        ) {
            Ok(_) => true,
            Err(e) => {
                debug!(signature=signature.as_str(), reason=?e, "Cannot verify signature with the given key");
                false
            }
        }
    }
}

/// Verify a Sigstore bundle transparency log entry end-to-end.
///
/// This is the single entry point for all tlog verification.  It performs
/// three steps in order:
///
/// 1. **SET verification** — the Signed Entry Timestamp (inclusion promise) is
///    a signature by the Rekor log key over the canonical JSON payload:
///    ```json
///    {"body":"<base64(body)>","integratedTime":<i64>,"logIndex":<i64>,"logID":"<hex(keyId)>"}
///    ```
/// 2. **Merkle inclusion proof** — offline verification that the entry leaf
///    hash is included in the log tree at the claimed index.
/// 3. **Body consistency** — the `canonicalized_body` must bind to the exact
///    bundle content provided (`dsse_payload`, `raw_sig`, `cert_der`).  A
///    valid SET + inclusion proof only proves that *some* entry was logged; this
///    step ensures the logged entry describes *this* artifact.  See
///    [`verify_bundle_tlog_body_consistency`] for the individual checks performed.
#[cfg(any(feature = "verify", feature = "sign"))]
fn verify_bundle_tlog_entry(
    tlog_entry: &sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry,
    rekor_pub_keys: &BTreeMap<String, CosignVerificationKey>,
    envelope_json: &[u8],
    dsse_payload: &[u8],
    raw_sig: &[u8],
    cert_der: &[u8],
) -> Result<()> {
    use crate::rekor::models::checkpoint::SignedCheckpoint;
    use crate::rekor::models::inclusion_proof::InclusionProof as RekorInclusionProof;
    use base64::{Engine as _, engine::general_purpose::STANDARD as base64};

    // 1) Identify the log by its key ID (hex of the raw key_id bytes).
    let log_id = tlog_entry.log_id.as_ref().ok_or_else(|| {
        SigstoreError::UnexpectedError("Sigstore bundle tlog entry missing logId".to_string())
    })?;
    let key_id_hex = hex::encode(&log_id.key_id);

    let rekor_key = rekor_pub_keys
        .get(&key_id_hex)
        .ok_or_else(|| SigstoreError::RekorPublicKeyNotFoundError(key_id_hex.clone()))?;

    // 2) Verify the Signed Entry Timestamp (inclusion promise).
    //    The SET is a signature over the canonical JSON of the entry payload.
    let inclusion_promise = tlog_entry.inclusion_promise.as_ref().ok_or_else(|| {
        SigstoreError::UnexpectedError(
            "Sigstore bundle tlog entry missing inclusionPromise (SET)".to_string(),
        )
    })?;

    // Build the SET payload: same shape as cosign/bundle.rs `Payload`.
    // `canonicalized_body` is the raw `body` field (not base64-encoded in the
    // struct; we must base64-encode it to match the JSON representation).
    let body_b64 = base64.encode(&tlog_entry.canonicalized_body);
    let set_payload = serde_json::json!({
        "body": body_b64,
        "integratedTime": tlog_entry.integrated_time,
        "logIndex": tlog_entry.log_index,
        "logID": key_id_hex,
    });
    let set_payload_canonical = serde_json_canonicalizer::to_vec(&set_payload).map_err(|e| {
        SigstoreError::UnexpectedError(format!("cannot canonicalize SET payload: {e}"))
    })?;

    rekor_key
        .verify_signature(
            Signature::Raw(&inclusion_promise.signed_entry_timestamp),
            &set_payload_canonical,
        )
        .map_err(|e| {
            SigstoreError::UnexpectedError(format!("Sigstore bundle SET verification failed: {e}"))
        })?;

    // 3) Verify the Merkle inclusion proof (required for v0.3 bundles).
    let proto_proof = tlog_entry.inclusion_proof.as_ref().ok_or_else(|| {
        SigstoreError::UnexpectedError(
            "Sigstore bundle tlog entry missing inclusionProof".to_string(),
        )
    })?;

    // Convert the proto InclusionProof into the rekor model type.
    let root_hash: [u8; 32] = proto_proof.root_hash.as_slice().try_into().map_err(|_| {
        SigstoreError::UnexpectedError(format!(
            "inclusion proof root_hash has unexpected length {}",
            proto_proof.root_hash.len()
        ))
    })?;

    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(proto_proof.hashes.len());
    for (i, h) in proto_proof.hashes.iter().enumerate() {
        let arr: [u8; 32] = h.as_slice().try_into().map_err(|_| {
            SigstoreError::UnexpectedError(format!(
                "inclusion proof hash[{i}] has unexpected length {}",
                h.len()
            ))
        })?;
        hashes.push(arr);
    }

    let checkpoint = proto_proof
        .checkpoint
        .as_ref()
        .map(|c| SignedCheckpoint::decode(&c.envelope))
        .transpose()
        .map_err(|e| SigstoreError::UnexpectedError(format!("cannot parse checkpoint: {e:?}")))?;

    let proof = RekorInclusionProof::new(
        proto_proof.log_index,
        root_hash,
        proto_proof.tree_size as u64,
        hashes,
        checkpoint,
    );

    proof
        .verify(&tlog_entry.canonicalized_body, rekor_key)
        .map_err(|e| {
            SigstoreError::UnexpectedError(format!(
                "Sigstore bundle inclusion proof verification failed: {e}"
            ))
        })?;

    // 4) Verify body consistency: the logged entry must describe this artifact.
    verify_bundle_tlog_body_consistency(
        tlog_entry,
        envelope_json,
        dsse_payload,
        raw_sig,
        cert_der,
    )?;

    Ok(())
}

/// Verify that the tlog entry's canonicalized body binds to the exact same
/// payload, signature, and certificate that are present in the bundle.
///
/// A valid SET + inclusion proof only proves that *some* entry was logged; it
/// does not prove that the logged entry describes *this* artifact.  Without
/// this cross-check, an attacker could substitute any previously-logged tlog
/// entry whose SET still verifies, making the bundle appear valid for an
/// unrelated artifact.
///
/// We check (following cosign-go and sigstore-go behaviour):
///   - `spec.payloadHash` == sha256(raw DSSE payload bytes)
///   - `spec.signatures[0].signature` (base64) == base64(raw signature bytes)
///   - `spec.signatures[0].verifier` (base64-PEM) decodes to the same DER cert
#[cfg(any(feature = "verify", feature = "sign"))]
fn verify_bundle_tlog_body_consistency(
    tlog_entry: &sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry,
    envelope_json: &[u8],
    dsse_payload: &[u8],
    raw_sig: &[u8],
    cert_der: &[u8],
) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
    use sha2::{Digest as _, Sha256};

    let body: serde_json::Value =
        serde_json::from_slice(&tlog_entry.canonicalized_body).map_err(|e| {
            SigstoreError::UnexpectedError(format!("cannot parse tlog canonicalized body: {e}"))
        })?;

    // --- 0. Entry type ---
    // The tlog body must be a DSSE entry (kind == "dsse", apiVersion == "0.0.1").
    // A hashedrekord or any other kind has a different body schema and must not
    // be accepted here.
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SigstoreError::UnexpectedError("tlog body missing 'kind'".to_string()))?;
    if kind != "dsse" {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body kind is '{kind}', expected 'dsse'"
        )));
    }

    let api_version = body
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError("tlog body missing 'apiVersion'".to_string())
        })?;
    if api_version != "0.0.1" {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body apiVersion is '{api_version}', expected '0.0.1'"
        )));
    }

    let spec = body
        .get("spec")
        .ok_or_else(|| SigstoreError::UnexpectedError("tlog body missing 'spec'".to_string()))?;

    // --- 1. envelope hash ---
    // sha256(canonical DSSE envelope JSON) must match spec.envelopeHash.  This
    // binds the payloadType and the overall envelope structure — payloadHash
    // alone only covers the raw payload bytes.
    let tlog_env_alg = spec
        .pointer("/envelopeHash/algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.envelopeHash.algorithm' missing or not a string".to_string(),
            )
        })?;
    if tlog_env_alg != "sha256" {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body envelopeHash algorithm is '{tlog_env_alg}', expected 'sha256'"
        )));
    }
    let tlog_env_hash = spec
        .pointer("/envelopeHash/value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.envelopeHash.value' missing or not a string".to_string(),
            )
        })?;
    let computed_env_hash = hex::encode(Sha256::digest(envelope_json));
    if computed_env_hash != tlog_env_hash {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body envelopeHash mismatch: tlog={tlog_env_hash} bundle={computed_env_hash}"
        )));
    }

    // --- 3. payload hash ---
    let tlog_payload_hash = spec
        .pointer("/payloadHash/value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.payloadHash.value' missing or not a string".to_string(),
            )
        })?;
    let tlog_payload_alg = spec
        .pointer("/payloadHash/algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("sha256");
    if tlog_payload_alg != "sha256" {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body payloadHash algorithm is '{tlog_payload_alg}', expected 'sha256'"
        )));
    }
    let computed_payload_hash = hex::encode(Sha256::digest(dsse_payload));
    if computed_payload_hash != tlog_payload_hash {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body payloadHash mismatch: tlog={tlog_payload_hash} bundle={}",
            computed_payload_hash
        )));
    }

    // --- 4. signature bytes ---
    let tlog_sigs = spec
        .get("signatures")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.signatures' missing or not an array".to_string(),
            )
        })?;
    if tlog_sigs.len() != 1 {
        return Err(SigstoreError::UnexpectedError(format!(
            "tlog body spec.signatures must have exactly 1 entry, got {}",
            tlog_sigs.len()
        )));
    }
    let tlog_sig_b64 = tlog_sigs[0]
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.signatures[0].signature' missing or not a string".to_string(),
            )
        })?;
    let tlog_sig_bytes = base64.decode(tlog_sig_b64).map_err(|e| {
        SigstoreError::UnexpectedError(format!("cannot base64-decode tlog body signature: {e}"))
    })?;
    if tlog_sig_bytes != raw_sig {
        return Err(SigstoreError::UnexpectedError(
            "tlog body signature does not match DSSE envelope signature".to_string(),
        ));
    }

    // --- 5. verifier (certificate) ---
    let tlog_verifier_b64 = tlog_sigs[0]
        .get("verifier")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SigstoreError::UnexpectedError(
                "tlog body 'spec.signatures[0].verifier' missing or not a string".to_string(),
            )
        })?;
    // The verifier field is base64(PEM-encoded certificate).
    let tlog_verifier_pem = base64.decode(tlog_verifier_b64).map_err(|e| {
        SigstoreError::UnexpectedError(format!("cannot base64-decode tlog body verifier: {e}"))
    })?;
    // Parse the PEM cert from the tlog body and compare DER bytes.
    let tlog_cert_der = {
        let pem_str = std::str::from_utf8(&tlog_verifier_pem).map_err(|_| {
            SigstoreError::UnexpectedError("tlog body verifier is not valid UTF-8 PEM".to_string())
        })?;
        x509_cert::Certificate::from_pem(pem_str)
            .map_err(|e| {
                SigstoreError::UnexpectedError(format!(
                    "cannot parse tlog body verifier PEM certificate: {e}"
                ))
            })?
            .to_der()
            .map_err(|e| {
                SigstoreError::UnexpectedError(format!(
                    "cannot re-encode tlog body verifier certificate to DER: {e}"
                ))
            })?
    };
    if tlog_cert_der != cert_der {
        return Err(SigstoreError::UnexpectedError(
            "tlog body verifier certificate does not match bundle certificate".to_string(),
        ));
    }

    Ok(())
}

/// Creates a list of [`SignatureLayer`] objects by inspecting
/// the given OCI manifest and its associated layers.
///
/// **Note well:** when Rekor and Fulcio data has been provided, the
/// returned `SignatureLayer` is guaranteed to be
/// verified using the given Rekor and Fulcio keys.
pub(crate) fn build_signature_layers(
    manifest: &oci_client::manifest::OciImageManifest,
    source_image_digest: &str,
    layers: &[oci_client::client::ImageLayer],
    rekor_pub_keys: Option<&BTreeMap<String, CosignVerificationKey>>,
    fulcio_cert_pool: Option<&CertificatePool>,
) -> Result<Vec<SignatureLayer>> {
    let mut signature_layers: Vec<SignatureLayer> = Vec::new();

    for manifest_layer in &manifest.layers {
        let matching_layer: Option<&oci_client::client::ImageLayer> = layers.iter().find(|l| {
            let tmp: ImageLayer = (*l).clone();
            tmp.sha256_digest() == manifest_layer.digest
        });
        if let Some(layer) = matching_layer {
            match SignatureLayer::new(
                manifest_layer,
                layer,
                source_image_digest,
                rekor_pub_keys,
                fulcio_cert_pool,
            ) {
                Ok(sl) => signature_layers.push(sl),
                Err(e) => {
                    info!(error = ?e, "Skipping OCI layer because of error");
                }
            }
        }
    }

    if signature_layers.is_empty() {
        Err(SigstoreError::SigstoreNoVerifiedLayer)
    } else {
        Ok(signature_layers)
    }
}

impl CertificateSignature {
    /// Ensures the given certificate can be trusted, then extracts
    /// its details and returns them as a `CertificateSignature` object
    pub(crate) fn from_certificate(
        cert_pem: &[u8],
        fulcio_cert_pool: &CertificatePool,
        trusted_bundle: &Bundle,
    ) -> Result<Self> {
        let cert = Certificate::from_pem(cert_pem)
            .map_err(|e| SigstoreError::X509Error(format!("parse from pem: {e}")))?;
        let integrated_time = trusted_bundle.payload.integrated_time;

        // ensure the certificate has been issued by Fulcio
        fulcio_cert_pool.verify_pem_cert(
            cert_pem,
            Some(pki_types::UnixTime::since_unix_epoch(
                cert.tbs_certificate.validity.not_before.to_unix_duration(),
            )),
        )?;

        crypto::certificate::is_trusted(&cert, integrated_time)?;

        let subject = CertificateSubject::from_certificate(&cert)?;
        let verification_key =
            CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info)
                .map_err(|e| {
                    SigstoreError::X509Error(format!(
                        "cannot extract public key from certificate: {e}"
                    ))
                })?;

        let issuer = get_cert_extension_by_oid(&cert, SIGSTORE_ISSUER_OID, "Issuer")?;

        let github_workflow_trigger = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_TRIGGER_OID,
            "GitHub Workflow trigger",
        )?;

        let github_workflow_sha = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_SHA_OID,
            "GitHub Workflow sha",
        )?;

        let github_workflow_name = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_NAME_OID,
            "GitHub Workflow name",
        )?;

        let github_workflow_repository = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_REPOSITORY_OID,
            "GitHub Workflow repository",
        )?;

        let github_workflow_ref = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_REF_OID,
            "GitHub Workflow ref",
        )?;

        Ok(CertificateSignature {
            verification_key,
            issuer,
            github_workflow_trigger,
            github_workflow_sha,
            github_workflow_name,
            github_workflow_repository,
            github_workflow_ref,
            subject,
        })
    }

    /// Create a `CertificateSignature` from a DER-encoded X.509 certificate
    /// and an `integrated_time` value taken from the transparency log entry.
    ///
    /// This is used when verifying Sigstore Bundle signatures (new bundle format),
    /// where the certificate is stored as raw DER bytes inside the bundle's
    /// `verificationMaterial.certificate.rawBytes` field (base64-encoded).
    pub(crate) fn from_der_certificate(
        cert_der: &[u8],
        fulcio_cert_pool: &CertificatePool,
        integrated_time: i64,
    ) -> Result<Self> {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| SigstoreError::X509Error(format!("parse from der: {e}")))?;

        // Ensure the certificate has been issued by Fulcio
        fulcio_cert_pool.verify_der_cert(
            cert_der,
            Some(pki_types::UnixTime::since_unix_epoch(
                cert.tbs_certificate.validity.not_before.to_unix_duration(),
            )),
        )?;

        crypto::certificate::is_trusted(&cert, integrated_time)?;

        let subject = CertificateSubject::from_certificate(&cert)?;
        let verification_key =
            CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info)
                .map_err(|e| {
                    SigstoreError::X509Error(format!(
                        "cannot extract public key from certificate: {e}"
                    ))
                })?;

        let issuer = get_cert_extension_by_oid(&cert, SIGSTORE_ISSUER_OID, "Issuer")?;

        let github_workflow_trigger = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_TRIGGER_OID,
            "GitHub Workflow trigger",
        )?;

        let github_workflow_sha = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_SHA_OID,
            "GitHub Workflow sha",
        )?;

        let github_workflow_name = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_NAME_OID,
            "GitHub Workflow name",
        )?;

        let github_workflow_repository = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_REPOSITORY_OID,
            "GitHub Workflow repository",
        )?;

        let github_workflow_ref = get_cert_extension_by_oid(
            &cert,
            SIGSTORE_GITHUB_WORKFLOW_REF_OID,
            "GitHub Workflow ref",
        )?;

        Ok(CertificateSignature {
            verification_key,
            issuer,
            github_workflow_trigger,
            github_workflow_sha,
            github_workflow_name,
            github_workflow_repository,
            github_workflow_ref,
            subject,
        })
    }
}

fn get_cert_extension_by_oid(
    cert: &Certificate,
    ext_oid: ObjectIdentifier,
    ext_oid_name: &str,
) -> Result<Option<String>> {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .ok_or(SigstoreError::X509Error(
            "Certificate's extension is empty".to_string(),
        ))?
        .iter()
        .find(|ext| ext.extn_id == ext_oid)
        .map(|ext| {
            String::from_utf8(ext.extn_value.clone().into_bytes()).map_err(|_| {
                SigstoreError::X509Error(format!(
                    "Certificate's extension Sigstore {ext_oid_name} is not UTF8 compatible"
                ))
            })
        })
        .transpose()
}

impl CertificateSubject {
    pub fn from_certificate(certificate: &Certificate) -> Result<CertificateSubject> {
        let (_, san) = certificate
            .tbs_certificate
            .get::<SubjectAltName>()
            .map_err(|e| {
                SigstoreError::CertificateParsingError(format!("get SAN ext failed: {e}"))
            })?
            .ok_or(SigstoreError::CertificateParsingError(
                "No SAN ext found".to_string(),
            ))?;

        for general_name in &san.0 {
            if let GeneralName::Rfc822Name(name) = general_name {
                return Ok(CertificateSubject::Email(name.to_string()));
            }

            if let GeneralName::UniformResourceIdentifier(uri) = general_name {
                return Ok(CertificateSubject::Uri(uri.to_string()));
            }
        }

        Err(SigstoreError::CertificateWithIncompleteSubjectAlternativeName)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    use crate::cosign::tests::{get_fulcio_cert_pool, get_rekor_public_key};

    pub(crate) fn build_correct_signature_layer_without_bundle()
    -> (SignatureLayer, CosignVerificationKey) {
        let public_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENptdY/l3nB0yqkXLBWkZWQwo6+cu
OSWS1X9vPavpiQOoTTGC0xX57OojUadxF1cdQmrsiReWg2Wn4FneJfa8xw==
-----END PUBLIC KEY-----"#;

        let signature = String::from(
            "MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=",
        );
        let verification_key =
            CosignVerificationKey::from_pem(public_key.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
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
                signature: Some(signature),
                bundle: None,
                certificate_signature: None,
                raw_data: serde_json::to_vec(&ss_value).unwrap(),
            },
            verification_key,
        )
    }

    pub(crate) fn build_bundle() -> Bundle {
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
        bundle
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

        let bundle = build_bundle();

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

        let fulcio_cert_pool = get_fulcio_cert_pool();
        let certificate_signature =
            CertificateSignature::from_certificate(cert_raw.as_bytes(), &fulcio_cert_pool, &bundle)
                .expect("Cannot create certificate signature");

        SignatureLayer {
            simple_signing: serde_json::from_value(ss_value.clone()).unwrap(),
            oci_digest: String::from(
                "sha256:5f481572d088dc4023afb35fced9530ced3d9b03bf7299c6f492163cb9f0452e",
            ),
            signature: Some(String::from(
                "MEUCIGqWScz7s9aP2sGXNFKeqivw3B6kPRs56AITIHnvd5igAiEA1kzbaV2Y5yPE81EN92NUFOl31LLJSvwsjFQ07m2XqaA=",
            )),
            bundle: Some(bundle),
            certificate_signature: Some(certificate_signature),
            raw_data: serde_json::to_vec(&ss_value).unwrap(),
        }
    }

    #[test]
    fn is_signed_by_key_fails_when_signature_is_not_valid() {
        let (signature_layer, _) = build_correct_signature_layer_without_bundle();
        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::default(),
        )
        .expect("Cannot create CosignVerificationKey");

        let actual = signature_layer.is_signed_by_key(&verification_key);
        assert!(!actual, "expected false, got true");
    }

    #[test]
    fn new_signature_layer_fails_because_bad_descriptor() {
        let descriptor = oci_client::manifest::OciDescriptor {
            media_type: "not what you would expected".into(),
            ..Default::default()
        };
        let layer = oci_client::client::ImageLayer {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            data: Vec::new().into(),
            annotations: None,
        };

        let (key_id, key) = get_rekor_public_key();
        let rekor_pub_keys = BTreeMap::from([(key_id, key)]);

        let fulcio_cert_pool = get_fulcio_cert_pool();

        let error = SignatureLayer::new(
            &descriptor,
            &layer,
            "source_image_digest is not relevant now",
            Some(&rekor_pub_keys),
            Some(&fulcio_cert_pool),
        )
        .expect_err("Didn't get an error");

        let found = matches!(error, SigstoreError::SigstoreMediaTypeNotFoundError);
        assert!(found, "Got a different error type: {}", error);
    }

    #[test]
    fn new_signature_layer_fails_because_bad_layer() {
        let descriptor = oci_client::manifest::OciDescriptor {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            ..Default::default()
        };
        let layer = oci_client::client::ImageLayer {
            media_type: "not what you would expect".into(),
            data: Vec::new().into(),
            annotations: None,
        };

        let (key_id, key) = get_rekor_public_key();
        let rekor_pub_keys = BTreeMap::from([(key_id, key)]);

        let fulcio_cert_pool = get_fulcio_cert_pool();

        let error = SignatureLayer::new(
            &descriptor,
            &layer,
            "source_image_digest is not relevant now",
            Some(&rekor_pub_keys),
            Some(&fulcio_cert_pool),
        )
        .expect_err("Didn't get an error");

        let found = matches!(error, SigstoreError::SigstoreMediaTypeNotFoundError);
        assert!(found, "Got a different error type: {}", error);
    }

    #[test]
    fn new_signature_layer_fails_because_checksum_mismatch() {
        let descriptor = oci_client::manifest::OciDescriptor {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            digest: "some digest".into(),
            ..Default::default()
        };
        let layer = oci_client::client::ImageLayer {
            media_type: super::SIGSTORE_OCI_MEDIA_TYPE.to_string(),
            data: "some other contents".into(),
            annotations: None,
        };

        let (key_id, key) = get_rekor_public_key();
        let rekor_pub_keys = BTreeMap::from([(key_id, key)]);

        let fulcio_cert_pool = get_fulcio_cert_pool();

        let error = SignatureLayer::new(
            &descriptor,
            &layer,
            "source_image_digest is not relevant now",
            Some(&rekor_pub_keys),
            Some(&fulcio_cert_pool),
        )
        .expect_err("Didn't get an error");

        let found = matches!(error, SigstoreError::SigstoreLayerDigestMismatchError);
        assert!(found, "Got a different error type: {}", error);
    }

    #[test]
    fn get_signature_from_annotations_success() {
        let mut annotations: BTreeMap<String, String> = BTreeMap::new();
        annotations.insert(SIGSTORE_SIGNATURE_ANNOTATION.into(), "foo".into());

        let actual = SignatureLayer::get_signature_from_annotations(&annotations);
        assert!(actual.is_ok());
    }

    #[test]
    fn get_signature_from_annotations_failure() {
        let annotations: BTreeMap<String, String> = BTreeMap::new();

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
        let annotations: BTreeMap<String, String> = BTreeMap::new();
        let (key_id, key) = get_rekor_public_key();
        let rekor_pub_keys = BTreeMap::from([(key_id, key)]);

        let actual =
            SignatureLayer::get_bundle_from_annotations(&annotations, Some(&rekor_pub_keys));
        assert!(actual.is_ok());
        assert!(actual.unwrap().is_none());
    }

    #[test]
    fn get_certificate_signature_from_annotations_returns_none() {
        let annotations: BTreeMap<String, String> = BTreeMap::new();
        let fulcio_cert_pool = get_fulcio_cert_pool();

        let actual = SignatureLayer::get_certificate_signature_from_annotations(
            &annotations,
            Some(&fulcio_cert_pool),
            None,
        );

        assert!(actual.is_none());
    }

    #[test]
    fn get_certificate_signature_from_annotations_fails_when_no_bundle_is_given() {
        let mut annotations: BTreeMap<String, String> = BTreeMap::new();

        // add a fake cert, contents are not relevant
        annotations.insert(SIGSTORE_CERT_ANNOTATION.to_string(), "a cert".to_string());

        let fulcio_cert_pool = get_fulcio_cert_pool();

        let cert = SignatureLayer::get_certificate_signature_from_annotations(
            &annotations,
            Some(&fulcio_cert_pool),
            None,
        );
        assert!(cert.is_none());
    }

    #[test]
    fn get_certificate_signature_from_annotations_fails_when_no_fulcio_pub_key_is_given() {
        let mut annotations: BTreeMap<String, String> = BTreeMap::new();

        // add a fake cert, contents are not relevant
        annotations.insert(SIGSTORE_CERT_ANNOTATION.to_string(), "a cert".to_string());

        let bundle = build_bundle();

        let cert = SignatureLayer::get_certificate_signature_from_annotations(
            &annotations,
            None,
            Some(&bundle),
        );
        assert!(cert.is_none());
    }

    #[test]
    fn is_signed_by_key() {
        // a SignatureLayer created with traditional signing
        let (sl, key) = build_correct_signature_layer_without_bundle();
        assert!(sl.is_signed_by_key(&key));

        // a SignatureLayer created with keyless signing -> there's no pub key
        let sl = build_correct_signature_layer_with_certificate();

        // fail because the signature layer wasn't signed with the given key
        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        assert!(!sl.is_signed_by_key(&verification_key));
    }

    // Testing CertificateSignature
    use crate::cosign::bundle::Payload;
    use crate::crypto::SigningScheme;
    use crate::crypto::tests::{CertGenerationOptions, generate_certificate};
    use chrono::{TimeDelta, Utc};
    use pem;
    use rstest::rstest;

    #[test]
    fn certificate_signature_from_certificate_using_email() -> anyhow::Result<()> {
        let expected_email = "test@sigstore.dev".to_string();
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                subject_email: Some(expected_email.clone()),
                ..Default::default()
            },
        )?;

        let issued_cert_pem = issued_cert.cert_pem.clone();

        let certs = vec![
            crate::registry::Certificate {
                encoding: crate::registry::CertificateEncoding::Pem,
                data: ca_data.cert_pem.clone(),
            }
            .try_into()?,
        ];
        let cert_pool = CertificatePool::from_certificates(certs, []).unwrap();

        let integrated_time = Utc::now()
            .checked_sub_signed(TimeDelta::try_minutes(1).unwrap())
            .unwrap();
        let bundle = Bundle {
            signed_entry_timestamp: "not relevant".to_string(),
            payload: Payload {
                body: "not relevant".to_string(),
                integrated_time: integrated_time.timestamp(),
                log_index: 0,
                log_id: "not relevant".to_string(),
            },
        };

        let certificate_signature =
            CertificateSignature::from_certificate(&issued_cert_pem, &cert_pool, &bundle)
                .expect("Didn't expect an error");

        let expected_issuer = match certificate_signature.subject.clone() {
            CertificateSubject::Email(mail) => mail == expected_email,
            _ => false,
        };
        assert!(
            expected_issuer,
            "Didn't get the expected subject: {:?}",
            certificate_signature.subject
        );

        Ok(())
    }

    #[test]
    fn certificate_signature_from_certificate_using_uri() -> anyhow::Result<()> {
        let expected_url = "https://sigstore.dev/test".to_string();
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                subject_email: None,
                subject_url: Some(expected_url.clone()),
                ..Default::default()
            },
        )?;

        let issued_cert_pem = issued_cert.cert_pem.clone();

        let certs = vec![
            crate::registry::Certificate {
                encoding: crate::registry::CertificateEncoding::Pem,
                data: ca_data.cert_pem.clone(),
            }
            .try_into()?,
        ];
        let cert_pool = CertificatePool::from_certificates(certs, []).unwrap();

        let integrated_time = Utc::now()
            .checked_sub_signed(TimeDelta::try_minutes(1).unwrap())
            .unwrap();
        let bundle = Bundle {
            signed_entry_timestamp: "not relevant".to_string(),
            payload: Payload {
                body: "not relevant".to_string(),
                integrated_time: integrated_time.timestamp(),
                log_index: 0,
                log_id: "not relevant".to_string(),
            },
        };

        let certificate_signature =
            CertificateSignature::from_certificate(&issued_cert_pem, &cert_pool, &bundle)
                .expect("Didn't expect an error");

        let expected_issuer = match certificate_signature.subject.clone() {
            CertificateSubject::Uri(url) => url == expected_url,
            _ => false,
        };
        assert!(
            expected_issuer,
            "Didn't get the expected subject: {:?}",
            certificate_signature.subject
        );

        Ok(())
    }

    #[test]
    fn certificate_signature_from_certificate_without_email_and_uri() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                subject_email: None,
                subject_url: None,
                ..Default::default()
            },
        )?;

        let issued_cert_pem = issued_cert.cert_pem.clone();

        let certs = vec![
            crate::registry::Certificate {
                encoding: crate::registry::CertificateEncoding::Pem,
                data: ca_data.cert_pem.clone(),
            }
            .try_into()?,
        ];
        let cert_pool = CertificatePool::from_certificates(certs, []).unwrap();

        let integrated_time = Utc::now()
            .checked_sub_signed(TimeDelta::try_minutes(1).unwrap())
            .unwrap();
        let bundle = Bundle {
            signed_entry_timestamp: "not relevant".to_string(),
            payload: Payload {
                body: "not relevant".to_string(),
                integrated_time: integrated_time.timestamp(),
                log_index: 0,
                log_id: "not relevant".to_string(),
            },
        };

        let error = CertificateSignature::from_certificate(&issued_cert_pem, &cert_pool, &bundle)
            .expect_err("Didn't get an error");
        assert!(matches!(
            error,
            SigstoreError::CertificateWithoutSubjectAlternativeName
        ));

        Ok(())
    }

    #[rstest]
    #[case::email(
        CertGenerationOptions {
            subject_email: Some("test@sigstore.dev".into()),
            subject_url: None,
            ..Default::default()
        },
        Some(CertificateSubject::Email("test@sigstore.dev".into())),
    )]
    #[case::uri(
        CertGenerationOptions {
            subject_email: None,
            subject_url: Some("https://sigstore.dev/test".into()),
            ..Default::default()
        },
        Some(CertificateSubject::Uri("https://sigstore.dev/test".into())),
    )]
    #[case::no_san(
        CertGenerationOptions {
            subject_email: None,
            subject_url: None,
            ..Default::default()
        },
        None,
    )]
    fn certificate_signature_from_der_certificate(
        #[case] opts: CertGenerationOptions,
        #[case] expected_subject: Option<CertificateSubject>,
    ) -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let cert_der =
            pem::parse(generate_certificate(Some(&ca_data), opts)?.cert_pem)?.into_contents();

        let certs = vec![
            crate::registry::Certificate {
                encoding: crate::registry::CertificateEncoding::Pem,
                data: ca_data.cert_pem.clone(),
            }
            .try_into()?,
        ];
        let cert_pool = CertificatePool::from_certificates(certs, []).unwrap();
        let integrated_time = Utc::now()
            .checked_sub_signed(TimeDelta::try_minutes(1).unwrap())
            .unwrap()
            .timestamp();

        let result =
            CertificateSignature::from_der_certificate(&cert_der, &cert_pool, integrated_time);

        match expected_subject {
            Some(subject) => {
                let cert_sig = result.expect("Didn't expect an error");
                assert_eq!(
                    cert_sig.subject, subject,
                    "Unexpected subject: {:?}",
                    cert_sig.subject
                );
            }
            None => {
                let error = result.expect_err("Didn't get an error");
                assert!(
                    matches!(
                        error,
                        SigstoreError::CertificateWithoutSubjectAlternativeName
                    ),
                    "Unexpected error variant: {error:?}"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn certificate_signature_from_der_certificate_rejects_bad_der() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let certs = vec![
            crate::registry::Certificate {
                encoding: crate::registry::CertificateEncoding::Pem,
                data: ca_data.cert_pem.clone(),
            }
            .try_into()?,
        ];
        let cert_pool = CertificatePool::from_certificates(certs, []).unwrap();

        let error = CertificateSignature::from_der_certificate(b"not valid der", &cert_pool, 0)
            .expect_err("Didn't get an error");
        assert!(
            matches!(error, SigstoreError::X509Error(ref msg) if msg.contains("parse from der")),
            "Unexpected error: {error:?}"
        );

        Ok(())
    }

    #[cfg(any(feature = "verify", feature = "sign"))]
    mod bundle_tests {
        use super::*;

        const REAL_BUNDLE_V03: &str = include_str!("../../tests/data/bundle_v03.json");

        enum V3BundleMutation {
            Payload,
            Statement,
            Predicate,
        }

        fn mutated_v3_bundle_fixture(kind: V3BundleMutation) -> Vec<u8> {
            let mut bundle: serde_json::Value =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must be valid JSON");

            let dsse = bundle
                .get_mut("dsseEnvelope")
                .and_then(serde_json::Value::as_object_mut)
                .expect("bundle must contain dsseEnvelope object");

            match kind {
                V3BundleMutation::Payload => {
                    dsse.insert(
                        "payloadType".to_string(),
                        serde_json::Value::String("application/json".to_string()),
                    );
                }
                V3BundleMutation::Statement | V3BundleMutation::Predicate => {
                    use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
                    let payload_b64 = dsse
                        .get("payload")
                        .and_then(serde_json::Value::as_str)
                        .expect("dsseEnvelope.payload must be present");
                    let payload_bytes = base64.decode(payload_b64).expect("payload must be base64");
                    let mut statement: serde_json::Value =
                        serde_json::from_slice(&payload_bytes).expect("payload must be JSON");

                    match kind {
                        V3BundleMutation::Statement => {
                            statement["_type"] = serde_json::Value::String(
                                "https://example.com/Statement/v1".into(),
                            );
                        }
                        V3BundleMutation::Predicate => {
                            statement["predicateType"] = serde_json::Value::String(
                                "https://example.com/predicate/v1".into(),
                            );
                        }
                        V3BundleMutation::Payload => unreachable!(),
                    }

                    let mutated_payload =
                        serde_json::to_vec(&statement).expect("mutated statement must serialize");
                    dsse.insert(
                        "payload".to_string(),
                        serde_json::Value::String(base64.encode(mutated_payload)),
                    );
                }
            }

            serde_json::to_vec(&bundle).expect("mutated bundle must serialize")
        }

        /// Verify that the real v0.3 bundle fixture is parseable as the proto `Bundle`
        /// type directly.
        #[test]
        fn proto_bundle_parses_real_fixture() {
            use sigstore_protobuf_specs::dev::sigstore::bundle::v1::{
                Bundle as ProtoBundle, bundle::Content,
            };

            let bundle: ProtoBundle =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse as proto Bundle");

            assert_eq!(
                bundle.media_type,
                "application/vnd.dev.sigstore.bundle.v0.3+json"
            );

            let vm = bundle
                .verification_material
                .expect("must have verification_material");
            assert_eq!(vm.tlog_entries.len(), 1);
            let tlog = &vm.tlog_entries[0];
            assert_eq!(tlog.integrated_time, 1775719409);
            assert_eq!(
                tlog.kind_version.as_ref().map(|kv| kv.kind.as_str()),
                Some("dsse")
            );

            assert!(
                matches!(bundle.content, Some(Content::DsseEnvelope(_))),
                "content must be DsseEnvelope"
            );
        }

        /// Parse the real v0.3 bundle fixture through `from_sigstore_bundle` and assert the
        /// `SignatureLayer` fields are populated correctly, or that a wrong digest is rejected.
        #[rstest]
        #[case::correct_digest(
            "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172",
            Some("sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172")
        )]
        #[case::wrong_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            None
        )]
        fn from_sigstore_bundle(
            #[case] subject_digest: &str,
            #[case] expected_manifest_digest: Option<&str>,
        ) {
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let (key_id, rekor_key) = get_rekor_public_key();
            let rekor_pub_keys = BTreeMap::from([(key_id, rekor_key)]);

            let result = SignatureLayer::from_sigstore_bundle(
                REAL_BUNDLE_V03.as_bytes(),
                layer_digest,
                subject_digest,
                &source_ref,
                None,
                Some(&rekor_pub_keys),
            );

            match expected_manifest_digest {
                Some(expected_digest) => {
                    let layer = result.expect("from_sigstore_bundle should succeed");

                    assert_eq!(
                        layer.simple_signing.critical.image.docker_manifest_digest,
                        expected_digest
                    );
                    assert_eq!(
                        layer.simple_signing.critical.identity.docker_reference,
                        "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                    );
                    assert_eq!(layer.oci_digest, layer_digest);
                    assert!(layer.signature.is_some(), "signature should be set");
                    assert!(
                        !layer.raw_data.is_empty(),
                        "raw_data (PAE) should be non-empty"
                    );
                    assert!(layer.bundle.is_none());
                    assert!(layer.certificate_signature.is_none());
                }
                None => {
                    assert!(result.is_err(), "mismatched digest should produce an error");
                }
            }
        }

        #[rstest]
        #[case::wrong_payload_type(V3BundleMutation::Payload, "unsupported DSSE payloadType")]
        #[case::wrong_statement_type(V3BundleMutation::Statement, "unsupported in-toto _type")]
        #[case::wrong_predicate_type(
            V3BundleMutation::Predicate,
            "unsupported in-toto predicateType"
        )]
        fn from_sigstore_bundle_rejects_unexpected_types(
            #[case] mutation: V3BundleMutation,
            #[case] expected_error_fragment: &str,
        ) {
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let subject_digest =
                "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172";
            let (key_id, rekor_key) = get_rekor_public_key();
            let rekor_pub_keys = BTreeMap::from([(key_id, rekor_key)]);

            let bundle = mutated_v3_bundle_fixture(mutation);

            let err = SignatureLayer::from_sigstore_bundle(
                &bundle,
                layer_digest,
                subject_digest,
                &source_ref,
                None,
                Some(&rekor_pub_keys),
            )
            .expect_err("invalid type fields must be rejected");

            match err {
                SigstoreError::UnexpectedError(msg) => {
                    assert!(
                        msg.contains(expected_error_fragment),
                        "error message should contain '{expected_error_fragment}', got '{msg}'"
                    );
                }
                other => panic!("unexpected error type: {other:?}"),
            }
        }

        /// Drives the Rekor key scenario for `from_sigstore_bundle_rekor_verification_cases`.
        enum RekorKeyScenario {
            /// The real production Rekor public key — verification must succeed.
            Valid,
            /// A freshly-generated ephemeral key registered under the correct key ID
            /// — lookup succeeds but cryptographic verification fails.
            WrongKey,
            /// No Rekor keys provided at all — must fail closed.
            Missing,
        }

        /// Verify Rekor transparency verification behavior for v0.3 bundles:
        /// valid key succeeds, wrong key fails cryptographically, and missing keys
        /// fail closed.
        #[rstest]
        #[case::valid_rekor_key(RekorKeyScenario::Valid)]
        #[case::wrong_rekor_key(RekorKeyScenario::WrongKey)]
        #[case::missing_rekor_keys(RekorKeyScenario::Missing)]
        fn from_sigstore_bundle_rekor_verification_cases(#[case] scenario: RekorKeyScenario) {
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let subject_digest =
                "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172";

            let rekor_pub_keys = match &scenario {
                RekorKeyScenario::Valid => {
                    let (key_id, key) = get_rekor_public_key();
                    Some(BTreeMap::from([(key_id, key)]))
                }
                RekorKeyScenario::WrongKey => {
                    // Generate an ephemeral key and register it under the real key
                    // ID so the map lookup succeeds but the SET signature check fails.
                    let ephemeral_key = SigningScheme::ECDSA_P256_SHA256_ASN1
                        .create_signer()
                        .expect("create ephemeral signer")
                        .to_verification_key()
                        .expect("derive verification key");
                    let (key_id, _) = get_rekor_public_key();
                    Some(BTreeMap::from([(key_id, ephemeral_key)]))
                }
                RekorKeyScenario::Missing => None,
            };

            let result = SignatureLayer::from_sigstore_bundle(
                REAL_BUNDLE_V03.as_bytes(),
                layer_digest,
                subject_digest,
                &source_ref,
                None,
                rekor_pub_keys.as_ref(),
            );
            let expect_ok = matches!(scenario, RekorKeyScenario::Valid);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "unexpected outcome for scenario: {result:?}"
            );
        }

        // -----------------------------------------------------------------------
        // DSSE signature cardinality
        // -----------------------------------------------------------------------

        /// Build a bundle fixture with `count` copies of the existing DSSE signature
        /// (0 = clear the array, 2 = duplicate the first entry, etc.).
        fn bundle_with_dsse_sig_count(count: usize) -> Vec<u8> {
            let mut bundle: serde_json::Value =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must be valid JSON");

            let sigs = bundle["dsseEnvelope"]["signatures"]
                .as_array()
                .expect("dsseEnvelope.signatures must be an array")
                .clone();
            let first = sigs
                .into_iter()
                .next()
                .expect("fixture has at least one sig");

            let new_sigs: Vec<serde_json::Value> = (0..count).map(|_| first.clone()).collect();
            bundle["dsseEnvelope"]["signatures"] = serde_json::Value::Array(new_sigs);

            serde_json::to_vec(&bundle).expect("re-serialise must succeed")
        }

        #[rstest]
        #[case::zero_signatures(0, "must have exactly 1 signature, got 0")]
        #[case::two_signatures(2, "must have exactly 1 signature, got 2")]
        fn from_sigstore_bundle_rejects_wrong_dsse_sig_count(
            #[case] count: usize,
            #[case] expected_fragment: &str,
        ) {
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let subject_digest =
                "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172";
            let (key_id, rekor_key) = get_rekor_public_key();
            let rekor_pub_keys = BTreeMap::from([(key_id, rekor_key)]);

            let bundle = bundle_with_dsse_sig_count(count);

            let err = SignatureLayer::from_sigstore_bundle(
                &bundle,
                layer_digest,
                subject_digest,
                &source_ref,
                None,
                Some(&rekor_pub_keys),
            )
            .expect_err("wrong signature count must be rejected");

            match err {
                SigstoreError::UnexpectedError(msg) => assert!(
                    msg.contains(expected_fragment),
                    "error should contain '{expected_fragment}', got '{msg}'"
                ),
                other => panic!("unexpected error type: {other:?}"),
            }
        }

        // -----------------------------------------------------------------------
        // Tlog body consistency (verify_bundle_tlog_body_consistency in isolation)
        // -----------------------------------------------------------------------

        /// Build a minimal `TransparencyLogEntry` with only `canonicalized_body`
        /// populated — sufficient for calling `verify_bundle_tlog_body_consistency`.
        fn tlog_entry_with_body(
            body: serde_json::Value,
        ) -> sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry {
            sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry {
                canonicalized_body: serde_json::to_vec(&body).expect("body must serialise"),
                ..Default::default()
            }
        }

        /// Extracted components of a v0.3 bundle needed for tlog body consistency tests.
        ///
        /// Using a named struct instead of a tuple makes call sites self-documenting
        /// and means adding new fields in future is a non-breaking change for callers
        /// that use struct-update syntax or field access.
        struct BundleConsistencyInputs {
            /// Raw DSSE payload bytes (decoded from the envelope).
            dsse_payload: Vec<u8>,
            /// Raw signature bytes from the single DSSE signature entry.
            raw_sig: Vec<u8>,
            /// DER-encoded signing certificate extracted from verificationMaterial.
            cert_der: Vec<u8>,
            /// Canonical JSON serialization of the DSSE envelope, used to verify
            /// `spec.envelopeHash` in the tlog body.
            envelope_json: Vec<u8>,
        }

        /// Extract the bundle components needed for tlog body consistency tests
        /// from the real v0.3 bundle fixture.
        fn real_bundle_consistency_inputs() -> BundleConsistencyInputs {
            let proto: sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse");

            let dsse = match proto.content.expect("must have content") {
                sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(
                    e,
                ) => e,
                _ => panic!("expected DsseEnvelope"),
            };
            // Serialize envelope JSON before consuming signatures.
            let envelope_json = serde_json::to_vec(&dsse).expect("envelope must serialise");
            let dsse_payload = dsse.payload.clone();
            let raw_sig = dsse
                .signatures
                .into_iter()
                .next()
                .expect("must have sig")
                .sig;

            let vm = proto.verification_material.expect("must have vm");
            let cert_der = match vm.content.expect("must have vm.content") {
                sigstore_protobuf_specs::dev::sigstore::bundle::v1::verification_material::Content::Certificate(c) => c.raw_bytes,
                _ => panic!("expected Certificate"),
            };

            BundleConsistencyInputs {
                dsse_payload,
                raw_sig,
                cert_der,
                envelope_json,
            }
        }

        /// Extract and parse the real tlog body from the fixture.
        fn real_tlog_body() -> serde_json::Value {
            let proto: sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must parse");
            let body_bytes = proto
                .verification_material
                .expect("vm")
                .tlog_entries
                .into_iter()
                .next()
                .expect("tlog entry")
                .canonicalized_body;
            serde_json::from_slice(&body_bytes).expect("body must be JSON")
        }

        #[test]
        fn tlog_body_consistency_accepts_real_fixture() {
            let inputs = real_bundle_consistency_inputs();
            let body = real_tlog_body();
            let entry = tlog_entry_with_body(body);

            verify_bundle_tlog_body_consistency(
                &entry,
                &inputs.envelope_json,
                &inputs.dsse_payload,
                &inputs.raw_sig,
                &inputs.cert_der,
            )
            .expect("real fixture must pass consistency check");
        }

        #[rstest]
        #[case::wrong_kind(
            "tlog body kind is 'hashedrekord', expected 'dsse'",
            Box::new(|body: &mut serde_json::Value| {
                body["kind"] = serde_json::json!("hashedrekord");
            }) as Box<dyn FnOnce(&mut serde_json::Value)>,
        )]
        #[case::wrong_api_version(
            "tlog body apiVersion is '0.0.2', expected '0.0.1'",
            Box::new(|body: &mut serde_json::Value| {
                body["apiVersion"] = serde_json::json!("0.0.2");
            }),
        )]
        #[case::envelope_hash_mismatch(
            "tlog body envelopeHash mismatch",
            Box::new(|body: &mut serde_json::Value| {
                body["spec"]["envelopeHash"]["value"] = serde_json::json!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
            }),
        )]
        #[case::envelope_hash_bad_algorithm(
            "envelopeHash algorithm is 'sha512', expected 'sha256'",
            Box::new(|body: &mut serde_json::Value| {
                body["spec"]["envelopeHash"]["algorithm"] = serde_json::json!("sha512");
            }),
        )]
        #[case::payload_hash_mismatch(
            "tlog body payloadHash mismatch",
            Box::new(|body: &mut serde_json::Value| {
                body["spec"]["payloadHash"]["value"] = serde_json::json!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
            }) as Box<dyn FnOnce(&mut serde_json::Value)>,
        )]
        #[case::payload_hash_bad_algorithm(
            "payloadHash algorithm is 'sha512'",
            Box::new(|body: &mut serde_json::Value| {
                body["spec"]["payloadHash"]["algorithm"] = serde_json::json!("sha512");
            }),
        )]
        #[case::signature_mismatch(
            "signature does not match",
            Box::new(|body: &mut serde_json::Value| {
                use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
                body["spec"]["signatures"][0]["signature"] =
                    serde_json::json!(base64.encode([0u8; 64]));
            }),
        )]
        #[case::verifier_cert_mismatch(
            "cannot parse tlog body verifier PEM certificate",
            Box::new(|body: &mut serde_json::Value| {
                use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
                // Replace the verifier with base64 of something that is not a PEM cert.
                body["spec"]["signatures"][0]["verifier"] =
                    serde_json::json!(base64.encode(b"not-a-cert"));
            }),
        )]
        fn tlog_body_consistency_rejects_tampered_body(
            #[case] expected_fragment: &str,
            #[case] mutate: Box<dyn FnOnce(&mut serde_json::Value)>,
        ) {
            let inputs = real_bundle_consistency_inputs();
            let mut body = real_tlog_body();
            mutate(&mut body);
            let entry = tlog_entry_with_body(body);

            let err = verify_bundle_tlog_body_consistency(
                &entry,
                &inputs.envelope_json,
                &inputs.dsse_payload,
                &inputs.raw_sig,
                &inputs.cert_der,
            )
            .expect_err("tampered body must be rejected");

            match err {
                SigstoreError::UnexpectedError(msg) => assert!(
                    msg.contains(expected_fragment),
                    "error should contain '{expected_fragment}', got '{msg}'"
                ),
                other => panic!("unexpected error type: {other:?}"),
            }
        }

        // -----------------------------------------------------------------------
        // Certificate validation fail-closed
        // -----------------------------------------------------------------------

        #[test]
        fn from_sigstore_bundle_with_unrecognised_cert_produces_no_certificate_signature() {
            // The real bundle cert was issued by production Fulcio; the test pool
            // uses different CA certs, so cert validation fails.  The layer must
            // still be returned — but with `certificate_signature: None` — so that
            // downstream CertificateVerifier constraints reject it rather than the
            // layer being silently dropped or causing a hard error.
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let subject_digest =
                "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172";
            let (key_id, rekor_key) = get_rekor_public_key();
            let rekor_pub_keys = BTreeMap::from([(key_id, rekor_key)]);
            let fulcio_pool = get_fulcio_cert_pool();

            let layer = SignatureLayer::from_sigstore_bundle(
                REAL_BUNDLE_V03.as_bytes(),
                layer_digest,
                subject_digest,
                &source_ref,
                Some(&fulcio_pool),
                Some(&rekor_pub_keys),
            )
            .expect("layer must be produced even when cert is not in pool");

            assert!(
                layer.certificate_signature.is_none(),
                "certificate_signature must be None when cert is not trusted by the pool"
            );
        }

        // -----------------------------------------------------------------------
        // Tlog entry cardinality
        // -----------------------------------------------------------------------

        /// Build a bundle JSON with the tlog_entries array duplicated to `count`
        /// copies of the real fixture entry.
        fn bundle_with_tlog_entry_count(count: usize) -> Vec<u8> {
            let mut bundle: serde_json::Value =
                serde_json::from_str(REAL_BUNDLE_V03).expect("fixture must be valid JSON");

            let entries = bundle["verificationMaterial"]["tlogEntries"]
                .as_array()
                .expect("tlogEntries must be an array")
                .clone();
            let first = entries
                .into_iter()
                .next()
                .expect("fixture has at least one tlog entry");

            let new_entries: Vec<serde_json::Value> = (0..count).map(|_| first.clone()).collect();
            bundle["verificationMaterial"]["tlogEntries"] = serde_json::Value::Array(new_entries);

            serde_json::to_vec(&bundle).expect("re-serialise must succeed")
        }

        #[rstest]
        #[case::zero_entries(0, "exactly 1 tlog entry, got 0")]
        #[case::two_entries(2, "exactly 1 tlog entry, got 2")]
        fn from_sigstore_bundle_rejects_wrong_tlog_entry_count(
            #[case] count: usize,
            #[case] expected_fragment: &str,
        ) {
            let source_ref: OciReference = "ghcr.io/kubewarden/kubewarden-controller:v1.34.0"
                .parse()
                .unwrap();
            let layer_digest =
                "sha256:121ecb638da858178a0d57de5686709769f15b47d9fa5e3270dd7c64aea046d5";
            let subject_digest =
                "sha256:c811d58de79c92f03214e63aa339484e488d694ae8a6283b5f3f17a9faf50172";
            let (key_id, rekor_key) = get_rekor_public_key();
            let rekor_pub_keys = BTreeMap::from([(key_id, rekor_key)]);

            let bundle = bundle_with_tlog_entry_count(count);

            let err = SignatureLayer::from_sigstore_bundle(
                &bundle,
                layer_digest,
                subject_digest,
                &source_ref,
                None,
                Some(&rekor_pub_keys),
            )
            .expect_err("wrong tlog entry count must be rejected");

            match err {
                SigstoreError::UnexpectedError(msg) => assert!(
                    msg.contains(expected_fragment),
                    "error should contain '{expected_fragment}', got '{msg}'"
                ),
                other => panic!("unexpected error type: {other:?}"),
            }
        }
    } // end mod bundle_tests
}
