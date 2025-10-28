//
// Copyright 2023 The Sigstore Authors.
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

use std::str::FromStr;

use crate::{
    bundle::{Bundle, models::Version as BundleVersion},
    crypto::certificate::{CertificateValidationError, is_leaf, is_root_ca},
    rekor::models as rekor,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{bundle, verification_material},
    rekor::v1::{InclusionProof, TransparencyLogEntry},
};
use thiserror::Error;
use tracing::{debug, error, warn};
use x509_cert::{
    Certificate,
    der::{Decode, Encode, EncodePem},
};

use super::policy::PolicyError;

#[derive(Error, Debug)]
pub enum Bundle01ProfileErrorKind {
    #[error("bundle must contain inclusion promise")]
    InclusionPromiseMissing,
}

#[derive(Error, Debug)]
pub enum Bundle02ProfileErrorKind {
    #[error("bundle must contain inclusion proof")]
    InclusionProofMissing,

    #[error("bundle must contain checkpoint")]
    CheckpointMissing,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum BundleProfileErrorKind {
    Bundle01Profile(#[from] Bundle01ProfileErrorKind),

    Bundle02Profile(#[from] Bundle02ProfileErrorKind),

    #[error("unknown bundle profile {0}")]
    Unknown(String),
}

#[derive(Error, Debug)]
pub enum BundleErrorKind {
    #[error("bundle missing VerificationMaterial")]
    VerificationMaterialMissing,

    #[error("bundle includes unsupported VerificationMaterial::Content")]
    VerificationMaterialContentUnsupported,

    #[error("bundle's certificate(s) are malformed")]
    CertificateMalformed(#[source] x509_cert::der::Error),

    #[error("bundle contains a root certificate")]
    RootInChain,

    #[error("bundle does not contain the signing (leaf) certificate")]
    NoLeaf(#[source] CertificateValidationError),

    #[error("bundle does not contain any certificates")]
    CertificatesMissing,

    #[error("bundle does not contain signature")]
    SignatureMissing,

    #[error("bundle DSSE envelope is invalid: {0}")]
    DsseInvalid(String),

    #[error("bundle needs 1 tlog entry, got {0}")]
    TlogEntry(usize),

    #[error(transparent)]
    BundleProfile(#[from] BundleProfileErrorKind),
}

#[derive(Error, Debug)]
pub enum CertificateErrorKind {
    #[error("certificate malformed")]
    Malformed(#[source] webpki::Error),

    #[error("certificate expired before time of signing")]
    Expired,

    #[error("certificate SCT verification failed")]
    Sct(#[source] crate::crypto::transparency::SCTError),

    #[error("certificate verification failed")]
    VerificationFailed(#[source] webpki::Error),
}

#[derive(Error, Debug)]
pub enum SignatureErrorKind {
    #[error("unsupported signature algorithm")]
    AlgoUnsupported(#[source] crate::errors::SigstoreError),

    #[error("signature verification failed")]
    VerificationFailed(#[source] crate::errors::SigstoreError),

    #[error("signature transparency materials are inconsistent")]
    Transparency,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum VerificationError {
    #[error("unable to read input")]
    Input(#[source] std::io::Error),

    Bundle(#[from] BundleErrorKind),

    Certificate(#[from] CertificateErrorKind),

    Signature(#[from] SignatureErrorKind),

    Policy(#[from] PolicyError),
}

pub type VerificationResult = Result<(), VerificationError>;

pub struct CheckedBundle {
    pub(crate) certificate: Certificate,
    pub(crate) signature: Vec<u8>,
    pub(crate) dsse_envelope: Option<sigstore_protobuf_specs::io::intoto::Envelope>,

    tlog_entry: TransparencyLogEntry,
}

impl TryFrom<Bundle> for CheckedBundle {
    type Error = BundleErrorKind;

    fn try_from(input: Bundle) -> Result<Self, Self::Error> {
        let (content, mut tlog_entries) = match input.verification_material {
            Some(m) => (m.content, m.tlog_entries),
            _ => return Err(BundleErrorKind::VerificationMaterialMissing),
        };

        // Parse the certificates. The first entry in the chain MUST be a leaf certificate, and the
        // rest of the chain MUST NOT include a root CA or any intermediate CAs that appear in an
        // independent root of trust.
        let certs = match content {
            Some(verification_material::Content::X509CertificateChain(ch)) => ch.certificates,
            Some(verification_material::Content::Certificate(cert)) => {
                vec![cert]
            }
            _ => return Err(BundleErrorKind::VerificationMaterialContentUnsupported),
        };
        let certs = certs
            .iter()
            .map(|c| c.raw_bytes.as_slice())
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(BundleErrorKind::CertificateMalformed)?;

        let [leaf_cert, chain_certs @ ..] = &certs[..] else {
            return Err(BundleErrorKind::CertificatesMissing);
        };

        is_leaf(leaf_cert).map_err(BundleErrorKind::NoLeaf)?;

        for chain_cert in chain_certs {
            if is_root_ca(chain_cert).is_ok() {
                return Err(BundleErrorKind::RootInChain);
            }
        }

        // Extract signature from either MessageSignature or DSSE envelope
        let (signature, dsse_envelope) = match input.content.ok_or(BundleErrorKind::SignatureMissing)? {
            bundle::Content::MessageSignature(s) => (s.signature, None),
            bundle::Content::DsseEnvelope(envelope) => {
                // For DSSE, we need to extract the signature from the envelope
                // DSSE uses PAE (Pre-Authentication Encoding): "DSSEv1 <payload_type_len> <payload_type> <payload_len> <payload>"
                if envelope.signatures.is_empty() {
                    return Err(BundleErrorKind::DsseInvalid("no signatures in envelope".to_string()));
                }
                // Use the first signature (bundles should have exactly one)
                if envelope.signatures.len() > 1 {
                    warn!("DSSE envelope contains multiple signatures, using first one");
                }
                // The signature bytes are already decoded from base64 by the protobuf deserializer
                (envelope.signatures[0].sig.clone(), Some(envelope))
            }
        };

        if tlog_entries.len() != 1 {
            return Err(BundleErrorKind::TlogEntry(tlog_entries.len()));
        }
        let tlog_entry = tlog_entries.remove(0);

        let (inclusion_promise, inclusion_proof) =
            (&tlog_entry.inclusion_promise, &tlog_entry.inclusion_proof);

        // `inclusion_proof` is a required field in the current protobuf spec,
        // but older versions of Rekor didn't provide it. Check invariants
        // here and selectively allow for this case.
        //
        // https://github.com/sigstore/sigstore-python/pull/634#discussion_r1182769140
        let check_01_bundle = || -> Result<(), BundleProfileErrorKind> {
            if inclusion_promise.is_none() {
                return Err(Bundle01ProfileErrorKind::InclusionPromiseMissing)?;
            }

            if matches!(
                inclusion_proof,
                Some(InclusionProof {
                    checkpoint: None,
                    ..
                })
            ) {
                debug!("0.1 bundle contains inclusion proof without checkpoint");
            }

            Ok(())
        };
        let check_02_bundle = || -> Result<(), BundleProfileErrorKind> {
            if inclusion_proof.is_none() {
                error!("bundle must contain inclusion proof");
                return Err(Bundle02ProfileErrorKind::InclusionProofMissing)?;
            }

            if matches!(
                inclusion_proof,
                Some(InclusionProof {
                    checkpoint: None,
                    ..
                })
            ) {
                error!("bundle must contain checkpoint");
                return Err(Bundle02ProfileErrorKind::CheckpointMissing)?;
            }

            Ok(())
        };
        let check_03_bundle = || -> Result<(), BundleProfileErrorKind> {
            // For Bundle 0.3, we require inclusion proof with checkpoint
            if inclusion_proof.is_none() {
                error!("bundle must contain inclusion proof");
                return Err(Bundle02ProfileErrorKind::InclusionProofMissing)?;
            }

            if matches!(
                inclusion_proof,
                Some(InclusionProof {
                    checkpoint: None,
                    ..
                })
            ) {
                error!("bundle must contain checkpoint");
                return Err(Bundle02ProfileErrorKind::CheckpointMissing)?;
            }

            // Bundle 0.3 requires either inclusion promise OR timestamp verification data
            // This check is handled at verification time when we have access to timestamp data
            // For now, we just ensure the inclusion proof is valid
            Ok(())
        };
        match BundleVersion::from_str(&input.media_type) {
            Ok(BundleVersion::Bundle0_1) => check_01_bundle()?,
            Ok(BundleVersion::Bundle0_2) => check_02_bundle()?,
            Ok(BundleVersion::Bundle0_3) | Ok(BundleVersion::Bundle0_3Alt) => check_03_bundle()?,
            Err(_) => return Err(BundleProfileErrorKind::Unknown(input.media_type))?,
        }

        Ok(Self {
            certificate: leaf_cert.clone(),
            signature,
            dsse_envelope,
            tlog_entry,
        })
    }
}

impl CheckedBundle {
    /// Returns the data that should be verified against the signature.
    ///
    /// For regular bundles, this is the input digest.
    /// For DSSE bundles, this is the PAE (Pre-Authentication Encoding).
    pub fn verification_data(&self, input_digest: &[u8]) -> Vec<u8> {
        if let Some(envelope) = &self.dsse_envelope {
            // For DSSE, verify against the PAE
            crate::bundle::dsse::pae(envelope)
        } else {
            // For regular bundles, verify against the input digest
            input_digest.to_vec()
        }
    }

    /// Returns true if this bundle contains a DSSE envelope.
    pub fn is_dsse(&self) -> bool {
        self.dsse_envelope.is_some()
    }

    /// Retrieves and checks consistency of the bundle's [TransparencyLogEntry].
    pub fn tlog_entry(&self, offline: bool, input_digest: &[u8]) -> Option<&TransparencyLogEntry> {
        let base64_pem_certificate =
            base64.encode(self.certificate.to_pem(pkcs8::LineEnding::LF).ok()?);

        let entry = if !offline && self.tlog_entry.inclusion_proof.is_none() {
            warn!("online rekor fetching is not implemented yet, but is necessary for this bundle");
            return None;
        } else {
            &self.tlog_entry
        };

        // Check if this is a DSSE bundle or regular hashedrekord
        if let Some(envelope) = &self.dsse_envelope {
            // For DSSE bundles, validate the transparency log entry
            // Supports both v0.0.1 and v0.0.2 formats
            use sha2::{Digest, Sha256};

            // Parse the canonicalized body as a DSSE entry
            let actual: serde_json::Value =
                serde_json::from_slice(&self.tlog_entry.canonicalized_body).ok()?;

            // Verify kind
            if actual.get("kind")?.as_str()? != "dsse" {
                debug!("DSSE entry has wrong kind");
                return None;
            }

            // Check API version and validate accordingly
            let api_version = actual.get("apiVersion")?.as_str()?;
            let spec = actual.get("spec")?;

            match api_version {
                "0.0.1" => {
                    // v0.0.1 format: spec.payloadHash.value (hex), spec.signatures[].signature, spec.signatures[].verifier
                    // Following sigstore-python's _validate_dsse_v001_entry_body logic

                    // Verify payload hash matches
                    let mut payload_hasher = Sha256::new();
                    payload_hasher.update(&envelope.payload);
                    let payload_hash = hex::encode(payload_hasher.finalize());

                    let tlog_payload_hash = spec.get("payloadHash")?
                        .get("value")?.as_str()?;
                    if payload_hash != tlog_payload_hash {
                        debug!("DSSE v0.0.1 payload hash mismatch: computed={}, tlog={}", payload_hash, tlog_payload_hash);
                        return None;
                    }

                    // Verify signature and verifier match
                    let sig_b64 = base64.encode(&envelope.signatures[0].sig);
                    let tlog_signatures = spec.get("signatures")?.as_array()?;
                    if tlog_signatures.is_empty() {
                        debug!("DSSE v0.0.1 tlog entry has no signatures");
                        return None;
                    }

                    let tlog_sig = tlog_signatures[0].get("signature")?.as_str()?;
                    let tlog_verifier = tlog_signatures[0].get("verifier")?.as_str()?;

                    if sig_b64 != tlog_sig {
                        debug!("DSSE v0.0.1 signature mismatch");
                        return None;
                    }

                    if base64_pem_certificate != tlog_verifier {
                        debug!("DSSE v0.0.1 verifier (certificate) mismatch");
                        return None;
                    }
                }
                "0.0.2" => {
                    // v0.0.2 format: spec.dsseV002.payloadHash.digest (base64),
                    // spec.dsseV002.signatures[].content, spec.dsseV002.signatures[].verifier.x509Certificate.rawBytes
                    // Following sigstore-python's _validate_dsse_v002_entry_body logic

                    let dsse_v002 = spec.get("dsseV002")?;

                    // Verify payload hash matches
                    let mut payload_hasher = Sha256::new();
                    payload_hasher.update(&envelope.payload);
                    let payload_hash_bytes = payload_hasher.finalize();
                    let payload_hash_b64 = base64.encode(payload_hash_bytes);

                    let tlog_payload_hash = dsse_v002.get("payloadHash")?
                        .get("digest")?.as_str()?;

                    // Verify algorithm is SHA2_256
                    let algorithm = dsse_v002.get("payloadHash")?
                        .get("algorithm")?.as_str()?;
                    if algorithm != "SHA2_256" {
                        debug!("DSSE v0.0.2 unexpected hash algorithm: {}", algorithm);
                        return None;
                    }

                    if payload_hash_b64 != tlog_payload_hash {
                        debug!("DSSE v0.0.2 payload hash mismatch: computed={}, tlog={}", payload_hash_b64, tlog_payload_hash);
                        return None;
                    }

                    // Verify signature and verifier match
                    let sig_b64 = base64.encode(&envelope.signatures[0].sig);
                    let tlog_signatures = dsse_v002.get("signatures")?.as_array()?;
                    if tlog_signatures.is_empty() {
                        debug!("DSSE v0.0.2 tlog entry has no signatures");
                        return None;
                    }

                    let tlog_sig = tlog_signatures[0].get("content")?.as_str()?;
                    if sig_b64 != tlog_sig {
                        debug!("DSSE v0.0.2 signature mismatch");
                        return None;
                    }

                    // For v0.0.2, the verifier is a complex object with x509Certificate.rawBytes
                    let verifier = tlog_signatures[0].get("verifier")?;
                    let cert_bytes = verifier.get("x509Certificate")?
                        .get("rawBytes")?.as_str()?;

                    // The certificate in v0.0.2 is base64-encoded DER
                    // We need to convert our PEM to DER and base64 encode it
                    let cert_der = self.certificate.to_der().ok()?;
                    let cert_der_b64 = base64.encode(cert_der);

                    if cert_der_b64 != cert_bytes {
                        debug!("DSSE v0.0.2 verifier (certificate) mismatch");
                        return None;
                    }
                }
                _ => {
                    debug!("Unsupported DSSE API version: {}", api_version);
                    return None;
                }
            }

            // All checks passed - the DSSE entry is valid
        } else {
            // Regular hashedrekord entry
            let expected_entry = rekor::Hashedrekord {
                kind: "hashedrekord".to_owned(),
                api_version: "0.0.1".to_owned(),
                spec: rekor::hashedrekord::Spec {
                    signature: rekor::hashedrekord::Signature {
                        content: base64.encode(&self.signature),
                        public_key: rekor::hashedrekord::PublicKey::new(base64_pem_certificate),
                    },
                    data: rekor::hashedrekord::Data {
                        hash: rekor::hashedrekord::Hash {
                            algorithm: rekor::hashedrekord::AlgorithmKind::sha256,
                            value: hex::encode(input_digest),
                        },
                    },
                },
            };

            let actual: serde_json::Value =
                serde_json::from_slice(&self.tlog_entry.canonicalized_body).ok()?;
            let expected: serde_json::Value = serde_json::to_value(expected_entry).ok()?;

            if actual != expected {
                return None;
            }
        }

        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsse_bundle_parsing() {
        // Test that we can parse a DSSE bundle without errors
        let bundle_json = include_str!("../../../tests/data/dsse_bundle.sigstore.json");

        let bundle: Bundle = serde_json::from_str(bundle_json)
            .expect("Failed to parse DSSE bundle JSON");

        // Verify it's a v0.3 bundle
        assert_eq!(bundle.media_type, "application/vnd.dev.sigstore.bundle.v0.3+json");

        // Try to convert to CheckedBundle - this validates the structure
        let checked = CheckedBundle::try_from(bundle);

        // The bundle should be valid structurally (though we can't fully verify without trust root)
        if let Err(e) = &checked {
            eprintln!("Error parsing DSSE bundle: {:?}", e);
        }
        assert!(checked.is_ok(), "DSSE bundle should be structurally valid: {:?}", checked.err());

        let checked = checked.unwrap();

        // Verify DSSE envelope is present
        assert!(checked.dsse_envelope.is_some(), "DSSE envelope should be present");
    }

    #[test]
    fn test_regular_bundle_v3_parsing() {
        // Test that we can parse a regular (non-DSSE) v0.3 bundle
        let bundle_json = include_str!("../../../tests/data/bundle_v3.txt.sigstore");

        let bundle: Bundle = serde_json::from_str(bundle_json)
            .expect("Failed to parse v0.3 bundle JSON");

        // Verify it's a v0.3 bundle
        assert_eq!(bundle.media_type, "application/vnd.dev.sigstore.bundle.v0.3+json");

        // Try to convert to CheckedBundle
        let checked = CheckedBundle::try_from(bundle);
        assert!(checked.is_ok(), "Regular v0.3 bundle should be structurally valid");

        let checked = checked.unwrap();

        // Verify DSSE envelope is NOT present
        assert!(checked.dsse_envelope.is_none(), "Regular bundle should not have DSSE envelope");
    }

    #[test]
    fn test_dsse_v001_tlog_verification_valid() {
        // Test that a valid DSSE v0.0.1 bundle passes transparency log verification
        let bundle_json = include_str!("../../../tests/data/dsse_v001_bundle.sigstore.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).unwrap();
        let checked = CheckedBundle::try_from(bundle).unwrap();

        // Verify the transparency log entry validates
        let empty_digest = vec![];
        let tlog_entry = checked.tlog_entry(true, &empty_digest);
        assert!(tlog_entry.is_some(), "DSSE v0.0.1 transparency log entry should validate");
    }

    #[test]
    fn test_dsse_v002_tlog_verification_valid() {
        // Test that a valid DSSE v0.0.2 bundle passes transparency log verification
        let bundle_json = include_str!("../../../tests/data/dsse_v002_bundle.sigstore.json");
        let bundle: Bundle = serde_json::from_str(bundle_json).unwrap();
        let checked = CheckedBundle::try_from(bundle).unwrap();

        // Verify the transparency log entry validates
        let empty_digest = vec![];
        let tlog_entry = checked.tlog_entry(true, &empty_digest);
        assert!(tlog_entry.is_some(), "DSSE v0.0.2 transparency log entry should validate");
    }

    #[test]
    fn test_dsse_tlog_verification_payload_tampered() {
        // Test that tampering with the payload causes transparency log verification to fail
        let bundle_json = include_str!("../../../tests/data/dsse_v001_bundle.sigstore.json");
        let mut bundle: Bundle = serde_json::from_str(bundle_json).unwrap();

        // Tamper with the DSSE payload
        if let Some(ref mut content) = bundle.content {
            if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
                envelope.payload[0] ^= 0xFF;
            }
        }

        let checked = CheckedBundle::try_from(bundle).unwrap();

        // Verify the transparency log entry validation FAILS
        let empty_digest = vec![];
        let tlog_entry = checked.tlog_entry(true, &empty_digest);
        assert!(tlog_entry.is_none(), "Transparency log verification should FAIL with tampered payload");
    }

    #[test]
    fn test_dsse_tlog_verification_signature_tampered() {
        // Test that tampering with the signature causes transparency log verification to fail
        let bundle_json = include_str!("../../../tests/data/dsse_v001_bundle.sigstore.json");
        let mut bundle: Bundle = serde_json::from_str(bundle_json).unwrap();

        // Tamper with the DSSE signature
        if let Some(ref mut content) = bundle.content {
            if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
                if !envelope.signatures.is_empty() {
                    envelope.signatures[0].sig[0] ^= 0xFF;
                }
            }
        }

        let checked = CheckedBundle::try_from(bundle).unwrap();

        // Verify the transparency log entry validation FAILS
        let empty_digest = vec![];
        let tlog_entry = checked.tlog_entry(true, &empty_digest);
        assert!(tlog_entry.is_none(), "Transparency log verification should FAIL with tampered signature");
    }

    #[test]
    fn test_dsse_v002_tlog_verification_payload_tampered() {
        // Test that tampering with v0.0.2 payload causes transparency log verification to fail
        let bundle_json = include_str!("../../../tests/data/dsse_v002_bundle.sigstore.json");
        let mut bundle: Bundle = serde_json::from_str(bundle_json).unwrap();

        // Tamper with the DSSE payload
        if let Some(ref mut content) = bundle.content {
            if let sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content::DsseEnvelope(envelope) = content {
                envelope.payload[10] ^= 0xFF;
            }
        }

        let checked = CheckedBundle::try_from(bundle).unwrap();

        // Verify the transparency log entry validation FAILS
        let empty_digest = vec![];
        let tlog_entry = checked.tlog_entry(true, &empty_digest);
        assert!(tlog_entry.is_none(), "DSSE v0.0.2 transparency log verification should FAIL with tampered payload");
    }
}
