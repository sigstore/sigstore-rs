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

//! Verifiers: async and blocking.

use std::io::{self, Read};

use base64::Engine;
use pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;
use x509_cert::der::Encode;

use crate::{
    bundle::Bundle,
    crypto::{
        CertificatePool, CosignVerificationKey, Signature,
        keyring::Keyring,
        merkle,
        transparency::{CertificateEmbeddedSCT, verify_sct},
    },
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    trust::TrustRoot,
};
use serde::Serialize;

#[cfg(feature = "sigstore-trust-root")]
use crate::trust::sigstore::SigstoreTrustRoot;

use super::{
    VerificationError, VerificationResult,
    models::{CertificateErrorKind, CheckedBundle, SignatureErrorKind},
    policy::VerificationPolicy,
};

/// An asynchronous Sigstore verifier.
///
/// For synchronous usage, see [`Verifier`].
pub struct Verifier {
    #[allow(dead_code)]
    rekor_config: RekorConfiguration,
    cert_pool: CertificatePool,
    ctfe_keyring: Keyring,
    rekor_keyring: Keyring,
}

impl Verifier {
    /// Constructs a [`Verifier`].
    ///
    /// For verifications against the public-good trust root, use [`Verifier::production()`].
    pub fn new<R: TrustRoot>(
        rekor_config: RekorConfiguration,
        trust_repo: R,
    ) -> SigstoreResult<Self> {
        let cert_pool = CertificatePool::from_certificates(trust_repo.fulcio_certs()?, [])?;
        let ctfe_keyring = Keyring::new(trust_repo.ctfe_keys()?.values().copied())?;
        let rekor_keyring = Keyring::new(trust_repo.rekor_keys()?.values().copied())?;

        Ok(Self {
            rekor_config,
            cert_pool,
            ctfe_keyring,
            rekor_keyring,
        })
    }

    /// Verifies an input digest against the given Sigstore Bundle, ensuring conformance to the
    /// provided [`VerificationPolicy`].
    pub async fn verify_digest<P>(
        &self,
        input_digest: Sha256,
        bundle: Bundle,
        policy: &P,
        offline: bool,
    ) -> VerificationResult
    where
        P: VerificationPolicy,
    {
        let input_digest = input_digest.finalize();
        let materials: CheckedBundle = bundle.try_into()?;

        // In order to verify an artifact, we need to achieve the following:
        //
        // 1) Verify that the signing certificate is signed by the certificate
        //    chain and that the signing certificate was valid at the time
        //    of signing.
        // 2) Verify that the signing certificate belongs to the signer.
        // 3) Verify that the artifact signature was signed by the public key in the
        //    signing certificate.
        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials (preventing CVE-2022-36056)
        // 5) Verify the inclusion proof supplied by Rekor for this artifact,
        //    if we're doing online verification.
        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp.

        // 1) Verify that the signing certificate is signed by the certificate
        //    chain and that the signing certificate was valid at the time
        //    of signing.
        let tbs_certificate = &materials.certificate.tbs_certificate;
        let issued_at = tbs_certificate.validity.not_before.to_unix_duration();
        let cert_der: CertificateDer = materials
            .certificate
            .to_der()
            .expect("failed to DER-encode constructed Certificate!")
            .into();
        let ee_cert = (&cert_der)
            .try_into()
            .map_err(CertificateErrorKind::Malformed)?;

        let trusted_chain = self
            .cert_pool
            .verify_cert_with_time(&ee_cert, UnixTime::since_unix_epoch(issued_at))
            .map_err(CertificateErrorKind::VerificationFailed)?;

        debug!("signing certificate chains back to trusted root");

        let sct_context =
            CertificateEmbeddedSCT::new_with_verified_path(&materials.certificate, &trusted_chain)
                .map_err(CertificateErrorKind::Sct)?;
        verify_sct(&sct_context, &self.ctfe_keyring).map_err(CertificateErrorKind::Sct)?;
        debug!("signing certificate's SCT is valid");

        // 2) Verify that the signing certificate belongs to the signer.
        policy.verify(&materials.certificate)?;
        debug!("signing certificate conforms to policy");

        // 3) Verify that the signature was signed by the public key in the signing certificate
        let signing_key: CosignVerificationKey = (&tbs_certificate.subject_public_key_info)
            .try_into()
            .map_err(SignatureErrorKind::AlgoUnsupported)?;

        // For DSSE bundles, we verify against the PAE; for regular bundles, against the digest
        let verify_sig = if materials.is_dsse() {
            // DSSE verification: verify raw signature against PAE (not prehashed)
            let pae = materials.verification_data(&input_digest);
            signing_key.verify_signature(Signature::Raw(&materials.signature), &pae)
        } else {
            // Regular verification: verify against prehashed input digest
            signing_key.verify_prehash(Signature::Raw(&materials.signature), &input_digest)
        };
        verify_sig.map_err(SignatureErrorKind::VerificationFailed)?;

        debug!("signature corresponds to public key");

        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials
        let log_entry = materials
            .tlog_entry(offline, &input_digest)
            .ok_or(SignatureErrorKind::Transparency)?;
        debug!("log entry is consistent with other materials");

        // 5) Verify the inclusion proof supplied by Rekor for this artifact
        if let Some(inclusion_proof) = &log_entry.inclusion_proof {
            debug!("verifying Merkle inclusion proof");

            // The hashes in the protobuf are already binary (Vec<u8>), no decoding needed
            let proof_hashes = &inclusion_proof.hashes;
            let root_hash = &inclusion_proof.root_hash;

            // Compute leaf hash using RFC 6962 format
            let leaf_hash = merkle::leaf_hash(&log_entry.canonicalized_body);

            // Verify the inclusion proof
            merkle::verify_inclusion(
                inclusion_proof.log_index as u64,
                inclusion_proof.tree_size as u64,
                &leaf_hash,
                &proof_hashes,
                &root_hash,
            )
            .map_err(|e| SignatureErrorKind::TransparencyLogError(e.to_string()))?;

            debug!("inclusion proof verified successfully");
        } else {
            debug!("no inclusion proof present, skipping verification");
        }

        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        if let Some(inclusion_promise) = &log_entry.inclusion_promise {
            debug!("verifying Signed Entry Timestamp (SET)");

            // The SET is a signature over a canonicalized JSON payload containing:
            // {body, integratedTime, logIndex, logID}
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct SetPayload<'a> {
                body: &'a str,
                integrated_time: i64,
                log_index: i64,
                #[serde(rename = "logID")]
                log_id: String,
            }

            // Convert canonicalized_body to base64 string
            let body_base64 = base64::engine::general_purpose::STANDARD
                .encode(&log_entry.canonicalized_body);

            // Get logID from the log entry for both verification and payload
            let log_id_struct = log_entry
                .log_id
                .as_ref()
                .ok_or_else(|| SignatureErrorKind::TransparencyLogError(
                    "log entry missing logID".into()
                ))?;

            // Extract key_id as &[u8; 32] for keyring verification
            let key_id: &[u8; 32] = log_id_struct
                .key_id
                .as_slice()
                .try_into()
                .map_err(|_| SignatureErrorKind::TransparencyLogError(
                    "log entry logID has invalid length (expected 32 bytes)".into()
                ))?;

            // Convert key_id to HEX string for SET payload (as per sigstore-go implementation)
            let log_id = hex::encode(&log_id_struct.key_id);

            let set_payload = SetPayload {
                body: &body_base64,
                integrated_time: log_entry.integrated_time,
                log_index: log_entry.log_index,
                log_id: log_id.clone(),
            };

            debug!("SET payload fields: body_len={}, integrated_time={}, log_index={}, log_id={}",
                   body_base64.len(), log_entry.integrated_time, log_entry.log_index, log_id);

            // Canonicalize the JSON using olpc-cjson
            let payload_json = serde_json::to_vec(&set_payload)
                .map_err(|e| SignatureErrorKind::TransparencyLogError(
                    format!("failed to serialize SET payload: {}", e)
                ))?;

            use olpc_cjson::CanonicalFormatter;
            let payload_value: serde_json::Value = serde_json::from_slice(&payload_json)
                .map_err(|e| SignatureErrorKind::TransparencyLogError(
                    format!("failed to parse SET payload: {}", e)
                ))?;
            let mut canonicalized = Vec::new();
            let mut ser = serde_json::Serializer::with_formatter(
                &mut canonicalized,
                CanonicalFormatter::new(),
            );
            payload_value.serialize(&mut ser)
                .map_err(|e| SignatureErrorKind::TransparencyLogError(
                    format!("failed to canonicalize SET payload: {}", e)
                ))?;

            debug!("SET payload (canonical JSON): {}", String::from_utf8_lossy(&canonicalized));
            debug!("SET signature (base64): {}", base64::engine::general_purpose::STANDARD.encode(&inclusion_promise.signed_entry_timestamp));

            // Verify the signature using Rekor's public key
            // Note: keyring.verify() will hash the canonicalized data internally with SHA256
            self.rekor_keyring
                .verify(
                    key_id,
                    &inclusion_promise.signed_entry_timestamp,
                    &canonicalized,
                )
                .map_err(|e| SignatureErrorKind::TransparencyLogError(
                    format!("SET signature verification failed: {}", e)
                ))?;

            debug!("SET verified successfully");
        } else {
            debug!("no inclusion promise present, skipping SET verification");
        }

        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp.
        let integrated_time = log_entry.integrated_time as u64;
        let not_before = tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if integrated_time < not_before || integrated_time > not_after {
            return Err(CertificateErrorKind::Expired)?;
        }
        debug!("data signed during validity period");

        debug!("successfully verified!");
        Ok(())
    }

    /// Verifies an input against the given Sigstore Bundle, ensuring conformance to the provided
    /// [`VerificationPolicy`].
    pub async fn verify<R, P>(
        &self,
        mut input: R,
        bundle: Bundle,
        policy: &P,
        offline: bool,
    ) -> VerificationResult
    where
        R: AsyncRead + Unpin + Send,
        P: VerificationPolicy,
    {
        // arbitrary buffer size, chosen to be a multiple of the digest size.
        let mut buf = [0u8; 1024];
        let mut hasher = Sha256::new();

        loop {
            match input
                .read(&mut buf)
                .await
                .map_err(VerificationError::Input)?
            {
                0 => break,
                n => hasher.update(&buf[..n]),
            }
        }

        self.verify_digest(hasher, bundle, policy, offline).await
    }
}

impl Verifier {
    /// Constructs an [`Verifier`] against the public-good trust root.
    #[cfg(feature = "sigstore-trust-root")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    pub async fn production() -> SigstoreResult<Verifier> {
        let updater = SigstoreTrustRoot::new(None).await?;

        Verifier::new(Default::default(), updater)
    }
}

pub mod blocking {
    use super::{Verifier as AsyncVerifier, *};

    /// A synchronous Sigstore verifier.
    pub struct Verifier {
        inner: AsyncVerifier,
        rt: tokio::runtime::Runtime,
    }

    impl Verifier {
        /// Constructs a synchronous Sigstore verifier.
        ///
        /// For verifications against the public-good trust root, use [`Verifier::production()`].
        pub fn new<R: TrustRoot>(
            rekor_config: RekorConfiguration,
            trust_repo: R,
        ) -> SigstoreResult<Self> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let inner = AsyncVerifier::new(rekor_config, trust_repo)?;

            Ok(Self { rt, inner })
        }

        /// Verifies an input digest against the given Sigstore Bundle, ensuring conformance to the
        /// provided [`VerificationPolicy`].
        pub fn verify_digest<P>(
            &self,
            input_digest: Sha256,
            bundle: Bundle,
            policy: &P,
            offline: bool,
        ) -> VerificationResult
        where
            P: VerificationPolicy,
        {
            self.rt.block_on(
                self.inner
                    .verify_digest(input_digest, bundle, policy, offline),
            )
        }

        /// Verifies an input against the given Sigstore Bundle, ensuring conformance to the provided
        /// [`VerificationPolicy`].
        pub fn verify<R, P>(
            &self,
            mut input: R,
            bundle: Bundle,
            policy: &P,
            offline: bool,
        ) -> VerificationResult
        where
            R: Read,
            P: VerificationPolicy,
        {
            let mut hasher = Sha256::new();
            io::copy(&mut input, &mut hasher).map_err(VerificationError::Input)?;

            self.verify_digest(hasher, bundle, policy, offline)
        }
    }

    impl Verifier {
        /// Constructs a synchronous [`Verifier`] against the public-good trust root.
        #[cfg(feature = "sigstore-trust-root")]
        #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
        pub fn production() -> SigstoreResult<Verifier> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let inner = rt.block_on(AsyncVerifier::production())?;

            Ok(Verifier { inner, rt })
        }
    }
}
