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
use chrono::{DateTime, Utc};
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
        transparency::{CertificateEmbeddedSCTs, verify_scts},
    },
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    trust::TrustRoot,
};
use serde::Serialize;

/// TSA certificate with its validity period from the trusted root
struct TsaCertificate {
    cert: CertificateDer<'static>,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
}

#[cfg(feature = "sigstore-trust-root")]
use crate::trust::sigstore::SigstoreTrustRoot;

use super::{
    VerificationError,
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
    tsa_certs: Vec<TsaCertificate>,
    tsa_root_certs: Vec<CertificateDer<'static>>,
    tsa_intermediate_certs: Vec<CertificateDer<'static>>,
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

        // For Rekor keys, we need to use the key IDs from the trusted root
        // rather than computing them, as they may not match RFC 6962 style IDs
        let rekor_keys: Vec<([u8; 32], &[u8])> = trust_repo
            .rekor_keys()?
            .iter()
            .filter_map(|(key_id_hex, key_bytes)| {
                let key_id_bytes = hex::decode(key_id_hex).ok()?;
                let key_id: [u8; 32] = key_id_bytes.try_into().ok()?;
                Some((key_id, *key_bytes))
            })
            .collect();
        let rekor_keyring =
            Keyring::new_with_ids(rekor_keys.iter().map(|(id, bytes)| (id, *bytes)))?;

        debug!("Fetching TSA certificates with validity periods from trust root");
        let tsa_certs: Vec<TsaCertificate> = trust_repo
            .tsa_certs_with_validity()?
            .into_iter()
            .map(|(cert, valid_from, valid_to)| TsaCertificate {
                cert: cert.into_owned(),
                valid_from,
                valid_to,
            })
            .collect();

        debug!("Fetching TSA root certificates for chain validation");
        let tsa_root_certs: Vec<CertificateDer<'static>> = trust_repo
            .tsa_root_certs()?
            .into_iter()
            .map(|cert| cert.into_owned())
            .collect();

        debug!("Fetching TSA intermediate certificates for chain validation");
        let tsa_intermediate_certs: Vec<CertificateDer<'static>> = trust_repo
            .tsa_intermediate_certs()?
            .into_iter()
            .map(|cert| cert.into_owned())
            .collect();

        Ok(Self {
            rekor_config,
            cert_pool,
            ctfe_keyring,
            rekor_keyring,
            tsa_certs,
            tsa_root_certs,
            tsa_intermediate_certs,
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
    ) -> Result<CheckedBundle, VerificationError>
    where
        P: VerificationPolicy,
    {
        let input_digest = input_digest.finalize();
        return self
            .verify_digest_bytes(&input_digest.into(), bundle, policy, offline)
            .await;
    }

    /// Verifies a pre-computed SHA256 digest against the given Sigstore Bundle, ensuring
    /// conformance to the provided [`VerificationPolicy`].
    ///
    /// This method is useful when you have already computed the digest of the artifact
    /// and want to avoid re-hashing it.
    ///
    /// # Arguments
    ///
    /// * `digest_bytes` - The SHA256 digest bytes (must be exactly 32 bytes)
    /// * `bundle` - The Sigstore bundle to verify against
    /// * `policy` - The verification policy to enforce
    /// * `offline` - Whether to perform offline verification (skips online checks)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use sigstore::bundle::verify::{Verifier, policy};
    /// # use sigstore::bundle::Bundle;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = Verifier::production().await?;
    /// let bundle: Bundle = todo!();
    /// let policy = policy::Identity::new("user@example.com", "https://issuer.example.com");
    ///
    /// // Pre-computed SHA256 digest (32 bytes)
    /// let digest: [u8; 32] = [0u8; 32]; // Your actual digest here
    ///
    /// verifier.verify_digest_bytes(&digest, bundle, &policy, false).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_digest_bytes<P>(
        &self,
        digest_bytes: &[u8; 32],
        bundle: Bundle,
        policy: &P,
        offline: bool,
    ) -> Result<CheckedBundle, VerificationError>
    where
        P: VerificationPolicy,
    {
        // Convert the digest bytes to Digest output type
        let input_digest: digest::Output<Sha256> = (*digest_bytes).into();
        let materials: CheckedBundle = bundle.try_into()?;

        // Reuse the existing verification logic by jumping to the point after finalization
        // We'll inline the verification logic here to avoid the finalize() call

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

        // Try to verify multiple SCTs (matching sigstore-go behavior).
        // This allows old bundles with rotated CTFE keys to still verify if they have
        // at least one SCT that can be verified with the current trust root.
        let scts_context =
            CertificateEmbeddedSCTs::new_with_verified_path(&materials.certificate, &trusted_chain)
                .map_err(CertificateErrorKind::Sct)?;
        // Use threshold of 1 - at least one SCT must be verifiable
        verify_scts(&scts_context, &self.ctfe_keyring, 1).map_err(CertificateErrorKind::Sct)?;
        debug!("signing certificate's SCT(s) are valid");

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

        // 3.5) Verify TSA timestamps if present (RFC 3161)
        let mut tsa_timestamp: Option<DateTime<Utc>> = None;
        if let Some(timestamp_data) = &materials.timestamp_verification_data
            && !timestamp_data.rfc3161_timestamps.is_empty()
        {
            debug!(
                "verifying {} RFC 3161 timestamp(s)",
                timestamp_data.rfc3161_timestamps.len()
            );

            for (i, ts) in timestamp_data.rfc3161_timestamps.iter().enumerate() {
                // Verify the RFC 3161 timestamp against the signature bytes
                let (tsa_cert, tsa_valid_for) = if let Some(tsa) = self.tsa_certs.first() {
                    let valid_for = match (tsa.valid_from, tsa.valid_to) {
                        (Some(from), Some(to)) => Some((from, to)),
                        _ => None,
                    };
                    (Some(tsa.cert.clone()), valid_for)
                } else {
                    (None, None)
                };

                debug!("Calling verify_timestamp_response for timestamp {}", i);
                let timestamp_result = crate::crypto::timestamp::verify_timestamp_response(
                    &ts.signed_timestamp,
                    &materials.signature,
                    crate::crypto::timestamp::VerifyOpts {
                        roots: self.tsa_root_certs.clone(),
                        intermediates: self.tsa_intermediate_certs.clone(),
                        tsa_certificate: tsa_cert,
                        tsa_valid_for,
                    },
                )
                .map_err(|e| {
                    debug!("RFC 3161 timestamp {} verification failed: {}", i, e);
                    SignatureErrorKind::TransparencyLogError(format!(
                        "failed to verify RFC 3161 timestamp {}: {}",
                        i, e
                    ))
                })?;

                debug!(
                    "RFC 3161 timestamp {} verified successfully: {}",
                    i, timestamp_result.time
                );

                // Store the first timestamp for certificate validity checking
                if tsa_timestamp.is_none() {
                    tsa_timestamp = Some(timestamp_result.time);
                }

                // Verify that the timestamp is within the signing certificate's validity period
                let timestamp_unix = timestamp_result.time.timestamp() as u64;
                let cert_not_before = tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs();
                let cert_not_after = tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs();
                if timestamp_unix < cert_not_before || timestamp_unix > cert_not_after {
                    return Err(SignatureErrorKind::TransparencyLogError(format!(
                        "RFC 3161 timestamp {} is outside signing certificate validity period (cert valid from {} to {}, timestamp is {})",
                        i, cert_not_before, cert_not_after, timestamp_unix
                    )))?;
                }
                debug!(
                    "RFC 3161 timestamp {} is within signing certificate validity period",
                    i
                );
            }
        }

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
                proof_hashes,
                root_hash,
            )
            .map_err(|e| SignatureErrorKind::TransparencyLogError(e.to_string()))?;

            debug!("inclusion proof verified successfully");

            // 5b) Verify the checkpoint signature if present (Rekor v2)
            if let Some(checkpoint) = &inclusion_proof.checkpoint {
                use crate::crypto::note::SignedNote;

                // Parse the checkpoint note
                let signed_note = SignedNote::from_text(&checkpoint.envelope).map_err(|e| {
                    SignatureErrorKind::TransparencyLogError(format!(
                        "failed to parse checkpoint: {}",
                        e
                    ))
                })?;

                // Check if this is a Rekor v1 Signed Tree Head (STH) by looking for
                // a numeric Tree ID suffix in the checkpoint origin (e.g., "rekor.sigstore.dev - 2605736670972794746").
                // Rekor v1 STHs have a different signature format and should not be verified as Rekor v2 checkpoints.
                let is_rekor_v1_sth = signed_note.checkpoint.origin.contains(" - ")
                    && signed_note
                        .checkpoint
                        .origin
                        .rsplit(" - ")
                        .next()
                        .map(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or(false);

                // Verify the checkpoint root hash matches the inclusion proof root hash
                // This check applies to both Rekor v1 and v2
                debug!("verifying checkpoint root hash against inclusion proof root hash");
                signed_note.verify_root_hash(root_hash).map_err(|e| {
                    SignatureErrorKind::TransparencyLogError(format!(
                        "checkpoint root hash mismatch: {}",
                        e
                    ))
                })?;
                debug!("checkpoint root hash matches");

                // Verify the checkpoint tree size matches the inclusion proof tree size
                // This check also applies to both Rekor v1 and v2
                debug!(
                    "verifying checkpoint tree size ({}) matches inclusion proof tree size ({})",
                    signed_note.checkpoint.tree_size, inclusion_proof.tree_size
                );
                if signed_note.checkpoint.tree_size != inclusion_proof.tree_size as u64 {
                    return Err(SignatureErrorKind::TransparencyLogError(format!(
                        "checkpoint tree size mismatch: checkpoint has {}, inclusion proof has {}",
                        signed_note.checkpoint.tree_size, inclusion_proof.tree_size
                    )))?;
                }
                debug!("checkpoint tree size matches");

                // Verify checkpoint/STH signature for both Rekor v1 and v2
                // The signature verification process is the same, just the format detection differs
                let checkpoint_type = if is_rekor_v1_sth {
                    "Rekor v1 STH"
                } else {
                    "Rekor v2 checkpoint"
                };
                debug!("verifying {} signature", checkpoint_type);

                // Get the log's key ID from the log entry
                debug!("getting log key ID from log entry");
                let log_id_struct = log_entry.log_id.as_ref().ok_or_else(|| {
                    SignatureErrorKind::TransparencyLogError(
                        "log entry missing logID for checkpoint verification".into(),
                    )
                })?;

                let key_id: [u8; 32] =
                    log_id_struct.key_id.as_slice().try_into().map_err(|_| {
                        SignatureErrorKind::TransparencyLogError(
                            "log entry logID has invalid length (expected 32 bytes)".into(),
                        )
                    })?;
                debug!("log key ID: {}", hex::encode(key_id));

                // Find the signature in the checkpoint that matches the log's key ID
                // Note signatures use the first 4 bytes of the key ID (keyhint)
                let key_id_prefix: [u8; 4] = [key_id[0], key_id[1], key_id[2], key_id[3]];
                debug!(
                    "looking for checkpoint signature with key ID prefix: {}",
                    hex::encode(key_id_prefix)
                );
                let checkpoint_sig =
                    signed_note.find_signature(&key_id_prefix).ok_or_else(|| {
                        SignatureErrorKind::TransparencyLogError(format!(
                            "checkpoint does not contain signature from log (key ID: {})",
                            hex::encode(key_id_prefix)
                        ))
                    })?;
                debug!("found checkpoint signature for log");

                // Verify the signature over the checkpoint text
                debug!(
                    "verifying checkpoint signature (sig len: {}, data len: {})",
                    checkpoint_sig.signature.len(),
                    signed_note.checkpoint_text.len()
                );
                self.rekor_keyring
                    .verify(
                        &key_id,
                        &checkpoint_sig.signature,
                        signed_note.checkpoint_text.as_bytes(),
                    )
                    .map_err(|e| {
                        SignatureErrorKind::TransparencyLogError(format!(
                            "checkpoint signature verification failed: {}",
                            e
                        ))
                    })?;

                debug!("{} verified successfully", checkpoint_type);
            } else {
                debug!("no checkpoint present (Rekor v1), skipping checkpoint verification");
            }
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
            let body_base64 =
                base64::engine::general_purpose::STANDARD.encode(&log_entry.canonicalized_body);

            // Get logID from the log entry for both verification and payload
            let log_id_struct = log_entry.log_id.as_ref().ok_or_else(|| {
                SignatureErrorKind::TransparencyLogError("log entry missing logID".into())
            })?;

            // Extract key_id as &[u8; 32] for keyring verification
            let key_id: &[u8; 32] = log_id_struct.key_id.as_slice().try_into().map_err(|_| {
                SignatureErrorKind::TransparencyLogError(
                    "log entry logID has invalid length (expected 32 bytes)".into(),
                )
            })?;

            // Convert key_id to HEX string for SET payload (as per sigstore-go implementation)
            let log_id = hex::encode(&log_id_struct.key_id);

            let set_payload = SetPayload {
                body: &body_base64,
                integrated_time: log_entry.integrated_time,
                log_index: log_entry.log_index,
                log_id: log_id.clone(),
            };

            debug!(
                "SET payload fields: body_len={}, integrated_time={}, log_index={}, log_id={}",
                body_base64.len(),
                log_entry.integrated_time,
                log_entry.log_index,
                log_id
            );

            // Canonicalize the JSON using olpc-cjson
            let payload_json = serde_json::to_vec(&set_payload).map_err(|e| {
                SignatureErrorKind::TransparencyLogError(format!(
                    "failed to serialize SET payload: {}",
                    e
                ))
            })?;

            use olpc_cjson::CanonicalFormatter;
            let payload_value: serde_json::Value =
                serde_json::from_slice(&payload_json).map_err(|e| {
                    SignatureErrorKind::TransparencyLogError(format!(
                        "failed to parse SET payload: {}",
                        e
                    ))
                })?;
            let mut canonicalized = Vec::new();
            let mut ser = serde_json::Serializer::with_formatter(
                &mut canonicalized,
                CanonicalFormatter::new(),
            );
            payload_value.serialize(&mut ser).map_err(|e| {
                SignatureErrorKind::TransparencyLogError(format!(
                    "failed to canonicalize SET payload: {}",
                    e
                ))
            })?;

            debug!(
                "SET payload (canonical JSON): {}",
                String::from_utf8_lossy(&canonicalized)
            );
            debug!(
                "SET signature (base64): {}",
                base64::engine::general_purpose::STANDARD
                    .encode(&inclusion_promise.signed_entry_timestamp)
            );

            // Verify the signature using Rekor's public key
            // Note: keyring.verify() will hash the canonicalized data internally with SHA256
            self.rekor_keyring
                .verify(
                    key_id,
                    &inclusion_promise.signed_entry_timestamp,
                    &canonicalized,
                )
                .map_err(|e| {
                    SignatureErrorKind::TransparencyLogError(format!(
                        "SET signature verification failed: {}",
                        e
                    ))
                })?;

            debug!("SET verified successfully");
        } else {
            debug!("no inclusion promise present, skipping SET verification");
        }

        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp
        //    (Rekor v1) or TSA timestamp (Rekor v2).
        let signing_time = if log_entry.integrated_time == 0 {
            // Rekor v2: use TSA timestamp
            if let Some(tsa_time) = tsa_timestamp {
                debug!(
                    "using TSA timestamp for certificate validity check: {}",
                    tsa_time
                );
                tsa_time.timestamp() as u64
            } else {
                return Err(SignatureErrorKind::TransparencyLogError(
                    "Rekor v2 entry has no integrated_time and no TSA timestamp found".to_string(),
                ))?;
            }
        } else {
            // Rekor v1: use integrated_time
            debug!(
                "using Rekor integrated_time for certificate validity check: {}",
                log_entry.integrated_time
            );
            log_entry.integrated_time as u64
        };

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
        if signing_time < not_before || signing_time > not_after {
            return Err(CertificateErrorKind::Expired)?;
        }
        debug!("data signed during validity period");

        debug!("successfully verified!");
        Ok(materials)
    }

    /// Verifies an input against the given Sigstore Bundle, ensuring conformance to the provided
    /// [`VerificationPolicy`].
    pub async fn verify<R, P>(
        &self,
        mut input: R,
        bundle: Bundle,
        policy: &P,
        offline: bool,
    ) -> Result<CheckedBundle, VerificationError>
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
        ) -> Result<CheckedBundle, VerificationError>
        where
            P: VerificationPolicy,
        {
            self.rt.block_on(
                self.inner
                    .verify_digest(input_digest, bundle, policy, offline),
            )
        }

        /// Verifies a pre-computed SHA256 digest against the given Sigstore Bundle, ensuring
        /// conformance to the provided [`VerificationPolicy`].
        ///
        /// This method is useful when you have already computed the digest of the artifact
        /// and want to avoid re-hashing it.
        pub fn verify_digest_bytes<P>(
            &self,
            digest_bytes: &[u8; 32],
            bundle: Bundle,
            policy: &P,
            offline: bool,
        ) -> Result<CheckedBundle, VerificationError>
        where
            P: VerificationPolicy,
        {
            self.rt.block_on(
                self.inner
                    .verify_digest_bytes(digest_bytes, bundle, policy, offline),
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
        ) -> Result<CheckedBundle, VerificationError>
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
