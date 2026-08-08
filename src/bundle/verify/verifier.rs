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

use pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;
use x509_cert::der::Encode;

use crate::{
    bundle::Bundle,
    bundle::verify::models::{ArtifactDigest, BundleContent, CheckedBundle},
    crypto::{
        CertificatePool, CosignVerificationKey, Signature,
        keyring::Keyring,
        transparency::{CertificateEmbeddedSCT, verify_sct},
    },
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    trust::TrustRoot,
};

#[cfg(feature = "sigstore-trust-root")]
use crate::trust::sigstore::SigstoreTrustRoot;

use super::{
    VerificationError, VerificationResult,
    models::{CertificateErrorKind, SignatureErrorKind},
    policy::VerificationPolicy,
};

/// Verifies that `signature` over `input_digest` (or PAE bytes for DSSE) is valid for
/// `signing_key`, and that the bundle content is consistent with the provided `input_digest`.
///
/// For [`BundleContent::MessageSignature`], the signature is verified as a prehash signature
/// directly over `input_digest`.  Message signatures are always prehashed with SHA-256, so any
/// other digest algorithm is rejected.
///
/// For [`BundleContent::Dsse`], the signature is verified over the pre-computed PAE bytes stored
/// in the content, and the subject digests from the in-toto statement are compared against
/// `input_digest` to ensure the bundle describes the same artifact.  The bundle matches if *any*
/// subject carries `input_digest` under its algorithm, matching the behaviour of sigstore-go and
/// `gh attestation verify`.
pub(crate) fn verify_bundle_content(
    content: &BundleContent,
    signing_key: &CosignVerificationKey,
    signature: &[u8],
    input_digest: &ArtifactDigest,
) -> Result<(), SignatureErrorKind> {
    match content {
        BundleContent::MessageSignature => {
            let ArtifactDigest::Sha256(digest) = input_digest else {
                return Err(SignatureErrorKind::DigestAlgorithmUnsupported(
                    input_digest.algorithm(),
                ));
            };

            signing_key
                .verify_prehash(Signature::Raw(signature), digest)
                .map_err(SignatureErrorKind::VerificationFailed)
        }
        BundleContent::Dsse {
            pae,
            subject_digests,
            ..
        } => {
            // For DSSE, verify the signature over the PAE bytes, not the artifact hash.
            signing_key
                .verify_signature(Signature::Raw(signature), pae)
                .map_err(SignatureErrorKind::VerificationFailed)?;

            // Also verify that some in-toto statement subject matches the
            // artifact.  `ArtifactDigest` equality covers the algorithm as
            // well as the digest bytes.
            if !subject_digests.contains(input_digest) {
                return Err(SignatureErrorKind::SubjectDigestMismatch);
            }

            Ok(())
        }
    }
}

/// An asynchronous Sigstore verifier.
///
/// For synchronous usage, see [`Verifier`].
pub struct Verifier {
    #[allow(dead_code)]
    rekor_config: RekorConfiguration,
    cert_pool: CertificatePool,
    ctfe_keyring: Keyring,
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

        Ok(Self {
            rekor_config,
            cert_pool,
            ctfe_keyring,
        })
    }

    /// Verifies a SHA-256 input digest against the given Sigstore Bundle, ensuring conformance
    /// to the provided [`VerificationPolicy`].
    ///
    /// This is a convenience wrapper over [`Verifier::verify_digest_with`] for artifacts hashed
    /// with SHA-256.  Bundles whose in-toto subjects use another digest algorithm (npm
    /// provenance attestations, for example, carry `sha512` subjects) must be verified
    /// with [`Verifier::verify_digest_with`].
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
        self.verify_digest_with(input_digest.into(), bundle, policy, offline)
            .await
    }

    /// Verifies an input digest against the given Sigstore Bundle, ensuring conformance to the
    /// provided [`VerificationPolicy`].
    ///
    /// `input_digest` carries both the artifact digest and the algorithm that produced it; the
    /// bundle's in-toto statement is matched under that algorithm.  A DSSE bundle verifies if
    /// *any* of its subjects carries `input_digest` — an attestation listing every artifact of a
    /// release verifies each of them, matching the behaviour of sigstore-go and
    /// `gh attestation verify`.
    ///
    /// Bundles carrying a message signature rather than a DSSE envelope are always prehashed
    /// with SHA-256 and reject any other algorithm.
    pub async fn verify_digest_with<P>(
        &self,
        input_digest: ArtifactDigest,
        bundle: Bundle,
        policy: &P,
        offline: bool,
    ) -> VerificationResult
    where
        P: VerificationPolicy,
    {
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

        verify_bundle_content(
            &materials.content,
            &signing_key,
            &materials.signature,
            &input_digest,
        )?;

        debug!("signature corresponds to public key");

        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials
        let log_entry = materials
            .tlog_entry(offline, input_digest.as_bytes())
            .ok_or(SignatureErrorKind::Transparency)?;
        debug!("log entry is consistent with other materials");

        // 5) Verify the inclusion proof supplied by Rekor for this artifact,
        //    if we're doing online verification.
        // TODO(tnytown): Merkle inclusion; sigstore-rs#285

        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        // TODO(tnytown) SET verification; sigstore-rs#285

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
    ///
    /// The input is hashed with SHA-256.  Bundles whose in-toto subjects carry only another
    /// digest algorithm — npm provenance attestations, for example, carry `sha512` subjects —
    /// cannot be verified through here; hash the artifact yourself and use
    /// [`Verifier::verify_digest_with`].
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

        /// Verifies a SHA-256 input digest against the given Sigstore Bundle, ensuring
        /// conformance to the provided [`VerificationPolicy`].
        ///
        /// This is a convenience wrapper over [`Verifier::verify_digest_with`] for artifacts
        /// hashed with SHA-256.
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
            self.verify_digest_with(input_digest.into(), bundle, policy, offline)
        }

        /// Verifies an input digest against the given Sigstore Bundle, ensuring conformance to
        /// the provided [`VerificationPolicy`].
        ///
        /// See [`super::Verifier::verify_digest_with`] for the matching semantics.
        pub fn verify_digest_with<P>(
            &self,
            input_digest: ArtifactDigest,
            bundle: Bundle,
            policy: &P,
            offline: bool,
        ) -> VerificationResult
        where
            P: VerificationPolicy,
        {
            self.rt.block_on(
                self.inner
                    .verify_digest_with(input_digest, bundle, policy, offline),
            )
        }

        /// Verifies an input against the given Sigstore Bundle, ensuring conformance to the provided
        /// [`VerificationPolicy`].
        ///
        /// The input is hashed with SHA-256.  Bundles whose in-toto subjects carry only another
        /// digest algorithm — npm provenance attestations, for example, carry `sha512` subjects
        /// — cannot be verified through here; hash the artifact yourself and use
        /// [`Verifier::verify_digest_with`].
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use sha2::Digest as _;

    use crate::{
        bundle::verify::models::{ArtifactDigest, BundleContent, compute_pae},
        crypto::SigningScheme,
    };

    use super::verify_bundle_content;

    /// Builds a real ECDSA P-256 signer and returns `(verification_key, sign_fn)` where
    /// `sign_fn(msg)` produces a valid signature over `msg`.
    fn make_signer() -> (
        crate::crypto::CosignVerificationKey,
        impl Fn(&[u8]) -> Vec<u8>,
    ) {
        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .expect("failed to create signer");
        let vk = signer
            .to_verification_key()
            .expect("failed to derive verification key");
        (vk, move |msg: &[u8]| {
            signer.sign(msg).expect("signing failed")
        })
    }

    // ── DSSE cases ────────────────────────────────────────────────────────────

    #[test]
    fn dsse_valid_signature_and_matching_digest() {
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);
        let digest = ArtifactDigest::Sha256([0u8; 32]);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_digests: vec![digest],
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    /// npm provenance attestations describe their subject with a `sha512`
    /// digest and nothing else.
    #[test]
    fn dsse_valid_signature_and_matching_sha512_digest() {
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);
        let digest = ArtifactDigest::Sha512([7u8; 64]);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_digests: vec![digest],
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    /// sigstore-rs#596: one attestation may list every artifact of a release as
    /// a subject, so a match against any subject — not just the first — counts.
    #[rstest]
    #[case::first_subject(0)]
    #[case::second_subject(1)]
    #[case::third_subject(2)]
    fn dsse_matches_any_subject(#[case] matching_index: usize) {
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);
        let digest = ArtifactDigest::Sha256([matching_index as u8; 32]);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_digests: (0..3u8).map(|i| ArtifactDigest::Sha256([i; 32])).collect(),
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    /// A subject may carry several digests; a match under any one of them counts.
    #[rstest]
    #[case::sha256(ArtifactDigest::Sha256([3u8; 32]))]
    #[case::sha512(ArtifactDigest::Sha512([4u8; 64]))]
    fn dsse_matches_multi_digest_subject(#[case] digest: ArtifactDigest) {
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_digests: vec![
                ArtifactDigest::Sha256([3u8; 32]),
                ArtifactDigest::Sha512([4u8; 64]),
            ],
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    #[rstest]
    // No subject carries the presented digest.
    #[case::wrong_digest(vec![ArtifactDigest::Sha256([1u8; 32])])]
    // The subject digest's bytes match, but under a different algorithm than
    // the caller's: an artifact must be bound under the algorithm it was
    // hashed with.  (The subject's first 32 bytes equal the caller's digest.)
    #[case::algorithm_mismatch(vec![ArtifactDigest::Sha512([0u8; 64])])]
    fn dsse_valid_signature_wrong_digest(#[case] subject_digests: Vec<ArtifactDigest>) {
        let digest = ArtifactDigest::Sha256([0u8; 32]);
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_digests,
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        let err = verify_bundle_content(&content, &vk, &sig, &digest)
            .expect_err("expected a SubjectDigestMismatch error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::SubjectDigestMismatch
        ));
    }

    #[test]
    fn dsse_invalid_signature() {
        let (vk, _) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let bad_sig = vec![0u8; 64]; // garbage bytes
        let digest = ArtifactDigest::Sha256([0u8; 32]);

        let content = BundleContent::Dsse {
            pae,
            subject_digests: vec![digest],
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        let err = verify_bundle_content(&content, &vk, &bad_sig, &digest)
            .expect_err("expected VerificationFailed error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::VerificationFailed(_)
        ));
    }

    // ── MessageSignature cases ────────────────────────────────────────────────

    // MessageSignature uses verify_prehash: the signature is produced over the full message
    // by the signer (which hashes internally), while verify_prehash takes the pre-computed
    // SHA-256 digest. We sign the raw message and pass its digest separately.
    #[rstest]
    #[case::rsa_pss(SigningScheme::RSA_PSS_SHA256(2048))]
    #[case::rsa_pkcs1(SigningScheme::RSA_PKCS1_SHA256(2048))]
    fn message_signature_valid(#[case] scheme: SigningScheme) {
        let signer = scheme.create_signer().expect("failed to create signer");
        let vk = signer
            .to_verification_key()
            .expect("failed to derive verification key");
        let msg = b"test artifact";
        let sig = signer.sign(msg).expect("signing failed");
        // verify_prehash expects the SHA-256 digest of the original message.
        let digest = ArtifactDigest::Sha256(sha2::Sha256::digest(msg).into());

        let content = BundleContent::MessageSignature;

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    #[rstest]
    #[case::rsa_pss(SigningScheme::RSA_PSS_SHA256(2048))]
    #[case::rsa_pkcs1(SigningScheme::RSA_PKCS1_SHA256(2048))]
    fn message_signature_invalid_signature(#[case] scheme: SigningScheme) {
        let signer = scheme.create_signer().expect("failed to create signer");
        let vk = signer
            .to_verification_key()
            .expect("failed to derive verification key");
        let msg = b"test artifact";
        let bad_sig = vec![0u8; 64]; // garbage bytes
        let digest = ArtifactDigest::Sha256(sha2::Sha256::digest(msg).into());

        let content = BundleContent::MessageSignature;

        let err = verify_bundle_content(&content, &vk, &bad_sig, &digest)
            .expect_err("expected VerificationFailed error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::VerificationFailed(_)
        ));
    }

    #[rstest]
    #[case::rsa_pss(SigningScheme::RSA_PSS_SHA256(2048))]
    #[case::rsa_pkcs1(SigningScheme::RSA_PKCS1_SHA256(2048))]
    fn message_signature_wrong_digest(#[case] scheme: SigningScheme) {
        let signer = scheme.create_signer().expect("failed to create signer");
        let vk = signer
            .to_verification_key()
            .expect("failed to derive verification key");
        let msg = b"test artifact";
        let sig = signer.sign(msg).expect("signing failed");
        // Pass a digest for a *different* message.
        let wrong_digest =
            ArtifactDigest::Sha256(sha2::Sha256::digest(b"different artifact").into());

        let content = BundleContent::MessageSignature;

        let err = verify_bundle_content(&content, &vk, &sig, &wrong_digest)
            .expect_err("expected VerificationFailed error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::VerificationFailed(_)
        ));
    }

    /// Message signatures are prehashed with SHA-256 by construction, so a
    /// SHA-512 artifact digest can never be checked against one.
    #[rstest]
    #[case::rsa_pss(SigningScheme::RSA_PSS_SHA256(2048))]
    #[case::rsa_pkcs1(SigningScheme::RSA_PKCS1_SHA256(2048))]
    fn message_signature_rejects_non_sha256_digest(#[case] scheme: SigningScheme) {
        let signer = scheme.create_signer().expect("failed to create signer");
        let vk = signer
            .to_verification_key()
            .expect("failed to derive verification key");
        let msg = b"test artifact";
        let sig = signer.sign(msg).expect("signing failed");
        let digest = ArtifactDigest::Sha512(sha2::Sha512::digest(msg).into());

        let content = BundleContent::MessageSignature;

        let err = verify_bundle_content(&content, &vk, &sig, &digest)
            .expect_err("expected DigestAlgorithmUnsupported error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::DigestAlgorithmUnsupported("sha512")
        ));
    }

    // ── ArtifactDigest ────────────────────────────────────────────────────────

    #[test]
    fn artifact_digest_from_sha256_hasher_matches_finalized_digest() {
        // `verify_digest` funnels its `Sha256` hasher through this conversion, so
        // the wrapper and `verify_digest_with` must agree byte-for-byte.
        let msg = b"test artifact";
        let digest = ArtifactDigest::from(sha2::Sha256::new_with_prefix(msg));

        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(digest.as_bytes(), &sha2::Sha256::digest(msg)[..]);
        assert_eq!(digest.to_hex(), hex::encode(sha2::Sha256::digest(msg)));
    }

    // ── Real fixture: npm provenance ──────────────────────────────────────────

    /// Verification of a real npm SLSA provenance bundle, whose
    /// in-toto subject carries a `sha512` digest and nothing else.
    ///
    /// The trust root is pinned to a checked-in copy of the Sigstore Public Good
    /// Instance's `trusted_root.json`, so these tests never touch the network.
    /// The signing certificate is long expired by now; that is fine, and tested:
    /// validity is checked against the Rekor entry's `integratedTime`.
    #[cfg(feature = "sigstore-trust-root")]
    mod npm_provenance {
        use sha2::Digest as _;

        use crate::{
            bundle::{
                Bundle,
                verify::{
                    ArtifactDigest, SignatureErrorKind, VerificationError, Verifier,
                    policy::Identity,
                    test_data::{
                        NPM_CERT_IDENTITY, NPM_CERT_ISSUER, NPM_SLSA_BUNDLE_V03,
                        NPM_TARBALL_SHA512, SIGSTORE_TRUSTED_ROOT,
                    },
                },
            },
            trust::sigstore::SigstoreTrustRoot,
        };

        fn verifier() -> Verifier {
            let trust_root = SigstoreTrustRoot::from_trusted_root_json_unchecked(
                SIGSTORE_TRUSTED_ROOT.as_bytes(),
            )
            .expect("pinned trusted root must parse");
            Verifier::new(Default::default(), trust_root).expect("verifier must build")
        }

        fn bundle() -> Bundle {
            serde_json::from_str(NPM_SLSA_BUNDLE_V03).expect("fixture must be a valid bundle")
        }

        fn sha512(hex_digest: &str) -> ArtifactDigest {
            let bytes: [u8; 64] = hex::decode(hex_digest)
                .expect("digest must be hex")
                .try_into()
                .expect("digest must be 64 bytes");
            ArtifactDigest::Sha512(bytes)
        }

        #[tokio::test]
        async fn verifies_sha512_only_subject() {
            let policy = Identity::new(NPM_CERT_IDENTITY, NPM_CERT_ISSUER);

            verifier()
                .verify_digest_with(sha512(NPM_TARBALL_SHA512), bundle(), &policy, true)
                .await
                .expect("npm provenance bundle must verify against its sha512 subject");
        }

        #[tokio::test]
        async fn rejects_wrong_sha512_digest() {
            let policy = Identity::new(NPM_CERT_IDENTITY, NPM_CERT_ISSUER);
            let wrong = ArtifactDigest::Sha512([0u8; 64]);

            let err = verifier()
                .verify_digest_with(wrong, bundle(), &policy, true)
                .await
                .expect_err("a digest for a different artifact must not verify");
            assert!(matches!(
                err,
                VerificationError::Signature(SignatureErrorKind::SubjectDigestMismatch)
            ));
        }

        /// The SHA-256 `verify_digest` wrapper still reaches the same matching
        /// logic — and a SHA-256 digest never matches a `sha512`-only subject.
        #[tokio::test]
        async fn sha256_digest_does_not_match_sha512_subject() {
            let policy = Identity::new(NPM_CERT_IDENTITY, NPM_CERT_ISSUER);

            let err = verifier()
                .verify_digest(
                    sha2::Sha256::new_with_prefix(b"not the npm tarball"),
                    bundle(),
                    &policy,
                    true,
                )
                .await
                .expect_err("a sha256 digest must not match a sha512-only subject");
            assert!(matches!(
                err,
                VerificationError::Signature(SignatureErrorKind::SubjectDigestMismatch)
            ));
        }

        #[tokio::test]
        async fn rejects_mismatched_identity() {
            let policy = Identity::new("https://github.com/example/example", NPM_CERT_ISSUER);

            let err = verifier()
                .verify_digest_with(sha512(NPM_TARBALL_SHA512), bundle(), &policy, true)
                .await
                .expect_err("a bundle signed by another identity must not verify");
            assert!(matches!(err, VerificationError::Policy(_)));
        }
    }
}
