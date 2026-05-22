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
    bundle::verify::models::{BundleContent, CheckedBundle},
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
/// directly over `input_digest`.
///
/// For [`BundleContent::Dsse`], the signature is verified over the pre-computed PAE bytes stored
/// in the content, and the subject digest from the in-toto statement is compared against
/// `input_digest` to ensure the bundle describes the same artifact.
pub(crate) fn verify_bundle_content(
    content: &BundleContent,
    signing_key: &CosignVerificationKey,
    signature: &[u8],
    input_digest: &[u8],
) -> Result<(), SignatureErrorKind> {
    match content {
        BundleContent::MessageSignature => signing_key
            .verify_prehash(Signature::Raw(signature), input_digest)
            .map_err(SignatureErrorKind::VerificationFailed),
        BundleContent::Dsse {
            pae,
            subject_sha256_digest,
            ..
        } => {
            // For DSSE, verify the signature over the PAE bytes, not the artifact hash.
            signing_key
                .verify_signature(Signature::Raw(signature), pae)
                .map_err(SignatureErrorKind::VerificationFailed)?;

            // Also verify that the in-toto statement subject matches the artifact.
            let expected_hex = hex::encode(input_digest);
            if subject_sha256_digest != &expected_hex {
                return Err(SignatureErrorKind::Transparency);
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
            .tlog_entry(offline, &input_digest)
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use sha2::Digest as _;

    use crate::{
        bundle::verify::models::{BundleContent, compute_pae},
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
        let digest = [0u8; 32];
        let subject_sha256_digest = hex::encode(digest);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_sha256_digest,
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        assert!(verify_bundle_content(&content, &vk, &sig, &digest).is_ok());
    }

    #[test]
    fn dsse_valid_signature_wrong_digest() {
        let (vk, sign) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let sig = sign(&pae);
        let actual_digest = [0u8; 32];
        // subject_sha256_digest claims a *different* digest than what's presented
        let subject_sha256_digest = hex::encode([1u8; 32]);

        let content = BundleContent::Dsse {
            pae: pae.clone(),
            subject_sha256_digest,
            envelope_json: vec![],
            payload_bytes: vec![],
        };

        let err = verify_bundle_content(&content, &vk, &sig, &actual_digest)
            .expect_err("expected Transparency error");
        assert!(matches!(err, super::SignatureErrorKind::Transparency));
    }

    #[test]
    fn dsse_invalid_signature() {
        let (vk, _) = make_signer();
        let pae = compute_pae("application/vnd.in-toto+json", b"{}");
        let bad_sig = vec![0u8; 64]; // garbage bytes
        let digest = [0u8; 32];
        let subject_sha256_digest = hex::encode(digest);

        let content = BundleContent::Dsse {
            pae,
            subject_sha256_digest,
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
        let digest = sha2::Sha256::digest(msg).to_vec();

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
        let digest = sha2::Sha256::digest(msg).to_vec();

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
        let wrong_digest = sha2::Sha256::digest(b"different artifact").to_vec();

        let content = BundleContent::MessageSignature;

        let err = verify_bundle_content(&content, &vk, &sig, &wrong_digest)
            .expect_err("expected VerificationFailed error");
        assert!(matches!(
            err,
            super::SignatureErrorKind::VerificationFailed(_)
        ));
    }
}
