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

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;
use webpki::types::{CertificateDer, UnixTime};
use x509_cert::der::Encode;

use crate::{
    bundle::Bundle,
    crypto::{CertificatePool, CosignVerificationKey, Signature},
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    trust::TrustRoot,
};

#[cfg(feature = "sigstore-trust-root")]
use crate::trust::sigstore::SigstoreTrustRoot;

use super::{
    models::{CertificateErrorKind, CheckedBundle, SignatureErrorKind},
    policy::VerificationPolicy,
    VerificationError, VerificationResult,
};

/// An asynchronous Sigstore verifier.
///
/// For synchronous usage, see [`Verifier`].
pub struct Verifier {
    #[allow(dead_code)]
    rekor_config: RekorConfiguration,
    cert_pool: CertificatePool,
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

        Ok(Self {
            rekor_config,
            cert_pool,
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

        let _trusted_chain = self
            .cert_pool
            .verify_cert_with_time(&ee_cert, UnixTime::since_unix_epoch(issued_at))
            .map_err(CertificateErrorKind::VerificationFailed)?;

        debug!("signing certificate chains back to trusted root");

        // TODO(tnytown): verify SCT here, sigstore-rs#326

        // 2) Verify that the signing certificate belongs to the signer.
        policy.verify(&materials.certificate)?;
        debug!("signing certificate conforms to policy");

        // 3) Verify that the signature was signed by the public key in the signing certificate
        let signing_key: CosignVerificationKey = (&tbs_certificate.subject_public_key_info)
            .try_into()
            .map_err(SignatureErrorKind::AlgoUnsupported)?;

        let verify_sig =
            signing_key.verify_prehash(Signature::Raw(&materials.signature), &input_digest);
        verify_sig.map_err(SignatureErrorKind::VerificationFailed)?;

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
