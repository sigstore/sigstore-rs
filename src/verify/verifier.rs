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

use std::cell::OnceCell;

use tracing::debug;
use webpki::{
    types::{CertificateDer, UnixTime},
    EndEntityCert,
};

use x509_cert::der::Encode;

use crate::{
    crypto::{CertificatePool, CosignVerificationKey, Signature},
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    tuf::{Repository, SigstoreRepository},
    verify::VerificationError,
};

use super::{models::VerificationMaterials, policy::VerificationPolicy, VerificationResult};

pub struct Verifier<'a, R: Repository> {
    #[allow(dead_code)]
    rekor_config: RekorConfiguration,
    trust_repo: R,
    cert_pool: OnceCell<CertificatePool<'a>>,
}

impl<'a, R: Repository> Verifier<'a, R> {
    pub fn new(rekor_config: RekorConfiguration, trust_repo: R) -> SigstoreResult<Self> {
        Ok(Self {
            rekor_config,
            cert_pool: Default::default(),
            trust_repo,
        })
    }

    fn cert_pool(&'a self) -> SigstoreResult<&CertificatePool<'a>> {
        let init_cert_pool = || {
            let certs = self.trust_repo.fulcio_certs()?;
            CertificatePool::from_certificates(certs, [])
        };

        let cert_pool = init_cert_pool()?;
        Ok(self.cert_pool.get_or_init(|| cert_pool))
    }

    pub fn verify(
        &'a self,
        materials: VerificationMaterials,
        policy: &impl VerificationPolicy,
    ) -> VerificationResult {
        let store = self
            .cert_pool()
            .expect("Failed to construct certificate pool");

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
        let Ok(ee_cert) = (&cert_der).try_into() else {
            return Err(VerificationError::CertificateVerificationFailure);
        };

        let Ok(_trusted_chain) =
            store.verify_cert_with_time(&ee_cert, UnixTime::since_unix_epoch(issued_at))
        else {
            return Err(VerificationError::CertificateVerificationFailure);
        };

        debug!("signing certificate chains back to trusted root");

        // 2) Verify that the signing certificate belongs to the signer.
        if let Some(err) = policy.verify(&materials.certificate) {
            return Err(err)?;
        }
        debug!("signing certificate conforms to policy");

        // 3) Verify that the signature was signed by the public key in the signing certificate
        let Ok(signing_key): SigstoreResult<CosignVerificationKey> =
            (&tbs_certificate.subject_public_key_info).try_into()
        else {
            return Err(VerificationError::CertificateMalformed);
        };

        let verify_sig = signing_key.verify_prehash(
            Signature::Raw(&materials.signature),
            &materials.input_digest,
        );
        if verify_sig.is_err() {
            return Err(VerificationError::SignatureVerificationFailure);
        }
        debug!("signature corresponds to public key");

        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials
        let Some(log_entry) = materials.rekor_entry() else {
            return Err(VerificationError::CertificateMalformed);
        };
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
        if !(not_before <= integrated_time && integrated_time <= not_after) {
            return Err(VerificationError::CertificateExpired);
        }
        debug!("data signed during validity period");

        debug!("successfully verified!");
        Ok(())
    }
}

impl<'a> Verifier<'a, SigstoreRepository> {
    pub fn production() -> SigstoreResult<Verifier<'a, SigstoreRepository>> {
        let updater = SigstoreRepository::new(None)?;

        Verifier::<'a, SigstoreRepository>::new(Default::default(), updater)
    }
}
