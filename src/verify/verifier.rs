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

use const_oid::db::rfc5280::ID_KP_CODE_SIGNING;
use pkcs8::der::{Encode, EncodePem};
use rustls_pki_types::UnixTime;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};

use crate::{
    crypto::{CertificatePool, CosignVerificationKey, Signature},
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    tuf::{Repository, SigstoreRepository},
    verify::VerificationError,
};

use super::{models::VerificationMaterials, policy::VerificationPolicy, VerificationResult};

pub struct Verifier<'a, R: Repository> {
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

    /// TODO(tnytown): Evil (?) interior mutability hack to work around lifetime issues.
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

        // 1) Verify that the signing certificate is signed by the root certificate and that the
        //    signing certificate was valid at the time of signing.

        // 1) Verify that the signing certificate is signed by the certificate
        //    chain and that the signing certificate was valid at the time
        //    of signing.
        let issued_at = materials
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();
        let cert_der = &materials.certificate.to_der().unwrap();
        store
            .verify_cert_with_time(cert_der, UnixTime::since_unix_epoch(issued_at))
            .or(Err(VerificationError::CertificateVerificationFailure))?;

        // 2) Verify that the signing certificate belongs to the signer.

        // TODO(tnytown): How likely is a malformed certificate in this position? Do we want to
        // account for it and create an error type as opposed to unwrapping?
        let (_, key_usage_ext): (bool, KeyUsage) = materials
            .certificate
            .tbs_certificate
            .get()
            .expect("Malformed certificate")
            .expect("Malformed certificate");

        if !key_usage_ext.digital_signature() {
            return Err(VerificationError::CertificateTypeError(
                "Key usage is not of type `digital signature`".into(),
            ));
        }

        let (_, extended_key_usage_ext): (bool, ExtendedKeyUsage) = materials
            .certificate
            .tbs_certificate
            .get()
            .expect("Malformed certificate")
            .expect("Malformed certificate");

        if !extended_key_usage_ext.0.contains(&ID_KP_CODE_SIGNING) {
            return Err(VerificationError::CertificateTypeError(
                "Extended key usage does not contain `code signing`".into(),
            ));
        }

        policy.verify(&materials.certificate)?;

        // 3) Verify that the signature was signed by the public key in the signing certificate
        let signing_key: SigstoreResult<CosignVerificationKey> = (&materials
            .certificate
            .tbs_certificate
            .subject_public_key_info)
            .try_into();

        let signing_key =
            signing_key.expect("Malformed certificate (cannot deserialize public key)");

        signing_key
            .verify_prehash(
                Signature::Raw(&materials.signature),
                &materials.input_digest,
            )
            .or(Err(VerificationError::SignatureVerificationFailure))?;

        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials
        let log_entry = materials.rekor_entry();

        // 5) Verify the inclusion proof supplied by Rekor for this artifact,
        //    if we're doing online verification.
        // TODO(tnytown): Merkle inclusion

        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        // TODO(tnytown) SET verification

        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp.
        let integrated_time = log_entry.integrated_time as u64;
        let not_before = materials
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = materials
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if !(not_before <= integrated_time && integrated_time <= not_after) {
            return Err(VerificationError::CertificateExpired);
        }

        Ok(())
    }
}

impl<'a> Verifier<'a, SigstoreRepository> {
    pub fn production() -> SigstoreResult<Verifier<'a, SigstoreRepository>> {
        let updater = SigstoreRepository::new(None)?;

        Verifier::<'a, SigstoreRepository>::new(Default::default(), updater)
    }
}
