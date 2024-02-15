//
// Copyright 2022 The Sigstore Authors.
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

use const_oid::db::rfc5280::ID_KP_CODE_SIGNING;
use webpki::{
    types::{CertificateDer, TrustAnchor, UnixTime},
    EndEntityCert, KeyUsage, VerifiedPath,
};

use crate::errors::{Result, SigstoreError};

/// A collection of trusted root certificates.
#[derive(Default, Debug)]
pub(crate) struct CertificatePool<'a> {
    trusted_roots: Vec<TrustAnchor<'a>>,
    intermediates: Vec<CertificateDer<'a>>,
}

impl<'a> CertificatePool<'a> {
    /// Builds a `CertificatePool` instance using the provided list of [`Certificate`].
    pub(crate) fn from_certificates<R, I>(
        trusted_roots: R,
        untrusted_intermediates: I,
    ) -> Result<CertificatePool<'a>>
    where
        R: IntoIterator<Item = CertificateDer<'a>>,
        I: IntoIterator<Item = CertificateDer<'a>>,
    {
        Ok(CertificatePool {
            trusted_roots: trusted_roots
                .into_iter()
                .map(|x| Ok(webpki::anchor_from_trusted_cert(&x)?.to_owned()))
                .collect::<std::result::Result<Vec<_>, webpki::Error>>()?,
            intermediates: untrusted_intermediates.into_iter().collect(),
        })
    }

    /// Ensures the given certificate has been issued by one of the trusted root certificates
    /// An `Err` is returned when the verification fails.
    ///
    /// **Note well:** certificates issued by Fulcio are, by design, valid only
    /// for a really limited amount of time.
    /// Because of that the validity checks performed by this method are more
    /// relaxed. The validity checks are done inside of
    /// [`crate::crypto::verify_validity`] and [`crate::crypto::verify_expiration`].
    pub(crate) fn verify_pem_cert(
        &self,
        cert_pem: &[u8],
        verification_time: Option<UnixTime>,
    ) -> Result<()> {
        let cert_pem = pem::parse(cert_pem)?;
        if cert_pem.tag() != "CERTIFICATE" {
            return Err(SigstoreError::CertificatePoolError(
                "PEM file is not a certificate".into(),
            ));
        }

        self.verify_der_cert(cert_pem.contents(), verification_time)
    }

    /// Ensures the given certificate has been issued by one of the trusted root certificates
    /// An `Err` is returned when the verification fails.
    ///
    /// **Note well:** certificates issued by Fulcio are, by design, valid only
    /// for a really limited amount of time.
    /// Because of that the validity checks performed by this method are more
    /// relaxed. The validity checks are done inside of
    /// [`crate::crypto::verify_validity`] and [`crate::crypto::verify_expiration`].
    pub(crate) fn verify_der_cert(
        &self,
        der: &[u8],
        verification_time: Option<UnixTime>,
    ) -> Result<()> {
        let der = CertificateDer::from(der);
        let cert = EndEntityCert::try_from(&der)?;

        self.verify_cert_with_time(&cert, verification_time.unwrap_or(UnixTime::now()))?;

        Ok(())
    }

    pub(crate) fn verify_cert_with_time<'cert>(
        &'a self,
        cert: &'cert EndEntityCert<'cert>,
        verification_time: UnixTime,
    ) -> Result<VerifiedPath<'cert>>
    where
        'a: 'cert,
    {
        let signing_algs = webpki::ALL_VERIFICATION_ALGS;
        let eku_code_signing = ID_KP_CODE_SIGNING.as_bytes();

        Ok(cert.verify_for_usage(
            signing_algs,
            &self.trusted_roots,
            self.intermediates.as_slice(),
            verification_time,
            KeyUsage::required(eku_code_signing),
            None,
            None,
        )?)
    }
}
