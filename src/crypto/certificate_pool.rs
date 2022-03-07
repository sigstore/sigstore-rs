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

use crate::{
    errors::{Result, SigstoreError},
    registry::Certificate,
};

/// A collection of trusted root certificates
#[derive(Default, Debug)]
pub(crate) struct CertificatePool {
    trusted_roots: Vec<picky::x509::Cert>,
}

impl CertificatePool {
    /// Build a `CertificatePool` instance using the provided list of [`Certificate`]
    pub(crate) fn from_certificates(certs: &[Certificate]) -> Result<Self> {
        let mut trusted_roots = vec![];

        for c in certs {
            let pc = match c.encoding {
                crate::registry::CertificateEncoding::Pem => {
                    let pem_str = String::from_utf8(c.data.clone()).map_err(|_| {
                        SigstoreError::UnexpectedError("certificate is not PEM encoded".to_string())
                    })?;
                    picky::x509::Cert::from_pem_str(&pem_str)
                }
                crate::registry::CertificateEncoding::Der => picky::x509::Cert::from_der(&c.data),
            }?;

            if !matches!(pc.ty(), picky::x509::certificate::CertType::Root) {
                return Err(SigstoreError::CertificatePoolError(
                    "Cannot add non-root certificate".to_string(),
                ));
            }

            trusted_roots.push(pc);
        }

        Ok(CertificatePool { trusted_roots })
    }

    /// Ensures the given certificate has been issued by one of the trusted root certificates
    /// An `Err` is returned when the verification fails.
    ///
    /// **Note well:** certificates issued by Fulciuo are, by design, valid only
    /// for a really limited amount of time.
    /// Because of that the validity checks performed by this method are more
    /// relaxed. The validity checks are done inside of
    /// [`crate::crypto::verify_validity`] and [`crate::crypto::verify_expiration`].
    pub(crate) fn verify(&self, cert_pem: &[u8]) -> Result<()> {
        let cert_pem_str = String::from_utf8(cert_pem.to_vec()).map_err(|_| {
            SigstoreError::UnexpectedError("Cannot convert cert back to string".to_string())
        })?;
        let cert = picky::x509::Cert::from_pem_str(&cert_pem_str)?;

        let verified = self.trusted_roots.iter().any(|trusted_root| {
            let chain = [trusted_root.clone()];
            cert.verifier()
                .chain(chain.iter())
                .exact_date(&cert.valid_not_before())
                .verify()
                .is_ok()
        });

        if verified {
            Ok(())
        } else {
            Err(SigstoreError::CertificateValidityError(
                "Not issued by a trusted root".to_string(),
            ))
        }
    }
}
