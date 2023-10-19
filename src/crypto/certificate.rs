//
// Copyright 2021 The Sigstore Authors.
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

use chrono::{DateTime, NaiveDateTime, Utc};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use x509_cert::{
    ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName},
    Certificate,
};

use crate::errors::{Result, SigstoreError};

pub type DERCert = Vec<u8>;

/// Ensure the given certificate can be trusted for verifying cosign
/// signatures.
///
/// The following checks are performed against the given certificate:
/// * The certificate has the right set of key usages
/// * The certificate cannot be used before the current time
pub(crate) fn is_trusted(certificate: &Certificate, integrated_time: i64) -> Result<()> {
    verify_key_usages(certificate)?;
    verify_has_san(certificate)?;
    verify_validity(certificate)?;
    verify_expiration(certificate, integrated_time)?;

    Ok(())
}

pub(crate) fn verify_key_usages(certificate: &Certificate) -> Result<()> {
    let (_, key_usage) = certificate
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|_| SigstoreError::CertificateWithoutDigitalSignatureKeyUsage)?
        .ok_or(SigstoreError::CertificateWithoutDigitalSignatureKeyUsage)?;

    if key_usage.0.bits() & KeyUsages::DigitalSignature as u16 == 1 {
        return Err(SigstoreError::CertificateWithoutDigitalSignatureKeyUsage);
    }

    let (_, key_ext_usage) = certificate
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|_| SigstoreError::CertificateWithoutCodeSigningKeyUsage)?
        .ok_or(SigstoreError::CertificateWithoutCodeSigningKeyUsage)?;

    // code signing
    if !key_ext_usage.0.iter().any(|ext| *ext == ID_KP_CODE_SIGNING) {
        return Err(SigstoreError::CertificateWithoutCodeSigningKeyUsage);
    }

    Ok(())
}

pub(crate) fn verify_has_san(certificate: &Certificate) -> Result<()> {
    if certificate
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|_| SigstoreError::CertificateWithoutSubjectAlternativeName)?
        .is_some()
    {
        Ok(())
    } else {
        Err(SigstoreError::CertificateWithoutSubjectAlternativeName)
    }
}

pub(crate) fn verify_validity(certificate: &Certificate) -> Result<()> {
    // Comment taken from cosign verification code:
    // THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
    // THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
    // WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
    let validity = &certificate.tbs_certificate.validity;
    if std::time::SystemTime::now() < validity.not_before.to_system_time() {
        Err(SigstoreError::CertificateValidityError(
            validity.not_before.to_string(),
        ))
    } else {
        Ok(())
    }
}

fn verify_expiration(certificate: &Certificate, integrated_time: i64) -> Result<()> {
    let it = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDateTime::from_timestamp_opt(integrated_time, 0)
            .ok_or(SigstoreError::X509Error("timestamp is not legal".into()))?,
        Utc,
    );
    let validity = &certificate.tbs_certificate.validity;
    let not_before: DateTime<Utc> = validity.not_before.to_system_time().into();
    if it < not_before {
        return Err(
            SigstoreError::CertificateExpiredBeforeSignaturesSubmittedToRekor {
                integrated_time: it.to_string(),
                not_before: validity.not_before.to_string(),
            },
        );
    }

    let not_after: DateTime<Utc> = validity.not_after.to_system_time().into();
    if it > not_after {
        return Err(
            SigstoreError::CertificateIssuedAfterSignaturesSubmittedToRekor {
                integrated_time: it.to_string(),
                not_after: validity.not_after.to_string(),
            },
        );
    }

    Ok(())
}

/// Check if the given certificate is a leaf in the context of the Sigstore profile.
///
/// * It is not a root or intermediate CA;
/// * It has `keyUsage.digitalSignature`
/// * It has `CODE_SIGNING` as an `ExtendedKeyUsage`.
///
/// This function does not evaluate the trustworthiness of the certificate.
pub(crate) fn is_leaf(certificate: &Certificate) -> Result<()> {
    let tbs = &certificate.tbs_certificate;

    // Only V3 certificates should appear in the context of Sigstore; earlier versions of X.509 lack
    // extensions and have ambiguous CA behavior.
    if tbs.version != x509_cert::Version::V3 {
        return Err(SigstoreError::CertificateUnsupportedVersionError);
    }

    // TODO(tnytown): cert_is_ca

    verify_key_usages(certificate)?;

    Ok(())
}

pub(crate) fn is_root_ca(certificate: &Certificate) -> Result<()> {
    // TODO(tnytown)
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tests::*;

    use chrono::{Duration, Utc};
    use x509_cert::der::Decode;

    #[test]
    fn verify_cert_key_usages_success() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), CertGenerationOptions::default())?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;
        assert!(verify_key_usages(&cert).is_ok());

        Ok(())
    }

    #[test]
    fn verify_cert_key_usages_failure_because_no_digital_signature() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                digital_signature_key_usage: false,
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        let err = verify_key_usages(&cert).expect_err("Was supposed to return an error");
        let found = match err {
            SigstoreError::CertificateWithoutDigitalSignatureKeyUsage => true,
            _ => false,
        };
        assert!(found, "Didn't get expected error, got {:?} instead", err);

        Ok(())
    }

    #[test]
    fn verify_cert_key_usages_failure_because_no_code_signing() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                code_signing_extended_key_usage: false,
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        let err = verify_key_usages(&cert).expect_err("Was supposed to return an error");
        let found = match err {
            SigstoreError::CertificateWithoutCodeSigningKeyUsage => true,
            _ => false,
        };
        assert!(found, "Didn't get expected error, got {:?} instead", err);

        Ok(())
    }

    #[test]
    fn verify_cert_failure_because_no_san() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                subject_email: None,
                subject_url: None,
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        let error = verify_has_san(&cert).expect_err("Didn't get an error");
        let found = match error {
            SigstoreError::CertificateWithoutSubjectAlternativeName => true,
            _ => false,
        };
        assert!(found, "Didn't get the expected error: {}", error);

        Ok(())
    }

    #[test]
    fn verify_cert_validity_success() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), CertGenerationOptions::default())?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        assert!(verify_validity(&cert).is_ok());

        Ok(())
    }

    #[test]
    fn verify_cert_validity_failure() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                not_before: Utc::now().checked_add_signed(Duration::days(5)).unwrap(),
                not_after: Utc::now().checked_add_signed(Duration::days(6)).unwrap(),
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        let err = verify_validity(&cert).expect_err("Was expecting an error");
        let found = match err {
            SigstoreError::CertificateValidityError(_) => true,
            _ => false,
        };
        assert!(found, "Didn't get expected error, got {:?} instead", err);

        Ok(())
    }

    #[test]
    fn verify_cert_expiration_success() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let integrated_time = Utc::now();

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                not_before: Utc::now().checked_sub_signed(Duration::days(1)).unwrap(),
                not_after: Utc::now().checked_add_signed(Duration::days(1)).unwrap(),
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        assert!(verify_expiration(&cert, integrated_time.timestamp(),).is_ok());

        Ok(())
    }

    #[test]
    fn verify_cert_expiration_failure() -> anyhow::Result<()> {
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let integrated_time = Utc::now().checked_add_signed(Duration::days(5)).unwrap();

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                not_before: Utc::now().checked_sub_signed(Duration::days(1)).unwrap(),
                not_after: Utc::now().checked_add_signed(Duration::days(1)).unwrap(),
                ..Default::default()
            },
        )?;
        let issued_cert_pem = issued_cert.cert.to_pem().unwrap();
        let pem = pem::parse(issued_cert_pem)?;
        let cert = x509_cert::Certificate::from_der(pem.contents())?;

        let err = verify_expiration(&cert, integrated_time.timestamp())
            .expect_err("Was expecting an error");
        let found = match err {
            SigstoreError::CertificateIssuedAfterSignaturesSubmittedToRekor {
                integrated_time: _,
                not_after: _,
            } => true,
            _ => false,
        };
        assert!(found, "Didn't get expected error, got {:?} instead", err);

        Ok(())
    }
}
