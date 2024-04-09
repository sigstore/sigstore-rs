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

use chrono::{DateTime, Utc};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use thiserror::Error;
use x509_cert::{
    ext::pkix::{constraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName},
    Certificate,
};

use crate::errors::{Result, SigstoreError};

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
        DateTime::from_timestamp(integrated_time, 0)
            .ok_or(SigstoreError::X509Error("timestamp is not legal".into()))?
            .naive_utc(),
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

#[derive(Debug, Error)]
pub enum ExtensionErrorKind {
    #[error("certificate missing extension: {0}")]
    Missing(&'static str),

    #[error("certificate extension bit not asserted: {0}")]
    BitUnset(&'static str),

    #[error("certificate's {0} extension not marked as critical")]
    NotCritical(&'static str),
}

#[derive(Debug, Error)]
pub enum NotLeafErrorKind {
    #[error("certificate is a CA: CAs are not leaves")]
    IsCA,
}

#[derive(Debug, Error)]
pub enum NotCAErrorKind {
    #[error("certificate is not a CA: CAs must assert cA and keyCertSign")]
    NotCA,

    #[error("certificate is not a root CA")]
    NotRootCA,

    #[error("certificate in invalid state: cA={ca}, keyCertSign={key_cert_sign}")]
    Invalid { ca: bool, key_cert_sign: bool },
}

#[derive(Debug, Error)]
#[error(transparent)]
pub enum CertificateValidationError {
    #[error("only X509 V3 certificates are supported")]
    VersionUnsupported,

    #[error("malformed certificate")]
    Malformed(#[source] x509_cert::der::Error),

    NotLeaf(#[from] NotLeafErrorKind),

    NotCA(#[from] NotCAErrorKind),

    Extension(#[from] ExtensionErrorKind),
}

/// Check if the given certificate is a leaf in the context of the Sigstore profile.
///
/// * It is not a root or intermediate CA;
/// * It has `keyUsage.digitalSignature`
/// * It has `CODE_SIGNING` as an `ExtendedKeyUsage`.
///
/// This function does not evaluate the trustworthiness of the certificate.
pub(crate) fn is_leaf(
    certificate: &Certificate,
) -> core::result::Result<(), CertificateValidationError> {
    // NOTE(jl): following structure of sigstore-python over the slightly different handling found
    // in `verify_key_usages`.
    let tbs = &certificate.tbs_certificate;

    // Only V3 certificates should appear in the context of Sigstore; earlier versions of X.509 lack
    // extensions and have ambiguous CA behavior.
    if tbs.version != x509_cert::Version::V3 {
        Err(CertificateValidationError::VersionUnsupported)?;
    }

    if is_ca(certificate).is_ok() {
        Err(NotLeafErrorKind::IsCA)?;
    };

    let digital_signature = match tbs
        .get::<KeyUsage>()
        .map_err(CertificateValidationError::Malformed)?
    {
        None => Err(ExtensionErrorKind::Missing("KeyUsage"))?,
        Some((_, key_usage)) => key_usage.digital_signature(),
    };

    if !digital_signature {
        Err(ExtensionErrorKind::BitUnset("KeyUsage.digitalSignature"))?;
    }

    // Finally, we check to make sure the leaf has an `ExtendedKeyUsages`
    // extension that includes a codesigning entitlement. Sigstore should
    // never issue a leaf that doesn't have this extended usage.

    let extended_key_usage = match tbs
        .get::<ExtendedKeyUsage>()
        .map_err(CertificateValidationError::Malformed)?
    {
        None => Err(ExtensionErrorKind::Missing("ExtendedKeyUsage"))?,
        Some((_, extended_key_usage)) => extended_key_usage,
    };

    if !extended_key_usage.0.contains(&ID_KP_CODE_SIGNING) {
        Err(ExtensionErrorKind::BitUnset(
            "ExtendedKeyUsage.digitalSignature",
        ))?;
    }

    Ok(())
}

/// Checks if the given `certificate` is a CA certificate.
///
/// This does **not** indicate trustworthiness of the given `certificate`, only if it has the
/// appropriate interior state.
///
/// This function is **not** naively invertible: users **must** use the dedicated `is_leaf`
/// utility function to determine whether a particular leaf upholds Sigstore's invariants.
pub(crate) fn is_ca(
    certificate: &Certificate,
) -> core::result::Result<(), CertificateValidationError> {
    let tbs = &certificate.tbs_certificate;

    // Only V3 certificates should appear in the context of Sigstore; earlier versions of X.509 lack
    // extensions and have ambiguous CA behavior.
    if tbs.version != x509_cert::Version::V3 {
        return Err(CertificateValidationError::VersionUnsupported);
    }

    // Valid CA certificates must have the following set:
    //
    // - `BasicKeyUsage.keyCertSign`
    // - `BasicConstraints.ca`
    //
    // Any other combination of states is inconsistent and invalid, meaning
    // that we won't treat the certificate as neither a leaf nor a CA.

    let ca = match tbs
        .get::<constraints::BasicConstraints>()
        .map_err(CertificateValidationError::Malformed)?
    {
        None => Err(ExtensionErrorKind::Missing("BasicConstraints"))?,
        Some((false, _)) => {
            // BasicConstraints must be marked as critical, per RFC 5280 4.2.1.9.
            Err(ExtensionErrorKind::NotCritical("BasicConstraints"))?
        }
        Some((true, v)) => v.ca,
    };

    let key_cert_sign = match tbs
        .get::<KeyUsage>()
        .map_err(CertificateValidationError::Malformed)?
    {
        None => Err(ExtensionErrorKind::Missing("KeyUsage"))?,
        Some((_, v)) => v.key_cert_sign(),
    };

    // both states set, this is a CA.
    if ca && key_cert_sign {
        return Ok(());
    }

    if !(ca || key_cert_sign) {
        Err(NotCAErrorKind::NotCA)?;
    }

    // Anything else is an invalid state that should never occur.
    Err(NotCAErrorKind::Invalid { ca, key_cert_sign })?
}

/// Returns `True` if and only if the given `Certificate` indicates
/// that it's a root CA.
///
/// This is **not** a verification function, and it does not establish
/// the trustworthiness of the given certificate.
pub(crate) fn is_root_ca(
    certificate: &Certificate,
) -> core::result::Result<(), CertificateValidationError> {
    // NOTE(ww): This function is obnoxiously long to make the different
    // states explicit.

    let tbs = &certificate.tbs_certificate;

    // Only V3 certificates should appear in the context of Sigstore; earlier versions of X.509 lack
    // extensions and have ambiguous CA behavior.
    if tbs.version != x509_cert::Version::V3 {
        return Err(CertificateValidationError::VersionUnsupported);
    }

    // Non-CAs can't possibly be root CAs.
    is_ca(certificate)?;

    // A certificate that is its own issuer and signer is considered a root CA.
    if tbs.issuer != tbs.subject {
        Err(NotCAErrorKind::NotRootCA)?
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tests::*;

    use chrono::TimeDelta;
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
                not_before: Utc::now()
                    .checked_add_signed(TimeDelta::try_days(5).unwrap())
                    .unwrap(),
                not_after: Utc::now()
                    .checked_add_signed(TimeDelta::try_days(6).unwrap())
                    .unwrap(),
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
                not_before: Utc::now()
                    .checked_sub_signed(TimeDelta::try_days(1).unwrap())
                    .unwrap(),
                not_after: Utc::now()
                    .checked_add_signed(TimeDelta::try_days(1).unwrap())
                    .unwrap(),
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

        let integrated_time = Utc::now()
            .checked_add_signed(TimeDelta::try_days(5).unwrap())
            .unwrap();

        let issued_cert = generate_certificate(
            Some(&ca_data),
            CertGenerationOptions {
                not_before: Utc::now()
                    .checked_sub_signed(TimeDelta::try_days(1).unwrap())
                    .unwrap(),
                not_after: Utc::now()
                    .checked_add_signed(TimeDelta::try_days(1).unwrap())
                    .unwrap(),
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
