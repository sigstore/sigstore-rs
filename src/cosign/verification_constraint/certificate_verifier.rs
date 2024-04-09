use chrono::{DateTime, Utc};
use pkcs8::der::Decode;
use tracing::warn;
use webpki::types::CertificateDer;
use x509_cert::Certificate;

use super::VerificationConstraint;
use crate::cosign::signature_layers::SignatureLayer;
use crate::crypto::{certificate_pool::CertificatePool, CosignVerificationKey};
use crate::errors::{Result, SigstoreError};

/// Verify signature layers using the public key defined inside of a x509 certificate
#[derive(Debug)]
pub struct CertificateVerifier {
    cert_verification_key: CosignVerificationKey,
    cert_validity: x509_cert::time::Validity,
    require_rekor_bundle: bool,
}

impl CertificateVerifier {
    /// Create a new instance of `CertificateVerifier` using the PEM encoded
    /// certificate.
    ///
    /// * `cert_bytes`: PEM encoded certificate
    /// * `require_rekor_bundle`: require the  signature layer to have a Rekor
    ///    bundle. Having a Rekor bundle allows further checks to be performed,
    ///    like ensuring the signature has been produced during the validity
    ///    time frame of the certificate. It is recommended to set this value
    ///    to `true` to have a more secure verification process.
    /// * `cert_chain`: the certificate chain that is used to verify the provided
    ///   certificate. When not specified, the certificate is assumed to be trusted
    pub fn from_pem(
        cert_bytes: &[u8],
        require_rekor_bundle: bool,
        cert_chain: Option<&[crate::registry::Certificate]>,
    ) -> Result<Self> {
        let pem = pem::parse(cert_bytes)?;
        Self::from_der(pem.contents(), require_rekor_bundle, cert_chain)
    }

    /// Create a new instance of `CertificateVerifier` using the DER encoded
    /// certificate.
    ///
    /// * `cert_bytes`: DER encoded certificate
    /// * `require_rekor_bundle`: require the  signature layer to have a Rekor
    ///    bundle. Having a Rekor bundle allows further checks to be performed,
    ///    like ensuring the signature has been produced during the validity
    ///    time frame of the certificate. It is recommended to set this value
    ///    to `true` to have a more secure verification process.
    /// * `cert_chain`: the certificate chain that is used to verify the provided
    ///   certificate. When not specified, the certificate is assumed to be trusted
    pub fn from_der(
        cert_bytes: &[u8],
        require_rekor_bundle: bool,
        cert_chain: Option<&[crate::registry::Certificate]>,
    ) -> Result<Self> {
        let cert = Certificate::from_der(cert_bytes)
            .map_err(|e| SigstoreError::X509Error(format!("parse from der {e}")))?;
        crate::crypto::certificate::verify_key_usages(&cert)?;
        crate::crypto::certificate::verify_has_san(&cert)?;
        crate::crypto::certificate::verify_validity(&cert)?;

        if let Some(certs) = cert_chain {
            let certs = certs
                .iter()
                .map(|c| CertificateDer::try_from(c.clone()))
                .collect::<Result<Vec<_>>>()?;
            let cert_pool = CertificatePool::from_certificates(certs, [])?;
            cert_pool.verify_der_cert(cert_bytes, None)?;
        }

        let subject_public_key_info = &cert.tbs_certificate.subject_public_key_info;
        let cosign_verification_key = CosignVerificationKey::try_from(subject_public_key_info)?;

        Ok(Self {
            cert_verification_key: cosign_verification_key,
            cert_validity: cert.tbs_certificate.validity,
            require_rekor_bundle,
        })
    }
}

impl VerificationConstraint for CertificateVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        if !signature_layer.is_signed_by_key(&self.cert_verification_key) {
            return Ok(false);
        }
        match &signature_layer.bundle {
            Some(bundle) => {
                let it = DateTime::<Utc>::from_naive_utc_and_offset(
                    DateTime::from_timestamp(bundle.payload.integrated_time, 0)
                        .ok_or(SigstoreError::UnexpectedError(
                            "timestamp is not legal".into(),
                        ))?
                        .naive_utc(),
                    Utc,
                );
                let not_before: DateTime<Utc> =
                    self.cert_validity.not_before.to_system_time().into();
                if it < not_before {
                    warn!(
                        integrated_time = it.to_string(),
                        not_before = self.cert_validity.not_before.to_string(),
                        "certificate verification: ignoring layer, certificate expired before signature submitted to rekor"
                    );
                    return Ok(false);
                }

                let not_after: DateTime<Utc> = self.cert_validity.not_after.to_system_time().into();
                if it > not_after {
                    warn!(
                        integrated_time = it.to_string(),
                        not_after = self.cert_validity.not_after.to_string(),
                        "certificate verification: ignoring layer, certificate issued after signatured submitted to rekor"
                    );
                    return Ok(false);
                }
                Ok(true)
            }
            None => {
                if self.require_rekor_bundle {
                    warn!("certificate verifier: ignoring layer because rekor bundle is missing");
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::cosign::bundle::Bundle;
    use crate::crypto::tests::*;
    use crate::registry;

    use pkcs8::der::asn1::UtcTime;
    use serde_json::json;
    use x509_cert::time::{Time, Validity};

    #[test]
    fn verify_certificate_() -> anyhow::Result<()> {
        // use the correct CA chain
        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let ca_cert = registry::Certificate {
            encoding: registry::CertificateEncoding::Pem,
            data: ca_data.cert.to_pem()?,
        };
        let cert_chain = vec![ca_cert];

        let issued_cert = generate_certificate(Some(&ca_data), CertGenerationOptions::default())?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;

        let verifier = CertificateVerifier::from_pem(&issued_cert_pem, false, Some(&cert_chain));
        assert!(verifier.is_ok());

        // Use a different CA chain
        let another_ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let another_ca_cert = registry::Certificate {
            encoding: registry::CertificateEncoding::Pem,
            data: another_ca_data.cert.to_pem()?,
        };
        let cert_chain = vec![another_ca_cert];
        let verifier = CertificateVerifier::from_pem(&issued_cert_pem, false, Some(&cert_chain));
        assert!(verifier.is_err());

        // No cert chain
        let verifier = CertificateVerifier::from_pem(&issued_cert_pem, false, None);
        assert!(verifier.is_ok());

        Ok(())
    }

    /// Create a SignatureLayer using some hard coded value. Returns the
    /// certificate that can be used to successfully verify the layer
    fn test_data() -> (SignatureLayer, String) {
        let ss_value = json!({
            "critical": {
              "identity": {
                "docker-reference": "registry-testing.svc.lan/kubewarden/pod-privileged"
              },
              "image": {
                "docker-manifest-digest": "sha256:f1143ec2786e13d7d3335dbb498528438d910648469d3f39647e1cde6914da8d"
              },
              "type": "cosign container image signature"
            },
            "optional": null
        });

        let bundle = build_bundle();

        let cert_pem_raw = r#"-----BEGIN CERTIFICATE-----
MIICsTCCAligAwIBAgIUR8wkyvHURfBVH6K2uhfTJZItw3owCgYIKoZIzj0EAwIw
gZIxCzAJBgNVBAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMRIwEAYDVQQHEwlOdXJl
bWJlcmcxEzARBgNVBAoTCkt1YmV3YXJkZW4xIzAhBgNVBAsTGkt1YmV3YXJkZW4g
SW50ZXJtZWRpYXRlIENBMSMwIQYDVQQDExpLdWJld2FyZGVuIEludGVybWVkaWF0
ZSBDQTAeFw0yMjExMTAxMDM4MDBaFw0yMzExMTAxMDM4MDBaMIGFMQswCQYDVQQG
EwJERTEQMA4GA1UECBMHQmF2YXJpYTESMBAGA1UEBxMJTnVyZW1iZXJnMRMwEQYD
VQQKEwpLdWJld2FyZGVuMRgwFgYDVQQLEw9LdWJld2FyZGVuIFVzZXIxITAfBgNV
BAMTGHVzZXIxLmN1c3RvbS13aWRnZXRzLmNvbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABEKjBtYLmtwhXNV1/uBanNn5YLD/QY/lfhPleBzenCL7CC2iocu8m3WM
PMfd06tE/9HbBAITf64Oc4Mp7abrzp2jgZYwgZMwDgYDVR0PAQH/BAQDAgeAMBMG
A1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFHsx7jle
7PzGarNvliop+/aTj9GsMB8GA1UdIwQYMBaAFKJu6pRjVGUXVCVkft0YQ+3o1GbQ
MB4GA1UdEQQXMBWBE3VzZXIxQGt1YmV3YXJkZW4uaW8wCgYIKoZIzj0EAwIDRwAw
RAIgPixAn47x4qLpu7Y/d0oyvbnOGtD5cY7rywdMOO7LYRsCIDsCyGUZIYMFfSrt
3K/aLG49dcv6FKBtZpF5+hYj1zKe
-----END CERTIFICATE-----"#
            .to_string();

        let signature_layer = SignatureLayer {
            simple_signing: serde_json::from_value(ss_value.clone()).unwrap(),
            oci_digest: String::from("sha256:f9b817c013972c75de8689d55c0d441c3eb84f6233ac75f6a9c722ea5db0058b"),
            signature: Some(String::from("MEYCIQCIqLEe6hnjEXP/YC2P9OIwEr2yMmwPNHLzvCPaoaXFOQIhALyTouhKNKc2ZVrR0GUQ7J0U5AtlyDZDLGnasAi7XnV/")),
            bundle: Some(bundle),
            certificate_signature: None,
            raw_data: serde_json::to_vec(&ss_value).unwrap(),
        };

        (signature_layer, cert_pem_raw)
    }

    fn build_bundle() -> Bundle {
        let bundle_value = json!({
            "SignedEntryTimestamp": "MEUCIG5TYOXkiPm7RGYgDIPHwRQW5NyoSPuwxvJe4ByB9c37AiEAyD0dVcsiJ5Lp+QY5SL80jDxfc75BtjRnticVf7SiFD0=",
            "Payload": {
              "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJmOWI4MTdjMDEzOTcyYzc1ZGU4Njg5ZDU1YzBkNDQxYzNlYjg0ZjYyMzNhYzc1ZjZhOWM3MjJlYTVkYjAwNThiIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUNJcUxFZTZobmpFWFAvWUMyUDlPSXdFcjJ5TW13UE5ITHp2Q1Bhb2FYRk9RSWhBTHlUb3VoS05LYzJaVnJSMEdVUTdKMFU1QXRseURaRExHbmFzQWk3WG5WLyIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnpWRU5EUVd4cFowRjNTVUpCWjBsVlVqaDNhM2wyU0ZWU1prSldTRFpMTW5Wb1psUktXa2wwZHpOdmQwTm5XVWxMYjFwSmVtb3dSVUYzU1hjS1oxcEplRU42UVVwQ1owNVdRa0ZaVkVGclVrWk5Va0YzUkdkWlJGWlJVVWxGZDJSRFdWaGFhR050YkdoTlVrbDNSVUZaUkZaUlVVaEZkMnhQWkZoS2JBcGlWMHBzWTIxamVFVjZRVkpDWjA1V1FrRnZWRU5yZERGWmJWWXpXVmhLYTFwWE5IaEpla0ZvUW1kT1ZrSkJjMVJIYTNReFdXMVdNMWxZU210YVZ6Um5DbE5YTlRCYVdFcDBXbGRTY0ZsWVVteEpSVTVDVFZOTmQwbFJXVVJXVVZGRVJYaHdUR1JYU214a01rWjVXa2RXZFVsRmJIVmtSMVo1WWxkV2EyRlhSakFLV2xOQ1JGRlVRV1ZHZHpCNVRXcEZlRTFVUVhoTlJFMDBUVVJDWVVaM01IbE5la1Y0VFZSQmVFMUVUVFJOUkVKaFRVbEhSazFSYzNkRFVWbEVWbEZSUndwRmQwcEZVbFJGVVUxQk5FZEJNVlZGUTBKTlNGRnRSakpaV0Vwd1dWUkZVMDFDUVVkQk1WVkZRbmhOU2xSdVZubGFWekZwV2xoS2JrMVNUWGRGVVZsRUNsWlJVVXRGZDNCTVpGZEtiR1F5Um5sYVIxWjFUVkpuZDBabldVUldVVkZNUlhjNVRHUlhTbXhrTWtaNVdrZFdkVWxHVm5wYVdFbDRTVlJCWmtKblRsWUtRa0ZOVkVkSVZucGFXRWw0VEcxT01XTXpVblppVXpFellWZFNibHBZVW5wTWJVNTJZbFJDV2sxQ1RVZENlWEZIVTAwME9VRm5SVWREUTNGSFUwMDBPUXBCZDBWSVFUQkpRVUpGUzJwQ2RGbE1iWFIzYUZoT1ZqRXZkVUpoYms1dU5WbE1SQzlSV1M5c1ptaFFiR1ZDZW1WdVEwdzNRME15YVc5amRUaHRNMWROQ2xCTlptUXdOblJGTHpsSVlrSkJTVlJtTmpSUFl6Uk5jRGRoWW5KNmNESnFaMXBaZDJkYVRYZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZGxRVTFDVFVjS1FURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0wzZFJRMDFCUVhkSVVWbEVWbEl3VDBKQ1dVVkdTSE40TjJwc1pRbzNVSHBIWVhKT2RteHBiM0FyTDJGVWFqbEhjMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRkdTMHAxTm5CU2FsWkhWVmhXUTFaclpuUXdXVkVyTTI4eFIySlJDazFDTkVkQk1WVmtSVkZSV0UxQ1YwSkZNMVo2V2xoSmVGRkhkREZaYlZZeldWaEthMXBYTkhWaFZ6aDNRMmRaU1V0dldrbDZhakJGUVhkSlJGSjNRWGNLVWtGSloxQnBlRUZ1TkRkNE5IRk1jSFUzV1M5a01HOTVkbUp1VDBkMFJEVmpXVGR5ZVhka1RVOVBOMHhaVW5ORFNVUnpRM2xIVlZwSldVMUdabE55ZEFvelN5OWhURWMwT1dSamRqWkdTMEowV25CR05TdG9XV294ZWt0bENpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19",
              "integratedTime": 1668077126,
              "logIndex": 6821636,
              "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
            }
        });
        let bundle: Bundle = serde_json::from_value(bundle_value).expect("Cannot parse bundle");
        bundle
    }

    #[test]
    fn verify_correct_layer() {
        let (signature_layer, cert_pem_raw) = test_data();

        let vc = CertificateVerifier::from_pem(cert_pem_raw.as_bytes(), true, None)
            .expect("cannot create verification constraint");
        assert!(vc.verify(&signature_layer).expect("error while verifying"));
    }

    #[test]
    fn rekor_integration() {
        let (signature_layer, cert_pem_raw) = test_data();
        let signature_layer_without_rekor_bundle = SignatureLayer {
            bundle: None,
            ..signature_layer.clone()
        };
        assert!(signature_layer_without_rekor_bundle.bundle.is_none());

        let vc = CertificateVerifier::from_pem(cert_pem_raw.as_bytes(), true, None)
            .expect("cannot create verification constraint");
        assert!(vc.verify(&signature_layer).expect("error while verifying"));

        // layer verification fails because there's no rekor bundle
        assert!(!vc
            .verify(&signature_layer_without_rekor_bundle)
            .expect("error while verifying"));

        // verification constraint that does not enforce rekor integration
        let vc = CertificateVerifier::from_pem(cert_pem_raw.as_bytes(), false, None)
            .expect("cannot create verification constraint");
        assert!(vc
            .verify(&signature_layer_without_rekor_bundle)
            .expect("error while verifying"));
    }

    #[test]
    fn detect_signature_created_at_invalid_time() {
        let (signature_layer, cert_pem_raw) = test_data();

        let mut vc = CertificateVerifier::from_pem(cert_pem_raw.as_bytes(), true, None)
            .expect("cannot create verification constraint");
        let not_before = UtcTime::from_system_time(
            SystemTime::now()
                .checked_sub(Duration::from_secs(60))
                .expect("cannot sub time by 60 seconds"),
        )
        .expect("cannot create not_before timestamp");
        let not_after = UtcTime::from_system_time(
            SystemTime::now()
                .checked_add(Duration::from_secs(60))
                .expect("cannot add time by 60 seconds"),
        )
        .expect("cannot create not_after timestamp");
        let validity = Validity {
            not_before: Time::UtcTime(not_before),
            not_after: Time::UtcTime(not_after),
        };
        vc.cert_validity = validity;
        assert!(!vc.verify(&signature_layer).expect("error while verifying"));
    }
}
