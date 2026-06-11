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

//! Structures and constants required to perform cryptographic operations.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD_ENGINE};

use crate::errors::*;

pub use signing_key::SigStoreSigner;
pub use verification_key::CosignVerificationKey;
pub(crate) mod merkle;

/// Different digital signature algorithms.
/// * `RSA_PSS_SHA256`: RSA PSS padding using SHA-256 for RSA signatures.
///   The `usize` member represents the RSA key size in bits (2048/3072/4096).
/// * `RSA_PKCS1_SHA256`: PKCS#1 1.5 padding using SHA-256 for RSA signatures.
/// * `ECDSA_P256_SHA256_ASN1`: ASN.1 DER-encoded ECDSA signatures using P-256
///   and SHA-256. This is the default signing scheme.
/// * `ECDSA_P384_SHA384_ASN1`: ASN.1 DER-encoded ECDSA signatures using P-384
///   and SHA-384.
/// * `ECDSA_P521_SHA512_ASN1`: ASN.1 DER-encoded ECDSA signatures using P-521
///   and SHA-512.
/// * `ED25519`: Ed25519 signature using curve edwards25519.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SigningScheme {
    RSA_PSS_SHA256(usize),
    RSA_PKCS1_SHA256(usize),
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P521_SHA512_ASN1,
    ED25519,
}

impl std::fmt::Display for SigningScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningScheme::RSA_PSS_SHA256(_) => write!(f, "RSA_PSS_SHA256"),
            SigningScheme::RSA_PKCS1_SHA256(_) => write!(f, "RSA_PKCS1_SHA256"),
            SigningScheme::ECDSA_P256_SHA256_ASN1 => write!(f, "ECDSA_P256_SHA256_ASN1"),
            SigningScheme::ECDSA_P384_SHA384_ASN1 => write!(f, "ECDSA_P384_SHA384_ASN1"),
            SigningScheme::ECDSA_P521_SHA512_ASN1 => write!(f, "ECDSA_P521_SHA512_ASN1"),
            SigningScheme::ED25519 => write!(f, "ED25519"),
        }
    }
}

impl TryFrom<&str> for SigningScheme {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "ECDSA_P256_SHA256_ASN1" => Ok(Self::ECDSA_P256_SHA256_ASN1),
            "ECDSA_P384_SHA384_ASN1" => Ok(Self::ECDSA_P384_SHA384_ASN1),
            "ECDSA_P521_SHA512_ASN1" => Ok(Self::ECDSA_P521_SHA512_ASN1),
            "ED25519" => Ok(Self::ED25519),
            "RSA_PSS_SHA256" => Ok(Self::RSA_PSS_SHA256(DEFAULT_KEY_SIZE)),
            "RSA_PKCS1_SHA256" => Ok(Self::RSA_PKCS1_SHA256(DEFAULT_KEY_SIZE)),
            unknown => Err(format!("Unsupported signing algorithm: {unknown}")),
        }
    }
}

impl SigningScheme {
    /// Create a key-pair due to the given signing scheme.
    pub fn create_signer(&self) -> Result<SigStoreSigner> {
        Ok(match self {
            SigningScheme::ECDSA_P256_SHA256_ASN1 => {
                let keys = ECDSAKeys::new(EllipticCurve::P256)?;
                SigStoreSigner::ECDSA_P256_SHA256_ASN1(EcdsaSigner::from_ecdsa_keys(keys.inner())?)
            }
            SigningScheme::ECDSA_P384_SHA384_ASN1 => {
                let keys = ECDSAKeys::new(EllipticCurve::P384)?;
                SigStoreSigner::ECDSA_P384_SHA384_ASN1(EcdsaSigner::from_ecdsa_keys(keys.inner())?)
            }
            SigningScheme::ECDSA_P521_SHA512_ASN1 => {
                let keys = ECDSAKeys::new(EllipticCurve::P521)?;
                SigStoreSigner::ECDSA_P521_SHA512_ASN1(EcdsaSigner::from_ecdsa_keys(keys.inner())?)
            }
            SigningScheme::ED25519 => {
                SigStoreSigner::ED25519(Ed25519Signer::from_ed25519_keys(&Ed25519Keys::new()?)?)
            }
            SigningScheme::RSA_PSS_SHA256(bit_size) => {
                SigStoreSigner::RSA_PSS_SHA256(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha256,
                    PaddingScheme::PSS,
                ))
            }
            SigningScheme::RSA_PKCS1_SHA256(bit_size) => {
                SigStoreSigner::RSA_PKCS1_SHA256(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha256,
                    PaddingScheme::PKCS1v15,
                ))
            }
        })
    }
}

/// The default signature verification algorithm used by Sigstore.
/// Sigstore relies on NIST P-256
/// NIST P-256 is a Weierstrass curve specified in [FIPS 186-4: Digital Signature Standard (DSS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
/// Also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
impl Default for SigningScheme {
    fn default() -> Self {
        SigningScheme::ECDSA_P256_SHA256_ASN1
    }
}

/// A signature produced by a private key
pub enum Signature<'a> {
    /// Raw signature. There's no need to process the contents
    Raw(&'a [u8]),
    /// A base64 encoded signature
    Base64Encoded(&'a [u8]),
}

/// Newline bytes that base64 producers may insert (PEM-style line wrapping, or
/// signatures pulled from a registry). cosign decodes via Go's encoding/json,
/// which ignores `\n` and `\r`, so sigstore-rs strips exactly those two bytes
/// and nothing else: any other stray byte still fails the strict decode, which
/// keeps catching genuine corruption.
const BASE64_IGNORED_NEWLINES: &[u8] = b"\n\r";

impl Signature<'_> {
    /// Returns the raw signature bytes, decoding at the source.
    ///
    /// [`Signature::Raw`] is returned unchanged. [`Signature::Base64Encoded`]
    /// is base64-decoded, tolerating embedded newlines: the strict STANDARD
    /// engine is tried first (the common, unwrapped case pays nothing), and only
    /// on failure are `\n`/`\r` removed and the decode retried (see
    /// sigstore/sigstore-rs#550). Any other stray byte still fails, so genuine
    /// corruption is caught.
    pub fn decode_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Signature::Raw(data) => Ok(data.to_vec()),
            Signature::Base64Encoded(data) => match BASE64_STD_ENGINE.decode(data) {
                Ok(decoded) => Ok(decoded),
                Err(_) => {
                    let cleaned: Vec<u8> = data
                        .iter()
                        .copied()
                        .filter(|b| !BASE64_IGNORED_NEWLINES.contains(b))
                        .collect();
                    Ok(BASE64_STD_ENGINE.decode(cleaned)?)
                }
            },
        }
    }
}

#[cfg(feature = "cert")]
pub(crate) mod certificate;
#[cfg(feature = "cert")]
pub(crate) mod certificate_pool;
#[cfg(feature = "cert")]
pub(crate) use certificate_pool::CertificatePool;
#[cfg(feature = "cert")]
pub(crate) mod keyring;

pub mod verification_key;

use self::signing_key::{
    ecdsa::{ECDSAKeys, EllipticCurve, ec::EcdsaSigner},
    ed25519::{Ed25519Keys, Ed25519Signer},
    rsa::{DEFAULT_KEY_SIZE, DigestAlgorithm, PaddingScheme, RSASigner, keypair::RSAKeys},
};

pub mod signing_key;

#[cfg(any(feature = "sign", feature = "verify"))]
pub(crate) mod transparency;

#[cfg(test)]
pub(crate) mod tests {
    use chrono::{DateTime, TimeDelta, Utc};
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
        PKCS_ED25519, PKCS_RSA_SHA256, SanType,
    };
    use time::OffsetDateTime;

    #[test]
    fn signature_decode_bytes() {
        use super::Signature;

        // Raw signatures are returned unchanged.
        let raw = [1u8, 2, 3, 4];
        assert_eq!(Signature::Raw(&raw).decode_bytes().unwrap(), raw.to_vec());

        // A clean base64 signature decodes.
        let der = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=")
            .decode_bytes()
            .expect("clean base64 should decode");

        // The same value with an embedded newline and a trailing newline decodes
        // identically (cosign tolerates these). Built from explicit newline bytes
        // so the intent is clear and a formatter cannot silently drop them.
        const NEWLINE: u8 = b'\n';
        let unwrapped =
            b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=";
        let mut wrapped = unwrapped.to_vec();
        wrapped.insert(44, NEWLINE);
        wrapped.push(NEWLINE);
        assert_eq!(
            Signature::Base64Encoded(&wrapped).decode_bytes().unwrap(),
            der,
            "newlines should be tolerated and decode to the same bytes"
        );

        // A byte that is neither in the base64 alphabet nor a newline still
        // fails, so genuine corruption is caught.
        assert!(
            Signature::Base64Encoded(b"this@is@a@signature")
                .decode_bytes()
                .is_err(),
            "non-base64, non-newline input must fail to decode"
        );
    }

    pub(crate) const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENptdY/l3nB0yqkXLBWkZWQwo6+cu
OSWS1X9vPavpiQOoTTGC0xX57OojUadxF1cdQmrsiReWg2Wn4FneJfa8xw==
-----END PUBLIC KEY-----"#;

    pub(crate) struct CertData {
        /// PEM-encoded certificate bytes.
        pub cert_pem: Vec<u8>,
        pub key_pair: KeyPair,
        /// Stored CA params so we can reconstruct an `Issuer` when signing child certs.
        ca_params: Option<CertificateParams>,
    }

    pub(crate) struct CertGenerationOptions {
        pub digital_signature_key_usage: bool,
        pub code_signing_extended_key_usage: bool,
        pub subject_email: Option<String>,
        pub subject_url: Option<String>,
        pub subject_issuer: Option<String>,
        pub not_before: DateTime<chrono::Utc>,
        pub not_after: DateTime<chrono::Utc>,
        pub key_pair: KeyPair,
    }

    impl Default for CertGenerationOptions {
        fn default() -> Self {
            let not_before = Utc::now()
                .checked_sub_signed(TimeDelta::try_days(1).unwrap())
                .unwrap();
            let not_after = Utc::now()
                .checked_add_signed(TimeDelta::try_days(1).unwrap())
                .unwrap();

            // Sigstore relies on NIST P-256
            // NIST P-256 is a Weierstrass curve specified in FIPS 186-4: Digital Signature Standard (DSS):
            // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
            // Also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
            let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .expect("Cannot generate ECDSA P-256 key pair");

            CertGenerationOptions {
                digital_signature_key_usage: true,
                code_signing_extended_key_usage: true,
                subject_email: Some(String::from("tests@sigstore-rs.dev")),
                subject_issuer: Some(String::from("https://sigstore.dev/oauth")),
                subject_url: None,
                not_before,
                not_after,
                key_pair,
            }
        }
    }

    pub(crate) fn generate_ecdsa_p256_key_pair() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("Cannot generate ECDSA P-256 key pair")
    }

    pub(crate) fn generate_ecdsa_p384_key_pair() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .expect("Cannot generate ECDSA P-384 key pair")
    }

    pub(crate) fn generate_ed25519_key_pair() -> KeyPair {
        KeyPair::generate_for(&PKCS_ED25519).expect("Cannot generate Ed25519 key pair")
    }

    pub(crate) fn generate_rsa_key_pair() -> KeyPair {
        KeyPair::generate_for(&PKCS_RSA_SHA256).expect("Cannot generate RSA key pair")
    }

    fn chrono_to_offset_date_time(dt: DateTime<Utc>) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(dt.timestamp())
            .expect("Cannot convert DateTime to OffsetDateTime")
    }

    pub(crate) fn generate_certificate(
        issuer: Option<&CertData>,
        settings: CertGenerationOptions,
    ) -> anyhow::Result<CertData> {
        let mut params = CertificateParams::new(vec![])?;

        params
            .distinguished_name
            .push(DnType::OrganizationName, "tests");
        params
            .distinguished_name
            .push(DnType::CommonName, "sigstore.test");

        params.not_before = chrono_to_offset_date_time(settings.not_before);
        params.not_after = chrono_to_offset_date_time(settings.not_after);

        if issuer.is_none() {
            // CA certificate
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
            params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
        } else {
            // end-entity certificate
            params.is_ca = IsCa::NoCa;

            if settings.digital_signature_key_usage {
                params.key_usages.push(KeyUsagePurpose::DigitalSignature);
            }
            if settings.code_signing_extended_key_usage {
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::CodeSigning);
            }

            if settings.subject_email.is_some() && settings.subject_url.is_some() {
                panic!(
                    "cosign doesn't generate certificates with a SAN that has both email and url"
                );
            }
            if let Some(email) = settings.subject_email {
                params.subject_alt_names.push(SanType::Rfc822Name(
                    email.try_into().expect("invalid email SAN"),
                ));
            }
            if let Some(url) = settings.subject_url {
                params
                    .subject_alt_names
                    .push(SanType::URI(url.try_into().expect("invalid URI SAN")));
            }

            // Sigstore issuer OID: 1.3.6.1.4.1.57264.1.1
            if let Some(subject_issuer) = settings.subject_issuer {
                // The extension value is the raw UTF-8 bytes of the issuer string.
                // get_cert_extension_by_oid reads extn_value directly as UTF-8,
                // so we must not add any DER wrapping here.
                let ext = CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
                    subject_issuer.into_bytes(),
                );
                params.custom_extensions.push(ext);
            }
        }

        let (cert_pem, ca_params) = if let Some(issuer_data) = issuer {
            let ca_params = issuer_data
                .ca_params
                .as_ref()
                .expect("issuer CertData must have ca_params");
            // Reconstruct Issuer from the stored CA params and key pair.
            // KeyPair doesn't implement Clone, so we re-parse from PEM.
            let issuer_kp = KeyPair::from_pem(&issuer_data.key_pair.serialize_pem())?;
            let issuer_obj = rcgen::Issuer::from_params(ca_params, issuer_kp);
            let cert_pem = params
                .signed_by(&settings.key_pair, &issuer_obj)?
                .pem()
                .into_bytes();
            (cert_pem, None)
        } else {
            let ca_params = params.clone();
            let cert_pem = params.self_signed(&settings.key_pair)?.pem().into_bytes();
            (cert_pem, Some(ca_params))
        };

        Ok(CertData {
            cert_pem,
            key_pair: settings.key_pair,
            ca_params,
        })
    }
}
