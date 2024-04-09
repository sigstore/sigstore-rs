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

use sha2::{Sha256, Sha384};

use crate::errors::*;

pub use signing_key::SigStoreSigner;
pub use verification_key::CosignVerificationKey;

/// Different digital signature algorithms.
/// * `RSA_PSS_SHA256`: RSA PSS padding using SHA-256
/// for RSA signatures. All the `usize` member inside
/// an RSA enum represents the key size of the RSA key.
/// * `RSA_PSS_SHA384`: RSA PSS padding using SHA-384
/// for RSA signatures.
/// * `RSA_PSS_SHA512`: RSA PSS padding using SHA-512
/// for RSA signatures.
/// * `RSA_PKCS1_SHA256`: PKCS#1 1.5 padding using
/// SHA-256 for RSA signatures.
/// * `RSA_PKCS1_SHA384`: PKCS#1 1.5 padding using
/// SHA-384 for RSA signatures.
/// * `RSA_PKCS1_SHA512`: PKCS#1 1.5 padding using
/// SHA-512 for RSA signatures.
/// * `ECDSA_P256_SHA256_ASN1`: ASN.1 DER-encoded ECDSA
/// signatures using the P-256 curve and SHA-256. It
/// is the default signing scheme.
/// * `ECDSA_P384_SHA384_ASN1`: ASN.1 DER-encoded ECDSA
/// signatures using the P-384 curve and SHA-384.
/// * `ED25519`: ECDSA signature using SHA2-512
/// as the digest function and curve edwards25519. The
/// signature format please refer
/// to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.6).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SigningScheme {
    RSA_PSS_SHA256(usize),
    RSA_PSS_SHA384(usize),
    RSA_PSS_SHA512(usize),
    RSA_PKCS1_SHA256(usize),
    RSA_PKCS1_SHA384(usize),
    RSA_PKCS1_SHA512(usize),
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ED25519,
}

impl std::fmt::Display for SigningScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningScheme::RSA_PSS_SHA256(_) => write!(f, "RSA_PSS_SHA256"),
            SigningScheme::RSA_PSS_SHA384(_) => write!(f, "RSA_PSS_SHA384"),
            SigningScheme::RSA_PSS_SHA512(_) => write!(f, "RSA_PSS_SHA512"),
            SigningScheme::RSA_PKCS1_SHA256(_) => write!(f, "RSA_PKCS1_SHA256"),
            SigningScheme::RSA_PKCS1_SHA384(_) => write!(f, "RSA_PKCS1_SHA384"),
            SigningScheme::RSA_PKCS1_SHA512(_) => write!(f, "RSA_PKCS1_SHA512"),
            SigningScheme::ECDSA_P256_SHA256_ASN1 => write!(f, "ECDSA_P256_SHA256_ASN1"),
            SigningScheme::ECDSA_P384_SHA384_ASN1 => write!(f, "ECDSA_P384_SHA384_ASN1"),
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
            "ED25519" => Ok(Self::ED25519),
            "RSA_PSS_SHA256" => Ok(Self::RSA_PSS_SHA256(DEFAULT_KEY_SIZE)),
            "RSA_PSS_SHA384" => Ok(Self::RSA_PSS_SHA384(DEFAULT_KEY_SIZE)),
            "RSA_PSS_SHA512" => Ok(Self::RSA_PSS_SHA512(DEFAULT_KEY_SIZE)),
            "RSA_PKCS1_SHA256" => Ok(Self::RSA_PKCS1_SHA256(DEFAULT_KEY_SIZE)),
            "RSA_PKCS1_SHA384" => Ok(Self::RSA_PKCS1_SHA384(DEFAULT_KEY_SIZE)),
            "RSA_PKCS1_SHA512" => Ok(Self::RSA_PKCS1_SHA512(DEFAULT_KEY_SIZE)),
            unknown => Err(format!("Unsupported signing algorithm: {unknown}")),
        }
    }
}

impl SigningScheme {
    /// Create a key-pair due to the given signing scheme.
    pub fn create_signer(&self) -> Result<SigStoreSigner> {
        Ok(match self {
            SigningScheme::ECDSA_P256_SHA256_ASN1 => SigStoreSigner::ECDSA_P256_SHA256_ASN1(
                EcdsaSigner::<_, Sha256>::from_ecdsa_keys(&EcdsaKeys::<p256::NistP256>::new()?)?,
            ),
            SigningScheme::ECDSA_P384_SHA384_ASN1 => SigStoreSigner::ECDSA_P384_SHA384_ASN1(
                EcdsaSigner::<_, Sha384>::from_ecdsa_keys(&EcdsaKeys::<p384::NistP384>::new()?)?,
            ),
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
            SigningScheme::RSA_PSS_SHA384(bit_size) => {
                SigStoreSigner::RSA_PSS_SHA384(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha384,
                    PaddingScheme::PSS,
                ))
            }
            SigningScheme::RSA_PSS_SHA512(bit_size) => {
                SigStoreSigner::RSA_PSS_SHA512(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha512,
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
            SigningScheme::RSA_PKCS1_SHA384(bit_size) => {
                SigStoreSigner::RSA_PKCS1_SHA384(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha384,
                    PaddingScheme::PKCS1v15,
                ))
            }
            SigningScheme::RSA_PKCS1_SHA512(bit_size) => {
                SigStoreSigner::RSA_PKCS1_SHA512(RSASigner::from_rsa_keys(
                    &RSAKeys::new(*bit_size)?,
                    DigestAlgorithm::Sha512,
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

#[cfg(feature = "cert")]
pub(crate) mod certificate;
#[cfg(feature = "cert")]
pub(crate) mod certificate_pool;
#[cfg(feature = "cert")]
pub(crate) use certificate_pool::CertificatePool;

pub mod verification_key;

use self::signing_key::{
    ecdsa::ec::{EcdsaKeys, EcdsaSigner},
    ed25519::{Ed25519Keys, Ed25519Signer},
    rsa::{keypair::RSAKeys, DigestAlgorithm, PaddingScheme, RSASigner, DEFAULT_KEY_SIZE},
};

pub mod signing_key;

#[cfg(test)]
pub(crate) mod tests {
    use chrono::{DateTime, TimeDelta, Utc};
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::{BigNum, MsbOption};
    use openssl::conf::{Conf, ConfMethod};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{self, Id, PKey};
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509Extension, X509NameBuilder, X509};

    pub(crate) const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENptdY/l3nB0yqkXLBWkZWQwo6+cu
OSWS1X9vPavpiQOoTTGC0xX57OojUadxF1cdQmrsiReWg2Wn4FneJfa8xw==
-----END PUBLIC KEY-----"#;

    pub(crate) struct CertData {
        pub cert: X509,
        pub private_key: pkey::PKey<pkey::Private>,
    }

    pub(crate) struct CertGenerationOptions {
        pub digital_signature_key_usage: bool,
        pub code_signing_extended_key_usage: bool,
        pub subject_email: Option<String>,
        pub subject_url: Option<String>,
        //TODO: remove macro once https://github.com/sfackler/rust-openssl/issues/1411
        //is fixed
        #[allow(dead_code)]
        pub subject_issuer: Option<String>,
        pub not_before: DateTime<chrono::Utc>,
        pub not_after: DateTime<chrono::Utc>,
        pub private_key: pkey::PKey<pkey::Private>,
        pub public_key: pkey::PKey<pkey::Public>,
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
            let (private_key, public_key) = generate_ecdsa_p256_keypair();

            CertGenerationOptions {
                digital_signature_key_usage: true,
                code_signing_extended_key_usage: true,
                subject_email: Some(String::from("tests@sigstore-rs.dev")),
                subject_issuer: Some(String::from("https://sigstore.dev/oauth")),
                subject_url: None,
                not_before,
                not_after,
                private_key,
                public_key,
            }
        }
    }

    pub(crate) fn generate_ecdsa_p256_keypair(
    ) -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Cannot create EcGroup");
        let ec_private_key = EcKey::generate(&group).expect("Cannot create private key");
        let ec_public_key = ec_private_key.public_key();
        let ec_pub_key =
            EcKey::from_public_key(&group, ec_public_key).expect("Cannot create ec pub key");

        let public_key = pkey::PKey::from_ec_key(ec_pub_key).expect("Cannot create pkey");
        let private_key = pkey::PKey::from_ec_key(ec_private_key).expect("Cannot create pkey");

        (private_key, public_key)
    }

    pub(crate) fn generate_ecdsa_p384_keypair(
    ) -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("Cannot create EcGroup");
        let ec_private_key = EcKey::generate(&group).expect("Cannot create private key");
        let ec_public_key = ec_private_key.public_key();
        let ec_pub_key =
            EcKey::from_public_key(&group, ec_public_key).expect("Cannot create ec pub key");

        let public_key = pkey::PKey::from_ec_key(ec_pub_key).expect("Cannot create pkey");
        let private_key = pkey::PKey::from_ec_key(ec_private_key).expect("Cannot create pkey");

        (private_key, public_key)
    }

    pub(crate) fn generate_ed25519_keypair() -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>)
    {
        let private_key = PKey::generate_ed25519().expect("Cannot create private key");
        let public_key = private_key
            .raw_public_key()
            .expect("Cannot export public key");
        let public_key = PKey::public_key_from_raw_bytes(&public_key, Id::ED25519)
            .expect("Cannot create ec pub key");

        (private_key, public_key)
    }

    pub(crate) fn generate_rsa_keypair(
        bits: u32,
    ) -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>) {
        use openssl::rsa;

        let rsa_private_key = rsa::Rsa::generate(bits).expect("Cannot generate RSA key");
        let rsa_public_key_pem = rsa_private_key
            .public_key_to_pem()
            .expect("Cannot obtain public key");
        let rsa_public_key = rsa::Rsa::public_key_from_pem(&rsa_public_key_pem)
            .expect("Cannot create rsa_public_key");

        let private_key = pkey::PKey::from_rsa(rsa_private_key).expect("cannot create private_key");
        let public_key = pkey::PKey::from_rsa(rsa_public_key).expect("cannot create public_key");

        (private_key, public_key)
    }

    pub(crate) fn generate_dsa_keypair(
        bits: u32,
    ) -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>) {
        use openssl::dsa;

        let dsa_private_key = dsa::Dsa::generate(bits).expect("Cannot generate DSA key");
        let dsa_public_key_pem = dsa_private_key
            .public_key_to_pem()
            .expect("Cannot obtain public key");
        let dsa_public_key = dsa::Dsa::public_key_from_pem(&dsa_public_key_pem)
            .expect("Cannot create rsa_public_key");

        let private_key = pkey::PKey::from_dsa(dsa_private_key).expect("cannot create private_key");
        let public_key = pkey::PKey::from_dsa(dsa_public_key).expect("cannot create public_key");

        (private_key, public_key)
    }

    pub(crate) fn generate_certificate(
        issuer: Option<&CertData>,
        settings: CertGenerationOptions,
    ) -> anyhow::Result<CertData> {
        let mut x509_name_builder = X509NameBuilder::new()?;
        x509_name_builder.append_entry_by_text("O", "tests")?;
        x509_name_builder.append_entry_by_text("CN", "sigstore.test")?;
        let x509_name = x509_name_builder.build();

        let mut x509_builder = openssl::x509::X509::builder()?;
        x509_builder.set_subject_name(&x509_name)?;
        x509_builder
            .set_pubkey(&settings.public_key)
            .expect("Cannot set public key");

        // set serial number
        let mut big = BigNum::new().expect("Cannot create BigNum");
        big.rand(152, MsbOption::MAYBE_ZERO, true)?;
        let serial_number = Asn1Integer::from_bn(&big)?;
        x509_builder.set_serial_number(&serial_number)?;

        // set version 3
        x509_builder.set_version(2)?;

        // x509 v3 extensions
        let conf = Conf::new(ConfMethod::default())?;
        let x509v3_context = match issuer {
            Some(issuer_data) => x509_builder.x509v3_context(Some(&issuer_data.cert), Some(&conf)),
            None => x509_builder.x509v3_context(None, Some(&conf)),
        };

        let mut extensions: Vec<X509Extension> = Vec::new();

        let x509_extension_subject_key_identifier =
            SubjectKeyIdentifier::new().build(&x509v3_context)?;
        extensions.push(x509_extension_subject_key_identifier);

        // CA usage
        if issuer.is_none() {
            // CA usage
            let x509_basic_constraint_ca =
                BasicConstraints::new().critical().ca().pathlen(1).build()?;
            extensions.push(x509_basic_constraint_ca);
        } else {
            let x509_basic_constraint_ca = BasicConstraints::new().critical().build()?;
            extensions.push(x509_basic_constraint_ca);
        }

        // set key usage
        if issuer.is_some() {
            if settings.digital_signature_key_usage {
                let key_usage = KeyUsage::new().critical().digital_signature().build()?;
                extensions.push(key_usage);
            }

            if settings.code_signing_extended_key_usage {
                let extended_key_usage = ExtendedKeyUsage::new().code_signing().build()?;
                extensions.push(extended_key_usage);
            }
        } else {
            let key_usage = KeyUsage::new()
                .critical()
                .crl_sign()
                .key_cert_sign()
                .build()?;
            extensions.push(key_usage);
        }

        // extensions that diverge, based on whether we're creating the CA or
        // a certificate issued by it
        if issuer.is_none() {
        } else {
            let x509_extension_authority_key_identifier = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&x509v3_context)?;
            extensions.push(x509_extension_authority_key_identifier);

            if settings.subject_email.is_some() && settings.subject_url.is_some() {
                panic!(
                    "cosign doesn't generate certificates with a SAN that has both email and url"
                );
            }
            if let Some(email) = settings.subject_email {
                let x509_extension_san = SubjectAlternativeName::new()
                    .critical()
                    .email(&email)
                    .build(&x509v3_context)?;

                extensions.push(x509_extension_san);
            };
            if let Some(url) = settings.subject_url {
                let x509_extension_san = SubjectAlternativeName::new()
                    .critical()
                    .uri(&url)
                    .build(&x509v3_context)?;

                extensions.push(x509_extension_san);
            }
            //
            // TODO: uncomment once https://github.com/sfackler/rust-openssl/issues/1411
            // is fixed. This would allow to test also the parsing of the custom fields
            // added to certificate extensions
            //if let Some(subject_issuer) = settings.subject_issuer {
            //    let sigstore_issuer_asn1_obj = Asn1Object::from_str("1.3.6.1.4.1.57264.1.1")?; //&SIGSTORE_ISSUER_OID.to_string())?;

            //    let value = format!("ASN1:UTF8String:{}", subject_issuer);

            //    let sigstore_subject_issuer_extension = X509Extension::new_nid(
            //        None,
            //        Some(&x509v3_context),
            //        sigstore_issuer_asn1_obj.nid(),
            //        //&subject_issuer,
            //        &value,
            //    )?;

            //    extensions.push(sigstore_subject_issuer_extension);
            //}
        }

        for ext in extensions {
            x509_builder.append_extension(ext)?;
        }

        // setup validity
        let not_before = Asn1Time::from_unix(settings.not_before.timestamp())?;
        let not_after = Asn1Time::from_unix(settings.not_after.timestamp())?;
        x509_builder.set_not_after(&not_after)?;
        x509_builder.set_not_before(&not_before)?;

        // set issuer
        if let Some(issuer_data) = issuer {
            let issuer_name = issuer_data.cert.subject_name();
            x509_builder.set_issuer_name(issuer_name)?;
        } else {
            // self signed cert
            x509_builder.set_issuer_name(&x509_name)?;
        }

        // sign the cert
        let issuer_pkey = match issuer {
            Some(issuer_data) => issuer_data.private_key.clone(),
            None => settings.private_key.clone(),
        };
        x509_builder
            .sign(&issuer_pkey, MessageDigest::sha256())
            .expect("Cannot sign certificate");

        let x509 = x509_builder.build();

        Ok(CertData {
            cert: x509,
            private_key: settings.private_key,
        })
    }
}
