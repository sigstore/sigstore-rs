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

use aws_lc_rs::{
    digest::{self, SHA256, SHA384, SHA512},
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ED25519,
        RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256, UnparsedPublicKey,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD_ENGINE};
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use const_oid::db::rfc8410::ID_ED_25519;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use super::{
    Signature, SigningScheme,
    signing_key::{KeyPair, SigStoreSigner},
};

use crate::errors::*;

#[cfg(feature = "cosign")]
use crate::cosign::constants::ED25519 as ED25519_OID;

/// The curve OID for a given EC public key, extracted from the SPKI parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcCurve {
    P256,
    P384,
    P521,
}

/// Newline bytes that base64 producers may insert (PEM-style line wrapping, or
/// signatures pulled from a registry). cosign decodes via Go's encoding/json,
/// which ignores `\n` and `\r`, so sigstore-rs strips exactly those two bytes
/// and nothing else: any other stray byte still fails the strict decode, which
/// keeps catching genuine corruption.
const BASE64_IGNORED_NEWLINES: &[u8] = b"\n\r";

/// Decode a base64-encoded signature, tolerating embedded newlines.
///
/// The strict STANDARD engine is tried first, so the common case (no newlines)
/// pays nothing. Only if that fails are `\n`/`\r` removed and the decode retried
/// (see sigstore/sigstore-rs#550).
fn decode_base64_signature(data: &[u8]) -> Result<Vec<u8>> {
    match BASE64_STD_ENGINE.decode(data) {
        Ok(decoded) => Ok(decoded),
        Err(_) => {
            let cleaned: Vec<u8> = data
                .iter()
                .copied()
                .filter(|b| !BASE64_IGNORED_NEWLINES.contains(b))
                .collect();
            Ok(BASE64_STD_ENGINE.decode(cleaned)?)
        }
    }
}

/// A key that can be used to verify signatures.
///
/// Currently the following key formats are supported:
///
///   * RSA keys, using PSS padding and SHA-256 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-256 as the digest algorithm
///   * Ed25519 keys
///   * ECDSA keys, ASN.1 DER-encoded, using the P-256 curve and SHA-256
///   * ECDSA keys, ASN.1 DER-encoded, using the P-384 curve and SHA-384
///   * ECDSA keys, ASN.1 DER-encoded, using the P-521 curve and SHA-512
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CosignVerificationKey {
    RSA_PSS_SHA256(Vec<u8>),
    RSA_PKCS1_SHA256(Vec<u8>),
    ECDSA_P256_SHA256_ASN1(Vec<u8>),
    ECDSA_P384_SHA384_ASN1(Vec<u8>),
    ECDSA_P521_SHA512_ASN1(Vec<u8>),
    ED25519(Vec<u8>),
}

impl TryFrom<&SubjectPublicKeyInfoOwned> for CosignVerificationKey {
    type Error = SigstoreError;

    fn try_from(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        use x509_cert::der::Encode;
        // Encode the full SPKI to DER for aws-lc-rs.
        let spki_der = spki
            .to_der()
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;

        let algo_oid = spki.algorithm.oid;

        match algo_oid {
            ID_EC_PUBLIC_KEY => {
                // Detect curve from parameters OID.
                let curve = ec_curve_from_spki(spki)?;
                Ok(match curve {
                    EcCurve::P256 => CosignVerificationKey::ECDSA_P256_SHA256_ASN1(spki_der),
                    EcCurve::P384 => CosignVerificationKey::ECDSA_P384_SHA384_ASN1(spki_der),
                    EcCurve::P521 => CosignVerificationKey::ECDSA_P521_SHA512_ASN1(spki_der),
                })
            }
            RSA_ENCRYPTION => Ok(CosignVerificationKey::RSA_PKCS1_SHA256(spki_der)),
            #[cfg(feature = "cosign")]
            ED25519_OID => Ok(CosignVerificationKey::ED25519(spki_der)),
            oid if oid == ID_ED_25519 => Ok(CosignVerificationKey::ED25519(spki_der)),
            _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                "Key with algorithm OID {algo_oid} is not supported"
            ))),
        }
    }
}

/// Extract the EC curve from the SPKI AlgorithmIdentifier parameters.
fn ec_curve_from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<EcCurve> {
    let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
        SigstoreError::PublicKeyUnsupportedAlgorithmError(
            "EC key missing curve OID in parameters".into(),
        )
    })?;
    let curve_oid: const_oid::ObjectIdentifier = params.decode_as().map_err(|e| {
        SigstoreError::PublicKeyUnsupportedAlgorithmError(format!("Cannot parse EC curve OID: {e}"))
    })?;
    match curve_oid {
        SECP_256_R_1 => Ok(EcCurve::P256),
        SECP_384_R_1 => Ok(EcCurve::P384),
        SECP_521_R_1 => Ok(EcCurve::P521),
        other => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
            "Unsupported EC curve OID: {other}"
        ))),
    }
}

impl CosignVerificationKey {
    /// Builds a [`CosignVerificationKey`] from DER-encoded SPKI data.
    pub fn from_der(der_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        Ok(match signing_scheme {
            SigningScheme::RSA_PSS_SHA256(_) => {
                CosignVerificationKey::RSA_PSS_SHA256(der_data.to_vec())
            }
            SigningScheme::RSA_PKCS1_SHA256(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA256(der_data.to_vec())
            }
            SigningScheme::ECDSA_P256_SHA256_ASN1 => {
                CosignVerificationKey::ECDSA_P256_SHA256_ASN1(der_data.to_vec())
            }
            SigningScheme::ECDSA_P384_SHA384_ASN1 => {
                CosignVerificationKey::ECDSA_P384_SHA384_ASN1(der_data.to_vec())
            }
            SigningScheme::ECDSA_P521_SHA512_ASN1 => {
                CosignVerificationKey::ECDSA_P521_SHA512_ASN1(der_data.to_vec())
            }
            SigningScheme::ED25519 => CosignVerificationKey::ED25519(der_data.to_vec()),
        })
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded data.
    pub fn from_pem(pem_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::from_der(key_pem.contents(), signing_scheme)
    }

    /// Builds a [`CosignVerificationKey`] from DER-encoded public key data by auto-detecting
    /// the key type from the SubjectPublicKeyInfo algorithm OID.
    pub fn try_from_der(der_data: &[u8]) -> Result<Self> {
        use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned};
        let spki = SubjectPublicKeyInfoOwned::from_der(der_data).map_err(|e| {
            SigstoreError::KeyParsingError(format!("Cannot parse SPKI from DER: {e}"))
        })?;
        Self::try_from(&spki)
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded public key data by auto-detecting
    /// the key type.
    pub fn try_from_pem(pem_data: &[u8]) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::try_from_der(key_pem.contents())
    }

    /// Builds a `CosignVerificationKey` from [`SigStoreSigner`].
    pub fn from_sigstore_signer(signer: &SigStoreSigner) -> Result<Self> {
        signer.to_verification_key()
    }

    /// Builds a `CosignVerificationKey` from [`KeyPair`].
    pub fn from_key_pair(signer: &dyn KeyPair, signing_scheme: &SigningScheme) -> Result<Self> {
        signer.to_verification_key(signing_scheme)
    }

    /// Verify the signature provided was generated by this key over the provided message.
    pub fn verify_signature(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => decode_base64_signature(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(pub_key) => {
                UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(pub_key) => {
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(pub_key) => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(pub_key) => {
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P521_SHA512_ASN1(pub_key) => {
                UnparsedPublicKey::new(&ECDSA_P521_SHA512_ASN1, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ED25519(pub_key) => {
                UnparsedPublicKey::new(&ED25519, pub_key.as_slice())
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
        }
    }

    /// Verify the signature provided was generated by this key over the provided
    /// *pre-hashed* message (the `msg` slice contains the raw hash output, not the
    /// original data).
    pub(crate) fn verify_prehash(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => decode_base64_signature(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(pub_key) => {
                let d = digest::Digest::import_less_safe(msg, &SHA256)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pub_key.as_slice())
                    .verify_digest(&d, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(pub_key) => {
                let d = digest::Digest::import_less_safe(msg, &SHA256)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pub_key.as_slice())
                    .verify_digest(&d, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(pub_key) => {
                let d = digest::Digest::import_less_safe(msg, &SHA256)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key.as_slice())
                    .verify_digest(&d, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(pub_key) => {
                let d = digest::Digest::import_less_safe(msg, &SHA384)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pub_key.as_slice())
                    .verify_digest(&d, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P521_SHA512_ASN1(pub_key) => {
                let d = digest::Digest::import_less_safe(msg, &SHA512)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                UnparsedPublicKey::new(&ECDSA_P521_SHA512_ASN1, pub_key.as_slice())
                    .verify_digest(&d, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ED25519(_) => {
                unimplemented!("Ed25519 doesn't implement verify_prehash")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    use super::*;
    use crate::crypto::tests::*;

    #[test]
    fn verify_signature_success() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let outcome = verification_key.verify_signature(signature, msg.as_bytes());
        assert!(outcome.is_ok());
    }

    #[test]
    fn verify_signature_success_with_embedded_newlines() {
        // Same valid signature as `verify_signature_success`, but with newlines
        // embedded inside the base64 string (and a trailing newline). cosign
        // accepts this; sigstore-rs must too. See sigstore/sigstore-rs#550.
        // Build the wrapped input from the unwrapped signature plus explicit
        // newline bytes, so it is obvious the test exercises newline tolerance
        // and a formatter cannot silently drop the newlines.
        const NEWLINE: u8 = b'\n';
        let unwrapped =
            b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=";
        let mut wrapped = unwrapped.to_vec();
        wrapped.insert(44, NEWLINE); // a newline within the base64 body
        wrapped.push(NEWLINE); // and a trailing newline
        let signature = Signature::Base64Encoded(&wrapped);
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let outcome = verification_key.verify_signature(signature, msg.as_bytes());
        assert!(
            outcome.is_ok(),
            "signature with embedded newlines should verify, got {outcome:?}"
        );
    }

    #[test]
    fn verify_signature_failure_because_wrong_msg() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = "hello world";

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::PublicKeyVerificationError);
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_signature_failure_because_wrong_signature() {
        // Contains '@', which is not in the base64 alphabet and is not a
        // newline, so it must still fail to decode (only newlines are now
        // tolerated, see verify_signature_success_with_embedded_newlines).
        let signature = Signature::Base64Encoded(b"this@is@a@signature");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::Base64DecodeError(_));
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_signature_failure_because_wrong_verification_key() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");

        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::PublicKeyVerificationError);
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_rsa_signature() {
        let signature = Signature::Base64Encoded(b"umasnfYJyLbYPjiq1wIy086Ns+CrgiMoQUSGqPqlUmtWsY0hbngJ73hPfJFrppviPKdBeuUiiwgKagBKIXLEXjwxQp4eE3szwqkKoAnR/lByb7ahLgVQ4MB6xDQaHD53MYtj7aOvd4O7FqJltVVjEn7nM/Du2tL5y3jf6lD7VfHZE8uRocRlyppt8SfTc5L12mVlZ0YlfKYkd334A4y/reCy3Yws0j356Wj7GLScMU5uR11Y2y41rSyYm5uXhTerwNFXsRcPMAmenMarCdCmt4Lf4wpcJBCU172xiK+rIhbMgkLjjA772+auSYf1E8CySVah5CD0Td5YC3y8vIIYaA==");

        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvM/dHoi6nSy7hbKHLYUr
Xy6Bv35JbdoIzny5vSFiRXApr0KS56U8PugdGmh+vd7H8YNlx2YOJxzv02Blsrcm
WDZcXjE3Xpsi/IHFfRZLOdwwR+u8MNFxwRUVzxyIzKGtbREVVfXPfb2Xc6FL5/tE
vQtUKuR6XdzSaav2RnV5IybCB09s0Np0AUbdi5EfSe4INuqgY+VFYLjvM5onbAQL
N3bFLS4Quk66Dhv93Zi6NwopwL1F07UPC5uadkyePStP3PA0OAOemj9vZADOWx5a
dsGCKISs8iphNC5mDVoLy8Ry49Ms3eQXRjVQOMco3YNf8AhsIdxDNBVN8VTDKVkE
DwIDAQAB
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::RSA_PKCS1_SHA256(0),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry.suse.com/suse/sle-micro/5.0/toolbox"},"image":{"docker-manifest-digest":"sha256:356631f7603526a0af827741f5fe005acf19b7ef7705a34241a91c2d47a6db5e"},"type":"cosign container image signature"},"optional":{"creator":"OBS"}}"#;

        assert!(
            verification_key
                .verify_signature(signature, msg.as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn convert_ecdsa_p256_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let key_pair = generate_ecdsa_p256_key_pair();
        let issued_cert_generation_options = CertGenerationOptions {
            key_pair,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert_pem.clone();
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_ecdsa_p384_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let key_pair = generate_ecdsa_p384_key_pair();
        let issued_cert_generation_options = CertGenerationOptions {
            key_pair,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert_pem.clone();
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_rsa_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let key_pair = generate_rsa_key_pair();
        let issued_cert_generation_options = CertGenerationOptions {
            key_pair,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert_pem.clone();
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::RSA_PKCS1_SHA256(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_ed25519_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let key_pair = generate_ed25519_key_pair();
        let issued_cert_generation_options = CertGenerationOptions {
            key_pair,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;
        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert_pem.clone();
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ED25519(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_unsupported_curve_subject_public_key_to_cosign_verification_key()
    -> anyhow::Result<()> {
        // Construct a SubjectPublicKeyInfoOwned with an algorithm OID that is not
        // supported by CosignVerificationKey (id-Ed448, OID 1.3.101.113). This does
        // not require generating a real key — we only need the OID to hit the
        // unsupported-algorithm error path.
        use const_oid::ObjectIdentifier;
        use x509_cert::der::asn1::BitString;
        use x509_cert::spki::AlgorithmIdentifierOwned;

        // id-Ed448: a real algorithm OID, not in the Sigstore registry
        let id_ed448: ObjectIdentifier = const_oid::db::rfc8410::ID_ED_448;
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: id_ed448,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&[0u8; 57]).unwrap(),
        };

        let err = CosignVerificationKey::try_from(&spki);
        assert!(matches!(
            err,
            Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(_))
        ));

        Ok(())
    }
}
