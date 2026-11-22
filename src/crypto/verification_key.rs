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

use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use const_oid::db::rfc8410::ID_ED_25519;
use curve25519_dalek::edwards::CompressedEdwardsY;
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
        // Encode the full SPKI to DER for the active crypto backend.
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
            ED25519_OID => ed25519_from_spki(spki, spki_der),
            oid if oid == ID_ED_25519 => ed25519_from_spki(spki, spki_der),
            _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                "Key with algorithm OID {algo_oid} is not supported"
            ))),
        }
    }
}

/// Why an Ed25519 public key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Ed25519KeyError {
    #[error("Ed25519 public key must be 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Ed25519 public key is not a point on the curve")]
    NotOnCurve,
    #[error("Ed25519 public key is not canonically encoded")]
    NonCanonical,
    #[error("Ed25519 public key is a small-order point")]
    SmallOrder,
}

/// Rejects Ed25519 public keys that no honest signer produces.
///
/// Neither OpenSSL nor aws-lc rejects small-order keys when verifying, so the
/// check is done here, independent of the backend. A non-canonical encoding
/// would also let one key have several byte representations.
pub(crate) fn check_ed25519_point(key: &[u8]) -> std::result::Result<(), Ed25519KeyError> {
    let compressed = CompressedEdwardsY::from_slice(key)
        .map_err(|_| Ed25519KeyError::InvalidLength(key.len()))?;
    let point = compressed.decompress().ok_or(Ed25519KeyError::NotOnCurve)?;
    if point.compress() != compressed {
        return Err(Ed25519KeyError::NonCanonical);
    }
    if point.is_small_order() {
        return Err(Ed25519KeyError::SmallOrder);
    }
    Ok(())
}

fn check_ed25519_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<()> {
    let key = spki.subject_public_key.as_bytes().ok_or_else(|| {
        SigstoreError::KeyParsingError("Ed25519 public key is not octet-aligned".into())
    })?;
    check_ed25519_point(key).map_err(|e| SigstoreError::InvalidKeyFormat {
        error: e.to_string(),
    })
}

/// Validates the key material held by a [`CosignVerificationKey::ED25519`].
///
/// The variant normally holds a DER SubjectPublicKeyInfo. `aws-lc-rs` also
/// verifies with a bare 32-byte key, so that form is checked as well.
pub(crate) fn check_ed25519_key_material(data: &[u8]) -> Result<()> {
    use x509_cert::der::Decode;
    match SubjectPublicKeyInfoOwned::from_der(data) {
        Ok(spki) if spki.algorithm.oid == ID_ED_25519 => check_ed25519_spki(&spki),
        Ok(spki) => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
            "Expected an Ed25519 key, got algorithm OID {}",
            spki.algorithm.oid
        ))),
        Err(e) if data.len() != 32 => Err(SigstoreError::KeyParsingError(format!(
            "Cannot parse SPKI from DER: {e}"
        ))),
        Err(_) => check_ed25519_point(data).map_err(|e| SigstoreError::InvalidKeyFormat {
            error: e.to_string(),
        }),
    }
}

fn ed25519_from_spki(
    spki: &SubjectPublicKeyInfoOwned,
    spki_der: Vec<u8>,
) -> Result<CosignVerificationKey> {
    check_ed25519_spki(spki)?;
    Ok(CosignVerificationKey::ED25519(spki_der))
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
            SigningScheme::ED25519 => {
                check_ed25519_key_material(der_data)?;
                CosignVerificationKey::ED25519(der_data.to_vec())
            }
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
        self.check_key()?;
        let sig = signature.decode_bytes()?;
        let scheme = super::backend::VerifyScheme::from_cosign_key(self);
        if super::backend::verify_spki(scheme, self.spki(), msg, &sig) {
            Ok(())
        } else {
            Err(SigstoreError::PublicKeyVerificationError)
        }
    }

    /// Verify the signature provided was generated by this key over the provided
    /// *pre-hashed* message (the `msg` slice contains the raw hash output, not the
    /// original data).
    pub(crate) fn verify_prehash(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        self.check_key()?;
        let sig = signature.decode_bytes()?;
        let scheme = super::backend::VerifyScheme::from_cosign_key(self);
        if super::backend::verify_spki_prehash(scheme, self.spki(), msg, &sig) {
            Ok(())
        } else {
            Err(SigstoreError::PublicKeyVerificationError)
        }
    }

    /// The enum variants are public, so a key may not have come through a
    /// constructor; check it again before every verification.
    fn check_key(&self) -> Result<()> {
        match self {
            CosignVerificationKey::ED25519(key) => check_ed25519_key_material(key),
            _ => Ok(()),
        }
    }

    fn spki(&self) -> &[u8] {
        match self {
            CosignVerificationKey::RSA_PSS_SHA256(key)
            | CosignVerificationKey::RSA_PKCS1_SHA256(key)
            | CosignVerificationKey::ECDSA_P256_SHA256_ASN1(key)
            | CosignVerificationKey::ECDSA_P384_SHA384_ASN1(key)
            | CosignVerificationKey::ECDSA_P521_SHA512_ASN1(key)
            | CosignVerificationKey::ED25519(key) => key,
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
        let spki = cert.tbs_certificate().subject_public_key_info();

        let cosign_verification_key =
            CosignVerificationKey::try_from(spki).expect("conversion failed");

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
        let spki = cert.tbs_certificate().subject_public_key_info();

        let cosign_verification_key =
            CosignVerificationKey::try_from(spki).expect("conversion failed");

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
        let spki = cert.tbs_certificate().subject_public_key_info();

        let cosign_verification_key =
            CosignVerificationKey::try_from(spki).expect("conversion failed");

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
        let spki = cert.tbs_certificate().subject_public_key_info();

        let cosign_verification_key =
            CosignVerificationKey::try_from(spki).expect("conversion failed");

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

    /// DER SubjectPublicKeyInfo for a raw Ed25519 key of up to 126 bytes.
    fn ed25519_spki(key: &[u8]) -> Vec<u8> {
        let mut spki = vec![
            0x30,
            (key.len() + 10) as u8,
            0x30,
            0x05,
            0x06,
            0x03,
            0x2b,
            0x65,
            0x70,
            0x03,
            (key.len() + 1) as u8,
            0x00,
        ];
        spki.extend_from_slice(key);
        spki
    }

    fn hex32(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Asserts every Ed25519 constructor refuses `spki` and that a key built
    /// directly from the enum variant refuses to verify.
    fn assert_ed25519_rejected(spki: &[u8], expected: Ed25519KeyError) {
        let message = expected.to_string();
        let is_expected = |err: &SigstoreError| matches!(err, SigstoreError::InvalidKeyFormat { error } if *error == message);

        let err = CosignVerificationKey::try_from_der(spki).unwrap_err();
        assert!(is_expected(&err), "try_from_der: {err:?}");

        let err = CosignVerificationKey::from_der(spki, &SigningScheme::ED25519).unwrap_err();
        assert!(is_expected(&err), "from_der: {err:?}");

        let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki.to_vec()));
        let err = CosignVerificationKey::try_from_pem(pem.as_bytes()).unwrap_err();
        assert!(is_expected(&err), "try_from_pem: {err:?}");
        let err =
            CosignVerificationKey::from_pem(pem.as_bytes(), &SigningScheme::ED25519).unwrap_err();
        assert!(is_expected(&err), "from_pem: {err:?}");

        let parsed = SubjectPublicKeyInfoOwned::from_der(spki).unwrap();
        let err = CosignVerificationKey::try_from(&parsed).unwrap_err();
        assert!(is_expected(&err), "try_from(&spki): {err:?}");

        let direct = CosignVerificationKey::ED25519(spki.to_vec());
        let err = direct
            .verify_signature(Signature::Raw(&[0u8; 64]), b"msg")
            .unwrap_err();
        assert!(is_expected(&err), "verify_signature: {err:?}");
        let err = direct
            .verify_prehash(Signature::Raw(&[0u8; 64]), &[0u8; 32])
            .unwrap_err();
        assert!(is_expected(&err), "verify_prehash: {err:?}");
    }

    #[rstest::rstest]
    #[case::neutral("0100000000000000000000000000000000000000000000000000000000000000")]
    #[case::order_2("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    #[case::order_4_a("0000000000000000000000000000000000000000000000000000000000000000")]
    #[case::order_4_b("0000000000000000000000000000000000000000000000000000000000000080")]
    #[case::order_8_a("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")]
    #[case::order_8_b("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")]
    #[case::order_8_c("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")]
    #[case::order_8_d("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")]
    fn ed25519_rejects_small_order_key(#[case] key: &str) {
        let key = hex32(key);
        assert_eq!(check_ed25519_point(&key), Err(Ed25519KeyError::SmallOrder));
        assert_ed25519_rejected(&ed25519_spki(&key), Ed25519KeyError::SmallOrder);
    }

    #[test]
    fn ed25519_rejects_non_canonical_key() {
        // y = p + 3 encodes the same point as y = 3, which has large order.
        let key = hex32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let canonical = hex32("0300000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(check_ed25519_point(&canonical), Ok(()));
        assert_eq!(
            check_ed25519_point(&key),
            Err(Ed25519KeyError::NonCanonical)
        );
        assert_ed25519_rejected(&ed25519_spki(&key), Ed25519KeyError::NonCanonical);
    }

    #[test]
    fn ed25519_rejects_off_curve_key() {
        // No curve point has y = 2.
        let key = hex32("0200000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(check_ed25519_point(&key), Err(Ed25519KeyError::NotOnCurve));
        assert_ed25519_rejected(&ed25519_spki(&key), Ed25519KeyError::NotOnCurve);
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(31)]
    #[case(33)]
    fn ed25519_rejects_wrong_length_key(#[case] len: usize) {
        let mut key = hex32("0300000000000000000000000000000000000000000000000000000000000000");
        key.resize(len, 0);
        assert_eq!(
            check_ed25519_point(&key),
            Err(Ed25519KeyError::InvalidLength(len))
        );
        assert_ed25519_rejected(&ed25519_spki(&key), Ed25519KeyError::InvalidLength(len));
    }

    #[test]
    fn ed25519_rejects_small_order_raw_key() {
        // aws-lc-rs also verifies with a bare 32-byte key, so that form is
        // checked too.
        let key = hex32("0100000000000000000000000000000000000000000000000000000000000000");
        let err = CosignVerificationKey::from_der(&key, &SigningScheme::ED25519).unwrap_err();
        assert!(
            matches!(&err, SigstoreError::InvalidKeyFormat { error }
                if *error == Ed25519KeyError::SmallOrder.to_string()),
            "{err:?}"
        );
    }

    #[test]
    fn ed25519_accepts_honest_key() {
        use crate::crypto::signing_key::ed25519::{Ed25519Keys, Ed25519Signer};
        use crate::crypto::signing_key::{KeyPair, Signer};

        let keys = Ed25519Keys::new().unwrap();
        let spki = keys.public_key_to_der().unwrap();
        let parsed = SubjectPublicKeyInfoOwned::from_der(&spki).unwrap();
        check_ed25519_point(parsed.subject_public_key.as_bytes().unwrap()).unwrap();

        let sig = Ed25519Signer::from_ed25519_keys(&keys)
            .unwrap()
            .sign(b"payload")
            .unwrap();
        for vk in [
            CosignVerificationKey::try_from_der(&spki).unwrap(),
            CosignVerificationKey::from_der(&spki, &SigningScheme::ED25519).unwrap(),
            CosignVerificationKey::try_from(&parsed).unwrap(),
        ] {
            vk.verify_signature(Signature::Raw(&sig), b"payload")
                .unwrap();
            let err = vk
                .verify_signature(Signature::Raw(&sig), b"other")
                .unwrap_err();
            assert!(matches!(err, SigstoreError::PublicKeyVerificationError));
        }
    }

    /// `TryFrom<&SubjectPublicKeyInfoOwned>` matches cosign's Ed25519 OID
    /// first, while `check_ed25519_key_material` compares against
    /// `ID_ED_25519`. Both must name the same algorithm.
    #[cfg(feature = "cosign")]
    #[test]
    fn cosign_ed25519_oid_is_rfc8410_oid() {
        assert_eq!(ED25519_OID, ID_ED_25519);
    }

    /// The identity-point key is rejected at construction and at verification.
    #[test]
    fn identity_ed25519_key_is_rejected() {
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x01,
        ];
        spki.extend_from_slice(&[0u8; 31]);
        let mut sig = vec![0x01];
        sig.extend_from_slice(&[0u8; 63]);

        let err = CosignVerificationKey::try_from_der(&spki).unwrap_err();
        assert!(
            matches!(&err, SigstoreError::InvalidKeyFormat { error }
                if *error == Ed25519KeyError::SmallOrder.to_string()),
            "{err:?}"
        );

        let vk = CosignVerificationKey::ED25519(spki);
        for msg in ["hello", "payload", "release v9.9.9"] {
            let err = vk
                .verify_signature(Signature::Raw(&sig), msg.as_bytes())
                .unwrap_err();
            assert!(
                matches!(&err, SigstoreError::InvalidKeyFormat { error }
                    if *error == Ed25519KeyError::SmallOrder.to_string()),
                "{err:?}"
            );
        }
    }
}
