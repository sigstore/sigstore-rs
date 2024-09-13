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

use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use ed25519::pkcs8::DecodePublicKey as ED25519DecodePublicKey;
use rsa::{pkcs1v15, pss};
use sha2::{Digest, Sha256, Sha384};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};
use x509_cert::{der::referenced::OwnedToRef, spki::SubjectPublicKeyInfoOwned};

use super::{
    signing_key::{KeyPair, SigStoreSigner},
    Signature, SigningScheme,
};

use crate::errors::*;

#[cfg(feature = "cosign")]
use crate::cosign::constants::ED25519;

/// A key that can be used to verify signatures.
///
/// Currently the following key formats are supported:
///
///   * RSA keys, using PSS padding and SHA-256 as the digest algorithm
///   * RSA keys, using PSS padding and SHA-384 as the digest algorithm
///   * RSA keys, using PSS padding and SHA-512 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-256 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-384 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-512 as the digest algorithm
///   * Ed25519 keys, and SHA-512 as the digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-256 curve and SHA-256 as digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-384 curve and SHA-384 as digest algorithm
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CosignVerificationKey {
    RSA_PSS_SHA256(pss::VerifyingKey<sha2::Sha256>),
    RSA_PSS_SHA384(pss::VerifyingKey<sha2::Sha384>),
    RSA_PSS_SHA512(pss::VerifyingKey<sha2::Sha512>),
    RSA_PKCS1_SHA256(pkcs1v15::VerifyingKey<sha2::Sha256>),
    RSA_PKCS1_SHA384(pkcs1v15::VerifyingKey<sha2::Sha384>),
    RSA_PKCS1_SHA512(pkcs1v15::VerifyingKey<sha2::Sha512>),
    ECDSA_P256_SHA256_ASN1(ecdsa::VerifyingKey<p256::NistP256>),
    ECDSA_P384_SHA384_ASN1(ecdsa::VerifyingKey<p384::NistP384>),
    ED25519(ed25519_dalek::VerifyingKey),
}

/// Attempts to convert a [x509 Subject Public Key Info](x509_cert::spki::SubjectPublicKeyInfo) object into
/// a `CosignVerificationKey` one.
///
/// Currently can convert only the following types of keys:
///   * ECDSA P-256: assumes the SHA-256 digest algorithm is used
///   * ECDSA P-384: assumes the SHA-384 digest algorithm is used
///   * RSA: assumes PKCS1 padding is used
impl TryFrom<&SubjectPublicKeyInfoOwned> for CosignVerificationKey {
    type Error = SigstoreError;

    fn try_from(subject_pub_key_info: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let algorithm = subject_pub_key_info.algorithm.oid;
        let public_key_der = &subject_pub_key_info.subject_public_key;
        match algorithm {
            ID_EC_PUBLIC_KEY => {
                match public_key_der.raw_bytes().len() {
                    65 => Ok(CosignVerificationKey::ECDSA_P256_SHA256_ASN1(
                        ecdsa::VerifyingKey::try_from(subject_pub_key_info.owned_to_ref())
                            .map_err(|e| {
                                SigstoreError::PKCS8SpkiError(format!(
                                    "Ecdsa-P256 from der bytes to public key failed: {e}"
                                ))
                            })?,
                    )),
                    97 => Ok(CosignVerificationKey::ECDSA_P384_SHA384_ASN1(
                        ecdsa::VerifyingKey::try_from(subject_pub_key_info.owned_to_ref())
                            .map_err(|e| {
                                SigstoreError::PKCS8SpkiError(format!(
                                    "Ecdsa-P384 from der bytes to public key failed: {e}"
                                ))
                            })?,
                    )),
                    _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                        "EC with size {} is not supported",
                        // asn.1 encode caused different length
                        (public_key_der.raw_bytes().len() - 1) * 4
                    ))),
                }
            }
            RSA_ENCRYPTION => {
                let pubkey = rsa::RsaPublicKey::try_from(subject_pub_key_info.owned_to_ref())
                    .map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "RSA from der bytes to public key failed: {e}"
                        ))
                    })?;
                Ok(CosignVerificationKey::RSA_PKCS1_SHA256(
                    pkcs1v15::VerifyingKey::<sha2::Sha256>::from(pubkey),
                ))
            }
            //
            #[cfg(feature = "cosign")]
            ED25519 => Ok(CosignVerificationKey::ED25519(
                ed25519_dalek::VerifyingKey::try_from(subject_pub_key_info.owned_to_ref())?,
            )),
            _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                "Key with algorithm OID {} is not supported",
                algorithm
            ))),
        }
    }
}

impl CosignVerificationKey {
    /// Builds a [`CosignVerificationKey`] from DER-encoded data. The methods takes care
    /// of extracting the SubjectPublicKeyInfo from the DER-encoded data.
    pub fn from_der(der_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        Ok(match signing_scheme {
            SigningScheme::RSA_PSS_SHA256(_) => {
                CosignVerificationKey::RSA_PSS_SHA256(pss::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::RSA_PSS_SHA384(_) => {
                CosignVerificationKey::RSA_PSS_SHA384(pss::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::RSA_PSS_SHA512(_) => {
                CosignVerificationKey::RSA_PSS_SHA512(pss::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::RSA_PKCS1_SHA256(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA256(pkcs1v15::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::RSA_PKCS1_SHA384(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA384(pkcs1v15::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::RSA_PKCS1_SHA512(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA512(pkcs1v15::VerifyingKey::new(
                    rsa::RsaPublicKey::from_public_key_der(der_data).map_err(|e| {
                        SigstoreError::PKCS8SpkiError(format!(
                            "read rsa public key from der failed: {e}"
                        ))
                    })?,
                ))
            }
            SigningScheme::ECDSA_P256_SHA256_ASN1 => CosignVerificationKey::ECDSA_P256_SHA256_ASN1(
                ecdsa::VerifyingKey::from_public_key_der(der_data).map_err(|e| {
                    SigstoreError::PKCS8SpkiError(format!(
                        "Ecdsa-P256 from der bytes to public key failed: {e}"
                    ))
                })?,
            ),
            SigningScheme::ECDSA_P384_SHA384_ASN1 => CosignVerificationKey::ECDSA_P384_SHA384_ASN1(
                ecdsa::VerifyingKey::from_public_key_der(der_data).map_err(|e| {
                    SigstoreError::PKCS8SpkiError(format!(
                        "Ecdsa-P384 from der bytes to public key failed: {e}"
                    ))
                })?,
            ),
            SigningScheme::ED25519 => CosignVerificationKey::ED25519(
                ed25519_dalek::VerifyingKey::from_public_key_der(der_data)?,
            ),
        })
    }

    /// Builds a [`CosignVerificationKey`] from DER-encoded public key data. This function will
    /// set the verification algorithm due to the public key type, s.t.
    /// * `RSA public key`: `RSA_PKCS1_SHA256`
    /// * `EC public key with P-256 curve`: `ECDSA_P256_SHA256_ASN1`
    /// * `EC public key with P-384 curve`: `ECDSA_P384_SHA384_ASN1`
    /// * `Ed25519 public key`: `Ed25519`
    pub fn try_from_der(der_data: &[u8]) -> Result<Self> {
        if let Ok(p256vk) = ecdsa::VerifyingKey::from_public_key_der(der_data) {
            Ok(Self::ECDSA_P256_SHA256_ASN1(p256vk))
        } else if let Ok(p384vk) = ecdsa::VerifyingKey::from_public_key_der(der_data) {
            Ok(Self::ECDSA_P384_SHA384_ASN1(p384vk))
        } else if let Ok(ed25519bytes) =
            ed25519::pkcs8::PublicKeyBytes::from_public_key_der(der_data)
        {
            Ok(Self::ED25519(ed25519_dalek::VerifyingKey::from_bytes(
                ed25519bytes.as_ref(),
            )?))
        } else if let Ok(rsapk) = rsa::RsaPublicKey::from_public_key_der(der_data) {
            Ok(Self::RSA_PKCS1_SHA256(pkcs1v15::VerifyingKey::new(rsapk)))
        } else {
            Err(SigstoreError::InvalidKeyFormat {
                error: "Failed to parse the public key.".to_string(),
            })
        }
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded data. The methods takes care
    /// of decoding the PEM-encoded data and then extracting the SubjectPublicKeyInfo
    /// from the DER-encoded bytes.
    pub fn from_pem(pem_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::from_der(key_pem.contents(), signing_scheme)
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded public key data. This function will
    /// set the verification algorithm due to the public key type, s.t.
    /// * `RSA public key`: `RSA_PKCS1_SHA256`
    /// * `EC public key with P-256 curve`: `ECDSA_P256_SHA256_ASN1`
    /// * `EC public key with P-384 curve`: `ECDSA_P384_SHA384_ASN1`
    /// * `Ed25519 public key`: `Ed25519`
    pub fn try_from_pem(pem_data: &[u8]) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::try_from_der(key_pem.contents())
    }

    /// Builds a `CosignVerificationKey` from [`SigStoreSigner`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`SigStoreSigner`]'s public key.
    pub fn from_sigstore_signer(signer: &SigStoreSigner) -> Result<Self> {
        signer.to_verification_key()
    }

    /// Builds a `CosignVerificationKey` from [`KeyPair`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`KeyPair`]'s public key.
    pub fn from_key_pair(signer: &dyn KeyPair, signing_scheme: &SigningScheme) -> Result<Self> {
        signer.to_verification_key(signing_scheme)
    }

    /// Verify the signature provided has been actually generated by the given key
    /// when signing the provided message.
    pub fn verify_signature(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => BASE64_STD_ENGINE.decode(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA384(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA512(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA384(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA512(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            // ECDSA signatures are encoded in der.
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(inner) => {
                let mut hasher = Sha256::new();
                digest::Digest::update(&mut hasher, msg);
                let sig = ecdsa::Signature::from_der(&sig)?;
                inner
                    .verify_digest(hasher, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(inner) => {
                let mut hasher = Sha384::new();
                digest::Digest::update(&mut hasher, msg);
                let sig = ecdsa::Signature::from_der(&sig)?;
                inner
                    .verify_digest(hasher, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ED25519(inner) => {
                let sig = ed25519::Signature::from_slice(sig.as_slice())
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)?;
                inner
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
        }
    }

    /// Verify the signature provided has been actually generated by the given key
    /// when signing the provided prehashed message.
    pub(crate) fn verify_prehash(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => BASE64_STD_ENGINE.decode(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA384(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA512(inner) => {
                let sig = pss::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA384(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA512(inner) => {
                let sig = pkcs1v15::Signature::try_from(sig.as_slice())?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            // ECDSA signatures are encoded in der.
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(inner) => {
                let sig = ecdsa::Signature::from_der(&sig)?;
                inner
                    .verify_prehash(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(inner) => {
                let sig = ecdsa::Signature::from_der(&sig)?;
                inner
                    .verify_prehash(msg, &sig)
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
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

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
        let found = match err {
            SigstoreError::PublicKeyVerificationError => true,
            _ => false,
        };
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_signature_failure_because_wrong_signature() {
        let signature = Signature::Base64Encoded(b"this is a signature");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = match err {
            SigstoreError::Base64DecodeError(_) => true,
            _ => false,
        };
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
        let found = match err {
            SigstoreError::PublicKeyVerificationError => true,
            _ => false,
        };
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

        assert!(verification_key
            .verify_signature(signature, msg.as_bytes())
            .is_ok());
    }

    #[test]
    fn convert_ecdsa_p256_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let (private_key, public_key) = generate_ecdsa_p256_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
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
        let (private_key, public_key) = generate_ecdsa_p384_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
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
        let (private_key, public_key) = generate_rsa_keypair(2048);
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
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
        let (private_key, public_key) = generate_ed25519_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
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
    fn convert_unsupported_curve_subject_public_key_to_cosign_verification_key(
    ) -> anyhow::Result<()> {
        let (private_key, public_key) = generate_dsa_keypair(2048);
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let err = CosignVerificationKey::try_from(&spki);
        assert!(matches!(
            err,
            Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(_))
        ));

        Ok(())
    }
}
