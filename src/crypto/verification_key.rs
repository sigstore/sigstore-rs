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

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::{oid_registry::*, prelude::FromDer, x509::SubjectPublicKeyInfo};

use super::{
    signing_key::{KeyPair, SigStoreSigner},
    Signature, SignatureDigestAlgorithm,
};
use crate::errors::{Result, SigstoreError};

/// A key that can be used to verify signatures.
///
/// Underneath leverages [`ring`](https://crates.io/crates/ring) to implement all
/// the cryptographic operatations.
///
/// Currently the following key formats are supported:
///
///   * RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-256 as digest algorithm
///   * RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-384 as digest algorithm
///   * RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-512 as digest algorithm
///   * Ed25519 keys, and SHA-512 as the digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-256 curve and SHA-256 as digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-384 curve and SHA-384 as digest algorithm
#[derive(Debug, Clone)]
pub struct CosignVerificationKey {
    verification_algorithm: &'static dyn VerificationAlgorithm,
    data: Vec<u8>,
}

impl CosignVerificationKey {
    /// Builds a `CosignVerificationKey` from DER-encoded data. The methods takes care
    /// of extracting the SubjectPublicKeyInfo from the DER-encoded data.
    pub fn from_der(
        der_data: &[u8],
        verification_algorithm: &'static dyn signature::VerificationAlgorithm,
    ) -> Result<Self> {
        let (_, public_key) = SubjectPublicKeyInfo::from_der(der_data)?;
        let data = public_key.subject_public_key.data.into_owned();

        Ok(Self {
            data,
            verification_algorithm,
        })
    }

    /// Builds a `CosignVerificationKey` from PEM-encoded data. The methods takes care
    /// of decoding the PEM-encoded data and then extracting the SubjectPublicKeyInfo
    /// from the DER-encoded bytes.
    pub fn from_pem(
        pem_data: &[u8],
        signature_digest_algorithm: SignatureDigestAlgorithm,
    ) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;

        let (_, public_key) = SubjectPublicKeyInfo::from_der(key_pem.contents.as_slice())?;

        let signature_alg = &public_key.algorithm.algorithm;
        let verification_algorithm: Result<&dyn signature::VerificationAlgorithm> =
            if *signature_alg == OID_PKCS1_RSAENCRYPTION {
                match signature_digest_algorithm {
                    SignatureDigestAlgorithm::Sha256 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
                    SignatureDigestAlgorithm::Sha384 => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
                    SignatureDigestAlgorithm::Sha512 => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
                }
            } else if *signature_alg == OID_SIG_ED25519 {
                Ok(&signature::ED25519)
            } else if *signature_alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
                match signature_digest_algorithm {
                    SignatureDigestAlgorithm::Sha256 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
                    SignatureDigestAlgorithm::Sha384 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
                    SignatureDigestAlgorithm::Sha512 => {
                        Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(
                            "Cannot use ECDSA with sha512 digest".to_string(),
                        ))
                    }
                }
            } else {
                Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(
                    "unknown algorithm".to_string(),
                ))
            };

        let verification_algorithm = verification_algorithm?;
        let data = public_key.subject_public_key.data.into_owned();

        Ok(Self {
            verification_algorithm,
            data,
        })
    }

    /// Builds a `CosignVerificationKey` from [`SigStoreSigner`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`SigStoreSigner`]'s public key.
    pub fn from_sigstore_signer(signer: &SigStoreSigner) -> Result<Self> {
        signer.to_verification_key()
    }

    /// Builds a `CosignVerificationKey` from [`KeyPair`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`KeyPair`]'s public key.
    pub fn from_key_pair(
        signer: &dyn KeyPair,
        signature_digest_algorithm: SignatureDigestAlgorithm,
    ) -> Result<Self> {
        signer.to_verification_key(signature_digest_algorithm)
    }

    /// Verify the signature provided has been actually generated by the given key
    /// when signing the provided message.
    pub fn verify_signature(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let key = UnparsedPublicKey::new(self.verification_algorithm, &self.data);

        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => base64::decode(data)?,
        };

        key.verify(msg, &sig)
            .map_err(|_| SigstoreError::PublicKeyVerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tests::*;

    #[test]
    fn verify_signature_success() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key = CosignVerificationKey::from_pem(
            PUBLIC_KEY.as_bytes(),
            SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let outcome = verification_key.verify_signature(signature, &msg.as_bytes());
        assert!(outcome.is_ok());
    }

    #[test]
    fn verify_signature_failure_because_wrong_msg() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key = CosignVerificationKey::from_pem(
            PUBLIC_KEY.as_bytes(),
            SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = "hello world";

        let err = verification_key
            .verify_signature(signature, &msg.as_bytes())
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
        let verification_key = CosignVerificationKey::from_pem(
            PUBLIC_KEY.as_bytes(),
            SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, &msg.as_bytes())
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
            SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, &msg.as_bytes())
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
            SignatureDigestAlgorithm::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry.suse.com/suse/sle-micro/5.0/toolbox"},"image":{"docker-manifest-digest":"sha256:356631f7603526a0af827741f5fe005acf19b7ef7705a34241a91c2d47a6db5e"},"type":"cosign container image signature"},"optional":{"creator":"OBS"}}"#;

        assert!(verification_key
            .verify_signature(signature, &msg.as_bytes())
            .is_ok());
    }
}
