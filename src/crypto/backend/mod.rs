// Copyright 2026 The Sigstore Authors.
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

//! Crypto operations selected by the TLS feature.
//!
//! `native-tls` uses OpenSSL. `rustls-tls` uses `aws-lc-rs`. Enabling both
//! compiles the OpenSSL implementation; `aws-lc-rs` stays in the dependency
//! graph because Cargo features are additive.

#[cfg(feature = "native-tls")]
mod openssl;
#[cfg(feature = "native-tls")]
pub(crate) use openssl::*;

#[cfg(all(not(feature = "native-tls"), feature = "rustls-tls"))]
mod aws_lc;
#[cfg(all(not(feature = "native-tls"), feature = "rustls-tls"))]
pub(crate) use aws_lc::*;

#[cfg(not(any(feature = "native-tls", feature = "rustls-tls")))]
compile_error!(
    "sigstore requires the `native-tls` or `rustls-tls` feature to select a crypto backend"
);

/// Elliptic curve used by ECDSA key generation and signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcdsaCurve {
    P256,
    P384,
    P521,
}

/// Signature scheme for a SubjectPublicKeyInfo public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyScheme {
    RsaPssSha256,
    RsaPkcs1Sha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Ed25519,
}

impl VerifyScheme {
    /// Scheme used to verify a signature with this cosign public key.
    pub(crate) fn from_cosign_key(key: &crate::crypto::CosignVerificationKey) -> Self {
        use crate::crypto::CosignVerificationKey;
        match key {
            CosignVerificationKey::RSA_PSS_SHA256(_) => Self::RsaPssSha256,
            CosignVerificationKey::RSA_PKCS1_SHA256(_) => Self::RsaPkcs1Sha256,
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(_) => Self::EcdsaP256Sha256,
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(_) => Self::EcdsaP384Sha384,
            CosignVerificationKey::ECDSA_P521_SHA512_ASN1(_) => Self::EcdsaP521Sha512,
            CosignVerificationKey::ED25519(_) => Self::Ed25519,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the crypto backend selected by the TLS feature.
    //!
    //! These call the functions re-exported by the parent module, so the same
    //! cases run against OpenSSL or `aws-lc-rs` depending on which one is compiled.

    use super::{EcdsaCurve, VerifyScheme};
    use rstest::rstest;
    use sha2::Digest;

    const MSG: &[u8] = b"backend-api";

    fn ecdsa_scheme(curve: EcdsaCurve) -> VerifyScheme {
        match curve {
            EcdsaCurve::P256 => VerifyScheme::EcdsaP256Sha256,
            EcdsaCurve::P384 => VerifyScheme::EcdsaP384Sha384,
            EcdsaCurve::P521 => VerifyScheme::EcdsaP521Sha512,
        }
    }

    fn message_digest(curve: EcdsaCurve, msg: &[u8]) -> Vec<u8> {
        match curve {
            EcdsaCurve::P256 => sha2::Sha256::digest(msg).to_vec(),
            EcdsaCurve::P384 => sha2::Sha384::digest(msg).to_vec(),
            EcdsaCurve::P521 => sha2::Sha512::digest(msg).to_vec(),
        }
    }

    fn sign_pkcs8(curve: EcdsaCurve, pkcs8: &[u8], msg: &[u8]) -> crate::errors::Result<Vec<u8>> {
        super::EcdsaSigningKey::from_pkcs8(curve, pkcs8)?.sign(msg)
    }

    fn p256_point(spki: &[u8]) -> Vec<u8> {
        use x509_cert::der::Decode;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        SubjectPublicKeyInfoOwned::from_der(spki)
            .unwrap()
            .subject_public_key
            .raw_bytes()
            .to_vec()
    }

    fn rsa_2048() -> &'static (zeroize::Zeroizing<Vec<u8>>, Vec<u8>) {
        use std::sync::OnceLock;
        static KEY: OnceLock<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> = OnceLock::new();
        KEY.get_or_init(|| super::rsa_generate(2048).expect("rsa 2048"))
    }

    #[rstest]
    #[case(0)]
    #[case(32)]
    fn fill_random(#[case] len: usize) {
        let mut buf = vec![0u8; len];
        super::fill_random(&mut buf);
        if len == 32 {
            let mut other = vec![0u8; len];
            super::fill_random(&mut other);
            assert_ne!(buf, other);
        }
    }

    #[rstest]
    #[case(EcdsaCurve::P256)]
    #[case(EcdsaCurve::P384)]
    #[case(EcdsaCurve::P521)]
    fn ecdsa_generate(#[case] curve: EcdsaCurve) {
        let (pkcs8, spki) = super::ecdsa_generate(curve).unwrap();
        assert!(!pkcs8.is_empty());
        assert!(!spki.is_empty());
    }

    #[rstest]
    #[case(EcdsaCurve::P256)]
    #[case(EcdsaCurve::P384)]
    #[case(EcdsaCurve::P521)]
    fn ecdsa_spki_from_pkcs8(#[case] curve: EcdsaCurve) {
        let (pkcs8, spki) = super::ecdsa_generate(curve).unwrap();
        assert_eq!(super::ecdsa_spki_from_pkcs8(&pkcs8).unwrap(), spki);
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_pkcs8(&b"not-pkcs8"[..])]
    fn ecdsa_spki_from_pkcs8_rejects(#[case] der: &[u8]) {
        assert!(super::ecdsa_spki_from_pkcs8(der).is_err());
    }

    #[rstest]
    #[case(EcdsaCurve::P256, true)]
    #[case(EcdsaCurve::P384, true)]
    #[case(EcdsaCurve::P521, true)]
    #[case(EcdsaCurve::P256, false)]
    fn ecdsa_sign(#[case] curve: EcdsaCurve, #[case] intact: bool) {
        let (pkcs8, spki) = super::ecdsa_generate(curve).unwrap();
        let sig = sign_pkcs8(curve, &pkcs8, MSG).unwrap();
        let msg = if intact { MSG } else { b"other".as_slice() };
        assert_eq!(
            super::verify_spki(ecdsa_scheme(curve), &spki, msg, &sig),
            intact
        );
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_pkcs8(&b"not-pkcs8"[..])]
    fn ecdsa_sign_rejects(#[case] pkcs8: &[u8]) {
        assert!(super::EcdsaSigningKey::from_pkcs8(EcdsaCurve::P256, pkcs8).is_err());
    }

    #[rstest]
    #[case(EcdsaCurve::P256)]
    #[case(EcdsaCurve::P384)]
    #[case(EcdsaCurve::P521)]
    fn ecdsa_signing_key_reused(#[case] curve: EcdsaCurve) {
        let (pkcs8, spki) = super::ecdsa_generate(curve).unwrap();
        let key = super::EcdsaSigningKey::from_pkcs8(curve, &pkcs8).unwrap();
        let first = key.sign(MSG).unwrap();
        let second = key.sign(b"another").unwrap();
        assert!(super::verify_spki(ecdsa_scheme(curve), &spki, MSG, &first));
        assert!(super::verify_spki(
            ecdsa_scheme(curve),
            &spki,
            b"another",
            &second
        ));
    }

    #[test]
    fn ecdsa_signing_key_rejects_curve_mismatch() {
        let (pkcs8, _) = super::ecdsa_generate(EcdsaCurve::P384).unwrap();
        assert!(super::EcdsaSigningKey::from_pkcs8(EcdsaCurve::P256, &pkcs8).is_err());
    }

    #[rstest]
    #[case(EcdsaCurve::P256, true)]
    #[case(EcdsaCurve::P384, true)]
    #[case(EcdsaCurve::P521, true)]
    #[case(EcdsaCurve::P256, false)]
    fn verify_spki_prehash(#[case] curve: EcdsaCurve, #[case] intact: bool) {
        let (pkcs8, spki) = super::ecdsa_generate(curve).unwrap();
        let sig = sign_pkcs8(curve, &pkcs8, MSG).unwrap();
        let digest = if intact {
            message_digest(curve, MSG)
        } else {
            message_digest(curve, b"other")
        };
        assert_eq!(
            super::verify_spki_prehash(ecdsa_scheme(curve), &spki, &digest, &sig),
            intact
        );
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_a_key(&b"not-a-key"[..])]
    fn verify_spki_rejects_key(#[case] spki: &[u8]) {
        assert!(!super::verify_spki(
            VerifyScheme::EcdsaP256Sha256,
            spki,
            MSG,
            b"sig"
        ));
        assert!(!super::verify_spki_prehash(
            VerifyScheme::EcdsaP256Sha256,
            spki,
            &[0u8; 32],
            b"sig"
        ));
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn verify_p256_point(#[case] intact: bool) {
        let (pkcs8, spki) = super::ecdsa_generate(EcdsaCurve::P256).unwrap();
        let point = p256_point(&spki);
        let sig = sign_pkcs8(EcdsaCurve::P256, &pkcs8, MSG).unwrap();
        let msg = if intact { MSG } else { b"other".as_slice() };
        assert_eq!(super::verify_p256_point(&point, msg, &sig), intact);
        if intact {
            assert!(!super::verify_p256_point(&[0x04, 1, 2, 3], MSG, &sig));
            assert!(!super::verify_p256_point(&point, MSG, &[]));
        }
    }

    #[rstest]
    #[case(2048)]
    fn rsa_generate(#[case] bits: usize) {
        let (pkcs8, spki) = super::rsa_generate(bits).unwrap();
        let (spki2, len) = super::rsa_from_pkcs8(&pkcs8).unwrap();
        assert_eq!(spki, spki2);
        assert_eq!(len, bits / 8);
    }

    #[rstest]
    #[case(0)]
    #[case(1024)]
    #[case(4095)]
    fn rsa_generate_rejects(#[case] bits: usize) {
        assert!(super::rsa_generate(bits).is_err());
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_pkcs8(&b"not-pkcs8"[..])]
    fn rsa_from_pkcs8_rejects(#[case] der: &[u8]) {
        assert!(super::rsa_from_pkcs8(der).is_err());
    }

    #[test]
    fn rsa_from_pkcs1() {
        let pem_bytes = std::fs::read("tests/data/keys/rsa_private.key").unwrap();
        let der = pem::parse(pem_bytes).unwrap().contents().to_vec();
        let (pkcs8, spki, len) = super::rsa_from_pkcs1(&der).unwrap();
        assert!(matches!(len, 256 | 384 | 512));
        let sig = super::rsa_sign(&pkcs8, false, MSG).unwrap();
        assert!(super::verify_spki(
            VerifyScheme::RsaPkcs1Sha256,
            &spki,
            MSG,
            &sig
        ));
        assert!(!super::verify_spki(
            VerifyScheme::RsaPkcs1Sha256,
            &spki,
            b"other",
            &sig
        ));
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_pkcs1(&b"not-pkcs1"[..])]
    fn rsa_from_pkcs1_rejects(#[case] der: &[u8]) {
        assert!(super::rsa_from_pkcs1(der).is_err());
    }

    #[rstest]
    #[case(true, true)]
    #[case(false, true)]
    #[case(true, false)]
    fn rsa_sign(#[case] pss: bool, #[case] intact: bool) {
        let (pkcs8, spki) = rsa_2048();
        let sig = super::rsa_sign(pkcs8, pss, MSG).unwrap();
        let scheme = if pss {
            VerifyScheme::RsaPssSha256
        } else {
            VerifyScheme::RsaPkcs1Sha256
        };
        let msg = if intact { MSG } else { b"other".as_slice() };
        assert_eq!(super::verify_spki(scheme, spki, msg, &sig), intact);
        assert_eq!(
            super::verify_spki_prehash(scheme, spki, &sha2::Sha256::digest(msg), &sig),
            intact
        );
    }

    #[rstest]
    #[case::empty_key(&b""[..])]
    #[case::not_pkcs8(&b"not-pkcs8"[..])]
    fn rsa_sign_rejects(#[case] pkcs8: &[u8]) {
        assert!(super::rsa_sign(pkcs8, false, MSG).is_err());
        assert!(super::rsa_sign(pkcs8, true, MSG).is_err());
    }

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn ed25519_sign(#[case] intact: bool) {
        let (pkcs8, spki) = super::ed25519_generate().unwrap();
        assert_eq!(super::ed25519_spki_from_pkcs8(&pkcs8).unwrap(), spki);
        let sig = super::ed25519_sign(&pkcs8, MSG).unwrap();
        let msg = if intact { MSG } else { b"other".as_slice() };
        assert_eq!(
            super::verify_spki(VerifyScheme::Ed25519, &spki, msg, &sig),
            intact
        );
        assert!(!super::verify_spki_prehash(
            VerifyScheme::Ed25519,
            &spki,
            &sha2::Sha256::digest(MSG),
            &sig
        ));
    }

    #[rstest]
    #[case(&b""[..])]
    #[case(&b"not-pkcs8"[..])]
    fn ed25519_rejects(#[case] der: &[u8]) {
        assert!(super::ed25519_spki_from_pkcs8(der).is_err());
        assert!(super::ed25519_sign(der, MSG).is_err());
    }

    #[test]
    fn verification_algs() {
        assert!(!super::verification_algs().is_empty());
    }
}
