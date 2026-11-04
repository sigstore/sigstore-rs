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

//! Crypto backend implemented with `aws-lc-rs`.
//!
//! This module is compiled when `rustls-tls` is enabled and `native-tls` is not.

use aws_lc_rs::{
    digest::{self, SHA256, SHA384, SHA512},
    encoding::AsDer,
    rand::{SecureRandom, SystemRandom},
    rsa::KeySize,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1,
        ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1, ECDSA_P521_SHA512_ASN1_SIGNING,
        ED25519, EcdsaKeyPair, Ed25519KeyPair, KeyPair as AwsKeyPair, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_SHA256, RSA_PSS_2048_8192_SHA256, RSA_PSS_SHA256, RsaKeyPair, UnparsedPublicKey,
    },
};

use super::{EcdsaCurve, VerifyScheme};
use crate::errors::*;

pub(crate) fn fill_random(buf: &mut [u8]) {
    SystemRandom::new()
        .fill(buf)
        .expect("SystemRandom::fill failed");
}

pub(crate) fn verify_spki(scheme: VerifyScheme, spki: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_alg(scheme, spki, msg, sig).is_ok()
}

pub(crate) fn verify_spki_prehash(
    scheme: VerifyScheme,
    spki: &[u8],
    digest_bytes: &[u8],
    sig: &[u8],
) -> bool {
    let alg = match scheme_alg(scheme) {
        Some(alg) => alg,
        None => return false,
    };
    let digest_alg = match scheme {
        VerifyScheme::EcdsaP384Sha384 => &SHA384,
        VerifyScheme::EcdsaP521Sha512 => &SHA512,
        VerifyScheme::Ed25519 => return false,
        _ => &SHA256,
    };
    let Ok(imported) = digest::Digest::import_less_safe(digest_bytes, digest_alg) else {
        return false;
    };
    UnparsedPublicKey::new(alg, spki)
        .verify_digest(&imported, sig)
        .is_ok()
}

pub(crate) fn verify_p256_point(point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(msg, sig)
        .is_ok()
}

pub(crate) fn ecdsa_generate(curve: EcdsaCurve) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let rng = SystemRandom::new();
    let alg = ecdsa_signing_alg(curve);
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let spki = ecdsa_spki_from_pkcs8(pkcs8.as_ref())?;
    Ok((zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()), spki))
}

pub(crate) fn ecdsa_spki_from_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    let curve = ecdsa_curve_from_pkcs8(der)?;
    let kp = EcdsaKeyPair::from_pkcs8(ecdsa_signing_alg(curve), der)
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    kp.public_key()
        .as_der()
        .map(|spki| spki.as_ref().to_vec())
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))
}

/// ECDSA private key imported from PKCS#8.
///
/// Construction parses the key and runs the `aws-lc-rs` key check once.
/// [`Self::sign`] reuses that key.
pub(crate) struct EcdsaSigningKey {
    key: EcdsaKeyPair,
}

impl EcdsaSigningKey {
    /// Import and validate a PKCS#8 ECDSA private key for `curve`.
    pub(crate) fn from_pkcs8(curve: EcdsaCurve, pkcs8: &[u8]) -> Result<Self> {
        let key = EcdsaKeyPair::from_pkcs8(ecdsa_signing_alg(curve), pkcs8)
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
        Ok(Self { key })
    }

    /// Sign `msg` and return an ASN.1 DER signature.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.key
            .sign(&SystemRandom::new(), msg)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|e| SigstoreError::SigningError(e.to_string()))
    }
}

pub(crate) fn rsa_generate(bits: usize) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let kp = RsaKeyPair::generate(rsa_key_size(bits)?)
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let pkcs8 = kp
        .as_der()
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let spki = kp
        .public_key()
        .as_der()
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    Ok((
        zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()),
        spki.as_ref().to_vec(),
    ))
}

pub(crate) fn rsa_from_pkcs8(der: &[u8]) -> Result<(Vec<u8>, usize)> {
    let kp =
        RsaKeyPair::from_pkcs8(der).map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let spki = kp
        .public_key()
        .as_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    Ok((spki.as_ref().to_vec(), kp.public_modulus_len()))
}

pub(crate) fn rsa_from_pkcs1(der: &[u8]) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>, usize)> {
    let kp =
        RsaKeyPair::from_der(der).map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let pkcs8 = kp
        .as_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let spki = kp
        .public_key()
        .as_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    Ok((
        zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()),
        spki.as_ref().to_vec(),
        kp.public_modulus_len(),
    ))
}

pub(crate) fn rsa_sign(pkcs8: &[u8], pss: bool, msg: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let kp =
        RsaKeyPair::from_pkcs8(pkcs8).map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    let alg = if pss {
        &RSA_PSS_SHA256
    } else {
        &RSA_PKCS1_SHA256
    };
    let mut sig = vec![0u8; kp.public_modulus_len()];
    kp.sign(alg, &rng, msg, &mut sig)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    Ok(sig)
}

pub(crate) fn ed25519_generate() -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let spki = ed25519_spki_from_pkcs8(pkcs8.as_ref())?;
    Ok((zeroize::Zeroizing::new(pkcs8.as_ref().to_vec()), spki))
}

pub(crate) fn ed25519_spki_from_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    let kp = Ed25519KeyPair::from_pkcs8(der)
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    kp.public_key()
        .as_der()
        .map(|spki| spki.as_ref().to_vec())
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))
}

pub(crate) fn ed25519_sign(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    Ok(kp.sign(msg).as_ref().to_vec())
}

pub(crate) fn verification_algs()
-> &'static [&'static dyn pki_types::SignatureVerificationAlgorithm] {
    webpki::ALL_VERIFICATION_ALGS
}

fn verify_alg(
    scheme: VerifyScheme,
    spki: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> std::result::Result<(), aws_lc_rs::error::Unspecified> {
    let Some(alg) = scheme_alg(scheme) else {
        return Err(aws_lc_rs::error::Unspecified);
    };
    UnparsedPublicKey::new(alg, spki).verify(msg, sig)
}

fn scheme_alg(
    scheme: VerifyScheme,
) -> Option<&'static dyn aws_lc_rs::signature::VerificationAlgorithm> {
    Some(match scheme {
        VerifyScheme::RsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
        VerifyScheme::RsaPkcs1Sha256 => &RSA_PKCS1_2048_8192_SHA256,
        VerifyScheme::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
        VerifyScheme::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1,
        VerifyScheme::EcdsaP521Sha512 => &ECDSA_P521_SHA512_ASN1,
        VerifyScheme::Ed25519 => &ED25519,
    })
}

fn ecdsa_signing_alg(curve: EcdsaCurve) -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
    match curve {
        EcdsaCurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaCurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        EcdsaCurve::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
    }
}

fn ecdsa_curve_from_pkcs8(der: &[u8]) -> Result<EcdsaCurve> {
    use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
    use pkcs8::PrivateKeyInfo;
    use x509_cert::der::Decode;

    let pki =
        PrivateKeyInfo::from_der(der).map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let params = pki
        .algorithm
        .parameters
        .ok_or_else(|| SigstoreError::KeyParsingError("missing algorithm parameters".into()))?;
    let oid = params
        .decode_as::<const_oid::ObjectIdentifier>()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    match oid {
        SECP_256_R_1 => Ok(EcdsaCurve::P256),
        SECP_384_R_1 => Ok(EcdsaCurve::P384),
        SECP_521_R_1 => Ok(EcdsaCurve::P521),
        other => Err(SigstoreError::KeyParsingError(format!(
            "unsupported curve OID: {other}"
        ))),
    }
}

fn rsa_key_size(bits: usize) -> Result<KeySize> {
    match bits {
        2048 => Ok(KeySize::Rsa2048),
        3072 => Ok(KeySize::Rsa3072),
        4096 => Ok(KeySize::Rsa4096),
        other => Err(SigstoreError::InvalidKeyFormat {
            error: format!("Unsupported RSA key size {other}; must be 2048, 3072, or 4096"),
        }),
    }
}
