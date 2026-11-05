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

//! Crypto backend implemented with OpenSSL.
//!
//! This module is compiled when `native-tls` is enabled. If `rustls-tls` is
//! also enabled, this implementation is still the one that runs.

use openssl::bn::{BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{HasPrivate, Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use zeroize::Zeroizing;

use super::{EcdsaCurve, VerifyScheme};
use crate::errors::*;

pub(crate) fn fill_random(buf: &mut [u8]) {
    rand_bytes(buf).expect("openssl::rand::rand_bytes failed");
}

pub(crate) fn verify_spki(scheme: VerifyScheme, spki: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pkey) = PKey::public_key_from_der(spki) else {
        return false;
    };
    key_matches_scheme(scheme, &pkey) && verify_message(scheme, &pkey, msg, sig)
}

pub(crate) fn verify_spki_prehash(
    scheme: VerifyScheme,
    spki: &[u8],
    digest: &[u8],
    sig: &[u8],
) -> bool {
    let Ok(pkey) = PKey::public_key_from_der(spki) else {
        return false;
    };
    key_matches_scheme(scheme, &pkey) && verify_digest(scheme, &pkey, digest, sig)
}

/// Public exponent accepted by `aws-lc-rs`: odd, greater than 1, and at most
/// 33 bits. A longer exponent makes verification expensive.
fn acceptable_rsa_public_exponent(exponent: &BigNumRef) -> bool {
    exponent.is_odd() && !exponent.is_negative() && (2..=33).contains(&exponent.num_bits())
}

fn key_matches_scheme(scheme: VerifyScheme, pkey: &PKey<Public>) -> bool {
    match scheme {
        VerifyScheme::RsaPssSha256 | VerifyScheme::RsaPkcs1Sha256 => {
            pkey.id() == Id::RSA
                && (2048..=8192).contains(&pkey.bits())
                && pkey
                    .rsa()
                    .is_ok_and(|key| acceptable_rsa_public_exponent(key.e()))
        }
        VerifyScheme::Ed25519 => pkey.id() == Id::ED25519,
        other => {
            let expected_curve = match other {
                VerifyScheme::EcdsaP256Sha256 => Nid::X9_62_PRIME256V1,
                VerifyScheme::EcdsaP384Sha384 => Nid::SECP384R1,
                VerifyScheme::EcdsaP521Sha512 => Nid::SECP521R1,
                _ => return false,
            };
            pkey.ec_key().ok().and_then(|key| key.group().curve_name()) == Some(expected_curve)
        }
    }
}

pub(crate) fn verify_p256_point(point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pkey) = p256_from_point(point) else {
        return false;
    };
    verify_message(VerifyScheme::EcdsaP256Sha256, &pkey, msg, sig)
}

pub(crate) fn ecdsa_generate(curve: EcdsaCurve) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(curve_nid(curve))
        .map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let key =
        EcKey::generate(&group).map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let pkey =
        PKey::from_ec_key(key).map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    material_from_private(&pkey, SigstoreError::KeyGenerationError)
}

pub(crate) fn ecdsa_spki_from_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pkcs8(der)
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    pkey.ec_key()
        .and_then(|key| key.check_key())
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    pkey.public_key_to_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))
}

/// ECDSA private key imported from PKCS#8.
///
/// Construction parses the key and runs `EC_KEY_check_key` once. [`Self::sign`]
/// reuses that key.
pub(crate) struct EcdsaSigningKey {
    curve: EcdsaCurve,
    key: PKey<Private>,
}

impl EcdsaSigningKey {
    /// Import and validate a PKCS#8 ECDSA private key for `curve`.
    pub(crate) fn from_pkcs8(curve: EcdsaCurve, pkcs8: &[u8]) -> Result<Self> {
        let key = PKey::private_key_from_pkcs8(pkcs8)
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
        let ec_key = key
            .ec_key()
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
        if ec_key.group().curve_name() != Some(curve_nid(curve)) {
            return Err(SigstoreError::KeyParsingError(
                "elliptic curve does not match PKCS#8 key".into(),
            ));
        }
        ec_key
            .check_key()
            .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
        Ok(Self { curve, key })
    }

    /// Sign `msg` and return an ASN.1 DER signature.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut signer = Signer::new(curve_digest(self.curve), &self.key)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        signer
            .update(msg)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        signer
            .sign_to_vec()
            .map_err(|e| SigstoreError::SigningError(e.to_string()))
    }
}

pub(crate) fn rsa_generate(bits: usize) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    if !matches!(bits, 2048 | 3072 | 4096) {
        return Err(SigstoreError::InvalidKeyFormat {
            error: format!("Unsupported RSA key size {bits}; must be 2048, 3072, or 4096"),
        });
    }
    let rsa =
        Rsa::generate(bits as u32).map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    material_from_private(&pkey, SigstoreError::KeyGenerationError)
}

pub(crate) fn rsa_from_pkcs8(der: &[u8]) -> Result<(Vec<u8>, usize)> {
    let pkey = PKey::private_key_from_pkcs8(der)
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let rsa = pkey
        .rsa()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    if !rsa
        .check_key()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?
    {
        return Err(SigstoreError::KeyParsingError("invalid RSA key".into()));
    }
    let spki = pkey
        .public_key_to_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    Ok((spki, rsa.size() as usize))
}

pub(crate) fn rsa_from_pkcs1(der: &[u8]) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>, usize)> {
    let rsa = Rsa::private_key_from_der(der)
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| SigstoreError::KeyParsingError(e.to_string()))?;
    let (pkcs8, spki) = material_from_private(&pkey, SigstoreError::KeyParsingError)?;
    Ok((pkcs8, spki, pkey.size()))
}

pub(crate) fn rsa_sign(pkcs8: &[u8], pss: bool, msg: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pkcs8(pkcs8)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    let md = MessageDigest::sha256();
    let mut signer =
        Signer::new(md, &pkey).map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    if pss {
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
        signer
            .set_rsa_mgf1_md(md)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    } else {
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    }
    signer
        .update(msg)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    signer
        .sign_to_vec()
        .map_err(|e| SigstoreError::SigningError(e.to_string()))
}

pub(crate) fn ed25519_generate() -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let pkey =
        PKey::generate_ed25519().map_err(|e| SigstoreError::KeyGenerationError(e.to_string()))?;
    material_from_private(&pkey, SigstoreError::KeyGenerationError)
}

pub(crate) fn ed25519_spki_from_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    let pkey = ed25519_pkey(der).map_err(SigstoreError::KeyParsingError)?;
    pkey.public_key_to_der()
        .map_err(|e| SigstoreError::KeyParsingError(e.to_string()))
}

pub(crate) fn ed25519_sign(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let pkey = ed25519_pkey(pkcs8).map_err(SigstoreError::SigningError)?;
    let mut signer = Signer::new_without_digest(&pkey)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))?;
    signer
        .sign_oneshot_to_vec(msg)
        .map_err(|e| SigstoreError::SigningError(e.to_string()))
}

pub(crate) fn verification_algs() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    CERT_ALGS
}

/// OpenSSL 3.0 rejects Ed25519 PKCS#8 documents that carry the optional
/// public key (RFC 8410 `OneAsymmetricKey` version 1). Those keys are what
/// `aws-lc-rs` writes, so fall back to the raw 32-byte seed.
fn ed25519_pkey(der: &[u8]) -> std::result::Result<PKey<openssl::pkey::Private>, String> {
    match PKey::private_key_from_pkcs8(der) {
        Ok(pkey) if pkey.id() == Id::ED25519 => Ok(pkey),
        Ok(_) => Err("expected an Ed25519 private key".into()),
        Err(err) => match ed25519_seed(der) {
            Some(seed) => {
                use x509_cert::der::Decode;
                let pkey = PKey::private_key_from_raw_bytes(&*seed, Id::ED25519)
                    .map_err(|e| e.to_string())?;
                let pki = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|e| e.to_string())?;
                if let Some(expected) = pki.public_key {
                    let expected = expected
                        .as_bytes()
                        .ok_or("Ed25519 public key is not octet-aligned")?;
                    let actual = pkey.raw_public_key().map_err(|e| e.to_string())?;
                    if actual.as_slice() != expected {
                        return Err("Ed25519 public key does not match private seed".into());
                    }
                }
                Ok(pkey)
            }
            None => Err(err.to_string()),
        },
    }
}

fn ed25519_seed(der: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    use const_oid::db::rfc8410::ID_ED_25519;
    use pkcs8::PrivateKeyInfoRef;
    use x509_cert::der::Decode;

    let pki = PrivateKeyInfoRef::from_der(der).ok()?;
    if pki.algorithm.oid != ID_ED_25519 {
        return None;
    }
    let bytes = pki.private_key.as_bytes();
    let seed = if bytes.len() == 32 {
        bytes
    } else if bytes.len() == 34 && bytes[0] == 0x04 && bytes[1] == 0x20 {
        &bytes[2..]
    } else {
        return None;
    };
    seed.try_into().ok().map(Zeroizing::new)
}

fn material_from_private<T: HasPrivate>(
    pkey: &PKey<T>,
    err: fn(String) -> SigstoreError,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
    let pkcs8 = pkey
        .private_key_to_pkcs8()
        .map_err(|e| err(e.to_string()))?;
    let spki = pkey.public_key_to_der().map_err(|e| err(e.to_string()))?;
    Ok((zeroize::Zeroizing::new(pkcs8), spki))
}

fn curve_nid(curve: EcdsaCurve) -> Nid {
    match curve {
        EcdsaCurve::P256 => Nid::X9_62_PRIME256V1,
        EcdsaCurve::P384 => Nid::SECP384R1,
        EcdsaCurve::P521 => Nid::SECP521R1,
    }
}

fn curve_digest(curve: EcdsaCurve) -> MessageDigest {
    match curve {
        EcdsaCurve::P256 => MessageDigest::sha256(),
        EcdsaCurve::P384 => MessageDigest::sha384(),
        EcdsaCurve::P521 => MessageDigest::sha512(),
    }
}

fn verify_message(scheme: VerifyScheme, pkey: &PKey<Public>, msg: &[u8], sig: &[u8]) -> bool {
    let result = match scheme {
        VerifyScheme::Ed25519 => Verifier::new_without_digest(pkey)
            .and_then(|mut verifier| verifier.verify_oneshot(sig, msg)),
        VerifyScheme::RsaPssSha256 | VerifyScheme::RsaPkcs1Sha256 => {
            let pss = matches!(scheme, VerifyScheme::RsaPssSha256);
            rsa_verifier(pkey, pss).and_then(|mut verifier| {
                verifier.update(msg)?;
                verifier.verify(sig)
            })
        }
        other => {
            let Some(digest) = scheme_digest(other) else {
                return false;
            };
            Verifier::new(digest, pkey).and_then(|mut verifier| {
                verifier.update(msg)?;
                verifier.verify(sig)
            })
        }
    };
    matches!(result, Ok(true))
}

fn rsa_verifier<'a>(
    pkey: &'a PKey<Public>,
    pss: bool,
) -> std::result::Result<Verifier<'a>, openssl::error::ErrorStack> {
    let md = MessageDigest::sha256();
    let mut verifier = Verifier::new(md, pkey)?;
    if pss {
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        verifier.set_rsa_mgf1_md(md)?;
    } else {
        verifier.set_rsa_padding(Padding::PKCS1)?;
    }
    Ok(verifier)
}

fn scheme_digest(scheme: VerifyScheme) -> Option<MessageDigest> {
    Some(match scheme {
        VerifyScheme::RsaPssSha256
        | VerifyScheme::RsaPkcs1Sha256
        | VerifyScheme::EcdsaP256Sha256 => MessageDigest::sha256(),
        VerifyScheme::EcdsaP384Sha384 => MessageDigest::sha384(),
        VerifyScheme::EcdsaP521Sha512 => MessageDigest::sha512(),
        VerifyScheme::Ed25519 => return None,
    })
}

fn verify_digest(scheme: VerifyScheme, pkey: &PKey<Public>, digest: &[u8], sig: &[u8]) -> bool {
    let Some(md) = scheme_md(scheme) else {
        return false;
    };
    let Ok(mut ctx) = PkeyCtx::new(pkey) else {
        return false;
    };
    if ctx.verify_init().is_err() || ctx.set_signature_md(md).is_err() {
        return false;
    }
    let padding_ok = match scheme {
        VerifyScheme::RsaPssSha256 => {
            ctx.set_rsa_padding(Padding::PKCS1_PSS).is_ok()
                && ctx
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .is_ok()
                && ctx.set_rsa_mgf1_md(md).is_ok()
        }
        VerifyScheme::RsaPkcs1Sha256 => ctx.set_rsa_padding(Padding::PKCS1).is_ok(),
        _ => true,
    };
    padding_ok && matches!(ctx.verify(digest, sig), Ok(true))
}

fn scheme_md(scheme: VerifyScheme) -> Option<&'static openssl::md::MdRef> {
    Some(match scheme {
        VerifyScheme::RsaPssSha256
        | VerifyScheme::RsaPkcs1Sha256
        | VerifyScheme::EcdsaP256Sha256 => Md::sha256(),
        VerifyScheme::EcdsaP384Sha384 => Md::sha384(),
        VerifyScheme::EcdsaP521Sha512 => Md::sha512(),
        VerifyScheme::Ed25519 => return None,
    })
}

fn p256_from_point(point: &[u8]) -> std::result::Result<PKey<Public>, openssl::error::ErrorStack> {
    ec_from_point(Nid::X9_62_PRIME256V1, point)
}

fn ec_from_point(
    nid: Nid,
    point: &[u8],
) -> std::result::Result<PKey<Public>, openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(nid)?;
    let mut bn_ctx = BigNumContext::new()?;
    let ec_point = EcPoint::from_bytes(&group, point, &mut bn_ctx)?;
    let ec_key = EcKey::from_public_key(&group, &ec_point)?;
    PKey::from_ec_key(ec_key)
}

#[derive(Debug)]
struct OpenSslAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    kind: CertAlg,
}

#[derive(Debug, Clone, Copy)]
enum CertAlg {
    EcdsaP256Sha256,
    EcdsaP256Sha384,
    EcdsaP256Sha512,
    EcdsaP384Sha256,
    EcdsaP384Sha384,
    EcdsaP384Sha512,
    EcdsaP521Sha256,
    EcdsaP521Sha384,
    EcdsaP521Sha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPkcs1Sha384Min3072,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    Ed25519,
}

impl SignatureVerificationAlgorithm for OpenSslAlgorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), InvalidSignature> {
        let pkey = cert_public_key(self.kind, public_key).map_err(|_| InvalidSignature)?;
        if cert_verify(&pkey, self.kind, message, signature) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

fn cert_public_key(
    kind: CertAlg,
    public_key: &[u8],
) -> std::result::Result<PKey<Public>, openssl::error::ErrorStack> {
    match kind {
        CertAlg::EcdsaP256Sha256 | CertAlg::EcdsaP256Sha384 | CertAlg::EcdsaP256Sha512 => {
            ec_point_key(Nid::X9_62_PRIME256V1, public_key)
        }
        CertAlg::EcdsaP384Sha256 | CertAlg::EcdsaP384Sha384 | CertAlg::EcdsaP384Sha512 => {
            ec_point_key(Nid::SECP384R1, public_key)
        }
        CertAlg::EcdsaP521Sha256 | CertAlg::EcdsaP521Sha384 | CertAlg::EcdsaP521Sha512 => {
            ec_point_key(Nid::SECP521R1, public_key)
        }
        CertAlg::RsaPkcs1Sha256
        | CertAlg::RsaPkcs1Sha384
        | CertAlg::RsaPkcs1Sha512
        | CertAlg::RsaPssSha256
        | CertAlg::RsaPssSha384
        | CertAlg::RsaPssSha512 => rsa_public_key(public_key, 2048),
        CertAlg::RsaPkcs1Sha384Min3072 => rsa_public_key(public_key, 3072),
        CertAlg::Ed25519 => PKey::public_key_from_raw_bytes(public_key, Id::ED25519),
    }
}

fn ec_point_key(
    nid: Nid,
    public_key: &[u8],
) -> std::result::Result<PKey<Public>, openssl::error::ErrorStack> {
    match public_key.first() {
        Some(0x04) | Some(0x02) | Some(0x03) => {}
        _ => return Err(openssl::error::ErrorStack::get()),
    }
    ec_from_point(nid, public_key)
}

fn rsa_public_key(
    public_key: &[u8],
    min_bits: u32,
) -> std::result::Result<PKey<Public>, openssl::error::ErrorStack> {
    let rsa = Rsa::public_key_from_der_pkcs1(public_key)?;
    if !acceptable_rsa_public_exponent(rsa.e()) {
        return Err(openssl::error::ErrorStack::get());
    }
    let pkey = PKey::from_rsa(rsa)?;
    if pkey.bits() < min_bits || pkey.bits() > 8192 {
        return Err(openssl::error::ErrorStack::get());
    }
    Ok(pkey)
}

fn cert_verify(pkey: &PKey<Public>, kind: CertAlg, message: &[u8], signature: &[u8]) -> bool {
    let result = match kind {
        CertAlg::Ed25519 => Verifier::new_without_digest(pkey)
            .and_then(|mut verifier| verifier.verify_oneshot(signature, message)),
        CertAlg::RsaPssSha256 | CertAlg::RsaPssSha384 | CertAlg::RsaPssSha512 => {
            let Some(digest) = cert_digest(kind) else {
                return false;
            };
            Verifier::new(digest, pkey).and_then(|mut verifier| {
                verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
                verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                verifier.set_rsa_mgf1_md(digest)?;
                verifier.update(message)?;
                verifier.verify(signature)
            })
        }
        other => {
            let Some(digest) = cert_digest(other) else {
                return false;
            };
            Verifier::new(digest, pkey).and_then(|mut verifier| {
                if matches!(
                    other,
                    CertAlg::RsaPkcs1Sha256
                        | CertAlg::RsaPkcs1Sha384
                        | CertAlg::RsaPkcs1Sha512
                        | CertAlg::RsaPkcs1Sha384Min3072
                ) {
                    verifier.set_rsa_padding(Padding::PKCS1)?;
                }
                verifier.update(message)?;
                verifier.verify(signature)
            })
        }
    };
    matches!(result, Ok(true))
}

/// Digest used to pre-hash the message before verification. Returns `None`
/// for algorithms that verify the raw message instead of a digest
fn cert_digest(kind: CertAlg) -> Option<MessageDigest> {
    Some(match kind {
        CertAlg::EcdsaP256Sha256
        | CertAlg::EcdsaP384Sha256
        | CertAlg::EcdsaP521Sha256
        | CertAlg::RsaPkcs1Sha256
        | CertAlg::RsaPssSha256 => MessageDigest::sha256(),
        CertAlg::EcdsaP256Sha384
        | CertAlg::EcdsaP384Sha384
        | CertAlg::EcdsaP521Sha384
        | CertAlg::RsaPkcs1Sha384
        | CertAlg::RsaPkcs1Sha384Min3072
        | CertAlg::RsaPssSha384 => MessageDigest::sha384(),
        CertAlg::EcdsaP256Sha512
        | CertAlg::EcdsaP384Sha512
        | CertAlg::EcdsaP521Sha512
        | CertAlg::RsaPkcs1Sha512
        | CertAlg::RsaPssSha512 => MessageDigest::sha512(),
        CertAlg::Ed25519 => return None,
    })
}

const RSA_PKCS1_SHA256_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_PKCS1_SHA384_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_PKCS1_SHA512_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

macro_rules! alg {
    ($name:ident, $pk:expr, $sig:expr, $kind:expr) => {
        static $name: OpenSslAlgorithm = OpenSslAlgorithm {
            public_key_alg_id: $pk,
            signature_alg_id: $sig,
            kind: $kind,
        };
    };
}

alg!(
    ECDSA_P256_SHA256,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA256,
    CertAlg::EcdsaP256Sha256
);
alg!(
    ECDSA_P256_SHA384,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA384,
    CertAlg::EcdsaP256Sha384
);
alg!(
    ECDSA_P256_SHA512,
    alg_id::ECDSA_P256,
    alg_id::ECDSA_SHA512,
    CertAlg::EcdsaP256Sha512
);
alg!(
    ECDSA_P384_SHA256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA256,
    CertAlg::EcdsaP384Sha256
);
alg!(
    ECDSA_P384_SHA384,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA384,
    CertAlg::EcdsaP384Sha384
);
alg!(
    ECDSA_P384_SHA512,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_SHA512,
    CertAlg::EcdsaP384Sha512
);
alg!(
    ECDSA_P521_SHA256,
    alg_id::ECDSA_P521,
    alg_id::ECDSA_SHA256,
    CertAlg::EcdsaP521Sha256
);
alg!(
    ECDSA_P521_SHA384,
    alg_id::ECDSA_P521,
    alg_id::ECDSA_SHA384,
    CertAlg::EcdsaP521Sha384
);
alg!(
    ECDSA_P521_SHA512,
    alg_id::ECDSA_P521,
    alg_id::ECDSA_SHA512,
    CertAlg::EcdsaP521Sha512
);
alg!(
    RSA_PKCS1_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA256,
    CertAlg::RsaPkcs1Sha256
);
alg!(
    RSA_PKCS1_SHA384,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA384,
    CertAlg::RsaPkcs1Sha384
);
alg!(
    RSA_PKCS1_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA512,
    CertAlg::RsaPkcs1Sha512
);
alg!(
    RSA_PKCS1_SHA256_ABSENT_ALG,
    alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA256_ABSENT,
    CertAlg::RsaPkcs1Sha256
);
alg!(
    RSA_PKCS1_SHA384_ABSENT_ALG,
    alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA384_ABSENT,
    CertAlg::RsaPkcs1Sha384
);
alg!(
    RSA_PKCS1_SHA512_ABSENT_ALG,
    alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA512_ABSENT,
    CertAlg::RsaPkcs1Sha512
);
alg!(
    RSA_PKCS1_SHA384_MIN3072,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA384,
    CertAlg::RsaPkcs1Sha384Min3072
);
alg!(
    RSA_PSS_SHA256,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA256,
    CertAlg::RsaPssSha256
);
alg!(
    RSA_PSS_SHA384,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA384,
    CertAlg::RsaPssSha384
);
alg!(
    RSA_PSS_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA512,
    CertAlg::RsaPssSha512
);
alg!(
    ED25519_ALG,
    alg_id::ED25519,
    alg_id::ED25519,
    CertAlg::Ed25519
);

static CERT_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P256_SHA512,
    &ECDSA_P384_SHA256,
    &ECDSA_P384_SHA384,
    &ECDSA_P384_SHA512,
    &ECDSA_P521_SHA256,
    &ECDSA_P521_SHA384,
    &ECDSA_P521_SHA512,
    &ED25519_ALG,
    &RSA_PKCS1_SHA256,
    &RSA_PKCS1_SHA384,
    &RSA_PKCS1_SHA512,
    &RSA_PKCS1_SHA256_ABSENT_ALG,
    &RSA_PKCS1_SHA384_ABSENT_ALG,
    &RSA_PKCS1_SHA512_ABSENT_ALG,
    &RSA_PKCS1_SHA384_MIN3072,
    &RSA_PSS_SHA256,
    &RSA_PSS_SHA384,
    &RSA_PSS_SHA512,
];

#[cfg(test)]
mod tests {
    use openssl::bn::BigNum;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    use super::{VerifyScheme, key_matches_scheme, rsa_public_key};

    fn public_key(exponent: &[u8]) -> PKey<openssl::pkey::Public> {
        let modulus = BigNum::from_slice(&[0xff; 256]).unwrap();
        let exponent = BigNum::from_slice(exponent).unwrap();
        let rsa = Rsa::from_public_components(modulus, exponent).unwrap();
        PKey::from_rsa(rsa).unwrap()
    }

    fn exponent_accepted(exponent: &[u8]) -> bool {
        let key = public_key(exponent);
        let pkcs1 = key.rsa().unwrap().public_key_to_der_pkcs1().unwrap();
        key_matches_scheme(VerifyScheme::RsaPkcs1Sha256, &key)
            && key_matches_scheme(VerifyScheme::RsaPssSha256, &key)
            && rsa_public_key(&pkcs1, 2048).is_ok()
    }

    #[test]
    fn rsa_public_exponent_matches_aws_lc() {
        assert!(exponent_accepted(&[0x01, 0x00, 0x01]));
        assert!(exponent_accepted(&[0x03]));
        assert!(exponent_accepted(&[0x01, 0xff, 0xff, 0xff, 0xff]));
        assert!(!exponent_accepted(&[0x02]));
        assert!(!exponent_accepted(&[0x01]));
        assert!(!exponent_accepted(&[0x02, 0x00, 0x00, 0x00, 0x01]));
    }
}
