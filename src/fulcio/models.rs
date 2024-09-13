// Copyright 2023 The Sigstore Authors.
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

//! Models for interfacing with Fulcio.
//!
//! <https://github.com/sigstore/fulcio/blob/9da27be4fb64b85c907ab9ddd8a5d3cbd38041d4/fulcio.proto>

use pem::Pem;
use pkcs8::der::EncodePem;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::Deserialize_repr;
use serde_with::{
    base64::{Base64, Standard},
    formats::Padded,
    serde_as, DeserializeAs, SerializeAs,
};
use x509_cert::Certificate;

fn serialize_x509_csr<S>(
    input: &x509_cert::request::CertReq,
    ser: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = input
        .to_pem(pkcs8::LineEnding::LF)
        .map_err(serde::ser::Error::custom)?;

    Base64::<Standard, Padded>::serialize_as(&encoded, ser)
}

fn deserialize_inner_detached_sct<'de, D>(de: D) -> std::result::Result<InnerDetachedSCT, D::Error>
where
    D: Deserializer<'de>,
{
    let buf: Vec<u8> = Base64::<Standard, Padded>::deserialize_as(de)?;
    serde_json::from_slice(&buf).map_err(serde::de::Error::custom)
}

fn deserialize_inner_detached_sct_signature<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let buf: Vec<u8> = Base64::<Standard, Padded>::deserialize_as(de)?;

    // The first two bytes indicate the signature and hash algorithms so let's skip those.
    // The next two bytes indicate the size of the signature.
    let signature_size = u16::from_be_bytes(buf[2..4].try_into().expect("unexpected length"));

    // This should be equal to the length of the remainder of the signature buffer.
    let signature = buf[4..].to_vec();
    if signature_size as usize != signature.len() {
        return Err(serde::de::Error::custom("signature size mismatch"));
    }
    Ok(signature)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningCertificateRequest {
    #[serde(serialize_with = "serialize_x509_csr")]
    pub certificate_signing_request: x509_cert::request::CertReq,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SigningCertificate {
    SignedCertificateDetachedSct(SigningCertificateDetachedSCT),
    SignedCertificateEmbeddedSct(SigningCertificateEmbeddedSCT),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateDetachedSCT {
    pub chain: CertificateChain,
    #[serde(deserialize_with = "deserialize_inner_detached_sct")]
    pub signed_certificate_timestamp: InnerDetachedSCT,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateEmbeddedSCT {
    pub chain: CertificateChain,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CertificateChain {
    pub certificates: Vec<Pem>,
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct InnerDetachedSCT {
    pub sct_version: SCTVersion,
    #[serde_as(as = "Base64")]
    pub id: [u8; 32],
    pub timestamp: u64,
    #[serde(deserialize_with = "deserialize_inner_detached_sct_signature")]
    pub signature: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub extensions: Vec<u8>,
}

#[derive(Deserialize_repr, PartialEq, Debug, Clone)]
#[repr(u8)]
pub enum SCTVersion {
    V1 = 0,
}

pub struct CertificateResponse {
    pub cert: Certificate,
    pub chain: Vec<Certificate>,
    pub detached_sct: Option<SigningCertificateDetachedSCT>,
}
