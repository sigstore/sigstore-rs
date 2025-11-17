use digest::generic_array::GenericArray;
use ecdsa::{SigningKey, VerifyingKey};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use signature::{SignerMut, Verifier};

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PredicateType {
    #[serde(rename = "https://slsa.dev/provenance/v0.2")]
    SLSAv0_2,
    #[serde(rename = "https://slsa.dev/provenance/v1")]
    SLSAv1_0,
}

pub type SourceDigest = String;
pub type DigestSetSource = HashMap<String, String>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuilderV0_1 {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSource {
    pub uri: Option<String>,
    pub digest: Option<DigestSetSource>,
    pub entry_point: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invocation {
    pub config_source: Option<ConfigSource>,
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    pub environment: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Completeness {
    pub parameters: Option<bool>,
    pub environment: Option<bool>,
    pub materials: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Material {
    pub uri: Option<String>,
    pub digest: Option<DigestSetSource>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub build_invocation_id: Option<String>,
    pub build_started_on: Option<String>,
    pub build_finished_on: Option<String>,
    pub completeness: Option<Completeness>,
    pub reproducible: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SLSAPredicateV0_2 {
    pub builder: BuilderV0_1,
    pub build_type: String,
    pub invocation: Option<Invocation>,
    pub metadata: Option<Metadata>,
    pub build_config: Option<HashMap<String, serde_json::Value>>,
    pub materials: Option<Vec<Material>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    pub name: Option<String>,
    pub uri: Option<String>,
    pub digest: Option<DigestSetSource>,
    pub content: Option<Vec<u8>>,
    pub download_location: Option<String>,
    pub media_type: Option<String>,
    pub annotations: Option<HashMap<String, serde_json::Value>>,
}

impl ResourceDescriptor {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.uri.is_none() && self.digest.is_none() && self.content.is_none() {
            return Err(
                "A ResourceDescriptor MUST specify one of uri, digest or content at a minimum",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuilderV1_0 {
    pub id: String,
    pub builder_dependencies: Option<Vec<ResourceDescriptor>>,
    pub version: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMetadata {
    pub invocation_id: Option<String>,
    pub started_on: Option<String>,
    pub finished_on: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    pub builder: BuilderV1_0,
    pub metadata: Option<BuildMetadata>,
    pub byproducts: Option<Vec<ResourceDescriptor>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    pub build_type: String,
    pub external_parameters: HashMap<String, serde_json::Value>,
    pub internal_parameters: Option<HashMap<String, serde_json::Value>>,
    pub resolved_dependencies: Option<Vec<ResourceDescriptor>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SLSAPredicateV1_0 {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Digest {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

pub type DigestSet = HashMap<Digest, String>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Subject {
    pub name: Option<String>,
    pub digest: DigestSet,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed in-toto statement")]
    MalformedStatement,
    #[error("unexpected digest algorithm: {0}")]
    UnexpectedDigestAlgorithm(String),
    #[error("invalid statement: {0}")]
    InvalidStatement(String),
    #[error("DSSE: exactly 1 signature allowed, got {0}")]
    InvalidSignatureCount(usize),
    #[error("DSSE: invalid signature")]
    InvalidSignature,
}

pub struct StatementBuilder {
    subjects: Vec<Subject>,
    predicate_type: Option<String>,
    predicate: Option<serde_json::Value>,
}

impl StatementBuilder {
    pub fn new() -> Self {
        Self {
            subjects: Vec::new(),
            predicate_type: None,
            predicate: None,
        }
    }

    pub fn subjects(mut self, subjects: Vec<Subject>) -> Self {
        self.subjects = subjects;
        self
    }

    pub fn predicate_type(mut self, predicate_type: String) -> Self {
        self.predicate_type = Some(predicate_type);
        self
    }

    pub fn predicate(mut self, predicate: serde_json::Value) -> Self {
        self.predicate = Some(predicate);
        self
    }

    pub fn build(self) -> Result<Statement, Error> {
        if self.subjects.is_empty() || self.predicate_type.is_none() {
            return Err(Error::InvalidStatement(
                "missing required fields".to_string(),
            ));
        }

        Ok(Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: self.subjects,
            predicate_type: self.predicate_type.unwrap(),
            predicate: self.predicate,
        })
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Envelope {
    #[serde_as(as = "Base64")]
    payload: Vec<u8>,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<Signature>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Signature {
    #[serde_as(as = "Base64")]
    sig: Vec<u8>,
}

impl Envelope {
    const TYPE: &'static str = "application/vnd.in-toto+json";

    pub fn from_json(contents: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(contents)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

fn pae(type_: &str, body: &[u8]) -> Vec<u8> {
    let mut pae = format!("DSSEv1 {} {} ", type_.len(), type_).into_bytes();
    pae.extend_from_slice(format!("{} ", body.len()).as_bytes());
    pae.extend_from_slice(body);
    pae
}

impl Statement {
    fn pae(&self) -> Vec<u8> {
        pae(
            "application/vnd.in-toto+json",
            &serde_json::to_vec(self).unwrap(),
        )
    }
}

pub fn sign(key: &SigningKey<NistP256>, stmt: &Statement) -> Result<Envelope, Error> {
    let pae = stmt.pae();
    let mut key = key.clone();
    let signature: ecdsa::Signature<NistP256> = key.try_sign(&pae).expect("failed to sign");

    Ok(Envelope {
        payload: serde_json::to_vec(stmt).unwrap(),
        payload_type: Envelope::TYPE.to_string(),
        signatures: vec![Signature {
            sig: signature.to_vec(),
        }],
    })
}

/// Verify the signature of an envelope and return the payload if the signature is valid.
pub fn verify(key: &VerifyingKey<NistP256>, evp: &Envelope) -> Result<Vec<u8>, Error> {
    if evp.signatures.len() != 1 {
        return Err(Error::InvalidSignatureCount(evp.signatures.len()));
    }

    let pae = pae(&evp.payload_type, &evp.payload);
    let sig = GenericArray::clone_from_slice(&evp.signatures[0].sig);
    let sig = ecdsa::Signature::from_bytes(&sig).map_err(|_| Error::InvalidSignature)?;

    key.verify(&pae, &sig)
        .map_err(|_| Error::InvalidSignature)?;

    Ok(evp.payload.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as base64, Engine as _};

    #[test]
    fn test_roundtrip() {
        let raw = serde_json::json!({
            "payload": base64.encode("foo"),
            "payloadType": "application/vnd.dsse.envelope.v1+json",
            "signatures": [
                {"sig": base64.encode("lol")},
                {"sig": base64.encode("lmao")},
            ],
        })
        .to_string();

        let evp = Envelope::from_json(raw.as_bytes()).unwrap();

        assert_eq!(evp.payload, b"foo");
        assert_eq!(evp.payload_type, "application/vnd.dsse.envelope.v1+json");
        assert_eq!(
            evp.signatures,
            vec![
                Signature {
                    sig: b"lol".to_vec()
                },
                Signature {
                    sig: b"lmao".to_vec()
                },
            ]
        );

        let serialized = evp.to_json().unwrap();
        assert_eq!(serialized, raw);
        assert_eq!(Envelope::from_json(serialized.as_bytes()).unwrap(), evp);
    }

    #[test]
    fn test_sign_verify() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let vkey = VerifyingKey::from(&key);
        let digest_set = DigestSet::from_iter(vec![(Digest::Sha256, "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b".to_string())]);
        let stmt = Statement {
            type_: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("foo".to_string()),
                digest: digest_set,
            }],
            predicate_type: "https://slsa.dev/provenance/v0.2".to_string(),
            predicate: None,
        };

        let evp = sign(&key, &stmt).unwrap();
        let payload = verify(&vkey, &evp).unwrap();

        assert_eq!(payload, serde_json::to_vec(&stmt).unwrap());
    }
}
