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

//! The errors that can be raised by sigstore-rs

use thiserror::Error;

/// Errors related to Merkle tree operations (RFC 6962)
#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Merkle tree verification: leaf index {index} >= tree size {tree_size}")]
    LeafIndexOutOfBounds { index: u64, tree_size: u64 },

    #[error("Merkle tree inclusion proof: invalid leaf hash size (got {got}, expected 32)")]
    InvalidLeafHashSize { got: usize },

    #[error("Merkle tree inclusion proof: invalid root hash size (got {got}, expected 32)")]
    InvalidRootHashSize { got: usize },

    #[error(
        "Merkle tree inclusion proof: invalid proof hash size at index {index} (got {got}, expected 32)"
    )]
    InvalidProofHashSize { index: usize, got: usize },

    #[error("Merkle tree inclusion proof: wrong proof size (got {got}, expected {expected})")]
    WrongInclusionProofSize { got: usize, expected: usize },

    #[error(
        "Merkle tree inclusion proof verification failed: computed root hash does not match expected root"
    )]
    InclusionProofVerificationFailed,

    #[error("Merkle consistency proof: new tree size {new_size} < old tree size {old_size}")]
    TreeCannotShrink { old_size: u64, new_size: u64 },

    #[error("Merkle consistency proof: roots must match when tree sizes are equal")]
    RootsMustMatchForEqualSizes,

    #[error("Merkle consistency proof: proof must be empty when tree sizes are equal")]
    ProofMustBeEmptyForEqualSizes,

    #[error(
        "Merkle consistency proof: empty tree (size 0) cannot be consistent with non-empty tree"
    )]
    EmptyTreeInconsistentWithNonEmpty,

    #[error("Merkle consistency proof: proof must be empty when old tree is empty")]
    ProofMustBeEmptyForEmptyTree,

    #[error("Merkle consistency proof: proof cannot be empty for non-trivial consistency")]
    ProofCannotBeEmpty,

    #[error("Merkle consistency proof: insufficient proof hashes")]
    InsufficientProofHashes,

    #[error("Merkle consistency proof: wrong proof size (got {got}, expected {expected})")]
    WrongConsistencyProofSize { got: usize, expected: usize },

    #[error("Merkle consistency proof: old root mismatch (expected {expected:x?}, got {got:x?})")]
    OldRootMismatch { expected: Vec<u8>, got: Vec<u8> },

    #[error("Merkle consistency proof: new root mismatch (expected {expected:x?}, got {got:x?})")]
    NewRootMismatch { expected: Vec<u8>, got: Vec<u8> },
}

#[cfg(feature = "cosign")]
use crate::cosign::{
    constraint::SignConstraintRefVec, verification_constraint::VerificationConstraintRefVec,
};

#[cfg(feature = "cosign")]
#[cfg_attr(docsrs, doc(cfg(feature = "cosign")))]
#[derive(Error, Debug)]
#[error("Several Signature Layers failed verification")]
pub struct SigstoreVerifyConstraintsError<'a> {
    pub unsatisfied_constraints: VerificationConstraintRefVec<'a>,
}

#[cfg(feature = "cosign")]
#[cfg_attr(docsrs, doc(cfg(feature = "cosign")))]
#[derive(Error, Debug)]
#[error("Several Constraints failed to apply on the SignatureLayer")]
pub struct SigstoreApplicationConstraintsError<'a> {
    pub unapplied_constraints: SignConstraintRefVec<'a>,
}

pub type Result<T> = std::result::Result<T, SigstoreError>;

#[derive(Error, Debug)]
pub enum SigstoreError {
    #[error("failed to parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("failed to construct redirect URL")]
    RedirectUrlRequestLineError,

    #[error("failed to construct oauth code pair")]
    CodePairError,

    #[error("invalid key format: {error}")]
    InvalidKeyFormat { error: String },

    #[error("Unable to parse identity token: {0}")]
    IdentityTokenError(String),

    #[error("unmatched key type {key_typ} and signing scheme {scheme}")]
    UnmatchedKeyAndSigningScheme { key_typ: String, scheme: String },

    #[error("x509 error: {0}")]
    X509Error(String),

    #[error(transparent)]
    FromPEMError(#[from] pem::PemError),

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),

    #[error("Public key with unsupported algorithm: {0}")]
    PublicKeyUnsupportedAlgorithmError(String),

    #[error("Public key verification error")]
    PublicKeyVerificationError,

    #[error("X.509 certificate version is not V3")]
    CertificateUnsupportedVersionError,

    #[error("Certificate validity check failed: cannot be used before {0}")]
    CertificateValidityError(String),

    #[error("Certificate has not been issued for {0}")]
    CertificateInvalidEmail(String),

    #[error(
        "Certificate expired before signatures were entered in log: {integrated_time} is before {not_before}"
    )]
    CertificateExpiredBeforeSignaturesSubmittedToRekor {
        integrated_time: String,
        not_before: String,
    },

    #[error(
        "Certificate was issued after signatures were entered in log: {integrated_time} is after {not_after}"
    )]
    CertificateIssuedAfterSignaturesSubmittedToRekor {
        integrated_time: String,
        not_after: String,
    },

    #[error("Bundled certificate does not have digital signature key usage")]
    CertificateWithoutDigitalSignatureKeyUsage,

    #[error("Bundled certificate does not have code signing extended key usage")]
    CertificateWithoutCodeSigningKeyUsage,

    #[error("Certificate without Subject Alternative Name")]
    CertificateWithoutSubjectAlternativeName,

    #[error("Certificate with incomplete Subject Alternative Name")]
    CertificateWithIncompleteSubjectAlternativeName,

    #[error("Certificate pool error: {0}")]
    CertificatePoolError(String),

    #[error("Signing session expired")]
    ExpiredSigningSession(),

    #[error("Fulcio request unsuccessful: {0}")]
    FulcioClientError(String),

    #[error("Cannot fetch manifest of {image}: {error}")]
    RegistryFetchManifestError { image: String, error: String },

    #[error("Cannot pull manifest of {image}: {error}")]
    RegistryPullManifestError { image: String, error: String },

    #[error("Cannot pull {image}: {error}")]
    RegistryPullError { image: String, error: String },

    #[error("Cannot push {image}: {error}")]
    RegistryPushError { image: String, error: String },

    #[error("Rekor request unsuccessful: {0}")]
    RekorClientError(String),

    #[error("Rekor public key not found for key id {0}")]
    RekorPublicKeyNotFoundError(String),

    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),

    #[cfg(feature = "cert")]
    #[error(transparent)]
    KeyringError(#[from] crate::crypto::keyring::KeyringError),

    #[cfg(any(feature = "sign", feature = "verify"))]
    #[error(transparent)]
    SCTError(#[from] crate::crypto::transparency::SCTError),

    // HACK(tnytown): Remove when we rework the Fulcio V2 endpoint.
    #[cfg(any(feature = "fulcio", feature = "oauth"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "fulcio", feature = "oauth"))))]
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error("OCI reference not valid: {reference}")]
    OciReferenceNotValidError { reference: String },

    #[error("Sigstore bundle malformed: {0}")]
    SigstoreBundleMalformedError(String),

    #[error("Layer doesn't have Sigstore media type")]
    SigstoreMediaTypeNotFoundError,

    #[error("Layer digest mismatch")]
    SigstoreLayerDigestMismatchError,

    #[error("Missing signature annotation")]
    SigstoreAnnotationNotFoundError,

    #[error("Rekor bundle missing")]
    SigstoreRekorBundleNotFoundError,

    #[error("Fulcio certificates not provided")]
    SigstoreFulcioCertificatesNotProvidedError,

    #[error("No Signature Layer passed verification")]
    SigstoreNoVerifiedLayer,

    #[cfg(feature = "sigstore-trust-root")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[error(transparent)]
    TufError(#[from] Box<tough::error::Error>),

    #[error("TUF target {0} not found inside of repository")]
    TufTargetNotFoundError(String),

    #[error("{0}")]
    TufMetadataError(String),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("{0}")]
    UnexpectedError(String),

    #[error("{0}")]
    VerificationConstraintError(String),

    #[error("{0}")]
    VerificationMaterialError(String),

    #[error("{0}")]
    ApplyConstraintError(String),

    #[error("Verification of OIDC claims received from OpenIdProvider failed")]
    ClaimsVerificationError,

    #[cfg(feature = "oauth")]
    #[error("Claims configuration error: {0}")]
    ClaimsConfigurationError(#[from] openidconnect::ConfigurationError),

    #[error("Failed to access token endpoint")]
    ClaimsAccessPointError,

    #[error("Failed to get id_token")]
    NoIDToken,

    #[error("Pkcs8 error : {0}")]
    PKCS8Error(String),

    #[error("Pkcs8 spki error : {0}")]
    PKCS8SpkiError(String),

    #[error("Pkcs8 der encoding/decoding error : {0}")]
    PKCS8DerError(String),

    #[error(transparent)]
    ECDSAError(#[from] ecdsa::Error),

    #[error(transparent)]
    ECError(#[from] elliptic_curve::Error),

    #[error(transparent)]
    ScryptKDFInvalidParamsError(#[from] scrypt::errors::InvalidParams),

    #[error(transparent)]
    ScryptKDFInvalidOutputLenError(#[from] scrypt::errors::InvalidOutputLen),

    #[error("Failed to encrypt the private key: {0}")]
    PrivateKeyEncryptError(String),

    #[error("Failed to decrypt the private key: {0}")]
    PrivateKeyDecryptError(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::error::Error),

    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    WebPKIError(#[from] webpki::Error),

    #[error("Failed to parse the key: {0}")]
    KeyParseError(String),

    #[error(transparent)]
    RSAError(#[from] rsa::errors::Error),

    #[error(transparent)]
    PKCS1Error(#[from] pkcs1::Error),

    #[error(transparent)]
    Ed25519PKCS8Error(#[from] ed25519_dalek::pkcs8::spki::Error),

    #[error(transparent)]
    X509ParseError(#[from] x509_cert::der::Error),

    #[error(transparent)]
    X509BuilderError(#[from] x509_cert::builder::Error),
}
