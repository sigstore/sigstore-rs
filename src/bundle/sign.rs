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

//! Types for signing artifacts and producing Sigstore bundles.

use std::io::{self, Read};
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use hex;
use p256::NistP256;
use pkcs8::der::{Encode, EncodePem};
use sha2::{Digest, Sha256};
use signature::DigestSigner;
use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle;
use sigstore_protobuf_specs::dev::sigstore::bundle::v1::{
    verification_material, Bundle, VerificationMaterial,
};
use sigstore_protobuf_specs::dev::sigstore::common::v1::{
    HashAlgorithm, HashOutput, MessageSignature, X509Certificate, X509CertificateChain,
};
use sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry;
use tokio::io::AsyncRead;
use tokio_util::io::SyncIoBridge;
use url::Url;
use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
use x509_cert::builder::{Builder, RequestBuilder as CertRequestBuilder};
use x509_cert::ext::pkix as x509_ext;

use crate::bundle::models::Version;
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::fulcio::{self, FulcioClient, FULCIO_ROOT};
use crate::oauth::IdentityToken;
use crate::rekor::apis::configuration::Configuration as RekorConfiguration;
use crate::rekor::apis::entries_api::create_log_entry;
use crate::rekor::models::{hashedrekord, proposed_entry::ProposedEntry as ProposedLogEntry};

/// An asynchronous Sigstore signing session.
///
/// Sessions hold a provided user identity and key materials tied to that identity. A single
/// session may be used to sign multiple items. For more information, see [`SigningSession::sign`].
///
/// This signing session operates asynchronously. To construct a synchronous [`blocking::SigningSession`],
/// use [`SigningContext::blocking_signer()`].
pub struct SigningSession<'ctx> {
    context: &'ctx SigningContext,
    identity_token: IdentityToken,
    private_key: ecdsa::SigningKey<NistP256>,
    certs: fulcio::CertificateResponse,
}

impl<'ctx> SigningSession<'ctx> {
    async fn new(
        context: &'ctx SigningContext,
        identity_token: IdentityToken,
    ) -> SigstoreResult<SigningSession<'ctx>> {
        let (private_key, certs) = Self::materials(&context.fulcio, &identity_token).await?;
        Ok(Self {
            context,
            identity_token,
            private_key,
            certs,
        })
    }

    async fn materials(
        fulcio: &FulcioClient,
        token: &IdentityToken,
    ) -> SigstoreResult<(ecdsa::SigningKey<NistP256>, fulcio::CertificateResponse)> {
        let subject =
                // SEQUENCE OF RelativeDistinguishedName
                vec![
                    // SET OF AttributeTypeAndValue
                    vec![
                        // AttributeTypeAndValue, `emailAddress=...`
                        AttributeTypeAndValue {
                            oid: const_oid::db::rfc3280::EMAIL_ADDRESS,
                            value: AttributeValue::new(
                                pkcs8::der::Tag::Utf8String,
                                token.unverified_claims().email.as_ref(),
                            )?,
                        }
                    ].try_into()?
                ].into();

        let mut rng = rand::thread_rng();
        let private_key = ecdsa::SigningKey::from(p256::SecretKey::random(&mut rng));
        let mut builder = CertRequestBuilder::new(subject, &private_key)?;
        builder.add_extension(&x509_ext::BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })?;

        let cert_req = builder.build::<p256::ecdsa::DerSignature>()?;
        Ok((private_key, fulcio.request_cert_v2(cert_req, token).await?))
    }

    /// Check if the session's identity token or key material is expired.
    ///
    /// If the session is expired, it cannot be used for signing operations, and a new session
    /// must be created with a fresh identity token.
    pub fn is_expired(&self) -> bool {
        let not_after = self
            .certs
            .cert
            .tbs_certificate
            .validity
            .not_after
            .to_system_time();

        !self.identity_token.in_validity_period() || SystemTime::now() > not_after
    }

    async fn sign_digest(&self, hasher: Sha256) -> SigstoreResult<SigningArtifact> {
        if self.is_expired() {
            return Err(SigstoreError::ExpiredSigningSession());
        }

        // TODO(tnytown): verify SCT here, sigstore-rs#326

        // Sign artifact.
        let input_hash: &[u8] = &hasher.clone().finalize();
        let artifact_signature: p256::ecdsa::Signature = self.private_key.sign_digest(hasher);
        let signature_bytes = artifact_signature.to_der().as_bytes().to_owned();

        let cert = &self.certs.cert;

        // Create the transparency log entry.
        let proposed_entry = ProposedLogEntry::Hashedrekord {
            api_version: "0.0.1".to_owned(),
            spec: hashedrekord::Spec {
                signature: hashedrekord::Signature {
                    content: base64.encode(&signature_bytes),
                    public_key: hashedrekord::PublicKey::new(
                        base64.encode(cert.to_pem(pkcs8::LineEnding::LF)?),
                    ),
                },
                data: hashedrekord::Data {
                    hash: hashedrekord::Hash {
                        algorithm: hashedrekord::AlgorithmKind::sha256,
                        value: hex::encode(input_hash),
                    },
                },
            },
        };

        let log_entry = create_log_entry(&self.context.rekor_config, proposed_entry)
            .await
            .map_err(|err| SigstoreError::RekorClientError(err.to_string()))?;
        let log_entry = log_entry
            .try_into()
            .or(Err(SigstoreError::RekorClientError(
                "Rekor returned malformed LogEntry".into(),
            )))?;

        // TODO(tnytown): Maybe run through the verification flow here? See sigstore-rs#296.

        Ok(SigningArtifact {
            input_digest: input_hash.to_owned(),
            cert: cert.to_der()?,
            signature: signature_bytes,
            log_entry,
        })
    }

    /// Signs for the input with the session's identity. If the identity is expired,
    /// [`SigstoreError::ExpiredSigningSession`] is returned.
    pub async fn sign<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        input: R,
    ) -> SigstoreResult<SigningArtifact> {
        if self.is_expired() {
            return Err(SigstoreError::ExpiredSigningSession());
        }

        let mut sync_input = SyncIoBridge::new(input);
        let hasher = tokio::task::spawn_blocking(move || -> SigstoreResult<_> {
            let mut hasher = Sha256::new();
            io::copy(&mut sync_input, &mut hasher)?;
            Ok(hasher)
        })
        .await??;

        self.sign_digest(hasher).await
    }
}

pub mod blocking {
    use super::{SigningSession as AsyncSigningSession, *};

    /// A synchronous Sigstore signing session.
    ///
    /// Sessions hold a provided user identity and key materials tied to that identity. A single
    /// session may be used to sign multiple items. For more information, see [`SigningSession::sign`].
    ///
    /// This signing session operates synchronously, thus it cannot be used in an asynchronous context.
    /// To construct an asynchronous [`SigningSession`], use [`SigningContext::signer()`].
    pub struct SigningSession<'ctx> {
        inner: AsyncSigningSession<'ctx>,
        rt: tokio::runtime::Runtime,
    }

    impl<'ctx> SigningSession<'ctx> {
        pub(crate) fn new(ctx: &'ctx SigningContext, token: IdentityToken) -> SigstoreResult<Self> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let inner = rt.block_on(AsyncSigningSession::new(ctx, token))?;
            Ok(Self { inner, rt })
        }

        /// Check if the session's identity token or key material is expired.
        ///
        /// If the session is expired, it cannot be used for signing operations, and a new session
        /// must be created with a fresh identity token.
        pub fn is_expired(&self) -> bool {
            self.inner.is_expired()
        }

        /// Signs for the input with the session's identity. If the identity is expired,
        /// [`SigstoreError::ExpiredSigningSession`] is returned.
        pub fn sign<R: Read>(&self, mut input: R) -> SigstoreResult<SigningArtifact> {
            let mut hasher = Sha256::new();
            io::copy(&mut input, &mut hasher)?;
            self.rt.block_on(self.inner.sign_digest(hasher))
        }
    }
}

/// A Sigstore signing context.
///
/// Contexts hold Fulcio (CA) and Rekor (CT) configurations which signing sessions can be
/// constructed against. Use [`SigningContext::production`] to create a context against
/// the public-good Sigstore infrastructure.
pub struct SigningContext {
    fulcio: FulcioClient,
    rekor_config: RekorConfiguration,
}

impl SigningContext {
    /// Manually constructs a [`SigningContext`] from its constituent data.
    pub fn new(fulcio: FulcioClient, rekor_config: RekorConfiguration) -> Self {
        Self {
            fulcio,
            rekor_config,
        }
    }

    /// Returns a [`SigningContext`] configured against the public-good production Sigstore
    /// infrastructure.
    pub fn production() -> SigstoreResult<Self> {
        Ok(Self::new(
            FulcioClient::new(
                Url::parse(FULCIO_ROOT).expect("constant FULCIO root fails to parse!"),
                crate::fulcio::TokenProvider::Oauth(OauthTokenProvider::default()),
            ),
            Default::default(),
        ))
    }

    /// Configures and returns a [`SigningSession`] with the held context.
    pub async fn signer(&self, identity_token: IdentityToken) -> SigstoreResult<SigningSession> {
        SigningSession::new(self, identity_token).await
    }

    /// Configures and returns a [`blocking::SigningSession`] with the held context.
    ///
    /// Async contexts must use [`SigningContext::signer`].
    pub fn blocking_signer(
        &self,
        identity_token: IdentityToken,
    ) -> SigstoreResult<blocking::SigningSession> {
        blocking::SigningSession::new(self, identity_token)
    }
}

/// A signature and its associated metadata.
pub struct SigningArtifact {
    input_digest: Vec<u8>,
    cert: Vec<u8>,
    signature: Vec<u8>,
    log_entry: TransparencyLogEntry,
}

impl SigningArtifact {
    /// Consumes the signing artifact and produces a Sigstore [`Bundle`].
    ///
    /// The resulting bundle can be serialized with [`serde_json`].
    pub fn to_bundle(self) -> Bundle {
        // NOTE: We explicitly only include the leaf certificate in the bundle's "chain"
        // here: the specs explicitly forbid the inclusion of the root certificate,
        // and discourage inclusion of any intermediates (since they're in the root of
        // trust already).
        let x509_certificate_chain = X509CertificateChain {
            certificates: vec![X509Certificate {
                raw_bytes: self.cert,
            }],
        };

        let verification_material = Some(VerificationMaterial {
            timestamp_verification_data: None,
            tlog_entries: vec![self.log_entry],
            content: Some(verification_material::Content::X509CertificateChain(
                x509_certificate_chain,
            )),
        });

        let message_signature = MessageSignature {
            message_digest: Some(HashOutput {
                algorithm: HashAlgorithm::Sha2256.into(),
                digest: self.input_digest,
            }),
            signature: self.signature,
        };
        Bundle {
            media_type: Version::Bundle0_2.to_string(),
            verification_material,
            content: Some(bundle::Content::MessageSignature(message_signature)),
        }
    }
}
