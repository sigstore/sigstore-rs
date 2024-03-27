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

//! Types for signing artifacts and producing Sigstore Bundles.

use std::io::{self, Read};
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use json_syntax::Print;
use p256::NistP256;
use pkcs8::der::{Encode, EncodePem};
use sha2::{Digest, Sha256};
use signature::DigestSigner;
use sigstore_protobuf_specs::{
    Bundle, DevSigstoreBundleV1VerificationMaterial, DevSigstoreCommonV1HashOutput,
    DevSigstoreCommonV1LogId, DevSigstoreCommonV1MessageSignature,
    DevSigstoreCommonV1X509Certificate, DevSigstoreCommonV1X509CertificateChain,
    DevSigstoreRekorV1Checkpoint, DevSigstoreRekorV1InclusionPromise,
    DevSigstoreRekorV1InclusionProof, DevSigstoreRekorV1KindVersion,
    DevSigstoreRekorV1TransparencyLogEntry,
};
use tokio::io::AsyncRead;
use tokio_util::io::SyncIoBridge;
use url::Url;
use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
use x509_cert::builder::{Builder, RequestBuilder as CertRequestBuilder};
use x509_cert::ext::pkix as x509_ext;

use crate::bundle::Version;
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::fulcio::{self, FulcioClient, FULCIO_ROOT};
use crate::oauth::IdentityToken;
use crate::rekor::apis::configuration::Configuration as RekorConfiguration;
use crate::rekor::apis::entries_api::create_log_entry;
use crate::rekor::models::LogEntry;
use crate::rekor::models::{hashedrekord, proposed_entry::ProposedEntry as ProposedLogEntry};

/// An asynchronous Sigstore signing session.
///
/// Sessions hold a provided user identity and key materials tied to that identity. A single
/// session may be used to sign multiple items. For more information, see [`AsyncSigningSession::sign`](Self::sign).
///
/// This signing session operates asynchronously. To construct a synchronous [SigningSession],
/// use [`SigningContext::signer()`].
pub struct AsyncSigningSession<'ctx> {
    context: &'ctx SigningContext,
    identity_token: IdentityToken,
    private_key: ecdsa::SigningKey<NistP256>,
    certs: fulcio::CertificateResponse,
}

impl<'ctx> AsyncSigningSession<'ctx> {
    async fn new(
        context: &'ctx SigningContext,
        identity_token: IdentityToken,
    ) -> SigstoreResult<AsyncSigningSession<'ctx>> {
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

        // TODO(tnytown): Verify SCT here.

        // Sign artifact.
        let input_hash: &[u8] = &hasher.clone().finalize();
        let artifact_signature: p256::ecdsa::Signature = self.private_key.sign_digest(hasher);

        // Prepare inputs.
        let b64_artifact_signature = base64.encode(artifact_signature.to_der());
        let cert = &self.certs.cert;

        // Create the transparency log entry.
        let proposed_entry = ProposedLogEntry::Hashedrekord {
            api_version: "0.0.1".to_owned(),
            spec: hashedrekord::Spec {
                signature: hashedrekord::Signature {
                    content: b64_artifact_signature.clone(),
                    public_key: hashedrekord::PublicKey::new(
                        base64.encode(cert.to_pem(pkcs8::LineEnding::CRLF)?),
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

        let entry = create_log_entry(&self.context.rekor_config, proposed_entry)
            .await
            .map_err(|err| SigstoreError::RekorClientError(err.to_string()))?;

        // TODO(tnytown): Maybe run through the verification flow here? See sigstore-rs#296.

        Ok(SigningArtifact {
            input_digest: base64.encode(input_hash),
            cert: cert.to_der()?,
            b64_signature: b64_artifact_signature,
            log_entry: entry,
        })
    }

    /// Signs for the input with the session's identity. If the identity is expired,
    /// [SigstoreError::ExpiredSigningSession] is returned.
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

/// A synchronous Sigstore signing session.
///
/// Sessions hold a provided user identity and key materials tied to that identity. A single
/// session may be used to sign multiple items. For more information, see [`SigningSession::sign`](Self::sign).
///
/// This signing session operates synchronously, thus it cannot be used in an asynchronous context.
/// To construct an asynchronous [SigningSession], use [`SigningContext::async_signer()`].
pub struct SigningSession<'ctx> {
    inner: AsyncSigningSession<'ctx>,
    rt: tokio::runtime::Runtime,
}

impl<'ctx> SigningSession<'ctx> {
    fn new(ctx: &'ctx SigningContext, token: IdentityToken) -> SigstoreResult<Self> {
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
    /// [SigstoreError::ExpiredSigningSession] is returned.
    pub fn sign<R: Read>(&self, mut input: R) -> SigstoreResult<SigningArtifact> {
        let mut hasher = Sha256::new();
        io::copy(&mut input, &mut hasher)?;
        self.rt.block_on(self.inner.sign_digest(hasher))
    }
}

/// A Sigstore signing context.
///
/// Contexts hold Fulcio (CA) and Rekor (CT) configurations which signing sessions can be
/// constructed against. Use [`SigningContext::production`](Self::production) to create a context against
/// the public-good Sigstore infrastructure.
pub struct SigningContext {
    fulcio: FulcioClient,
    rekor_config: RekorConfiguration,
}

impl SigningContext {
    /// Manually constructs a [SigningContext] from its constituent data.
    pub fn new(fulcio: FulcioClient, rekor_config: RekorConfiguration) -> Self {
        Self {
            fulcio,
            rekor_config,
        }
    }

    /// Returns a [SigningContext] configured against the public-good production Sigstore
    /// infrastructure.
    pub fn production() -> Self {
        Self::new(
            FulcioClient::new(
                Url::parse(FULCIO_ROOT).expect("constant FULCIO root fails to parse!"),
                crate::fulcio::TokenProvider::Oauth(OauthTokenProvider::default()),
            ),
            Default::default(),
        )
    }

    /// Configures and returns an [AsyncSigningSession] with the held context.
    pub async fn async_signer(
        &self,
        identity_token: IdentityToken,
    ) -> SigstoreResult<AsyncSigningSession> {
        AsyncSigningSession::new(self, identity_token).await
    }

    /// Configures and returns a [SigningContext] with the held context.
    ///
    /// Async contexts must use [`SigningContext::async_signer`](Self::async_signer).
    pub fn signer(&self, identity_token: IdentityToken) -> SigstoreResult<SigningSession> {
        SigningSession::new(self, identity_token)
    }
}

/// A signature and its associated metadata.
pub struct SigningArtifact {
    input_digest: String,
    cert: Vec<u8>,
    b64_signature: String,
    log_entry: LogEntry,
}

impl SigningArtifact {
    /// Consumes the signing artifact and produces a Sigstore [Bundle].
    ///
    /// The resulting bundle can be serialized with [serde_json].
    pub fn to_bundle(self) -> Bundle {
        #[inline]
        fn hex_to_base64<S: AsRef<str>>(hex: S) -> String {
            let decoded = hex::decode(hex.as_ref()).expect("Malformed data in Rekor response");
            base64.encode(decoded)
        }

        // NOTE: We explicitly only include the leaf certificate in the bundle's "chain"
        // here: the specs explicitly forbid the inclusion of the root certificate,
        // and discourage inclusion of any intermediates (since they're in the root of
        // trust already).
        let x_509_certificate_chain = Some(DevSigstoreCommonV1X509CertificateChain {
            certificates: Some(vec![DevSigstoreCommonV1X509Certificate {
                raw_bytes: Some(base64.encode(&self.cert)),
            }]),
        });

        let inclusion_proof = if let Some(proof) = self.log_entry.verification.inclusion_proof {
            let hashes = proof.hashes.iter().map(hex_to_base64).collect();
            Some(DevSigstoreRekorV1InclusionProof {
                checkpoint: Some(DevSigstoreRekorV1Checkpoint {
                    envelope: Some(proof.checkpoint),
                }),
                hashes: Some(hashes),
                log_index: Some(proof.log_index.to_string()),
                root_hash: Some(hex_to_base64(proof.root_hash)),
                tree_size: Some(proof.tree_size.to_string()),
            })
        } else {
            None
        };

        let canonicalized_body = {
            let mut body = json_syntax::to_value(self.log_entry.body)
                .expect("failed to parse constructed Body!");
            body.canonicalize();
            Some(base64.encode(body.compact_print().to_string()))
        };

        // TODO(tnytown): When we fix `sigstore_protobuf_specs`, have the Rekor client APIs convert
        // responses into types from the specs as opposed to returning the raw `LogEntry` model type.
        let tlog_entry = DevSigstoreRekorV1TransparencyLogEntry {
            canonicalized_body,
            inclusion_promise: Some(DevSigstoreRekorV1InclusionPromise {
                // XX: sigstore-python deserializes the SET from base64 here because their protobuf
                // library transparently serializes `bytes` fields as base64.
                signed_entry_timestamp: Some(self.log_entry.verification.signed_entry_timestamp),
            }),
            inclusion_proof,
            integrated_time: Some(self.log_entry.integrated_time.to_string()),
            kind_version: Some(DevSigstoreRekorV1KindVersion {
                kind: Some("hashedrekord".to_owned()),
                version: Some("0.0.1".to_owned()),
            }),
            log_id: Some(DevSigstoreCommonV1LogId {
                key_id: Some(hex_to_base64(self.log_entry.log_i_d)),
            }),
            log_index: Some(self.log_entry.log_index.to_string()),
        };

        let verification_material = Some(DevSigstoreBundleV1VerificationMaterial {
            public_key: None,
            timestamp_verification_data: None,
            tlog_entries: Some(vec![tlog_entry]),
            x_509_certificate_chain,
        });

        let message_signature = Some(DevSigstoreCommonV1MessageSignature {
            message_digest: Some(DevSigstoreCommonV1HashOutput {
                algorithm: Some("SHA2_256".to_owned()),
                digest: Some(self.input_digest),
            }),
            signature: Some(self.b64_signature),
        });
        Bundle {
            dsse_envelope: None,
            media_type: Some(Version::Bundle0_2.to_string()),
            message_signature,
            verification_material,
        }
    }
}
