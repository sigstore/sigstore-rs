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

use std::{
    io::{self, Read},
    time::SystemTime,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use elliptic_curve::rand_core;
use hex;
use p256::NistP256;
use pkcs8::der::{Encode, EncodePem};
use sha2::{Digest, Sha256};
use signature::{DigestSigner, Signer};
use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle;
use sigstore_protobuf_specs::dev::sigstore::bundle::v1::{
    Bundle, VerificationMaterial, verification_material,
};
use sigstore_protobuf_specs::dev::sigstore::common::v1::{
    HashAlgorithm, HashOutput, MessageSignature, X509Certificate,
};
use sigstore_protobuf_specs::dev::sigstore::rekor::v1::TransparencyLogEntry;
use tokio::io::AsyncRead;
use tokio_util::io::SyncIoBridge;
use url::Url;
use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
use x509_cert::builder::{Builder, RequestBuilder as CertRequestBuilder};
use x509_cert::ext::pkix as x509_ext;

use crate::bundle::intoto::Statement;
use crate::bundle::models::Version;
use crate::crypto::keyring::Keyring;
use crate::crypto::transparency::{verify_sct, verify_scts};
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::fulcio::{self, FULCIO_ROOT, FulcioClient};
use crate::oauth::IdentityToken;
use crate::rekor::client::RekorClient;
use crate::rekor::client_v1::RekorV1Client;
use crate::rekor::client_v2::RekorV2Client;
use crate::rekor::models::{hashedrekord, proposed_entry::ProposedEntry as ProposedLogEntry};
use crate::trust::TrustRoot;
use crate::{bundle::dsse, crypto::transparency::CertificateEmbeddedSCTs};

#[cfg(feature = "sigstore-trust-root")]
use crate::trust::sigstore::SigstoreTrustRoot;

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
        // Use email if available, otherwise use sub (for GitHub Actions OIDC tokens)
        let identity = token
            .unverified_claims()
            .email
            .as_ref()
            .or(token.unverified_claims().sub.as_ref())
            .ok_or_else(|| {
                SigstoreError::IdentityTokenError(
                    "Token must have either 'email' or 'sub' claim".to_string(),
                )
            })?;

        let subject =
                // SEQUENCE OF RelativeDistinguishedName
                vec![
                    // SET OF AttributeTypeAndValue
                    vec![
                        // AttributeTypeAndValue, `emailAddress=...` (or sub for GitHub Actions)
                        AttributeTypeAndValue {
                            oid: const_oid::db::rfc3280::EMAIL_ADDRESS,
                            value: AttributeValue::new(
                                pkcs8::der::Tag::Utf8String,
                                identity.as_ref(),
                            )?,
                        }
                    ].try_into()?
                ].into();

        let private_key = ecdsa::SigningKey::from(p256::SecretKey::random(&mut rand_core::OsRng));
        let mut builder = CertRequestBuilder::new(subject, &private_key)?;
        builder.add_extension(&x509_ext::BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })?;

        let cert_req = builder.build::<p256::ecdsa::DerSignature>()?;
        let certs = fulcio.request_cert_v2(cert_req, token).await?;

        Ok((private_key, certs))
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

        // Verify SCTs from the Fulcio-issued certificate
        if let Some(detached_sct) = &self.certs.detached_sct {
            // Detached SCT - use single SCT verification
            verify_sct(detached_sct, &self.context.ctfe_keyring)?;
        } else {
            // Embedded SCTs - use multi-SCT verification with threshold of 1
            // This allows signing to work even if some CTFE keys in the trust root
            // are malformed or missing, as long as at least one SCT can be verified
            let scts = CertificateEmbeddedSCTs::new(&self.certs.cert, &self.certs.chain)?;
            verify_scts(&scts, &self.context.ctfe_keyring, 1)?;
        }

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

        let log_entry = self
            .context
            .rekor_client
            .create_entry(proposed_entry)
            .await
            .map_err(|err| SigstoreError::RekorClientError(err.to_string()))?;
        let log_entry = log_entry
            .try_into()
            .or(Err(SigstoreError::RekorClientError(
                "Rekor returned malformed LogEntry".into(),
            )))?;

        // Request TSA timestamp for Rekor v2 (required by Sigstore spec)
        // Rekor v2 uses checkpoint timestamps, but TSA provides an independent trusted timestamp
        let is_rekor_v2 = self.context.rekor_client.api_version() == 2;
        let tsa_timestamp = if is_rekor_v2 {
            if let Some(ref tsa_url) = self.context.tsa_url {
                tracing::debug!(
                    "Rekor v2 detected, requesting TSA timestamp from: {}",
                    tsa_url
                );
                use crate::crypto::tsa::TimestampAuthorityClient;
                let tsa_client = TimestampAuthorityClient::new(tsa_url.clone());
                let timestamp_bytes = tsa_client.request_timestamp(&signature_bytes).await?;
                tracing::debug!("TSA timestamp received: {} bytes", timestamp_bytes.len());
                Some(timestamp_bytes)
            } else {
                tracing::warn!(
                    "Rekor v2 requires TSA timestamp per Sigstore spec - bundle may fail verification"
                );
                None
            }
        } else {
            None
        };

        // TODO(tnytown): Maybe run through the verification flow here? See sigstore-rs#296.

        Ok(SigningArtifact {
            content: SigningArtifactContent::MessageSignature {
                input_digest: input_hash.to_owned(),
                signature: signature_bytes,
            },
            cert: cert.to_der()?,
            log_entry,
            tsa_timestamp,
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

    /// Signs an in-toto statement with a DSSE envelope.
    ///
    /// This creates a DSSE envelope containing the statement, signs the Pre-Authentication
    /// Encoding (PAE), and submits the result to Rekor as a DSSE entry.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use sigstore::bundle::intoto::{StatementBuilder, Subject};
    /// # use sigstore::bundle::sign::SigningContext;
    /// # use serde_json::json;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Get identity token from OAuth flow (not shown)
    /// # let token = unimplemented!();
    ///
    /// let ctx = SigningContext::production()?;
    /// let session = ctx.signer(token).await?;
    ///
    /// let statement = StatementBuilder::new()
    ///     .subject(Subject::new("myapp.tar.gz", "sha256", "abc123..."))
    ///     .predicate_type("https://slsa.dev/provenance/v1")
    ///     .predicate(json!({"buildType": "test"}))
    ///     .build()
    ///     .unwrap();
    ///
    /// let artifact = session.sign_dsse(&statement).await?;
    /// let bundle = artifact.to_bundle();
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign_dsse(&self, statement: &Statement) -> SigstoreResult<SigningArtifact> {
        if self.is_expired() {
            return Err(SigstoreError::ExpiredSigningSession());
        }

        // Create the DSSE envelope
        let mut envelope = dsse::DsseEnvelope::from_statement(statement).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to create DSSE envelope: {}", e))
        })?;

        // Compute the PAE
        let pae_bytes = envelope.pae();

        // Sign the PAE directly (not pre-hashed)
        // The Signer trait will handle hashing internally
        let pae_signature: p256::ecdsa::Signature = self.private_key.sign(&pae_bytes);
        let signature_bytes = pae_signature.to_der().as_bytes().to_owned();

        // Add signature to envelope
        envelope.add_signature(signature_bytes.clone(), String::new());

        let cert = &self.certs.cert;

        // Convert certificate to PEM and base64 encode for Rekor submission
        let cert_pem = cert.to_pem(pkcs8::LineEnding::LF)?;
        let cert_base64 = base64.encode(cert_pem.as_bytes());

        // Build the DSSE envelope JSON for Rekor v0.0.1
        // NOTE: Do NOT include the keyid field - cosign doesn't include it
        let envelope_json = serde_json::json!({
            "payload": base64.encode(envelope.payload()),
            "payloadType": envelope.payload_type().to_string(),
            "signatures": envelope.signatures().iter().map(|sig| {
                serde_json::json!({
                    "sig": base64.encode(&sig.sig),
                })
            }).collect::<Vec<_>>(),
        });

        let envelope_json_string = serde_json::to_string(&envelope_json).map_err(|e| {
            SigstoreError::UnexpectedError(format!("Failed to serialize envelope: {}", e))
        })?;

        // Use "dsse" kind with v0.0.1 API, matching cosign's implementation
        let proposed_entry = ProposedLogEntry::Dsse {
            api_version: "0.0.1".to_owned(),
            spec: serde_json::json!({
                "proposedContent": {
                    "envelope": envelope_json_string,
                    "verifiers": [cert_base64],
                },
            }),
        };

        let log_entry = self
            .context
            .rekor_client
            .create_entry(proposed_entry)
            .await
            .map_err(|err| SigstoreError::RekorClientError(err.to_string()))?;
        let log_entry = log_entry
            .try_into()
            .or(Err(SigstoreError::RekorClientError(
                "Rekor returned malformed LogEntry".into(),
            )))?;

        // Request TSA timestamp for Rekor v2 (required by Sigstore spec)
        // Rekor v2 uses checkpoint timestamps, but TSA provides an independent trusted timestamp
        let is_rekor_v2 = self.context.rekor_client.api_version() == 2;
        let tsa_timestamp = if is_rekor_v2 {
            if let Some(ref tsa_url) = self.context.tsa_url {
                tracing::debug!(
                    "Rekor v2 detected, requesting TSA timestamp from: {}",
                    tsa_url
                );
                use crate::crypto::tsa::TimestampAuthorityClient;
                let tsa_client = TimestampAuthorityClient::new(tsa_url.clone());
                let timestamp_bytes = tsa_client.request_timestamp(&signature_bytes).await?;
                tracing::debug!("TSA timestamp received: {} bytes", timestamp_bytes.len());
                Some(timestamp_bytes)
            } else {
                tracing::warn!(
                    "Rekor v2 requires TSA timestamp per Sigstore spec - bundle may fail verification"
                );
                None
            }
        } else {
            None
        };

        Ok(SigningArtifact {
            content: SigningArtifactContent::DsseEnvelope {
                envelope: envelope.into_inner(),
            },
            cert: cert.to_der()?,
            log_entry,
            tsa_timestamp,
        })
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

        /// Signs an in-toto statement with a DSSE envelope.
        ///
        /// This creates a DSSE envelope containing the statement, signs the Pre-Authentication
        /// Encoding (PAE), and submits the result to Rekor as a DSSE entry.
        ///
        /// This is the synchronous version of [`SigningSession::sign_dsse`].
        pub fn sign_dsse(&self, statement: &Statement) -> SigstoreResult<SigningArtifact> {
            self.rt.block_on(self.inner.sign_dsse(statement))
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
    rekor_client: Box<dyn RekorClient>,
    ctfe_keyring: Keyring,
    tsa_url: Option<String>,
}

impl SigningContext {
    /// Manually constructs a [`SigningContext`] from its constituent data.
    pub fn new(
        fulcio: FulcioClient,
        rekor_client: Box<dyn RekorClient>,
        ctfe_keyring: Keyring,
    ) -> Self {
        Self {
            fulcio,
            rekor_client,
            ctfe_keyring,
            tsa_url: None,
        }
    }

    /// Manually constructs a [`SigningContext`] with TSA URL support.
    pub fn new_with_tsa(
        fulcio: FulcioClient,
        rekor_client: Box<dyn RekorClient>,
        ctfe_keyring: Keyring,
        tsa_url: Option<String>,
    ) -> Self {
        Self {
            fulcio,
            rekor_client,
            ctfe_keyring,
            tsa_url,
        }
    }

    /// Returns a [`SigningContext`] configured against the public-good production Sigstore
    /// infrastructure.
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[cfg(feature = "sigstore-trust-root")]
    pub async fn async_production() -> SigstoreResult<Self> {
        let trust_root = SigstoreTrustRoot::new(None).await?;
        Ok(Self::new(
            FulcioClient::new(
                Url::parse(FULCIO_ROOT).expect("constant FULCIO root fails to parse!"),
                crate::fulcio::TokenProvider::Oauth(OauthTokenProvider::default()),
            ),
            Box::new(RekorV1Client::new("https://rekor.sigstore.dev".to_string())),
            Keyring::new(trust_root.ctfe_keys()?.values().copied())?,
        ))
    }

    /// Returns a [`SigningContext`] configured against the public-good production Sigstore
    /// infrastructure.
    ///
    /// Async callers should use [`SigningContext::async_production`].
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[cfg(feature = "sigstore-trust-root")]
    pub fn production() -> SigstoreResult<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(Self::async_production())
    }

    /// Returns a [`SigningContext`] configured with a custom trust root.
    ///
    /// This allows using a custom Sigstore trust root for signing operations,
    /// which is useful for testing or private deployments.
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[cfg(feature = "sigstore-trust-root")]
    pub fn from_trust_root(trust_root: SigstoreTrustRoot) -> SigstoreResult<Self> {
        Self::from_trust_root_and_signing_config(trust_root, None)
    }

    /// Returns a [`SigningContext`] configured with a custom trust root and signing config.
    ///
    /// This is the recommended way to create a signing context with custom configuration.
    /// The signing config is used to extract Fulcio CA URLs and Rekor transparency log
    /// service configuration (including the API version).
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The Sigstore trust root to use
    /// * `signing_config` - Optional signing configuration with CA and tlog service URLs
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore::trust::sigstore::SigstoreTrustRoot;
    /// use sigstore::bundle::sign::SigningContext;
    /// use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig;
    ///
    /// let trust_root = SigstoreTrustRoot::new(None).await?;
    /// let config: SigningConfig = serde_json::from_slice(&config_bytes)?;
    /// let ctx = SigningContext::from_trust_root_and_signing_config(trust_root, Some(&config))?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[cfg(feature = "sigstore-trust-root")]
    pub fn from_trust_root_and_signing_config(
        trust_root: SigstoreTrustRoot,
        signing_config: Option<
            &sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig,
        >,
    ) -> SigstoreResult<Self> {
        // Extract configuration from signing_config if provided
        let (fulcio_url, rekor_url, rekor_api_version, tsa_url) =
            if let Some(config) = signing_config {
                let fulcio = if !config.ca_urls.is_empty() {
                    Some(config.ca_urls[0].url.clone())
                } else {
                    None
                };

                let (rekor, rekor_version) = if !config.rekor_tlog_urls.is_empty() {
                    (
                        Some(config.rekor_tlog_urls[0].url.clone()),
                        Some(config.rekor_tlog_urls[0].major_api_version),
                    )
                } else {
                    (None, None)
                };

                let tsa = if !config.tsa_urls.is_empty() {
                    Some(config.tsa_urls[0].url.clone())
                } else {
                    None
                };

                (fulcio, rekor, rekor_version, tsa)
            } else {
                (None, None, None, None)
            };

        Self::from_trust_root_and_fulcio(
            trust_root,
            fulcio_url,
            rekor_url,
            rekor_api_version,
            tsa_url,
        )
    }

    /// Returns a [`SigningContext`] configured with a custom trust root and optional Fulcio URL.
    ///
    /// This allows using a custom Sigstore trust root and Fulcio instance for signing operations.
    /// If no Fulcio URL is provided, defaults to the production Fulcio instance.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The Sigstore trust root to use
    /// * `fulcio_url` - Optional custom Fulcio URL (defaults to production)
    /// * `rekor_url` - Optional custom Rekor URL (defaults to production v1)
    /// * `rekor_api_version` - Optional Rekor API version (defaults to 1)
    /// * `tsa_url` - Optional TSA URL for timestamp requests
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[cfg(feature = "sigstore-trust-root")]
    pub fn from_trust_root_and_fulcio(
        trust_root: SigstoreTrustRoot,
        fulcio_url: Option<String>,
        rekor_url: Option<String>,
        rekor_api_version: Option<u32>,
        tsa_url: Option<String>,
    ) -> SigstoreResult<Self> {
        // Convert hex-encoded key IDs from trust root to [u8; 32]
        let ctfe_keys = trust_root.ctfe_keys()?;
        let keys_with_ids: Vec<([u8; 32], &[u8])> = ctfe_keys
            .iter()
            .filter_map(|(key_id_hex, key_bytes)| {
                // Decode hex key ID to bytes
                let key_id_vec = hex::decode(key_id_hex).ok()?;
                let key_id: [u8; 32] = key_id_vec.try_into().ok()?;
                Some((key_id, *key_bytes))
            })
            .collect();

        let fulcio_url_str = fulcio_url.as_deref().unwrap_or(FULCIO_ROOT);
        let fulcio_url_parsed = Url::parse(fulcio_url_str)
            .map_err(|e| SigstoreError::UnexpectedError(format!("Invalid Fulcio URL: {}", e)))?;

        // Determine Rekor client based on API version
        let rekor_client: Box<dyn RekorClient> = match rekor_api_version.unwrap_or(1) {
            2 => {
                let url = rekor_url.unwrap_or_else(|| "https://rekor.sigstore.dev".to_string());
                Box::new(RekorV2Client::new(url))
            }
            _ => {
                let url = rekor_url.unwrap_or_else(|| "https://rekor.sigstore.dev".to_string());
                Box::new(RekorV1Client::new(url))
            }
        };

        Ok(Self::new_with_tsa(
            FulcioClient::new(
                fulcio_url_parsed,
                crate::fulcio::TokenProvider::Oauth(OauthTokenProvider::default()),
            ),
            rekor_client,
            Keyring::new_with_ids(keys_with_ids.iter().map(|(id, bytes)| (id, *bytes)))?,
            tsa_url,
        ))
    }

    /// Configures and returns a [`SigningSession`] with the held context.
    pub async fn signer(
        &self,
        identity_token: IdentityToken,
    ) -> SigstoreResult<SigningSession<'_>> {
        SigningSession::new(self, identity_token).await
    }

    /// Configures and returns a [`blocking::SigningSession`] with the held context.
    ///
    /// Async contexts must use [`SigningContext::signer`].
    pub fn blocking_signer(
        &self,
        identity_token: IdentityToken,
    ) -> SigstoreResult<blocking::SigningSession<'_>> {
        blocking::SigningSession::new(self, identity_token)
    }
}

/// The content type of a signing artifact.
enum SigningArtifactContent {
    /// A message signature (hashedrekord)
    MessageSignature {
        input_digest: Vec<u8>,
        signature: Vec<u8>,
    },
    /// A DSSE envelope (intoto)
    DsseEnvelope {
        envelope: sigstore_protobuf_specs::io::intoto::Envelope,
    },
}

/// A signature and its associated metadata.
pub struct SigningArtifact {
    content: SigningArtifactContent,
    cert: Vec<u8>,
    log_entry: TransparencyLogEntry,
    tsa_timestamp: Option<Vec<u8>>,
}

impl SigningArtifact {
    /// Consumes the signing artifact and produces a Sigstore [`Bundle`].
    ///
    /// The resulting bundle can be serialized with [`serde_json`].
    pub fn to_bundle(self) -> Bundle {
        use sigstore_protobuf_specs::dev::sigstore::bundle::v1::TimestampVerificationData;

        // Bundle 0.3 uses a single certificate field instead of a certificate chain
        let certificate = X509Certificate {
            raw_bytes: self.cert,
        };

        // Include TSA timestamp if present
        let timestamp_verification_data =
            self.tsa_timestamp
                .map(|timestamp_bytes| TimestampVerificationData {
                    rfc3161_timestamps: vec![
                    sigstore_protobuf_specs::dev::sigstore::common::v1::Rfc3161SignedTimestamp {
                        signed_timestamp: timestamp_bytes,
                    },
                ],
                });

        let verification_material = Some(VerificationMaterial {
            timestamp_verification_data,
            tlog_entries: vec![self.log_entry],
            content: Some(verification_material::Content::Certificate(certificate)),
        });

        let content = match self.content {
            SigningArtifactContent::MessageSignature {
                input_digest,
                signature,
            } => {
                let message_signature = MessageSignature {
                    message_digest: Some(HashOutput {
                        algorithm: HashAlgorithm::Sha2256.into(),
                        digest: input_digest,
                    }),
                    signature,
                };
                bundle::Content::MessageSignature(message_signature)
            }
            SigningArtifactContent::DsseEnvelope { envelope } => {
                bundle::Content::DsseEnvelope(envelope)
            }
        };

        Bundle {
            media_type: Version::Bundle0_3.to_string(),
            verification_material,
            content: Some(content),
        }
    }
}
