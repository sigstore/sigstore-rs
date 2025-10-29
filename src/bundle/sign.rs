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

use crate::bundle::dsse;
use crate::bundle::intoto::Statement;
use crate::bundle::models::Version;
use crate::crypto::keyring::Keyring;
use crate::crypto::transparency::{CertificateEmbeddedSCT, verify_sct};
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::fulcio::{self, FULCIO_ROOT, FulcioClient};
use crate::oauth::IdentityToken;
use crate::rekor::apis::configuration::Configuration as RekorConfiguration;
use crate::rekor::apis::entries_api::create_log_entry;
use crate::rekor::models::{hashedrekord, proposed_entry::ProposedEntry as ProposedLogEntry};
use crate::trust::TrustRoot;

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

        if let Some(detached_sct) = &self.certs.detached_sct {
            verify_sct(detached_sct, &self.context.ctfe_keyring)?;
        } else {
            let sct = CertificateEmbeddedSCT::new(&self.certs.cert, &self.certs.chain)?;
            verify_sct(&sct, &self.context.ctfe_keyring)?;
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
            content: SigningArtifactContent::MessageSignature {
                input_digest: input_hash.to_owned(),
                signature: signature_bytes,
            },
            cert: cert.to_der()?,
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
        let mut envelope = dsse::create_envelope(statement)
            .map_err(|e| SigstoreError::UnexpectedError(format!("Failed to create DSSE envelope: {}", e)))?;

        eprintln!("[2] Envelope created");
        eprintln!("[2] Envelope.payload (raw JSON bytes) length: {} bytes", envelope.payload.len());
        if let Ok(payload_str) = String::from_utf8(envelope.payload.clone()) {
            eprintln!("[2] Envelope.payload content: {}", payload_str);
        }
        eprintln!("[2] Envelope.payloadType: {}", envelope.payload_type);

        // Compute the PAE
        let pae_bytes = dsse::pae(&envelope);

        eprintln!("[3] PAE computed");
        eprintln!("[3] PAE length: {} bytes", pae_bytes.len());
        eprintln!("[3] PAE first 200 bytes: {}", String::from_utf8_lossy(&pae_bytes[..pae_bytes.len().min(200)]));
        eprintln!("[3] PAE hex (FULL): {}", hex::encode(&pae_bytes));

        // Write PAE to file for external verification
        std::fs::write("/tmp/rust-pae-bytes.bin", &pae_bytes).ok();
        eprintln!("[3] PAE written to /tmp/rust-pae-bytes.bin");

        // Sign the PAE directly (not pre-hashed)
        // The Signer trait will handle hashing internally
        eprintln!("[4] Signing PAE with Signer::sign() (will hash internally with SHA256)");
        eprintln!("[4] BYTES TO SIGN (hex, FULL): {}", hex::encode(&pae_bytes));

        let pae_signature: p256::ecdsa::Signature = self.private_key.sign(&pae_bytes);
        let signature_bytes = pae_signature.to_der().as_bytes().to_owned();

        // Also compute hash for debugging
        let pae_hash = Sha256::digest(&pae_bytes);
        eprintln!("[4] PAE SHA256 hash (for reference): {}", hex::encode(&pae_hash));

        eprintln!("[5] Signature computed");
        eprintln!("[5] Signature length: {} bytes", signature_bytes.len());
        eprintln!("[5] Signature hex: {}", hex::encode(&signature_bytes));
        eprintln!("[5] Signature base64: {}", base64.encode(&signature_bytes));

        // Add signature to envelope
        dsse::add_signature(&mut envelope, signature_bytes.clone(), String::new());

        eprintln!("[6] Signature added to envelope");

        let cert = &self.certs.cert;

        // Create the DSSE Rekor entry
        // For intoto v0.0.2, Rekor expects:
        // - content.envelope: the complete DSSE envelope with payloadType and signatures
        // - Each signature needs a publicKey field (the certificate)

        // Get the public key from the certificate
        // For intoto v0.0.1, we need base64(PEM)

        eprintln!("\n[CERT-DEBUG] Converting certificate to PEM...");
        let cert_pem = cert.to_pem(pkcs8::LineEnding::LF)?;
        eprintln!("[CERT-DEBUG] PEM length: {} bytes", cert_pem.len());
        eprintln!("[CERT-DEBUG] PEM (first 100 chars): {}", &cert_pem[..cert_pem.len().min(100)]);

        // Write out the PEM to a temp file for debugging
        std::fs::write("/tmp/rust-cert-debug.pem", &cert_pem).ok();
        eprintln!("[CERT-DEBUG] Certificate written to /tmp/rust-cert-debug.pem for inspection");

        let cert_base64 = base64.encode(cert_pem.as_bytes());
        eprintln!("[CERT-DEBUG] Base64 length: {} bytes", cert_base64.len());

        // Build the envelope with signatures (no publicKey in the signatures themselves for v0.0.1)
        let _rekor_signatures = envelope.signatures.iter().map(|sig| {
            serde_json::json!({
                "keyid": sig.keyid.clone(),
                "sig": base64.encode(&sig.sig),
                "publicKey": cert_base64.clone(),
            })
        }).collect::<Vec<_>>();

        // Build the DSSE envelope JSON for Rekor v0.0.1
        // The v0.0.1 API expects the envelope serialized to JSON as a string
        // NOTE: Do NOT include the keyid field - cosign doesn't include it and it causes verification to fail

        eprintln!("\n[ENCODE-1] Building envelope JSON structure...");
        eprintln!("[ENCODE-1] Envelope.payload (raw bytes): {} bytes", envelope.payload.len());
        eprintln!("[ENCODE-1] Envelope.payload (as UTF-8 string): {}",
            String::from_utf8(envelope.payload.clone()).unwrap_or_else(|_| "<not UTF-8>".to_string()));
        eprintln!("[ENCODE-1] Envelope.payloadType: {}", envelope.payload_type);
        eprintln!("[ENCODE-1] Number of signatures: {}", envelope.signatures.len());

        for (i, sig) in envelope.signatures.iter().enumerate() {
            eprintln!("[ENCODE-1] Signature #{} length: {} bytes", i, sig.sig.len());
            eprintln!("[ENCODE-1] Signature #{} hex: {}", i, hex::encode(&sig.sig));
            eprintln!("[ENCODE-1] Signature #{} base64: {}", i, base64.encode(&sig.sig));
        }

        let envelope_json = serde_json::json!({
            "payload": base64.encode(&envelope.payload),  // Base64 encode the raw payload bytes for JSON
            "payloadType": envelope.payload_type.clone(),
            "signatures": envelope.signatures.iter().map(|sig| {
                serde_json::json!({
                    "sig": base64.encode(&sig.sig),
                })
            }).collect::<Vec<_>>(),
        });

        eprintln!("[ENCODE-2] Envelope JSON object created");
        eprintln!("[ENCODE-2] Envelope JSON (pretty):\n{}", serde_json::to_string_pretty(&envelope_json).unwrap());

        let envelope_json_string = serde_json::to_string(&envelope_json)
            .map_err(|e| SigstoreError::UnexpectedError(format!("Failed to serialize envelope: {}", e)))?;

        eprintln!("[ENCODE-3] Envelope JSON string length: {} bytes", envelope_json_string.len());
        eprintln!("[ENCODE-3] Envelope JSON string: {}", envelope_json_string);

        // Use "dsse" kind with v0.0.1 API, matching cosign's implementation
        // The spec needs proposedContent with envelope and verifiers
        let proposed_entry = ProposedLogEntry::Dsse {
            api_version: "0.0.1".to_owned(),
            spec: serde_json::json!({
                "proposedContent": {
                    "envelope": envelope_json_string,
                    "verifiers": [cert_base64],
                },
            }),
        };

        eprintln!("\nDEBUG: Submitting to Rekor with:");
        eprintln!("  Kind: dsse");
        eprintln!("  API Version: 0.0.1");
        eprintln!("  Envelope payload length: {} bytes", envelope.payload.len());
        if let Ok(payload_str) = String::from_utf8(envelope.payload.clone()) {
            eprintln!("  Envelope payload (base64): {}", payload_str);
        }
        eprintln!("  Envelope signatures count: {}", envelope.signatures.len());
        eprintln!("  Certificate length: {} bytes", cert_base64.len());

        // Decode and log the PAE for debugging
        eprintln!("\n  PAE verification:");
        let test_pae = dsse::pae(&envelope);
        eprintln!("    PAE length: {} bytes", test_pae.len());
        eprintln!("    PAE (hex, first 100 bytes): {}", hex::encode(&test_pae[..test_pae.len().min(100)]));

        if let Ok(pretty_spec) = serde_json::to_string_pretty(&proposed_entry) {
            eprintln!("\n  Full Proposed Entry:\n{}", pretty_spec);
        }

        eprintln!("\n[7] Final envelope for Rekor submission:");
        eprintln!("[7] Envelope JSON: {}", envelope_json_string);
        eprintln!("==========================================\n");

        let log_entry = create_log_entry(&self.context.rekor_config, proposed_entry)
            .await
            .map_err(|err| {
                eprintln!("DEBUG: Rekor submission failed!");
                eprintln!("  Error type: {:?}", err);
                match &err {
                    crate::rekor::apis::Error::ResponseError(resp) => {
                        eprintln!("  HTTP Status: {}", resp.status);
                        eprintln!("  Response body: {}", resp.content);
                        if let Some(entity) = &resp.entity {
                            eprintln!("  Parsed error entity: {:#?}", entity);
                        }
                    }
                    _ => {
                        eprintln!("  Other error: {}", err);
                    }
                }
                SigstoreError::RekorClientError(err.to_string())
            })?;
        let log_entry = log_entry
            .try_into()
            .or(Err(SigstoreError::RekorClientError(
                "Rekor returned malformed LogEntry".into(),
            )))?;

        Ok(SigningArtifact {
            content: SigningArtifactContent::DsseEnvelope { envelope },
            cert: cert.to_der()?,
            log_entry,
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
    rekor_config: RekorConfiguration,
    ctfe_keyring: Keyring,
}

impl SigningContext {
    /// Manually constructs a [`SigningContext`] from its constituent data.
    pub fn new(
        fulcio: FulcioClient,
        rekor_config: RekorConfiguration,
        ctfe_keyring: Keyring,
    ) -> Self {
        Self {
            fulcio,
            rekor_config,
            ctfe_keyring,
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
            Default::default(),
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
}

impl SigningArtifact {
    /// Consumes the signing artifact and produces a Sigstore [`Bundle`].
    ///
    /// The resulting bundle can be serialized with [`serde_json`].
    pub fn to_bundle(self) -> Bundle {
        // Bundle 0.3 uses a single certificate field instead of a certificate chain
        let certificate = X509Certificate {
            raw_bytes: self.cert,
        };

        let verification_material = Some(VerificationMaterial {
            timestamp_verification_data: None,
            tlog_entries: vec![self.log_entry],
            content: Some(verification_material::Content::Certificate(certificate)),
        });

        let content = match self.content {
            SigningArtifactContent::MessageSignature { input_digest, signature } => {
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
