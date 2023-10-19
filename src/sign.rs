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

use std::cell::OnceCell;
use std::io::{self, Read};
use std::str::FromStr;
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use hex;
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
use url::Url;
use x509_cert::builder::{Builder, RequestBuilder as CertRequestBuilder};
use x509_cert::{ext::pkix as x509_ext, name::Name as X509Name};

use crate::bundle::Version;
use crate::errors::{Result as SigstoreResult, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::fulcio::{self, FulcioClient, FULCIO_ROOT};
use crate::oauth::IdentityToken;
use crate::rekor::apis::configuration::Configuration as RekorConfiguration;
use crate::rekor::apis::entries_api::create_log_entry;
use crate::rekor::models::LogEntry;
use crate::rekor::models::{hashedrekord, proposed_entry::ProposedEntry as ProposedLogEntry};

/// A Sigstore signing session.
///
/// Sessions hold a provided user identity and key materials tied to that identity. A single
/// session may be used to sign multiple items. For more information, see [`Self::sign()`].
pub struct SigningSession<'ctx> {
    context: &'ctx SigningContext,
    identity_token: IdentityToken,
    private_key: ecdsa::SigningKey<NistP256>,
    certs: OnceCell<fulcio::CertificateResponse>,
}

impl<'ctx> SigningSession<'ctx> {
    fn new(context: &'ctx SigningContext, identity_token: IdentityToken) -> Self {
        Self {
            context,
            identity_token,
            private_key: Self::private_key(),
            certs: Default::default(),
        }
    }

    fn private_key() -> ecdsa::SigningKey<NistP256> {
        let mut rng = rand::thread_rng();
        let secret_key = p256::SecretKey::random(&mut rng);
        ecdsa::SigningKey::from(secret_key)
    }

    fn certs(&self) -> SigstoreResult<&fulcio::CertificateResponse> {
        fn init_certs(
            fulcio: &FulcioClient,
            identity: &IdentityToken,
            private_key: &ecdsa::SigningKey<NistP256>,
        ) -> SigstoreResult<fulcio::CertificateResponse> {
            let subject = X509Name::from_str(&format!(
                "emailAddress={}",
                identity.unverified_claims().email
            ))
            .unwrap();

            let mut builder = CertRequestBuilder::new(subject, private_key)?;
            builder
                .add_extension(&x509_ext::BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                })
                .unwrap();

            let cert_req = builder
                .build::<p256::ecdsa::DerSignature>()
                .expect("CSR signing failed");
            fulcio.request_cert_v2(cert_req, identity)
        }

        let resp = init_certs(
            &self.context.fulcio,
            &self.identity_token,
            &self.private_key,
        )?;
        Ok(self.certs.get_or_init(|| resp))
    }

    /// Check if the session's identity token or key material is expired.
    ///
    /// If the session is expired, it cannot be used for signing operations, and a new session
    /// must be created with a fresh identity token.
    pub fn is_expired(&self) -> bool {
        self.identity_token.appears_to_be_expired()
            || self.certs().is_ok_and(|certs| {
                let not_after = certs
                    .cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_system_time();

                SystemTime::now() > not_after
            })
    }

    /// Signs for the input with the session's identity. If the identity is expired,
    /// [SigstoreError::ExpiredSigningSession] is returned.
    ///
    /// TODO(tnytown): Make this async safe. We may need to make the underlying trait functions
    /// implementations async and wrap them with executors for the sync variants. Our async
    /// variants would also need to use async variants of common traits (AsyncRead? AsyncHasher?)
    pub fn sign<R: Read>(&self, input: &mut R) -> SigstoreResult<SigningArtifact> {
        if self.is_expired() {
            return Err(SigstoreError::ExpiredSigningSession());
        }

        let mut hasher = Sha256::new();
        io::copy(input, &mut hasher)?;

        let certs = self.certs()?;
        // TODO(tnytown): Verify SCT here.

        // Sign artifact.
        let input_hash: &[u8] = &hasher.clone().finalize();
        let artifact_signature: p256::ecdsa::Signature = self.private_key.sign_digest(hasher);

        // Prepare inputs.
        let b64_artifact_signature = base64.encode(artifact_signature.to_der());
        let cert = &certs.cert;

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

        // HACK(tnytown): We aren't async yet.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let entry = rt
            .block_on(create_log_entry(&self.context.rekor_config, proposed_entry))
            .map_err(|err| {
                eprintln!("original: {err:?}");
                SigstoreError::RekorClientError(err.to_string())
            })?;

        // TODO(tnytown): Maybe run through the verification flow here? See sigstore-rs#296.

        Ok(SigningArtifact {
            input_digest: base64.encode(input_hash),
            cert: cert.to_der()?,
            b64_signature: b64_artifact_signature,
            log_entry: entry,
        })
    }
}

/// A Sigstore signing context.
///
/// Contexts hold Fulcio (CA) and Rekor (CT) configurations which signing sessions can be
/// constructed against. Use [`Self::production()`] to create a context against the public-good
/// Sigstore infrastructure.
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
                Url::parse(FULCIO_ROOT).unwrap(),
                crate::fulcio::TokenProvider::Oauth(OauthTokenProvider::default()),
            ),
            Default::default(),
        )
    }

    /// Configures and returns a [SigningSession] with the held context.
    pub fn signer(&self, identity_token: IdentityToken) -> SigningSession {
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
    /// The resulting bundle can be serialized with with [serde_json].
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
            let mut body = json_syntax::to_value(self.log_entry.body).unwrap();
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
