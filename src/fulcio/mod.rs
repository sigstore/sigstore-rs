mod models;

pub mod oauth;

use crate::crypto::signing_key::SigStoreSigner;
use crate::crypto::SigningScheme;
use crate::errors::{Result, SigstoreError};
use crate::fulcio::models::{CreateSigningCertificateRequest, SigningCertificate};
use crate::fulcio::oauth::OauthTokenProvider;
use crate::oauth::IdentityToken;
use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use openidconnect::core::CoreIdToken;
use reqwest::{header, Body};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use url::Url;
use x509_cert::{der::Decode, Certificate};

pub use models::{CertificateResponse, SigningCertificateDetachedSCT};

/// Default public Fulcio server root.
pub const FULCIO_ROOT: &str = "https://fulcio.sigstore.dev/";

/// Path within Fulcio to obtain a signing certificate.
pub const SIGNING_CERT_PATH: &str = "api/v1/signingCert";
pub const SIGNING_CERT_V2_PATH: &str = "api/v2/signingCert";

const CONTENT_TYPE_HEADER_NAME: &str = "content-type";

/// Fulcio certificate signing request
///
/// Used to present a public key and signed challenge/proof-of-key in exchange
/// for a signed X509 certificate in return.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Csr {
    public_key: Option<PublicKey>,
    signed_email_address: Option<String>,
}

impl TryFrom<Csr> for Body {
    type Error = serde_json::Error;

    fn try_from(csr: Csr) -> std::result::Result<Self, Self::Error> {
        Ok(Body::from(serde_json::to_string(&csr)?))
    }
}

/// Internal newtype to control serde jsonification.
#[derive(Debug)]
struct PublicKey(String, SigningScheme);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut pk = serializer.serialize_struct("PublicKey", 2)?;
        pk.serialize_field("content", &self.0)?;
        pk.serialize_field(
            "algorithm",
            match self.1 {
                SigningScheme::ECDSA_P256_SHA256_ASN1 | SigningScheme::ECDSA_P384_SHA384_ASN1 => {
                    "ecdsa"
                }
                SigningScheme::ED25519 => "ed25519",
                SigningScheme::RSA_PSS_SHA256(_)
                | SigningScheme::RSA_PSS_SHA384(_)
                | SigningScheme::RSA_PSS_SHA512(_)
                | SigningScheme::RSA_PKCS1_SHA256(_)
                | SigningScheme::RSA_PKCS1_SHA384(_)
                | SigningScheme::RSA_PKCS1_SHA512(_) => "rsa",
            },
        )?;
        pk.end()
    }
}

/// The PEM-encoded certificate chain returned by Fulcio.
pub struct FulcioCert(String);

impl AsRef<[u8]> for FulcioCert {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for FulcioCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Provider for Fulcio token.
#[allow(clippy::large_enum_variant)]
pub enum TokenProvider {
    /// A Static provider consists of a tuple where the first value is a
    /// OIDC token. The second is the value of the challenge.
    ///
    /// To figure out the correct value for the challenge one can list the
    /// issuers available:
    /// ```console
    /// $ curl -Ls https://fulcio.sigstore.dev/api/v2/configuration | jq
    /// ```
    /// Find the issuer of the token, and then find the value of the
    /// `challengeClaim` which will specify which value of the OIDC token's
    /// claims to use.
    ///
    /// For example, if the token was issued from
    /// `https://token.actions.githubusercontent.com`:
    /// ```json
    /// {
    ///   "issuerUrl": "https://token.actions.githubusercontent.com",
    ///   "audience": "sigstore",
    ///   "challengeClaim": "sub",
    ///   "spiffeTrustDomain": ""
    /// }
    /// ```
    /// In this case the value of the challenge should be the value of the
    /// `sub` (`subject`) claim of the token.
    ///
    Static((CoreIdToken, String)),
    Oauth(OauthTokenProvider),
}

impl TokenProvider {
    /// Retrieve a token and the challenge-to-sign from the provider.
    pub async fn get_token(&self) -> Result<(CoreIdToken, String)> {
        match self {
            TokenProvider::Static(inner) => Ok(inner.clone()),
            TokenProvider::Oauth(auth) => auth.get_token().await,
        }
    }
}

/// Client for creating and holding ephemeral key pairs, and easily
/// getting a Fulcio-signed certificate chain.
pub struct FulcioClient {
    root_url: Url,
    token_provider: TokenProvider,
}

impl FulcioClient {
    /// Create a new Fulcio client.
    ///
    /// * root_url: The root Fulcio server URL.
    /// * token_provider: Provider capable of providing a CoreIdToken and the challenge to sign.
    ///
    /// Returns a configured Fulcio client.
    pub fn new(root_url: Url, token_provider: TokenProvider) -> Self {
        Self {
            root_url,
            token_provider,
        }
    }

    /// Request a certificate from Fulcio
    ///
    /// * signing_scheme: The signing scheme to use.
    ///
    /// Returns a tuple of the appropriately-configured sigstore signer and the Fulcio-issued certificate chain.
    pub async fn request_cert(
        self,
        signing_scheme: SigningScheme,
    ) -> Result<(SigStoreSigner, FulcioCert)> {
        let (token, challenge) = self.token_provider.get_token().await?;

        let signer = signing_scheme.create_signer()?;
        let signature = signer.sign(challenge.as_bytes())?;
        let signature = BASE64_STD_ENGINE.encode(signature);

        let key_pair = signer.to_sigstore_keypair()?;
        let public_key = key_pair.public_key_to_der()?;
        let public_key = BASE64_STD_ENGINE.encode(public_key);

        let csr = Csr {
            public_key: Some(PublicKey(public_key, signing_scheme)),
            signed_email_address: Some(signature),
        };

        let csr = TryInto::<Body>::try_into(csr)?;

        let client = reqwest::Client::new();
        let response = client
            .post(self.root_url.join(SIGNING_CERT_PATH)?)
            .header(CONTENT_TYPE_HEADER_NAME, "application/json")
            .bearer_auth(token.to_string())
            .body(csr)
            .send()
            .await
            .map_err(|_| SigstoreError::SigstoreFulcioCertificatesNotProvidedError)?;

        let cert = response
            .text()
            .await
            .map_err(|_| SigstoreError::SigstoreFulcioCertificatesNotProvidedError)?;

        Ok((signer, FulcioCert(cert)))
    }

    /// Request a certificate from Fulcio with the V2 endpoint.
    ///
    /// TODO(tnytown): This (and other API clients) should be autogenerated. See sigstore-rs#209.
    ///
    /// <https://github.com/sigstore/fulcio/blob/main/fulcio.proto>
    ///
    /// Additionally, it might not be reasonable to expect callers to correctly construct and pass
    /// in an X509 CSR.
    pub async fn request_cert_v2(
        &self,
        request: x509_cert::request::CertReq,
        identity: &IdentityToken,
    ) -> Result<CertificateResponse> {
        let client = reqwest::Client::new();

        macro_rules! headers {
            ($($key:expr => $val:expr),+) => {
                {
                    let mut map = reqwest::header::HeaderMap::new();
                    $( map.insert($key, $val.parse().unwrap()); )+
                    map
                }
            }
        }
        let headers = headers!(
            header::AUTHORIZATION => format!("Bearer {}", identity.to_string()),
            header::CONTENT_TYPE => "application/json",
            header::ACCEPT => "application/pem-certificate-chain"
        );

        let response = client
            .post(self.root_url.join(SIGNING_CERT_V2_PATH)?)
            .headers(headers)
            .json(&CreateSigningCertificateRequest {
                certificate_signing_request: request,
            })
            .send()
            .await?;
        let response = response.json().await?;

        let (certs, detached_sct) = match response {
            SigningCertificate::SignedCertificateDetachedSct(ref sc) => {
                (&sc.chain.certificates, Some(sc.clone()))
            }
            SigningCertificate::SignedCertificateEmbeddedSct(ref sc) => {
                (&sc.chain.certificates, None)
            }
        };

        if certs.len() < 2 {
            return Err(SigstoreError::FulcioClientError(
                "Certificate chain too short: certs.len() < 2".into(),
            ));
        }

        let cert = Certificate::from_der(certs[0].contents())?;
        let chain = certs[1..]
            .iter()
            .map(|pem| Certificate::from_der(pem.contents()))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(CertificateResponse {
            cert,
            chain,
            detached_sct,
        })
    }
}
