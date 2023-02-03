pub mod oauth;

use crate::crypto::signing_key::SigStoreSigner;
use crate::crypto::SigningScheme;
use crate::errors::{Result, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use base64::{engine::general_purpose::STANDARD as BASE64_STD_ENGINE, Engine as _};
use openidconnect::core::CoreIdToken;
use reqwest::Body;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use url::Url;

/// Default public Fulcio server root.
pub const FULCIO_ROOT: &str = "https://fulcio.sigstore.dev/";

/// Path within Fulcio to obtain a signing certificate.
pub const SIGNING_CERT_PATH: &str = "api/v2/signingCert";

const CONTENT_TYPE_HEADER_NAME: &str = "content-type";

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Credentials {
    oidc_identity_token: String,
}

#[derive(Debug)]
struct PublicKey {
    algorithm: Option<SigningScheme>,
    content: String,
}
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut pk = serializer.serialize_struct("PublicKey", 2)?;
        pk.serialize_field("content", &self.content)?;
        pk.serialize_field(
            "algorithm",
            match self.algorithm {
                Some(SigningScheme::ECDSA_P256_SHA256_ASN1)
                | Some(SigningScheme::ECDSA_P384_SHA384_ASN1) => "ECDSA",
                Some(SigningScheme::ED25519) => "ED25519",
                Some(SigningScheme::RSA_PSS_SHA256(_))
                | Some(SigningScheme::RSA_PSS_SHA384(_))
                | Some(SigningScheme::RSA_PSS_SHA512(_))
                | Some(SigningScheme::RSA_PKCS1_SHA256(_))
                | Some(SigningScheme::RSA_PKCS1_SHA384(_))
                | Some(SigningScheme::RSA_PKCS1_SHA512(_)) => "RSA",
                _ => "PUBLIC_KEY_ALGORITHM_UNSPECIFIED",
            },
        )?;
        pk.end()
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequest {
    public_key: PublicKey,
    proof_of_possession: String,
}
/// Fulcio certificate signing request
///
/// Used to present a public key and signed challenge/proof-of-key in exchange
/// for a signed X509 certificate in return.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Csr {
    credentials: Credentials,
    public_key_request: PublicKeyRequest,
    certificate_signing_request: Option<String>,
}

impl TryFrom<Csr> for Body {
    type Error = serde_json::Error;

    fn try_from(csr: Csr) -> std::result::Result<Self, Self::Error> {
        Ok(Body::from(serde_json::to_string(&csr)?))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Chain {
    certificates: Vec<FulcioCert>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedCertificateDetachedSct {
    chain: Chain,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedCertificateEmbeddedSct {
    chain: Chain,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CsrResponse {
    signed_certificate_detached_sct: Option<SignedCertificateDetachedSct>,
    signed_certificate_embedded_sct: Option<SignedCertificateEmbeddedSct>,
}

/// The PEM-encoded certificate chain returned by Fulcio.
#[derive(Deserialize, Clone)]
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
        let public_key = key_pair.public_key_to_pem()?;
        let csr = Csr {
            credentials: Credentials {
                oidc_identity_token: token.to_string(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKey {
                    algorithm: Some(signing_scheme),
                    content: public_key,
                },
                proof_of_possession: signature,
            },
            certificate_signing_request: None,
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

        let cert_response = response
            .json::<CsrResponse>()
            .await
            .map_err(|_| SigstoreError::SigstoreFulcioCertificatesNotProvidedError)?;

        let cert: FulcioCert;

        if let Some(signed_certificate_detached_sct) = cert_response.signed_certificate_detached_sct
        {
            cert = signed_certificate_detached_sct.chain.certificates[0].clone();
        } else if let Some(signed_certificate_embedded_sct) =
            cert_response.signed_certificate_embedded_sct
        {
            cert = signed_certificate_embedded_sct.chain.certificates[0].clone();
        } else {
            return Err(SigstoreError::CertificateRequestError);
        }

        Ok((signer, cert))
    }
}
