pub mod oauth;

use crate::crypto::signing_key::SigStoreSigner;
use crate::crypto::SigningScheme;
use crate::errors::{Result, SigstoreError};
use crate::fulcio::oauth::OauthTokenProvider;
use openidconnect::core::CoreIdToken;
use openssl::x509::X509;
use reqwest::Body;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use url::Url;

/// Default public Fulcio server root.
pub const FULCIO_ROOT: &str = "https://fulcio.sigstore.dev/";

/// Path within Fulcio to obtain a signing certificate.
pub const SIGNING_CERT_PATH: &str = "api/v1/signingCert";

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
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
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

impl FulcioCert {
    pub fn new(s: &str) -> FulcioCert {
        FulcioCert(String::from(s))
    }

    pub fn to_inner(&self) -> &str {
        &self.0
    }

    pub fn to_x509(&self) -> Result<X509> {
        let x509 = X509::from_pem(self.to_inner().as_bytes())?;
        Ok(x509)
    }

    pub fn extract_pubkey_string(&self) -> Result<String> {
        let certificate = self.to_x509()?;
        let pub_key_pem = certificate.public_key()?.public_key_to_pem()?;
        String::from_utf8(pub_key_pem).map_err(|e| SigstoreError::from(e.utf8_error()))
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
        let signature = base64::encode(signature);

        let key_pair = signer.to_sigstore_keypair()?;
        let public_key = key_pair.public_key_to_der()?;
        let public_key = base64::encode(public_key);

        let csr = Csr {
            public_key: Some(PublicKey(public_key, signing_scheme)),
            signed_email_address: Some(signature),
        };

        let csr: Body = csr.try_into()?;

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
}
