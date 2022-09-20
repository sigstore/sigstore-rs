use crate::crypto::signing_key::{SigStoreSigner, SigningScheme};
use crate::errors::{Result, SigstoreError};
use openidconnect::core::CoreIdToken;
use openidconnect::reqwest::async_http_client;
use reqwest::header::HeaderName;
use reqwest::Body;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter, Write};
use std::io::Read;
use std::str::from_utf8;
use url::Url;
use x509_parser::nom::AsBytes;

/// Default public Fulcio server root.
pub const FULCIO_ROOT: &'static str = "https://fulcio.sigstore.dev/";

/// Path within Fulcio to obtain a signing certificate.
pub const SIGNING_CERT_PATH: &str = "api/v1/signingCert";

const CONTENT_TYPE: HeaderName = HeaderName::from_static("content-type");

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
            },
        )?;
        pk.end()
    }
}

pub struct FulcioCert(pub String);

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

/// Client for creating and holding ephemeral key pairs, and easily
/// getting a Fulcio-signed certificate chain.
pub struct FulcioClient<'c> {
    root_url: Url,
    token: &'c CoreIdToken,
    challenge: &'c str,
    signer: SigStoreSigner,
    signing_scheme: SigningScheme,
}

impl<'c> FulcioClient<'c> {
    /// Create a new Fulcio client.
    ///
    /// * root_url: The root Fulcio server URL.
    /// * token: The id_token JWT authenticating to Fulcio
    /// * challenge: The cleartext challenge to sign to prove key ownership to Fulcio. Currently the user's email address.
    /// * signing_scheme: The signing scheme to use.
    ///
    /// Returns either a configured Fulcio client or an error.
    pub fn new(
        root_url: Url,
        token: &'c CoreIdToken,
        challenge: &'c str,
        signing_scheme: SigningScheme,
    ) -> Result<Self> {
        let mut signer = signing_scheme.create_signer().unwrap();

        Ok(Self {
            root_url,
            token,
            challenge,
            signer,
            signing_scheme,
        })
    }

    /// Request a certificate from Fulcio
    ///
    /// Returns a tuple of the appropriately-configured sigstore signer and the Fulcio-issued certificate chain.
    pub async fn request_cert(mut self) -> Result<(SigStoreSigner, FulcioCert)> {
        let signature = self.signer.sign(self.challenge.as_bytes()).unwrap();
        let signature = base64::encode(signature);

        let key_pair = self.signer.to_sigstore_keypair().unwrap();
        let public_key = key_pair.public_key_to_der().unwrap();
        let public_key = base64::encode(public_key);

        let csr = Csr {
            public_key: Some(PublicKey(public_key, self.signing_scheme)),
            signed_email_address: Some(signature),
        };

        let csr: Body = csr
            .try_into()
            .map_err(|err| SigstoreError::SerdeJsonError(err))?;

        let client = reqwest::Client::new();
        let response = client
            .post(self.root_url.join(SIGNING_CERT_PATH)?)
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(self.token.to_string())
            .body(csr)
            .send()
            .await
            .map_err(|_| SigstoreError::SigstoreFulcioCertificatesNotProvidedError)?;

        let cert = response
            .text()
            .await
            .map_err(|_| SigstoreError::SigstoreFulcioCertificatesNotProvidedError)?;

        Ok((self.signer, FulcioCert(cert)))
    }
}
