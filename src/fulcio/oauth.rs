use crate::errors::Result;
use crate::errors::SigstoreError;
use crate::oauth::openidflow::{OpenIDAuthorize, RedirectListener};
use openidconnect::core::CoreIdToken;

/// Default client id ("sigstore").
pub const DEFAULT_CLIENT_ID: &str = "sigstore";

/// Default client secret (the empty string)
pub const DEFAULT_CLIENT_SECRET: &str = "";

/// Default issuer (Oauth provider at sigstore.dev)
pub const DEFAULT_ISSUER: &str = "https://oauth2.sigstore.dev/auth";

/// Default local redirect port (8080)
pub const DEFAULT_REDIRECT_PORT: u32 = 8080;

/// Token provider that performs a human-involved OIDC flow to acquire a token id.
#[derive(Default)]
pub struct OauthTokenProvider {
    client_id: Option<String>,
    client_secret: Option<String>,
    issuer: Option<String>,
    redirect_port: Option<u32>,
}

impl OauthTokenProvider {
    /// Set a non-default client-id.
    pub fn with_client_id(self, client_id: &str) -> Self {
        Self {
            client_id: Some(client_id.to_string()),
            client_secret: self.client_secret,
            issuer: self.issuer,
            redirect_port: self.redirect_port,
        }
    }

    /// Set a non-default client secret.
    pub fn with_client_secret(self, client_secret: &str) -> Self {
        Self {
            client_id: self.client_id,
            client_secret: Some(client_secret.to_string()),
            issuer: self.issuer,
            redirect_port: self.redirect_port,
        }
    }

    /// Set a non-default issuer.
    pub fn with_issuer(self, issuer: &str) -> Self {
        Self {
            client_id: self.client_id,
            client_secret: self.client_secret,
            issuer: Some(issuer.to_string()),
            redirect_port: self.redirect_port,
        }
    }

    /// Set a non-default redirect port.
    pub fn with_redirect_port(self, port: u32) -> Self {
        Self {
            client_id: self.client_id,
            client_secret: self.client_secret,
            issuer: self.issuer,
            redirect_port: Some(port),
        }
    }

    fn redirect_url(&self) -> String {
        format!(
            "http://localhost:{}",
            self.redirect_port.unwrap_or(DEFAULT_REDIRECT_PORT)
        )
    }

    /// Perform human-involved OIDC flow to acquire an id token, along with
    /// the extracted email claim value for use in signed challenge with Fulcio.
    pub async fn get_token(&self) -> Result<(CoreIdToken, String)> {
        let oidc_url = OpenIDAuthorize::new(
            self.client_id
                .as_ref()
                .unwrap_or(&DEFAULT_CLIENT_ID.to_string()),
            self.client_secret
                .as_ref()
                .unwrap_or(&DEFAULT_CLIENT_SECRET.to_string()),
            self.issuer.as_ref().unwrap_or(&DEFAULT_ISSUER.to_string()),
            &self.redirect_url(),
        )
        .auth_url_async()
        .await;

        match oidc_url.as_ref() {
            Ok(url) => {
                webbrowser::open(url.0.as_ref())?;
                println!(
                    "Open this URL in a browser if it does not automatically open for you:\n{}\n",
                    url.0,
                );
            }
            Err(e) => println!("{e}"),
        }

        let oidc_url = oidc_url?;
        let result = RedirectListener::new(
            &format!(
                "127.0.0.1:{}",
                self.redirect_port.unwrap_or(DEFAULT_REDIRECT_PORT)
            ),
            oidc_url.1.clone(), // client
            oidc_url.2.clone(), // nonce
            oidc_url.3,         // pkce_verifier
        )
        .redirect_listener_async()
        .await;

        if let Ok((_, id_token)) = result {
            let verifier = oidc_url.1.id_token_verifier();
            let nonce = &oidc_url.2;

            let claims = id_token.claims(&verifier, nonce);
            if let Ok(claims) = claims {
                if let Some(email) = claims.email() {
                    let email = &**email;
                    return Ok((id_token.clone(), email.clone()));
                }
            }
        }

        Err(SigstoreError::NoIDToken)
    }
}
