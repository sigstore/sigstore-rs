//
// Copyright 2022 The Sigstore Authors.
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

//! This provides a method for retreiving a OpenID Connect ID Token and scope from the
//! sigstore project.
//!
//! The main entry point is the [`openidflow::auth_url`](openidflow::auth_url) function.
//! This requires four parameters:
//! - `client_id`: the client ID of the application
//! - `client_secret`: the client secret of the application
//! - `issuer`: the URL of the OpenID Connect server
//! - `redirect_uri`: the URL of the callback endpoint
//!
//! The function returns a tuple of the following:
//! - `authorize_url`: the URL to open in the browser
//! - `client`: the client object
//! - `nonce`: the nonce value
//! - `pkce_verifier`: the PKCE verifier
//!
//! The `authorize_url` is a URL that can be opened in a browser. The user will be
//! prompted to login and authorize the application. The user will be redirected to
//! the `redirect_uri` URL with a code parameter.
//!
//! The `client` is a client object that can be used to make requests to the OpenID
//! Connect server.
//!
//! The `nonce` is a random value that is used to prevent replay attacks.
//!
//! The `pkce_verifier` is a PKCE verifier that can be used to generate the code_verifier
//! value.
//!
//! Once you have recieved the above tuple, you can use the [`openidflow::redirect_listener`](openidflow::redirect_listener)
//! function to get the ID Token and scope.
//!
//! The `redirect_listener` function requires the following parameters:
//! - `redirect_url`: the address to listen on
//! - `client`: the client object
//! - `nonce`: the nonce value
//! - `pkce_verifier`: the PKCE verifier
//!
//! The `redirect_url` is the address to listen on. The `client` is the client object
//! that can be used to make requests to the OpenID Connect server.
//!
//! It maybe prefered to instead develop your own listener. If so bypass using the
//! [`openidflow::redirect_listener`](openidflow::redirect_listener) function and
//! simple send the values retrieved from the [`openidflow::auth_url`](openidflow::auth_url)
//! to your own listener.
//!

use crate::errors::{Result, SigstoreError};

use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

/// Generate a authorization URL for the OpenID Connect flow and return to the caller.
/// The caller can then pass the values to the redirect listener, or should they wish to
/// they could alternatively pass the values to their own method for handling the redirect.
pub fn auth_url(
    oidc_client_id: &str,
    oidc_client_secret: &str,
    oidc_issuer: &str,
    redirect_url: &str,
) -> (Url, CoreClient, Nonce, PkceCodeVerifier) {
    let oidc_client_id = ClientId::new(oidc_client_id.to_owned());
    let oidc_client_secret = ClientSecret::new(oidc_client_secret.to_owned());
    let oidc_issuer = IssuerUrl::new(oidc_issuer.to_owned()).expect("Missing the OIDC_ISSUER.");

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let provider_metadata = CoreProviderMetadata::discover(&oidc_issuer, http_client)
        .unwrap_or_else(|_err| {
            println!("Failed to discover OpenID Provider");
            unreachable!();
        });

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        oidc_client_id,
        Some(oidc_client_secret),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_owned()).expect("Invalid redirect URL"));

    let (authorize_url, _, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    (authorize_url, client, nonce, pkce_verifier)
}

/// The redirect listener spawns a listening TCP server on the specified port.
/// It will then extract values such as the email address and access token
pub fn redirect_listener(
    redirect_url: String,
    client: CoreClient,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
) -> Result<CoreIdTokenClaims> {
    let listener = TcpListener::bind(redirect_url)?;

    #[allow(clippy::manual_flatten)]
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line)?;

                let redirect_url = request_line
                    .split_whitespace()
                    .nth(1)
                    .ok_or(SigstoreError::RedirectUrlRequestLineError)?;
                let url = Url::parse(format!("http://localhost{}", redirect_url).as_str())?;

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .ok_or(SigstoreError::CodePairError)?;

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());
            }

            let html_page = r#"<html>
            <title>Sigstore Auth</title>
            <body>
            <h1>Sigstore Auth Successful</h1>
            <p>You may now close this page.</p>
            </body>
            </html>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                html_page.len(),
                html_page
            );
            stream.write_all(response.as_bytes())?;

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request(http_client)
                .unwrap_or_else(|_err| {
                    println!("Failed to access token endpoint");
                    unreachable!();
                });

            let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
            let id_token_claims: &CoreIdTokenClaims = token_response
                .extra_fields()
                .id_token()
                .expect("Server did not return an ID token")
                .claims(&id_token_verifier, &nonce)
                .unwrap_or_else(|_err| {
                    println!("Failed to verify ID token");
                    unreachable!();
                });

            return Ok(id_token_claims.clone());
        }
    }
    unreachable!()
}

#[test]
fn test_auth_url() {
    let (url, _, _, _) = auth_url(
        "sigstore",
        "some_secret",
        "https://oauth2.sigstore.dev/auth",
        "http://localhost:8080",
    );
    assert!(url.to_string().contains("https://oauth2.sigstore.dev/auth"));
    assert!(url.to_string().contains("response_type=code"));
    assert!(url.to_string().contains("client_id=sigstore"));
    assert!(url.to_string().contains("scope=openid+email"));
}
