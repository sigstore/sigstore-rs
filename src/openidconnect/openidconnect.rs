//
// Copyright 2021 The Sigstore Authors.
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

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
};
use url::Url;

use crate::cosign::Client;

#[derive(Debug, PartialEq)]
pub struct OpenID {
    pub(crate) oidc_client_id: String,
    pub(crate) oidc_client_secret: String,
    pub(crate) oidc_issuer: String,
}


impl OpenID {
    pub fn auth_url(oidc_client_id: String, oidc_client_secret: String, oidc_issuer: String) -> (Url, CsrfToken, CoreClient, Nonce) {
        let oidc_client_id = ClientId::new(oidc_client_id);
        let oidc_client_secret = ClientSecret::new(oidc_client_secret);
        let oidc_issuer = IssuerUrl::new(oidc_issuer).expect("Missing the OIDC_ISSUER.");

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
        .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
        );

        let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )

        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

        // println!(
        //     "Open this URL in your browser:\n{}\n",
        //     authorize_url.to_string()
        // );
        // if open::that(authorize_url.to_string()).is_ok() {
        //     println!("Look at your browser !");
        // }

        // redirect_listener(csrf_state, client, nonce);
        return (authorize_url, csrf_state, client, nonce);
    }
}

pub fn redirect_listener(csrf_state: CsrfToken, client: CoreClient, nonce: Nonce) {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    let result = for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let html_page = "<html><body>Sigstore Auth Successful!</body></html>";

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                html_page.len(),
                html_page
            );
            // let _newstate = &state;
            stream.write_all(response.as_bytes()).unwrap();
            println!(
                "Open ID state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .request(http_client)
                .unwrap_or_else(|_err| {
                    println!("Failed to access token endpoint");
                    unreachable!();
                });

            // println!(
            //     "sigstore returned access token:\n{}\n",
            //     token_response.access_token().secret()
            // );
            // println!("sigstore eturned scopes: {:?}", token_response.scopes());

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
            // println!("Sigstore returned ID token: {:?}", id_token_claims);
            // The server will terminate itself after collecting the first code.
            println!(
                "User with e-mail address {} has authenticated successfully",
                id_token_claims.email().map(|email| email.as_str()).unwrap_or("<not provided>"),
            );
            break;
        }
    };
}
