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

extern crate sigstore;
use sigstore::oauth;

fn main() {
    let (authorize_url, client, nonce, pkce_verifier) = oauth::openidflow::auth_url(
        "sigstore",
        "",
        "https://oauth2.sigstore.dev/auth",
        "http://localhost:8080",
    );
    if open::that(authorize_url.to_string()).is_ok() {
        println!("Open this URL in your browser:\n{}\n", authorize_url);
    }

    let result = oauth::openidflow::redirect_listener(
        "127.0.0.1:8080".to_string(),
        client,
        nonce,
        pkce_verifier,
    );
    match result {
        Ok(token_response) => {
            println!("Email {:?}", token_response.email().unwrap().to_string());
            println!(
                "Access Token:{:?}",
                token_response.access_token_hash().unwrap().to_string()
            );
        }
        Err(err) => {
            println!("{}", err);
        }
    }
}
