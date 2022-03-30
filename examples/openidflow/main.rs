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

extern crate sigstore;
use sigstore::oauth;

fn main() {
    let oidc_url = oauth::openidflow::OpenIDAuthorize::new(
        "sigstore",
        "",
        "https://oauth2.sigstore.dev/auth",
        "http://localhost:8080",
    );

    let authz = oidc_url.auth_url();
    println!("auth0: {:?}", authz.0.to_string());
    if open::that(authz.0.to_string()).is_ok() {
        println!("Open this URL in your browser:\n{}\n", authz.0.to_string());
    }

    let redirectz = oauth::openidflow::RedirectListner::new(
        "127.0.0.1:8080",
        authz.1,
        authz.2,
        authz.3,

    );
    let result = redirectz.redirect_listener();
    match result{
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