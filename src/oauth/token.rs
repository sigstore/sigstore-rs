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

use std::fmt;

use chrono::{DateTime, Utc};
use openidconnect::core::CoreIdToken;
use serde::Deserialize;

use base64::{engine::general_purpose::STANDARD_NO_PAD as base64, Engine as _};

use crate::errors::SigstoreError;

#[derive(Deserialize)]
pub struct Claims {
    pub aud: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    #[serde(default)]
    pub nbf: Option<DateTime<Utc>>,
    pub email: Option<String>,
    pub iss: String,
    pub sub: Option<String>,
}

pub type UnverifiedClaims = Claims;

// identity is the claim that we believe Fulcio uses: Depending on the issuer it is
// either a "sub" or "email" claim.
#[derive(Debug, PartialEq)]
pub enum Identity {
    Sub(String),
    Email(String),
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identity::Sub(sub) => sub.fmt(f),
            Identity::Email(email) => email.fmt(f),
        }
    }
}

/// A Sigstore token.
pub struct IdentityToken {
    original_token: String,
    claims: UnverifiedClaims,
    pub identity: Identity,
}

impl IdentityToken {
    /// Returns the **unverified** claim set for the token.
    ///
    /// The [UnverifiedClaims] returned from this method should not be used to enforce security
    /// invariants.
    pub fn unverified_claims(&self) -> &UnverifiedClaims {
        &self.claims
    }

    /// Returns whether or not this token is within its self-stated validity period.
    pub fn in_validity_period(&self) -> bool {
        let now = Utc::now();

        if let Some(nbf) = self.claims.nbf {
            nbf <= now && now < self.claims.exp
        } else {
            now < self.claims.exp
        }
    }
}

impl TryFrom<&str> for IdentityToken {
    type Error = SigstoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: [&str; 3] = value.split('.').collect::<Vec<_>>().try_into().or(Err(
            SigstoreError::IdentityTokenError("Malformed JWT".into()),
        ))?;

        let claims = base64
            .decode(parts[1])
            .or(Err(SigstoreError::IdentityTokenError(
                "Malformed JWT: Unable to decode claims".into(),
            )))?;
        let claims: Claims = serde_json::from_slice(&claims).or(Err(
            SigstoreError::IdentityTokenError("Malformed JWT: claims JSON malformed".into()),
        ))?;
        if claims.aud != "sigstore" {
            return Err(SigstoreError::IdentityTokenError(
                "Not a Sigstore JWT".into(),
            ));
        }

        // Find the identity claim that we believe Fulcio used for this token.
        // This means a few special cases and fall back on "sub" claim
        let identity = match claims.iss.as_str() {
            "https://accounts.google.com"
            | "https://oauth2.sigstore.dev/auth"
            | "https://oauth2.sigstage.dev/auth" => {
                if let Some(email) = claims.email.as_ref() {
                    Identity::Email(email.clone())
                } else {
                    return Err(SigstoreError::IdentityTokenError(
                        "Email claim not found in JWT".into(),
                    ));
                }
            }
            _ => {
                if let Some(sub) = claims.sub.as_ref() {
                    Identity::Sub(sub.clone())
                } else {
                    return Err(SigstoreError::IdentityTokenError(
                        "Sub claim not found in JWT".into(),
                    ));
                }
            }
        };

        Ok(IdentityToken {
            original_token: value.to_owned(),
            claims,
            identity,
        })
    }
}

impl From<CoreIdToken> for IdentityToken {
    fn from(value: CoreIdToken) -> Self {
        value
            .to_string()
            .as_str()
            .try_into()
            .expect("Token conversion failed")
    }
}

impl std::fmt::Display for IdentityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original_token.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn interactive_token() {
        let content = fs::read_to_string("tests/data/tokens/interactive-token.txt").unwrap();
        let identity_token = IdentityToken::try_from(content.as_str()).unwrap();
        assert_eq!(
            identity_token.claims.email,
            Some(String::from("jku@goto.fi"))
        );
        assert_eq!(
            identity_token.identity,
            Identity::Email(String::from("jku@goto.fi"))
        );
        assert_eq!(identity_token.claims.aud, "sigstore");
        assert_eq!(
            identity_token.claims.iss,
            "https://oauth2.sigstore.dev/auth"
        );
        assert_eq!(
            identity_token.claims.exp,
            DateTime::parse_from_rfc3339("2024-10-21T12:15:30Z").unwrap()
        );
    }

    #[test]
    fn github_actions_token() {
        let content = fs::read_to_string("tests/data/tokens/gha-token.txt").unwrap();
        let identity_token = IdentityToken::try_from(content.as_str()).unwrap();
        assert_eq!(identity_token.claims.email, None);
        assert_eq!(
            identity_token.claims.sub,
            Some(String::from("repo:sigstore-conformance/extremely-dangerous-public-oidc-beacon:ref:refs/heads/main"))
        );
        assert_eq!(
            identity_token.identity,
            Identity::Sub(String::from("repo:sigstore-conformance/extremely-dangerous-public-oidc-beacon:ref:refs/heads/main"))
        );
        assert_eq!(identity_token.claims.aud, "sigstore");
        assert_eq!(
            identity_token.claims.iss,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(
            identity_token.claims.exp,
            DateTime::parse_from_rfc3339("2024-10-21T07:29:49Z").unwrap()
        );
    }
}
