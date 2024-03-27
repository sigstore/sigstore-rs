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
    pub email: String,
}

pub type UnverifiedClaims = Claims;

/// A Sigstore token.
pub struct IdentityToken {
    original_token: String,
    claims: UnverifiedClaims,
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

        Ok(IdentityToken {
            original_token: value.to_owned(),
            claims,
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
