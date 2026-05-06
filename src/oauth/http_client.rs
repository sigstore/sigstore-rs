//
// Copyright 2026 The Sigstore Authors.
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

/// Adapter to use reqwest as the HTTP client for openidconnect/oauth2.
///
/// The `openidconnect` crate defines HTTP client traits (`AsyncHttpClient`,
/// `SyncHttpClient`) that are HTTP-client-agnostic. This module provides
/// implementations backed by the `reqwest` version used by this crate,
/// avoiding the need to pull in a second copy of reqwest via openidconnect's
/// built-in support.
use std::{future::Future, pin::Pin};

use openidconnect::{
    AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse, SyncHttpClient, http,
};

/// A wrapper around [`reqwest::Client`] that implements [`AsyncHttpClient`]
/// for use with the `openidconnect` crate.
pub(crate) struct AsyncReqwestClient(pub reqwest::Client);

impl<'c> AsyncHttpClient<'c> for AsyncReqwestClient {
    type Error = HttpClientError<reqwest::Error>;

    #[cfg(target_arch = "wasm32")]
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;
    #[cfg(not(target_arch = "wasm32"))]
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self
                .0
                .execute(request.try_into().map_err(Box::new)?)
                .await
                .map_err(Box::new)?;

            let mut builder = http::Response::builder().status(response.status());

            #[cfg(not(target_arch = "wasm32"))]
            {
                builder = builder.version(response.version());
            }

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            builder
                .body(response.bytes().await.map_err(Box::new)?.to_vec())
                .map_err(HttpClientError::Http)
        })
    }
}

/// A wrapper around [`reqwest::blocking::Client`] that implements [`SyncHttpClient`]
/// for use with the `openidconnect` crate.
///
/// Not available on `wasm32` targets.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct SyncReqwestClient(pub reqwest::blocking::Client);

#[cfg(not(target_arch = "wasm32"))]
impl SyncHttpClient for SyncReqwestClient {
    type Error = HttpClientError<reqwest::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let response = self
            .0
            .execute(request.try_into().map_err(Box::new)?)
            .map_err(Box::new)?;

        let mut builder = http::Response::builder()
            .status(response.status())
            .version(response.version());

        for (name, value) in response.headers().iter() {
            builder = builder.header(name, value);
        }

        builder
            .body(response.bytes().map_err(Box::new)?.to_vec())
            .map_err(HttpClientError::Http)
    }
}
