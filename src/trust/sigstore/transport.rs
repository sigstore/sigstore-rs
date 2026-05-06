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

//! A [`tough::Transport`] implementation backed by `reqwest` (0.13).
//!
//! This replaces tough's built-in `HttpTransport` (which depends on reqwest 0.12)
//! so that the entire crate uses a single version of reqwest.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_util::Stream;
use reqwest::Client;
use tough::{
    Bytes, FilesystemTransport, Transport, TransportError, TransportErrorKind, TransportStream,
};
use url::Url;

/// A [`Transport`] that fetches over HTTP(S) using `reqwest` 0.13 and
/// delegates `file://` URLs to [`FilesystemTransport`].
#[derive(Clone, Debug)]
pub(crate) struct ReqwestTransport {
    client: Client,
    file: FilesystemTransport,
}

impl ReqwestTransport {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            file: FilesystemTransport,
        }
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        match url.scheme() {
            "file" => self.file.fetch(url).await,
            "http" | "https" => {
                let response = self
                    .client
                    .get(url.as_str())
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                    .map_err(|e| {
                        let kind = match e.status() {
                            Some(s)
                                if s == reqwest::StatusCode::NOT_FOUND
                                    || s == reqwest::StatusCode::FORBIDDEN
                                    || s == reqwest::StatusCode::GONE =>
                            {
                                TransportErrorKind::FileNotFound
                            }
                            _ => TransportErrorKind::Other,
                        };
                        TransportError::new_with_cause(kind, url.clone(), e)
                    })?;

                Ok(Box::pin(BytesStreamAdapter {
                    inner: Box::pin(response.bytes_stream()),
                    url,
                }))
            }
            _ => Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url,
            )),
        }
    }
}

/// Adapts `reqwest::Response::bytes_stream()` into a [`TransportStream`] by
/// mapping `reqwest::Error` to `TransportError`.
struct BytesStreamAdapter {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + Sync>>,
    url: Url,
}

impl Stream for BytesStreamAdapter {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx).map(|opt| {
            opt.map(|result| {
                result.map_err(|e| {
                    TransportError::new_with_cause(TransportErrorKind::Other, self.url.clone(), e)
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use tough::IntoVec;

    fn transport() -> ReqwestTransport {
        ReqwestTransport::new(Client::new())
    }

    #[tokio::test]
    async fn unsupported_scheme() {
        let url = Url::parse("ftp://example.com/file.txt").expect("failed to parse URL");
        let err = transport()
            .fetch(url)
            .await
            .err()
            .expect("expected an error");
        assert_eq!(err.kind(), TransportErrorKind::UnsupportedUrlScheme);
    }

    #[tokio::test]
    async fn file_not_found_on_disk() {
        let url = Url::parse("file:///nonexistent/path/to/file.txt").expect("failed to parse URL");
        let err = transport()
            .fetch(url)
            .await
            .err()
            .expect("expected an error");
        assert_eq!(err.kind(), TransportErrorKind::FileNotFound);
    }

    #[tokio::test]
    async fn file_found_on_disk() {
        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        tmp.write_all(b"hello transport")
            .expect("failed to write to temp file");
        let url = Url::from_file_path(tmp.path()).expect("failed to build file URL");
        let stream = transport().fetch(url).await.expect("fetch failed");
        let body = stream.into_vec().await.expect("failed to read stream");
        assert_eq!(body, b"hello transport");
    }
}
