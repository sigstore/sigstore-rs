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

//! Helper structs to interact with the Sigstore TUF repository.
//!
//! The main interaction point is [`SigstoreTrustRoot`], which fetches Rekor's
//! public key and Fulcio's certificate.
//!
//! These can later be given to [`cosign::ClientBuilder`](crate::cosign::ClientBuilder)
//! to enable Fulcio and Rekor integrations.
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig;
use std::{fmt::Debug, path::PathBuf};
use tokio_util::bytes::BytesMut;
use tough::TargetName;
use tracing::debug;

use super::{BundledTrustRoot, Result, TrustConfig, TrustRootError};

macro_rules! trust_root_resource {
    ($dir:literal, $match_on:ident) => {
        trust_root_resource!(@with_resources $dir, $match_on, [
            "root.json",
            "trusted_root.json",
            "signing_config.json",
        ])
    };
    (@with_resources $dir:literal, $match_on:ident, [$($rsrc:literal,)+]) => {
        match $match_on.as_ref() {
        $(
            $rsrc => Some(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/trust_root/",
                $dir,
                "/",
                $rsrc
            )))
        ),+,
            _ => None,
        }
    };
}

/// Configuration used in fetching the root of trust.
#[derive(Default, Debug)]
pub struct TrustRootOptions {
    /// A directory for caching the root of trust and related artifacts. If `None`, the caching
    /// mechanism is disabled.
    pub cache_dir: Option<PathBuf>,
}

#[derive(thiserror::Error, Debug)]
pub enum RootUpdateError {
    #[error("TUF target not found")]
    NotFound,

    #[error("failed to parse target data: {0}")]
    Parse(#[source] serde_json::Error),

    #[error("TUF returned error on repository fetch: {0}")]
    Fetch(#[source] tough::error::Error),

    #[error("failed to cache target: {0}")]
    Cache(#[source] std::io::Error),
}

type UpdateResult<T> = std::result::Result<T, RootUpdateError>;

/// An instance of the Sigstore Public Good Infrastructure.
#[derive(Copy, Clone, Debug)]
pub enum Instance {
    Prod,
    Staging,
}

impl Instance {
    /// Returns the [`TrustConfig`] of the Sigstore instance, which encapsulates all data necessary
    /// for Sigstore signing ([`SigningConfig`]) and verification ([`BundledTrustRoot`]).
    pub async fn trust_config(
        &self,
        trust_root_options: TrustRootOptions,
    ) -> Result<TrustConfig<BundledTrustRoot>> {
        let tuf_url: url::Url = match self {
            Instance::Prod => "https://tuf-repo-cdn.sigstore.dev",
            Instance::Staging => "https://tuf-repo-cdn.sigstage.dev",
        }
        .parse()
        .expect("failed to parse constant URL!");

        let targets_url = tuf_url
            .clone()
            .join("targets")
            .expect("failed to construct constant URL!");

        let tuf_root = &self
            .static_resource("root.json")
            .expect("failed to fetch embedded TUF root!");

        let repository = tough::RepositoryLoader::new(tuf_root, tuf_url, targets_url)
            .expiration_enforcement(tough::ExpirationEnforcement::Safe)
            .load()
            .await
            .map_err(|e| TrustRootError::RootUpdate(RootUpdateError::Fetch(e)))?;

        let trust_root = BundledTrustRoot::from_tough(trust_root_options, &repository, |name| {
            self.static_resource(name)
        })
        .await?;

        let signing_config: SigningConfig = {
            let data = self
                .static_resource("signing_config.json")
                .expect("failed to read static signing config!");
            serde_json::from_slice(data).expect("failed to parse static signing config!")
        };

        Ok(TrustConfig {
            trust_root,
            signing_config,
        })
    }

    #[inline]
    pub fn static_resource<N>(&self, name: N) -> Option<&'static [u8]>
    where
        N: AsRef<str>,
    {
        match self {
            Instance::Prod => trust_root_resource!("prod", name),
            Instance::Staging => trust_root_resource!("staging", name),
        }
    }
}

/// Securely fetches Rekor public key and Fulcio certificates from Sigstore's TUF repository.
impl BundledTrustRoot {
    /// Constructs a new trust root from a [`tough::Repository`].
    async fn from_tough<F>(
        options: TrustRootOptions,
        repository: &tough::Repository,
        static_reader: F,
    ) -> UpdateResult<Self>
    where
        F: Fn(&str) -> Option<&'static [u8]>,
    {
        let TrustRootOptions { cache_dir } = options;
        let trusted_root =
            Self::fetch_target(cache_dir, static_reader, repository, "trusted_root.json")
                .await
                .map(|x: Vec<u8>| serde_json::from_slice(&x[..]))?
                .map_err(RootUpdateError::Parse)?;

        Ok(Self { trusted_root })
    }

    async fn fetch_target<N, F>(
        cache_dir: Option<PathBuf>,
        static_reader: F,
        repository: &tough::Repository,
        name: N,
    ) -> UpdateResult<Vec<u8>>
    where
        F: Fn(&str) -> Option<&'static [u8]>,
        N: TryInto<TargetName, Error = tough::error::Error>,
    {
        let name: TargetName = name.try_into().map_err(RootUpdateError::Fetch)?;
        let local_path = cache_dir.as_ref().map(|d| d.join(name.raw()));

        let read_remote_target = || async {
            match repository.read_target(&name).await {
                Ok(Some(s)) => Ok(s
                    .try_collect::<BytesMut>()
                    .await
                    .map_err(RootUpdateError::Fetch)?),
                Err(e) => Err(RootUpdateError::Fetch(e)),
                _ => Err(RootUpdateError::NotFound),
            }
        };

        // First, try reading the target from disk cache.
        let data = if let Some(Ok(local_data)) = local_path.as_ref().map(std::fs::read) {
            debug!("{}: reading from disk cache", name.raw());
            local_data.to_vec()
        // Try reading the target embedded into the binary.
        } else if let Some(embedded_data) = static_reader(name.raw()) {
            debug!("{}: reading from embedded resources", name.raw());
            embedded_data.to_vec()
        // If all else fails, read the data from the TUF repo.
        } else if let Ok(remote_data) = read_remote_target().await {
            debug!("{}: reading from remote", name.raw());
            remote_data.to_vec()
        } else {
            return Err(RootUpdateError::NotFound);
        };

        // Get metadata (hash) of the target and update the disk copy if it doesn't match.
        let Some(target) = repository.targets().signed.targets.get(&name) else {
            return Err(RootUpdateError::NotFound);
        };

        let data = if Sha256::digest(&data)[..] != target.hashes.sha256[..] {
            debug!("{}: out of date", name.raw());
            read_remote_target().await?.to_vec()
        } else {
            data
        };

        // Write our updated data back to the disk.
        if let Some(local_path) = local_path {
            std::fs::write(local_path, &data).map_err(RootUpdateError::Cache)?;
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::trust::TrustRoot;

    use super::*;
    use rstest::{fixture, rstest};
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn verify(root: &BundledTrustRoot, cache_dir: Option<&Path>) {
        if let Some(cache_dir) = cache_dir {
            assert!(
                cache_dir.join("trusted_root.json").exists(),
                "the trusted root was not cached"
            );
        }

        assert!(root.ca_certs().is_ok(), "no Fulcio certs established");
        assert!(root.tlog_keys().is_ok(), "no Rekor keys established");
        assert!(root.ctfe_keys().is_ok(), "no CTFE keys established");
    }

    #[fixture]
    fn cache_dir() -> TempDir {
        TempDir::new().expect("cannot create temp cache dir")
    }

    async fn trust_root(cache: Option<&Path>) -> BundledTrustRoot {
        let trust_config = Instance::Prod
            .trust_config(TrustRootOptions {
                cache_dir: cache.map(|p| p.to_owned()),
            })
            .await
            .expect("failed to construct prod trust config");

        trust_config.trust_root
    }

    #[rstest]
    #[tokio::test]
    async fn trust_root_fetch(#[values(None, Some(cache_dir()))] cache: Option<TempDir>) {
        let cache = cache.as_ref().map(|t| t.path());
        let root = trust_root(cache).await;

        verify(&root, cache);
    }

    #[rstest]
    #[tokio::test]
    async fn trust_root_outdated(cache_dir: TempDir) {
        let trusted_root_path = cache_dir.path().join("trusted_root.json");
        let outdated_data = b"fake trusted root";
        fs::write(&trusted_root_path, outdated_data)
            .expect("failed to write to trusted root cache");

        let cache = Some(cache_dir.path());
        let root = trust_root(cache).await;
        verify(&root, cache);

        let data = fs::read(&trusted_root_path).expect("failed to read from trusted root cache");
        assert_ne!(data, outdated_data, "TUF cache was not properly updated");
    }
}
