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

//! Helper Structs to interact with the Sigstore TUF repository.
//!
//! The main interaction point is [`SigstoreRepository`], which fetches Rekor's
//! public key and Fulcio's certificate.
//!
//! These can later be given to [`cosign::ClientBuilder`](crate::cosign::ClientBuilder)
//! to enable Fulcio and Rekor integrations.
//!
//! # Example
//!
//! The `SigstoreRepository` instance can be created via the [`SigstoreRepository::prefetch`]
//! method.
//!
//! ```rust,no_run
//! use sigstore::tuf::SigstoreRepository;
//! let repo = SigstoreRepository::new(None).unwrap().prefetch().unwrap();
//! ```
use std::{
    cell::OnceCell,
    io::Read,
    path::{Path, PathBuf},
};

mod constants;

use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::TimeRange,
    trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
};
use tough::TargetName;
use tracing::debug;
use webpki::types::CertificateDer;

use super::errors::{Result, SigstoreError};

/// A `Repository` owns all key material necessary for establishing a root of trust.
pub trait Repository {
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer>>;
    fn rekor_keys(&self) -> Result<Vec<&[u8]>>;
    fn ctfe_keys(&self) -> Result<Vec<&[u8]>>;
}

/// A `ManualRepository` is a [Repository] with out-of-band trust materials.
/// As it does not establish a trust root with TUF, users must initialize its materials themselves.
#[derive(Debug, Default)]
pub struct ManualRepository<'a> {
    pub fulcio_certs: Option<Vec<CertificateDer<'a>>>,
    pub rekor_key: Option<Vec<u8>>,
    pub ctfe_keys: Option<Vec<Vec<u8>>>,
}

impl Repository for ManualRepository<'_> {
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer>> {
        Ok(match &self.fulcio_certs {
            Some(certs) => certs.clone(),
            None => Vec::new(),
        })
    }

    fn rekor_keys(&self) -> Result<Vec<&[u8]>> {
        Ok(match &self.rekor_key {
            Some(key) => vec![&key[..]],
            None => Vec::new(),
        })
    }

    fn ctfe_keys(&self) -> Result<Vec<&[u8]>> {
        Ok(match &self.ctfe_keys {
            Some(keys) => keys.iter().map(|v| &v[..]).collect(),
            None => Vec::new(),
        })
    }
}

/// Securely fetches Rekor public key and Fulcio certificates from Sigstore's TUF repository.
#[derive(Debug)]
pub struct SigstoreRepository {
    repository: tough::Repository,
    checkout_dir: Option<PathBuf>,
    trusted_root: OnceCell<TrustedRoot>,
}

impl SigstoreRepository {
    /// Constructs a new trust repository established by a [tough::Repository].
    pub fn new(checkout_dir: Option<&Path>) -> Result<Self> {
        // These are statically defined and should always parse correctly.
        let metadata_base = url::Url::parse(constants::SIGSTORE_METADATA_BASE)?;
        let target_base = url::Url::parse(constants::SIGSTORE_TARGET_BASE)?;

        let repository = tough::RepositoryLoader::new(
            constants::static_resource("root.json").expect("Failed to fetch required resource!"),
            metadata_base,
            target_base,
        )
        .expiration_enforcement(tough::ExpirationEnforcement::Safe)
        .load()
        .map_err(Box::new)?;

        Ok(Self {
            repository,
            checkout_dir: checkout_dir.map(ToOwned::to_owned),
            trusted_root: OnceCell::default(),
        })
    }

    fn trusted_root(&self) -> Result<&TrustedRoot> {
        return if let Some(root) = self.trusted_root.get() {
            Ok(root)
        } else {
            let data = self.fetch_target("trusted_root.json")?;

            debug!("data:\n{}", String::from_utf8_lossy(&data));

            let root = serde_json::from_slice(&data[..])?;

            Ok(self.trusted_root.get_or_init(|| root))
        };
    }

    fn fetch_target<N>(&self, name: N) -> Result<Vec<u8>>
    where
        N: TryInto<TargetName, Error = tough::error::Error>,
    {
        let read_remote_target = |name: &TargetName| -> Result<Vec<u8>> {
            let Some(mut reader) = self.repository.read_target(name).map_err(Box::new)? else {
                return Err(SigstoreError::TufTargetNotFoundError(name.raw().to_owned()));
            };

            debug!("fetching target {} from remote", name.raw());

            let mut repo_data = Vec::new();
            reader.read_to_end(&mut repo_data)?;
            Ok(repo_data)
        };

        let name: TargetName = name.try_into().map_err(Box::new)?;
        let local_path = self.checkout_dir.as_ref().map(|d| d.join(name.raw()));

        // Try reading the target from disk cache.
        let data = if let Some(Ok(local_data)) = local_path.as_ref().map(std::fs::read) {
            local_data.to_vec()
        // Try reading the target embedded into the binary.
        } else if let Some(embedded_data) = constants::static_resource(name.raw()) {
            debug!("read embedded target {}", name.raw());
            embedded_data.to_vec()
        // If all else fails, read the data from the TUF repo.
        } else if let Ok(remote_data) = read_remote_target(&name) {
            remote_data
        } else {
            return Err(SigstoreError::TufTargetNotFoundError(name.raw().to_owned()));
        };

        // Get metadata (hash) of the target and update the disk copy if it doesn't match.
        let Some(target) = self.repository.targets().signed.targets.get(&name) else {
            return Err(SigstoreError::TufMetadataError(format!(
                "couldn't get metadata for {}",
                name.raw()
            )));
        };

        let data = if Sha256::digest(&data)[..] != target.hashes.sha256[..] {
            read_remote_target(&name)?
        } else {
            data
        };

        // Write the up-to-date data back to the disk. This doesn't need to succeed, as we can
        // always fetch the target again later.
        if let Some(local_path) = local_path {
            let _ = std::fs::write(local_path, &data);
        }

        Ok(data)
    }

    /// Prefetches trust materials.
    ///
    /// [Repository::fulcio_certs()] and [Repository::rekor_keys()] on [SigstoreRepository] lazily
    /// fetches the requested data, which is problematic for async callers. Those callers should
    /// use this method to fetch the trust root ahead of time.
    ///
    /// ```rust
    /// # use tokio::task::spawn_blocking;
    /// # use sigstore::tuf::SigstoreRepository;
    /// # use sigstore::errors::Result;
    /// # #[tokio::main]
    /// # async fn main() -> std::result::Result<(), anyhow::Error> {
    /// let repo: Result<SigstoreRepository> = spawn_blocking(|| Ok(SigstoreRepository::new(None)?.prefetch()?)).await?;
    /// // Now, get Fulcio and Rekor trust roots with the returned `SigstoreRepository`
    /// # Ok(())
    /// # }
    /// ```
    pub fn prefetch(self) -> Result<Self> {
        let _ = self.trusted_root()?;
        Ok(self)
    }

    #[inline]
    fn tlog_keys(tlogs: &[TransparencyLogInstance]) -> impl Iterator<Item = &[u8]> {
        tlogs
            .iter()
            .filter_map(|tlog| tlog.public_key.as_ref())
            .filter(|key| is_timerange_valid(key.valid_for.as_ref(), false))
            .filter_map(|key| key.raw_bytes.as_ref())
            .map(|key_bytes| key_bytes.as_slice())
    }

    #[inline]
    fn ca_keys(
        cas: &[CertificateAuthority],
        allow_expired: bool,
    ) -> impl Iterator<Item = &'_ [u8]> {
        cas.iter()
            .filter(move |ca| is_timerange_valid(ca.valid_for.as_ref(), allow_expired))
            .flat_map(|ca| ca.cert_chain.as_ref())
            .flat_map(|chain| chain.certificates.iter())
            .map(|cert| cert.raw_bytes.as_slice())
    }
}

impl Repository for SigstoreRepository {
    /// Fetch Fulcio certificates from the given TUF repository or reuse
    /// the local cache if its contents are not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    ///
    /// **Warning:** this method needs special handling when invoked from
    /// an async function because it performs blocking operations.
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer>> {
        let root = self.trusted_root()?;

        // Allow expired certificates: they may have been active when the
        // certificate was used to sign.
        let certs = Self::ca_keys(&root.certificate_authorities, true);
        let certs: Vec<_> = certs.map(CertificateDer::from).collect();

        if certs.is_empty() {
            Err(SigstoreError::TufMetadataError(
                "Fulcio certificates not found".into(),
            ))
        } else {
            Ok(certs)
        }
    }

    /// Fetch Rekor public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    ///
    /// **Warning:** this method needs special handling when invoked from
    /// an async function because it performs blocking operations.
    fn rekor_keys(&self) -> Result<Vec<&[u8]>> {
        let root = self.trusted_root()?;
        let keys: Vec<_> = Self::tlog_keys(&root.tlogs).collect();

        if keys.len() != 1 {
            Err(SigstoreError::TufMetadataError(
                "Did not find exactly 1 active Rekor key".into(),
            ))
        } else {
            Ok(keys)
        }
    }

    /// Fetch CTFE public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    ///
    /// **Warning:** this method needs special handling when invoked from
    /// an async function because it performs blocking operations.
    fn ctfe_keys(&self) -> Result<Vec<&[u8]>> {
        let root = self.trusted_root()?;
        let keys: Vec<_> = Self::tlog_keys(&root.ctlogs).collect();

        if keys.is_empty() {
            Err(SigstoreError::TufMetadataError(
                "CTFE keys not found".into(),
            ))
        } else {
            Ok(keys)
        }
    }
}

/// Given a `range`, checks that the the current time is not before `start`. If
/// `allow_expired` is `false`, also checks that the current time is not after
/// `end`.
fn is_timerange_valid(range: Option<&TimeRange>, allow_expired: bool) -> bool {
    let now = chrono::Utc::now().timestamp();

    let start = range.and_then(|r| r.start.as_ref()).map(|t| t.seconds);
    let end = range.and_then(|r| r.end.as_ref()).map(|t| t.seconds);

    match (start, end) {
        // If there was no validity period specified, the key is always valid.
        (None, _) => true,
        // Active: if the current time is before the starting period, we are not yet valid.
        (Some(start), _) if now < start => false,
        // If we want Expired keys, then we don't need to check the end.
        _ if allow_expired => true,
        // If there is no expiry date, the key is valid.
        (_, None) => true,
        // If we have an expiry date, check it.
        (_, Some(end)) => now <= end,
    }
}
