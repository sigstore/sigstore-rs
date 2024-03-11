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
    fs,
    io::Read,
    path::{Path, PathBuf},
};

mod constants;
mod trustroot;

use sha2::{Digest, Sha256};
use tough::TargetName;
use tracing::debug;
use webpki::types::CertificateDer;

use self::trustroot::{CertificateAuthority, TimeRange, TransparencyLogInstance, TrustedRoot};

use super::errors::{Result, SigstoreError};

pub use crate::repo::{ManualRepository, Repository};

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

        let repository =
            tough::RepositoryLoader::new(constants::SIGSTORE_ROOT, metadata_base, target_base)
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
        fn init_trusted_root(
            repository: &tough::Repository,
            checkout_dir: Option<&PathBuf>,
        ) -> Result<TrustedRoot> {
            let trusted_root_target = TargetName::new("trusted_root.json").map_err(Box::new)?;
            let local_path = checkout_dir.map(|d| d.join(trusted_root_target.raw()));

            let data = fetch_target_or_reuse_local_cache(
                repository,
                &trusted_root_target,
                local_path.as_ref(),
            )?;

            debug!("data:\n{}", String::from_utf8_lossy(&data));

            Ok(serde_json::from_slice(&data[..])?)
        }

        if let Some(root) = self.trusted_root.get() {
            return Ok(root);
        }

        let root = init_trusted_root(&self.repository, self.checkout_dir.as_ref())?;
        Ok(self.trusted_root.get_or_init(|| root))
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
            .filter(|key| is_timerange_valid(key.public_key.valid_for.as_ref(), false))
            .filter_map(|key| key.public_key.raw_bytes.as_ref())
            .map(|key_bytes| key_bytes.as_slice())
    }

    #[inline]
    fn ca_keys(
        cas: &[CertificateAuthority],
        allow_expired: bool,
    ) -> impl Iterator<Item = &'_ [u8]> {
        cas.iter()
            .filter(move |ca| is_timerange_valid(Some(&ca.valid_for), allow_expired))
            .flat_map(|ca| ca.cert_chain.certificates.iter())
            .map(|cert| cert.raw_bytes.as_slice())
    }
}

impl crate::repo::Repository for SigstoreRepository {
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
}

/// Given a `range`, checks that the the current time is not before `start`. If
/// `allow_expired` is `false`, also checks that the current time is not after
/// `end`.
fn is_timerange_valid(range: Option<&TimeRange>, allow_expired: bool) -> bool {
    let time = chrono::Utc::now();

    match range {
        // If there was no validity period specified, the key is always valid.
        None => true,
        // Active: if the current time is before the starting period, we are not yet valid.
        Some(range) if time < range.start => false,
        // If we want Expired keys, then the key is valid at this point.
        _ if allow_expired => true,
        // Otherwise, check that we are in range if the range has an end.
        Some(range) => match range.end {
            None => true,
            Some(end) => time <= end,
        },
    }
}

/// Download a file stored inside of a TUF repository, try to reuse a local
/// cache when possible.
///
/// * `repository`: TUF repository holding the file
/// * `target_name`: TUF representation of the file to be downloaded
/// * `local_file`: location where the file should be downloaded
///
/// This function will reuse the local copy of the file if contents
/// didn't change.
/// This check is done by comparing the digest of the local file, if found,
/// with the digest reported inside of the TUF repository metadata.
///
/// **Note well:** the `local_file` is updated whenever its contents are
/// outdated.
fn fetch_target_or_reuse_local_cache(
    repository: &tough::Repository,
    target_name: &TargetName,
    local_file: Option<&PathBuf>,
) -> Result<Vec<u8>> {
    let (local_file_outdated, local_file_contents) = if let Some(path) = local_file {
        is_local_file_outdated(repository, target_name, path)
    } else {
        Ok((true, None))
    }?;

    let data = if local_file_outdated {
        let data = fetch_target(repository, target_name)?;
        if let Some(path) = local_file {
            // update the local file to have latest data from the TUF repo
            fs::write(path, data.clone())?;
        }
        data
    } else {
        local_file_contents
            .expect("local file contents to not be 'None'")
            .as_bytes()
            .to_owned()
    };

    Ok(data)
}

/// Download a file from a TUF repository
fn fetch_target(repository: &tough::Repository, target_name: &TargetName) -> Result<Vec<u8>> {
    let data: Vec<u8>;
    match repository.read_target(target_name).map_err(Box::new)? {
        None => Err(SigstoreError::TufTargetNotFoundError(
            target_name.raw().to_string(),
        )),
        Some(reader) => {
            data = read_to_end(reader)?;
            Ok(data)
        }
    }
}

/// Compares the checksum of a local file, with the digest reported inside of
/// TUF repository metadata
fn is_local_file_outdated(
    repository: &tough::Repository,
    target_name: &TargetName,
    local_file: &Path,
) -> Result<(bool, Option<String>)> {
    let target = repository
        .targets()
        .signed
        .targets
        .get(target_name)
        .ok_or_else(|| SigstoreError::TufTargetNotFoundError(target_name.raw().to_string()))?;

    if local_file.exists() {
        let data = fs::read_to_string(local_file)?;
        let local_checksum = Sha256::digest(data.clone());
        let expected_digest: Vec<u8> = target.hashes.sha256.to_vec();

        if local_checksum.as_slice() == expected_digest.as_slice() {
            // local data is not outdated
            Ok((false, Some(data)))
        } else {
            Ok((true, None))
        }
    } else {
        Ok((true, None))
    }
}

/// Gets the goods from a read and makes a Vec
fn read_to_end<R: Read>(mut reader: R) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v)?;
    Ok(v)
}
