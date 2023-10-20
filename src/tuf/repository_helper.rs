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

use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tough::{RepositoryLoader, TargetName};
use url::Url;

use super::super::errors::{Result, SigstoreError};
use super::trustroot::{CertificateAuthority, TimeRange, TransparencyLogInstance, TrustedRoot};

pub(crate) struct RepositoryHelper {
    repository: tough::Repository,
    checkout_dir: Option<PathBuf>,
    trusted_root: Option<TrustedRoot>,
}

impl RepositoryHelper {
    pub(crate) fn new<R>(
        root: R,
        metadata_base: Url,
        target_base: Url,
        checkout_dir: Option<&Path>,
    ) -> Result<Self>
    where
        R: Read,
    {
        let repository = RepositoryLoader::new(SIGSTORE_ROOT, metadata_base, target_base)
            .expiration_enforcement(tough::ExpirationEnforcement::Safe)
            .load()
            .map_err(Box::new)?;

        Ok(Self {
            repository,
            checkout_dir: checkout_dir.map(|s| s.to_owned()),
            trusted_root: None,
        })
    }

    pub(crate) fn from_repo(repo: tough::Repository, checkout_dir: Option<&Path>) -> Self {
        Self {
            repository: repo,
            checkout_dir: checkout_dir.map(|s| s.to_owned()),
            trusted_root: None,
        }
    }

    fn trusted_root(&self) -> Result<&TrustedRoot> {
        if let Some(result) = self.trusted_root {
            return Ok(&result);
        }

        let trusted_root_target = TargetName::new("trusted_root.json").map_err(Box::new)?;
        let local_path = self
            .checkout_dir
            .as_ref()
            .map(|d| d.join(trusted_root_target.raw()));

        let data = fetch_target_or_reuse_local_cache(
            &self.repository,
            &trusted_root_target,
            local_path.as_ref(),
        )?;

        let result = serde_json::from_slice(&data[..])?;
        Ok(self.trusted_root.insert(result))
    }

    #[inline]
    fn tlog_keys(&self, tlogs: &Vec<TransparencyLogInstance>) -> Vec<&[u8]> {
        let mut result = Vec::new();

        for key in tlogs {
            // We won't accept expired keys for transparency logs.
            if !is_timerange_valid(key.public_key.valid_for, false) {
                continue;
            }

            if let Some(raw) = key.public_key.raw_bytes {
                result.push(&raw[..]);
            }
        }

        result
    }

    #[inline]
    fn ca_keys(&self, cas: &Vec<CertificateAuthority>, allow_expired: bool) -> Vec<&[u8]> {
        let mut certs = Vec::new();

        for ca in cas {
            if !is_timerange_valid(Some(ca.valid_for), allow_expired) {
                continue;
            }

            let certs_in_ca = ca.cert_chain.certificates;
            certs.extend(certs_in_ca.iter().map(|cert| &cert.raw_bytes[..]));
        }

        return certs;
    }

    /// Fetch Fulcio certificates from the given TUF repository or reuse
    /// the local cache if its contents are not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    pub(crate) fn fulcio_certs(&self) -> Result<Vec<CertificateDer>> {
        let root = self.trusted_root()?;

        // Allow expired certificates: they may have been active when the
        // certificate was used to sign.
        let certs = self.ca_keys(&root.certificate_authorities, true);
        let certs: Vec<_> = certs.iter().map(|v| CertificateDer::from(*v)).collect();

        if certs.is_empty() {
            Err(SigstoreError::TufMetadataError(
                "Fulcio certificates not found",
            ))
        } else {
            Ok(certs)
        }
    }

    /// Fetch Rekor public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    pub(crate) fn rekor_keys(&self) -> Result<Vec<&[u8]>> {
        let root = self.trusted_root()?;
        let keys = self.tlog_keys(&root.tlogs);

        if keys.len() != 1 {
            Err(SigstoreError::TufMetadataError(
                "Did not find exactly 1 active Rekor key",
            ))
        } else {
            Ok(keys)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::*;
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Returns the path to our test data directory
    fn test_data() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
    }

    fn local_tuf_repo() -> Result<tough::Repository> {
        let metadata_base_path = test_data().join("repository");
        let targets_base_path = metadata_base_path.join("targets");

        let metadata_base_url = format!(
            "file://{}",
            metadata_base_path
                .to_str()
                .ok_or_else(|| SigstoreError::UnexpectedError(String::from(
                    "Cannot convert metadata_base_path into a str"
                )))?
        );
        let metadata_base_url = url::Url::parse(&metadata_base_url).map_err(|_| {
            SigstoreError::UnexpectedError(String::from(
                "Cannot convert metadata_base_url into a URL",
            ))
        })?;

        let target_base_url = format!(
            "file://{}",
            targets_base_path
                .to_str()
                .ok_or_else(|| SigstoreError::UnexpectedError(String::from(
                    "Cannot convert targets_base_path into a str"
                )))?
        );
        let target_base_url = url::Url::parse(&target_base_url).map_err(|_| {
            SigstoreError::UnexpectedError(String::from(
                "Cannot convert targets_base_url into a URL",
            ))
        })?;
        // It's fine to ignore timestamp.json expiration inside of test env
        let repo = RepositoryLoader::new(SIGSTORE_ROOT, metadata_base_url, target_base_url)
            .expiration_enforcement(tough::ExpirationEnforcement::Unsafe)
            .load()
            .map_err(Box::new)?;
        Ok(repo)
    }

    fn find_target(name: &str) -> Result<PathBuf> {
        let path = test_data().join("repository").join("targets");

        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.is_dir() {
                continue;
            }

            // Heuristic: Filter for consistent snapshot targets. SHA256 hashes in hexadecimal
            // comprise of 64 characters, so our filename must be at least that long. The TUF repo
            // shouldn't ever contain paths with invalid Unicode (knock on wood), so we're doing
            // the lossy OsStr conversion here.
            let filename = path.file_name().unwrap().to_str().unwrap();
            if filename.len() < 64 {
                continue;
            }

            // Heuristic: see if the filename is in consistent snapshot format (<hash>.<name>).
            // NB: The consistent snapshot prefix should be ASCII, so indexing the string as
            // bytes is safe enough.
            if filename.as_bytes()[64] != b'.' {
                continue;
            }

            // At this point, we're probably dealing with a consistent snapshot.
            // Check if the name matches.
            if filename.ends_with(name) {
                return Ok(path);
            }
        }

        Err(SigstoreError::UnexpectedError(
            "Couldn't find a matching target".to_string(),
        ))
    }

    fn check_against_disk(helper: &RepositoryHelper) {
        let mut actual: Vec<&[u8]> = helper
            .fulcio_certs()
            .expect("fulcio certs could not be read")
            .iter()
            .map(|c| c.as_ref())
            .collect();
        let expected = ["fulcio.crt.pem", "fulcio_v1.crt.pem"].iter().map(|t| {
            let path = find_target(t)?;
            Ok(fs::read(path)?)
        });
        let mut expected = expected
            .collect::<Result<Vec<Vec<_>>>>()
            .expect("could not find targets");
        actual.sort();
        expected.sort();

        assert_eq!(actual, expected, "The fulcio cert is not what was expected");

        let actual = helper.rekor_keys().expect("rekor key cannot be read");
        let expected = fs::read(find_target("rekor.pub").expect("could not find targets"))
            .expect("cannot read rekor key from test data");
        let expected = pem::parse(expected).unwrap();
        assert_eq!(expected.tag(), "PUBLIC KEY");

        assert_eq!(
            actual,
            &[expected.contents()],
            "The rekor key is not what was expected"
        );
    }

    #[test]
    fn get_files_without_using_local_cache() {
        let repository = local_tuf_repo().expect("Local TUF repo should not fail");
        let helper = RepositoryHelper {
            repository,
            checkout_dir: None,
            trusted_root: None,
        };

        check_against_disk(&helper);
    }

    #[test]
    fn download_files_to_local_cache() {
        let cache_dir = TempDir::new().expect("Cannot create temp cache dir");

        let repository = local_tuf_repo().expect("Local TUF repo should not fail");
        let helper = RepositoryHelper {
            repository,
            checkout_dir: Some(cache_dir.path().to_path_buf()),
            trusted_root: None,
        };

        check_against_disk(&helper);
    }

    #[test]
    fn update_local_cache() {
        let cache_dir = TempDir::new().expect("Cannot create temp cache dir");

        // put some outdated files inside of the cache
        for filename in &["fulcio.crt.pem", "fulcio_v1.crt.pem"] {
            fs::write(cache_dir.path().join(filename), b"fake fulcio")
                .expect("Cannot write file to cache dir");
        }
        fs::write(
            cache_dir.path().join("trusted_root.json"),
            b"fake trusted root",
        )
        .expect("Cannot write file to cache dir");

        let repository = local_tuf_repo().expect("Local TUF repo should not fail");
        let helper = RepositoryHelper {
            repository,
            checkout_dir: Some(cache_dir.path().to_path_buf()),
            trusted_root: None,
        };

        check_against_disk(&helper);
    }

    #[test]
    fn deser_trusted_root() {
        let metadata_base_path = test_data().join("repository");
        let targets_base_path = metadata_base_path.join("targets");

        let repository = local_tuf_repo().expect("Local TUF repo should not fail");
        let helper = RepositoryHelper::from_repo(repository, None);

        helper
            .trusted_root()
            .expect("Trusted Root should deserialize");
    }
}
