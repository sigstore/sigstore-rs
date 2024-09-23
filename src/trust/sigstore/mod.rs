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
//! The main interaction point is [`SigstoreTrustRoot`], which fetches Rekor's
//! public key and Fulcio's certificate.
//!
//! These can later be given to [`cosign::ClientBuilder`](crate::cosign::ClientBuilder)
//! to enable Fulcio and Rekor integrations.
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio_util::bytes::BytesMut;

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::TimeRange,
    trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
};
use tough::TargetName;
use tracing::debug;
use webpki::types::CertificateDer;

mod constants;

use crate::errors::{Result, SigstoreError};
pub use crate::trust::{ManualTrustRoot, TrustRoot};

/// Securely fetches Rekor public key and Fulcio certificates from Sigstore's TUF repository.
#[derive(Debug)]
pub struct SigstoreTrustRoot {
    trusted_root: TrustedRoot,
}

pub enum TargetType {
    Authority(CertificateAuthority),
    Log(TransparencyLogInstance),
}
pub enum Target {
    CertificateAuthority,
    TimestampAuthority,
    Ctlog,
    Tlog,
}
impl SigstoreTrustRoot {
    // Needed to construct SigstoreTrustRoot from trusted_root.json
    pub fn from_trusted_root(trusted_root: TrustedRoot) -> Self {
        SigstoreTrustRoot { trusted_root }
    }
    /// Constructs a new trust root from a [`tough::Repository`].
    async fn from_tough(
        repository: &tough::Repository,
        checkout_dir: Option<&Path>,
    ) -> Result<Self> {
        let trusted_root = {
            let data = Self::fetch_target(repository, checkout_dir, "trusted_root.json").await?;
            serde_json::from_slice(&data[..])?
        };

        Ok(Self { trusted_root })
    }

    /// Constructs a new trust root backed by the Sigstore Public Good Instance.
    pub async fn new(cache_dir: Option<&Path>) -> Result<Self> {
        // These are statically defined and should always parse correctly.
        let metadata_base = url::Url::parse(constants::SIGSTORE_METADATA_BASE)?;
        let target_base = url::Url::parse(constants::SIGSTORE_TARGET_BASE)?;

        let repository = tough::RepositoryLoader::new(
            &constants::static_resource("root.json").expect("Failed to fetch embedded TUF root!"),
            metadata_base,
            target_base,
        )
        .expiration_enforcement(tough::ExpirationEnforcement::Safe)
        .load()
        .await
        .map_err(Box::new)?;

        Self::from_tough(&repository, cache_dir).await
    }

    async fn fetch_target<N>(
        repository: &tough::Repository,
        checkout_dir: Option<&Path>,
        name: N,
    ) -> Result<Vec<u8>>
    where
        N: TryInto<TargetName, Error = tough::error::Error>,
    {
        let name: TargetName = name.try_into().map_err(Box::new)?;
        let local_path = checkout_dir.as_ref().map(|d| d.join(name.raw()));

        let read_remote_target = || async {
            match repository.read_target(&name).await {
                Ok(Some(s)) => Ok(s.try_collect::<BytesMut>().await.map_err(Box::new)?),
                _ => Err(SigstoreError::TufTargetNotFoundError(name.raw().to_owned())),
            }
        };

        // First, try reading the target from disk cache.
        let data = if let Some(Ok(local_data)) = local_path.as_ref().map(std::fs::read) {
            debug!("{}: reading from disk cache", name.raw());
            local_data.to_vec()
        // Try reading the target embedded into the binary.
        } else if let Some(embedded_data) = constants::static_resource(name.raw()) {
            debug!("{}: reading from embedded resources", name.raw());
            embedded_data.to_vec()
        // If all else fails, read the data from the TUF repo.
        } else if let Ok(remote_data) = read_remote_target().await {
            debug!("{}: reading from remote", name.raw());
            remote_data.to_vec()
        } else {
            return Err(SigstoreError::TufTargetNotFoundError(name.raw().to_owned()));
        };

        // Get metadata (hash) of the target and update the disk copy if it doesn't match.
        let Some(target) = repository.targets().signed.targets.get(&name) else {
            return Err(SigstoreError::TufMetadataError(format!(
                "couldn't get metadata for {}",
                name.raw()
            )));
        };

        let data = if Sha256::digest(&data)[..] != target.hashes.sha256[..] {
            debug!("{}: out of date", name.raw());
            read_remote_target().await?.to_vec()
        } else {
            data
        };

        // Write our updated data back to the disk.
        if let Some(local_path) = local_path {
            std::fs::write(local_path, &data)?;
        }

        Ok(data)
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

    /// Save the trusted root to a file
    pub fn save_to_file(&self, file_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.trusted_root)
            .map_err(|e| SigstoreError::SerializationError(e.to_string()))?;

        std::fs::write(file_path, json).map_err(SigstoreError::from)
    }

    // Set a target in the TrustedRoot: Add or Update
    pub fn set_target(&mut self, new_target: TargetType, target_name: Target) -> Result<()> {
        match target_name {
            Target::CertificateAuthority => {
                if let TargetType::Authority(mut ca) = new_target {
                    // Check if the Certificate Authority already exists
                    let exists = self
                        .trusted_root
                        .certificate_authorities
                        .iter()
                        .any(|existing_ca| existing_ca.cert_chain == ca.cert_chain);

                    // If exists, update the Certificate Authority
                    if exists {
                        if let Some(existing_ca) = self
                            .trusted_root
                            .certificate_authorities
                            .iter_mut()
                            .find(|existing_ca| existing_ca.cert_chain == ca.cert_chain)
                        {
                            // If valid_for.start is not set; User wants to expire the target
                            if let Some(valid_for) = &mut ca.valid_for {
                                if valid_for.start.is_none() {
                                    valid_for.start = existing_ca.valid_for.clone().unwrap().start;
                                }
                            }
                            existing_ca.clone_from(&ca);
                        }
                    } else {
                        // Add the new Certificate Authority if it doesn't exist
                        if let Some(last_ca) = self.trusted_root.certificate_authorities.last_mut()
                        {
                            if let Some(valid_for) = &mut last_ca.valid_for {
                                if valid_for.end.is_none() {
                                    valid_for.end = ca.valid_for.clone().unwrap().start;
                                }
                            }
                        }
                        self.trusted_root.certificate_authorities.push(ca);
                    }
                } else {
                    return Err(SigstoreError::UnexpectedError(
                        "Expected a CertificateAuthority, but got a different target.".to_string(),
                    ));
                }
            }
            Target::TimestampAuthority => {
                if let TargetType::Authority(mut tsa) = new_target {
                    let exists = self
                        .trusted_root
                        .timestamp_authorities
                        .iter()
                        .any(|existing_tsa| existing_tsa.cert_chain == tsa.cert_chain);

                    if exists {
                        if let Some(existing_tsa) = self
                            .trusted_root
                            .timestamp_authorities
                            .iter_mut()
                            .find(|existing_tsa| existing_tsa.cert_chain == tsa.cert_chain)
                        {
                            // If valid_for.start is not set; User wants to expire the target
                            if let Some(valid_for) = &mut tsa.valid_for {
                                if valid_for.start.is_none() {
                                    valid_for.start = existing_tsa.valid_for.clone().unwrap().start;
                                }
                            }
                            existing_tsa.clone_from(&tsa);
                        }
                    } else {
                        if let Some(last_tsa) = self.trusted_root.timestamp_authorities.last_mut() {
                            if let Some(valid_for) = &mut last_tsa.valid_for {
                                if valid_for.end.is_none() {
                                    valid_for.end = tsa.valid_for.clone().unwrap().start;
                                }
                            }
                        }
                        self.trusted_root.timestamp_authorities.push(tsa);
                    }
                } else {
                    return Err(SigstoreError::UnexpectedError(
                        "Expected a TimestampAuthority, but got a different target.".to_string(),
                    ));
                }
            }
            Target::Ctlog => {
                if let TargetType::Log(mut ctlog) = new_target {
                    let exists = self.trusted_root.ctlogs.iter().any(|existing_ctlog| {
                        existing_ctlog.log_id == ctlog.log_id
                            || existing_ctlog.public_key == ctlog.public_key
                    });

                    if exists {
                        if let Some(existing_ctlog) = self
                            .trusted_root
                            .ctlogs
                            .iter_mut()
                            .find(|existing_ctlog| existing_ctlog.log_id == ctlog.log_id)
                        {
                            // If valid_for.start is not set; User wants to expire the target
                            if let Some(valid_for) = &mut ctlog
                                .public_key
                                .as_mut()
                                .and_then(|pk| pk.valid_for.as_mut())
                            {
                                if valid_for.start.is_none() {
                                    valid_for.start = existing_ctlog
                                        .clone()
                                        .public_key
                                        .unwrap()
                                        .valid_for
                                        .clone()
                                        .unwrap()
                                        .start;
                                }
                            }
                            existing_ctlog.clone_from(&ctlog);
                        }
                    } else {
                        if let Some(last_ctlog) = self.trusted_root.ctlogs.last_mut() {
                            if let Some(valid_for) = last_ctlog
                                .public_key
                                .as_mut()
                                .and_then(|pk| pk.valid_for.as_mut())
                            {
                                if valid_for.end.is_none() {
                                    valid_for.end = ctlog
                                        .clone()
                                        .public_key
                                        .unwrap()
                                        .valid_for
                                        .clone()
                                        .unwrap()
                                        .start;
                                }
                            }
                        }
                        self.trusted_root.ctlogs.push(ctlog);
                    }
                } else {
                    return Err(SigstoreError::UnexpectedError(
                        "Expected a Ctlog, but got a different target.".to_string(),
                    ));
                }
            }
            Target::Tlog => {
                if let TargetType::Log(mut tlog) = new_target {
                    let exists = self.trusted_root.tlogs.iter().any(|existing_tlog| {
                        existing_tlog.log_id == tlog.log_id
                            || existing_tlog.public_key == tlog.public_key
                    });

                    if exists {
                        if let Some(existing_tlog) = self
                            .trusted_root
                            .tlogs
                            .iter_mut()
                            .find(|existing_tlog| existing_tlog.log_id == tlog.log_id)
                        {
                            // If valid_for.start is not set; User wants to expire the target
                            if let Some(valid_for) = &mut tlog
                                .public_key
                                .as_mut()
                                .and_then(|pk| pk.valid_for.as_mut())
                            {
                                if valid_for.start.is_none() {
                                    valid_for.start = existing_tlog
                                        .clone()
                                        .public_key
                                        .unwrap()
                                        .valid_for
                                        .clone()
                                        .unwrap()
                                        .start;
                                }
                            }
                            existing_tlog.clone_from(&tlog);
                        }
                    } else {
                        if let Some(last_tlog) = self.trusted_root.tlogs.last_mut() {
                            if let Some(valid_for) = last_tlog
                                .public_key
                                .as_mut()
                                .and_then(|pk| pk.valid_for.as_mut())
                            {
                                if valid_for.end.is_none() {
                                    valid_for.end = tlog
                                        .clone()
                                        .public_key
                                        .unwrap()
                                        .valid_for
                                        .clone()
                                        .unwrap()
                                        .start;
                                }
                            }
                        }
                        self.trusted_root.tlogs.push(tlog);
                    }
                } else {
                    return Err(SigstoreError::UnexpectedError(
                        "Expected a Tlog, but got a different target.".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    // Delete a target from the TrustedRoot by its identifier raw bytes:
    // public key for tlogs and ctlogs, cert chain for certificate and timestamp authorities)
    pub fn delete_target(&mut self, target_type: &Target, identifier: &Vec<u8>) -> Result<()> {
        match target_type {
            Target::CertificateAuthority => {
                self.trusted_root.certificate_authorities.retain(|ca| {
                    ca.cert_chain.as_ref().map_or(true, |chain| {
                        chain
                            .certificates
                            .iter()
                            .any(|cert| cert.raw_bytes != *identifier)
                    })
                });
            }
            Target::TimestampAuthority => {
                self.trusted_root.timestamp_authorities.retain(|tsa| {
                    tsa.cert_chain.as_ref().map_or(true, |chain| {
                        chain
                            .certificates
                            .iter()
                            .any(|cert| cert.raw_bytes != *identifier)
                    })
                });
            }
            Target::Ctlog => {
                self.trusted_root.ctlogs.retain(|ctlog| {
                    ctlog
                        .public_key
                        .as_ref()
                        .map_or(true, |key| key.raw_bytes != Some(identifier.clone()))
                });
            }
            Target::Tlog => {
                self.trusted_root.tlogs.retain(|tlog| {
                    tlog.public_key
                        .as_ref()
                        .map_or(true, |key| key.raw_bytes != Some(identifier.clone()))
                });
            }
        }
        Ok(())
    }
}

impl crate::trust::TrustRoot for SigstoreTrustRoot {
    /// Fetch Fulcio certificates from the given TUF repository or reuse
    /// the local cache if its contents are not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer>> {
        // Allow expired certificates: they may have been active when the
        // certificate was used to sign.
        let certs = Self::ca_keys(&self.trusted_root.certificate_authorities, true);
        let certs: Vec<_> = certs
            .map(|c| CertificateDer::from(c).into_owned())
            .collect();

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
    fn rekor_keys(&self) -> Result<Vec<&[u8]>> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.tlogs).collect();

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
    fn ctfe_keys(&self) -> Result<Vec<&[u8]>> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.ctlogs).collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::Timestamp;
    use rstest::{fixture, rstest};
    use sigstore_protobuf_specs::dev::sigstore::{
        common::v1::{
            DistinguishedName, LogId, PublicKey, TimeRange, X509Certificate, X509CertificateChain,
        },
        trustroot::v1::{CertificateAuthority, TransparencyLogInstance},
    };
    use std::fs;
    use std::path::Path;
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn verify(root: &SigstoreTrustRoot, cache_dir: Option<&Path>) {
        if let Some(cache_dir) = cache_dir {
            assert!(
                cache_dir.join("trusted_root.json").exists(),
                "the trusted root was not cached"
            );
        }

        assert!(
            root.fulcio_certs().is_ok_and(|v| !v.is_empty()),
            "no Fulcio certs established"
        );
        assert!(
            root.rekor_keys().is_ok_and(|v| !v.is_empty()),
            "no Rekor keys established"
        );
        assert!(
            root.ctfe_keys().is_ok_and(|v| !v.is_empty()),
            "no CTFE keys established"
        );
    }

    #[fixture]
    fn cache_dir() -> TempDir {
        TempDir::new().expect("cannot create temp cache dir")
    }

    async fn trust_root(cache: Option<&Path>) -> SigstoreTrustRoot {
        SigstoreTrustRoot::new(cache)
            .await
            .expect("failed to construct SigstoreTrustRoot")
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

    #[test]
    fn test_is_timerange_valid() {
        fn range_from(start: i64, end: i64) -> TimeRange {
            let base = chrono::Utc::now();
            let start: SystemTime = (base + chrono::TimeDelta::seconds(start)).into();
            let end: SystemTime = (base + chrono::TimeDelta::seconds(end)).into();

            TimeRange {
                start: Some(start.into()),
                end: Some(end.into()),
            }
        }

        assert!(is_timerange_valid(None, true));
        assert!(is_timerange_valid(None, false));

        // Test lower bound conditions

        // Valid: 1 ago, 1 from now
        assert!(is_timerange_valid(Some(&range_from(-1, 1)), false));
        // Invalid: 1 from now, 1 from now
        assert!(!is_timerange_valid(Some(&range_from(1, 1)), false));

        // Test upper bound conditions

        // Invalid: 1 ago, 1 ago
        assert!(!is_timerange_valid(Some(&range_from(-1, -1)), false));
        // Valid: 1 ago, 1 ago
        assert!(is_timerange_valid(Some(&range_from(-1, -1)), true))
    }

    #[tokio::test]
    async fn test_add_new_certificate_authority() {
        let cache_dir = None;
        let mut trust_root = SigstoreTrustRoot::new(cache_dir)
            .await
            .expect("Failed to create SigstoreTrustRoot");
        let initial_length = trust_root.trusted_root.certificate_authorities.len();
        let new_ca = CertificateAuthority {
            subject: Some(DistinguishedName {
                organization: "sigstore.dev".to_string(),
                common_name: "sigstore".to_string(),
            }),
            uri: "https://fulcio_test.sigstore.dev".to_string(),
            cert_chain: Some(X509CertificateChain {
                certificates: vec![
                    X509Certificate {
                        raw_bytes: String::from("MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLguhzAKBggqhkjOPQQDAzAqMRUwEwYDVQEKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==").as_bytes().to_vec(),
                    },
                ],
            }),
            valid_for: Some(TimeRange{
                start: Some(Timestamp{
                    seconds: 1724155691,
                    nanos: 0,
                }),
                end: None,
            }),
        };
        let result =
            trust_root.set_target(TargetType::Authority(new_ca), Target::CertificateAuthority);
        assert!(result.is_ok(), "Failed to add new certificate authority");
        let new_length = trust_root.trusted_root.certificate_authorities.len();
        assert_eq!(
            trust_root.trusted_root.certificate_authorities.len(),
            initial_length + 1
        );

        let added_ca = &trust_root.trusted_root.certificate_authorities[new_length - 1];
        assert_eq!(added_ca.uri, "https://fulcio_test.sigstore.dev");
        assert_eq!(
            added_ca.valid_for.as_ref().unwrap().start,
            Some(Timestamp {
                seconds: 1724155691,
                nanos: 0,
            })
        );
        // Check expired certificate authority
        if initial_length > 0 {
            assert_eq!(
                trust_root.trusted_root.certificate_authorities[new_length - 2]
                    .valid_for
                    .as_ref()
                    .unwrap()
                    .end,
                Some(Timestamp {
                    seconds: 1724155691,
                    nanos: 0,
                })
            );
        }
    }

    #[tokio::test]
    async fn test_update_certificate_authority() {
        let cache_dir = None;
        let mut trust_root = SigstoreTrustRoot::new(cache_dir)
            .await
            .expect("Failed to create SigstoreTrustRoot");
        let initial_length = trust_root.trusted_root.certificate_authorities.len();

        // Update the last certificate authority
        let ca = &trust_root.trusted_root.certificate_authorities[initial_length - 1];
        let mut updated_ca = ca.clone();
        updated_ca.subject = Some(DistinguishedName {
            organization: "sigstore.test".to_string(),
            common_name: "sigstore".to_string(),
        });
        updated_ca.valid_for = Some(TimeRange {
            start: Some(Timestamp {
                seconds: 1724155691,
                nanos: 0,
            }),
            end: None,
        });
        let result = trust_root.set_target(
            TargetType::Authority(updated_ca),
            Target::CertificateAuthority,
        );
        let new_length = trust_root.trusted_root.certificate_authorities.len();
        let ca = &trust_root.trusted_root.certificate_authorities[new_length - 1];
        assert!(result.is_ok(), "Failed to update certificate authority");
        assert_eq!(
            ca.subject,
            Some(DistinguishedName {
                organization: "sigstore.test".to_string(),
                common_name: "sigstore".to_string(),
            })
        );
        assert_eq!(
            ca.valid_for.as_ref().unwrap().start,
            Some(Timestamp {
                seconds: 1724155691,
                nanos: 0,
            })
        );
    }

    #[tokio::test]
    async fn test_add_new_ctlog() {
        let cache_dir = None;
        let mut trust_root = SigstoreTrustRoot::new(cache_dir)
            .await
            .expect("Failed to create SigstoreTrustRoot");
        let initial_length = trust_root.trusted_root.ctlogs.len();
        let new_ctlog = TransparencyLogInstance {
            base_url: String::from("https://ctfe.sigstore.dev/test"),
            hash_algorithm: 256,
            public_key: Some(PublicKey{
                raw_bytes: Some(String::from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==").as_bytes().to_vec()),
                key_details: 256,
                valid_for: Some(TimeRange{
                    start: Some(Timestamp{
                        seconds: 1724155691,
                        nanos: 0,
                    }),
                    end: None,
                }),
            }),
            log_id: Some(LogId {
                key_id: String::from("CGCS8RhS/2hG0drJ4ScRWcYrBY9wzjSbea8IgY2b3I=").as_bytes().to_vec(),
            }),
            checkpoint_key_id: None,
        };

        let result = trust_root.set_target(TargetType::Log(new_ctlog), Target::Ctlog);
        assert!(result.is_ok(), "Failed to add new Ctlog entry");
        let new_length = trust_root.trusted_root.ctlogs.len();
        assert_eq!(trust_root.trusted_root.ctlogs.len(), initial_length + 1);

        let added_ctlog: &TransparencyLogInstance = &trust_root.trusted_root.ctlogs[new_length - 1];
        assert_eq!(added_ctlog.base_url, "https://ctfe.sigstore.dev/test");
        assert_eq!(
            added_ctlog
                .clone()
                .public_key
                .unwrap()
                .valid_for
                .as_ref()
                .unwrap()
                .start,
            Some(Timestamp {
                seconds: 1724155691,
                nanos: 0,
            })
        );
        // Check expired ctlog
        if initial_length > 0 {
            assert_eq!(
                trust_root.trusted_root.ctlogs[new_length - 2]
                    .clone()
                    .public_key
                    .unwrap()
                    .valid_for
                    .as_ref()
                    .unwrap()
                    .end,
                Some(Timestamp {
                    seconds: 1724155691,
                    nanos: 0,
                })
            );
        }
    }

    #[tokio::test]
    async fn test_delete_certificate_authority() {
        let cache_dir = None;
        let mut trust_root = SigstoreTrustRoot::new(cache_dir)
            .await
            .expect("Failed to create SigstoreTrustRoot");

        // Add a new CertificateAuthority
        let cert_raw_bytes = String::from("MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLguhzAKBggqhkjOPQQDAzAqMRUwEwYDVQEKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==").as_bytes().to_vec();
        let new_ca = CertificateAuthority {
            subject: Some(DistinguishedName {
                organization: "sigstore.dev".to_string(),
                common_name: "sigstore".to_string(),
            }),
            uri: "https://fulcio_test.sigstore.dev".to_string(),
            cert_chain: Some(X509CertificateChain {
                certificates: vec![X509Certificate {
                    raw_bytes: cert_raw_bytes.clone(),
                }],
            }),
            valid_for: Some(TimeRange {
                start: Some(Timestamp {
                    seconds: 1724155691,
                    nanos: 0,
                }),
                end: None,
            }),
        };
        let result =
            trust_root.set_target(TargetType::Authority(new_ca), Target::CertificateAuthority);
        assert!(result.is_ok(), "Failed to add new certificate authority");

        let cert_chain = X509Certificate {
            raw_bytes: cert_raw_bytes,
        };
        assert!(
            trust_root
                .trusted_root
                .certificate_authorities
                .iter()
                .any(|ca| {
                    ca.cert_chain
                        .as_ref()
                        .map_or(false, |chain| chain.certificates.contains(&cert_chain))
                }),
            "Certificate authority not found before deletion"
        );

        // Delete the CertificateAuthority by cert_chain
        let result = trust_root.delete_target(&Target::CertificateAuthority, &cert_chain.raw_bytes);
        assert!(result.is_ok(), "Failed to delete the certificate authority");

        // Verify the CertificateAuthority was deleted
        assert!(
            !trust_root
                .trusted_root
                .certificate_authorities
                .iter()
                .any(|ca| {
                    ca.cert_chain
                        .as_ref()
                        .map_or(false, |chain| chain.certificates.contains(&cert_chain))
                }),
            "Certificate authority was not correctly deleted"
        );
    }

    #[tokio::test]
    async fn test_delete_ctlog() {
        let cache_dir = None;
        let mut trust_root = SigstoreTrustRoot::new(cache_dir)
            .await
            .expect("Failed to create SigstoreTrustRoot");

        // Add a new ctlog
        let public_key_raw_bytes=String::from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==").as_bytes().to_vec();
        let new_ctlog = TransparencyLogInstance {
            base_url: String::from("https://ctfe.sigstore.dev/test"),
            hash_algorithm: 256,
            public_key: Some(PublicKey {
                raw_bytes: Some(public_key_raw_bytes.clone()),
                key_details: 256,
                valid_for: Some(TimeRange {
                    start: Some(Timestamp {
                        seconds: 1724155691,
                        nanos: 0,
                    }),
                    end: None,
                }),
            }),
            log_id: Some(LogId {
                key_id: String::from("CGCS8RhS/2hG0drJ4ScRWcYrBY9wzjSbea8IgY2b3I=")
                    .as_bytes()
                    .to_vec(),
            }),
            checkpoint_key_id: None,
        };

        let result = trust_root.set_target(TargetType::Log(new_ctlog), Target::Ctlog);
        assert!(result.is_ok(), "Failed to add new Ctlog entry");

        let public_key = PublicKey {
            raw_bytes: Some(public_key_raw_bytes),
            key_details: 256,
            valid_for: Some(TimeRange {
                start: Some(Timestamp {
                    seconds: 1724155691,
                    nanos: 0,
                }),
                end: None,
            }),
        };
        assert!(
            trust_root.trusted_root.ctlogs.iter().any(|ctlog| {
                ctlog
                    .public_key
                    .as_ref()
                    .map_or(false, |key| key.raw_bytes == public_key.raw_bytes)
            }),
            "Ctlog not found before deletion"
        );

        // Delete the ctlog by public key raw data
        let result =
            trust_root.delete_target(&Target::Ctlog, &public_key.raw_bytes.clone().unwrap());
        assert!(result.is_ok(), "Failed to delete the Ctlog");

        // Verify the ctlog was deleted
        assert!(
            !trust_root.trusted_root.ctlogs.iter().any(|ctlog| {
                ctlog
                    .public_key
                    .as_ref()
                    .map_or(false, |key| key.raw_bytes == public_key.raw_bytes)
            }),
            "Ctlog was not correctly deleted"
        );
    }
}
