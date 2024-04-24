//
// Copyright 2024 The Sigstore Authors.
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

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::TimeRange,
    trustroot::v1::{
        CertificateAuthority, ClientTrustConfig, SigningConfig, TransparencyLogInstance,
        TrustedRoot,
    },
};
use thiserror::Error;
use webpki::types::CertificateDer;

use crate::crypto::{
    keyring::{Keyring, KeyringError},
    CertificatePool,
};

#[cfg(feature = "sigstore-trust-root")]
pub mod sigstore;

#[derive(Error, Debug)]
#[error(transparent)]
pub enum TrustRootError {
    #[error("trust bundle malformed")]
    BundleMalformed,

    #[error("cert(s) malformed: {0}")]
    CertMalformed(#[from] webpki::Error),

    #[error("key(s) malformed: {0}")]
    KeyMalformed(#[from] KeyringError),

    #[cfg(feature = "sigstore-trust-root")]
    RootUpdate(#[from] sigstore::RootUpdateError),
}

type Result<T> = std::result::Result<T, TrustRootError>;

pub type TLogKeyring = Keyring;
pub type CTFEKeyring = Keyring;

/// A `TrustRoot` owns all key material necessary for establishing a root of trust.
pub trait TrustRoot {
    fn ca_certs(&self) -> Result<CertificatePool>;
    fn tlog_keys(&self) -> Result<TLogKeyring>;
    fn ctfe_keys(&self) -> Result<CTFEKeyring>;
}

// HACK(tnytown): Remove when cosign moves to Keyring for signature verification.
#[deprecated]
pub trait RawTrustRoot: TrustRoot {
    fn raw_tlog_keys(&self) -> Vec<Vec<u8>>;
}

/// A `ManualTrustRoot` is a [`TrustRoot`] with out-of-band trust materials.
/// As it does not establish a trust root with TUF, users must initialize its materials themselves.
#[derive(Debug, Default)]
pub struct ManualTrustRoot {
    /// Certificate Authority (Fulcio) certs.
    pub ca_certs: Vec<CertificateDer<'static>>,
    /// Artifact Transparency (Rekor) keys.
    pub tlog_keys: Vec<Vec<u8>>,
    /// Certificate Transparency (Fulcio) keys.
    pub ctfe_keys: Vec<Vec<u8>>,
}

impl TrustRoot for ManualTrustRoot {
    fn ca_certs(&self) -> Result<CertificatePool> {
        Ok(CertificatePool::from_certificates(
            self.ca_certs.clone(),
            [],
        )?)
    }

    fn tlog_keys(&self) -> Result<TLogKeyring> {
        Ok(TLogKeyring::new(&self.tlog_keys)?)
    }

    fn ctfe_keys(&self) -> Result<CTFEKeyring> {
        Ok(CTFEKeyring::new(&self.ctfe_keys)?)
    }
}

#[allow(deprecated)]
impl RawTrustRoot for ManualTrustRoot {
    fn raw_tlog_keys(&self) -> Vec<Vec<u8>> {
        self.tlog_keys.clone()
    }
}

/// A `BundledTrustRoot` is a [`TrustRoot`] backed by a [`TrustedRoot`] Protobuf message, typically
/// encoded as a JSON blob and distributed through TUF.
pub struct BundledTrustRoot {
    trusted_root: TrustedRoot,
}

impl From<TrustedRoot> for BundledTrustRoot {
    fn from(trusted_root: TrustedRoot) -> Self {
        Self { trusted_root }
    }
}

impl BundledTrustRoot {
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

impl TrustRoot for BundledTrustRoot {
    /// Fetch Fulcio certificates from the given TUF repository or reuse
    /// the local cache if its contents are not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn ca_certs(&self) -> Result<CertificatePool> {
        // Allow expired certificates: they may have been active when the
        // certificate was used to sign.
        let certs = Self::ca_keys(&self.trusted_root.certificate_authorities, true);
        let certs: Vec<_> = certs
            .map(|c| CertificateDer::from(c).into_owned())
            .collect();

        if certs.is_empty() {
            Err(TrustRootError::BundleMalformed)
        } else {
            Ok(CertificatePool::from_certificates(certs, [])?)
        }
    }

    /// Fetch Rekor public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn tlog_keys(&self) -> Result<TLogKeyring> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.tlogs).collect();

        if keys.len() != 1 {
            Err(TrustRootError::BundleMalformed)
        } else {
            Ok(TLogKeyring::new(keys)?)
        }
    }

    /// Fetch CTFE public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn ctfe_keys(&self) -> Result<CTFEKeyring> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.ctlogs).collect();

        if keys.is_empty() {
            Err(TrustRootError::BundleMalformed)
        } else {
            Ok(CTFEKeyring::new(keys)?)
        }
    }
}

#[allow(deprecated)]
impl RawTrustRoot for BundledTrustRoot {
    fn raw_tlog_keys(&self) -> Vec<Vec<u8>> {
        Self::tlog_keys(&self.trusted_root.tlogs)
            .map(|k| k.to_owned())
            .collect()
    }
}

/// `TrustConfig` manages necessary information necessary to contact and establish
/// trust in a Sigstore instance.
///
/// This type roughly mirrors [`ClientTrustConfig`] from `sigstore-protobuf-specs`.
///
/// [`ClientTrustConfig`]: sigstore_protobuf_specs::dev::sigstore::trustroot::v1::ClientTrustConfig
pub struct TrustConfig<R> {
    pub trust_root: R,
    pub signing_config: SigningConfig,
}

impl TryFrom<ClientTrustConfig> for TrustConfig<BundledTrustRoot> {
    type Error = TrustRootError;

    fn try_from(value: ClientTrustConfig) -> Result<Self> {
        let trusted_root = value.trusted_root.ok_or(TrustRootError::BundleMalformed)?;
        let signing_config = value
            .signing_config
            .ok_or(TrustRootError::BundleMalformed)?;

        Ok(TrustConfig {
            trust_root: BundledTrustRoot { trusted_root },
            signing_config,
        })
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
    use std::time::SystemTime;

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
}
