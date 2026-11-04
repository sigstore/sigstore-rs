//
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

//! Types for verifying Sigstore bundles with policies.

pub(crate) mod models;

pub use models::{
    ArtifactDigest, BundleErrorKind, CertificateErrorKind, SignatureErrorKind, VerificationError,
    VerificationResult,
};

pub mod policy;
pub use policy::{PolicyError, VerificationPolicy};

mod verifier;
pub use verifier::*;

/// Fixtures shared between the unit tests of this module's submodules.
#[cfg(test)]
pub(crate) mod test_data {
    /// `sigstore@5.0.0` npm SLSA provenance, from
    /// <https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0>.
    /// Its in-toto statement's only subject digest is a `sha512`.
    pub(crate) const NPM_SLSA_BUNDLE_V03: &str =
        include_str!("../../../tests/data/npm_slsa_bundle_v03.json");

    /// A pinned copy of the Sigstore Public Good Instance's `trusted_root.json`,
    /// so bundle verification tests never touch the network.
    pub(crate) const SIGSTORE_TRUSTED_ROOT: &str =
        include_str!("../../../tests/data/sigstore_trusted_root.json");

    /// SHA-512 of `sigstore-5.0.0.tgz`, i.e. [`NPM_SLSA_BUNDLE_V03`]'s only
    /// subject digest.
    pub(crate) const NPM_TARBALL_SHA512: &str = "849a897e81bf7b8a8541a6ae40bd3473a27a16b1cb0462ad905bd6dc96d34881053a12eb4a375233f81677fc9439f628fe0b0445e8535c60b5559597fbd5f80e";

    /// The SAN of [`NPM_SLSA_BUNDLE_V03`]'s signing certificate.
    pub(crate) const NPM_CERT_IDENTITY: &str =
        "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main";
    /// The OIDC issuer of [`NPM_SLSA_BUNDLE_V03`]'s signing certificate.
    pub(crate) const NPM_CERT_ISSUER: &str = "https://token.actions.githubusercontent.com";
}
