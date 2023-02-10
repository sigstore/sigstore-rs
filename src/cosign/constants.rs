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

use const_oid::ObjectIdentifier;

pub(crate) const SIGSTORE_ISSUER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
pub(crate) const SIGSTORE_GITHUB_WORKFLOW_TRIGGER_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.2");
pub(crate) const SIGSTORE_GITHUB_WORKFLOW_SHA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.3");
pub(crate) const SIGSTORE_GITHUB_WORKFLOW_NAME_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.4");
pub(crate) const SIGSTORE_GITHUB_WORKFLOW_REPOSITORY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.5");
pub(crate) const SIGSTORE_GITHUB_WORKFLOW_REF_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.6");
/// OID of Ed25519, which is not included in the RustCrypto repo yet.
pub(crate) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

pub(crate) const SIGSTORE_OCI_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
pub(crate) const SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
pub(crate) const SIGSTORE_BUNDLE_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
pub(crate) const SIGSTORE_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";
