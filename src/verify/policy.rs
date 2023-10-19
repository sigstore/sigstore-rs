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

//! Verifiers for certificate metadata.
//!
//! <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#extension-values>

use const_oid::ObjectIdentifier;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

use crate::verify::VerificationError;

use super::models::VerificationResult;

macro_rules! oids {
    ($($name:ident = $value:literal),+) => {
        $(const $name: ObjectIdentifier = ObjectIdentifier::new_unwrap($value);)+
    };
}

macro_rules! impl_policy {
    ($policy:ident, $oid:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $policy(pub String);

        impl const_oid::AssociatedOid for $policy {
            const OID: ObjectIdentifier = $oid;
        }

        impl SingleX509ExtPolicy for $policy {
            fn new<S: AsRef<str>>(val: S) -> Self {
                Self(val.as_ref().to_owned())
            }

            fn name() -> &'static str {
                stringify!($policy)
            }

            fn value(&self) -> &str {
                &self.0
            }
        }
    };
}

oids! {
    OIDC_ISSUER_OID = "1.3.6.1.4.1.57264.1.1",
    OIDC_GITHUB_WORKFLOW_TRIGGER_OID = "1.3.6.1.4.1.57264.1.2",
    OIDC_GITHUB_WORKFLOW_SHA_OID = "1.3.6.1.4.1.57264.1.3",
    OIDC_GITHUB_WORKFLOW_NAME_OID = "1.3.6.1.4.1.57264.1.4",
    OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = "1.3.6.1.4.1.57264.1.5",
    OIDC_GITHUB_WORKFLOW_REF_OID = "1.3.6.1.4.1.57264.1.6",
    OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7"

}

/// A trait for policies that check a single textual value against a X.509 extension.
pub trait SingleX509ExtPolicy {
    fn new<S: AsRef<str>>(val: S) -> Self;
    fn name() -> &'static str;
    fn value(&self) -> &str;
}

impl<T: SingleX509ExtPolicy + const_oid::AssociatedOid> VerificationPolicy for T {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult {
        let extensions = cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
        let mut extensions = extensions.iter().filter(|ext| ext.extn_id == T::OID);

        // Check for exactly one extension.
        let (Some(ext), None) = (extensions.next(), extensions.next()) else {
            return Err(VerificationError::PolicyFailure(
                "Cannot get policy extensions from certificate".into(),
            ));
        };

        // Parse raw string without DER encoding.
        let val = std::str::from_utf8(ext.extn_value.as_bytes()).unwrap();

        if val != self.value() {
            Err(VerificationError::PolicyFailure(format!(
                "Certificate's {} does not match (got {}, expected {})",
                T::name(),
                val,
                self.value()
            )))
        } else {
            Ok(())
        }
    }
}

impl_policy!(
    OIDCIssuer,
    OIDC_ISSUER_OID,
    "Checks the certificate's OIDC issuer."
);

impl_policy!(
    GitHubWorkflowTrigger,
    OIDC_GITHUB_WORKFLOW_TRIGGER_OID,
    "Checks the certificate's GitHub Actions workflow trigger."
);

impl_policy!(
    GitHubWorkflowSHA,
    OIDC_GITHUB_WORKFLOW_SHA_OID,
    "Checks the certificate's GitHub Actions workflow commit SHA."
);

impl_policy!(
    GitHubWorkflowName,
    OIDC_GITHUB_WORKFLOW_NAME_OID,
    "Checks the certificate's GitHub Actions workflow name."
);

impl_policy!(
    GitHubWorkflowRepository,
    OIDC_GITHUB_WORKFLOW_REPOSITORY_OID,
    "Checks the certificate's GitHub Actions workflow repository."
);

impl_policy!(
    GitHubWorkflowRef,
    OIDC_GITHUB_WORKFLOW_REF_OID,
    "Checks the certificate's GitHub Actions workflow ref."
);

/// An interface that all policies must conform to.
pub trait VerificationPolicy {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult;
}

/// The "any of" policy, corresponding to a logical OR between child policies.
///
/// An empty list of child policies is considered trivially invalid.
pub struct AnyOf<'a> {
    children: Vec<&'a dyn VerificationPolicy>,
}

impl<'a> AnyOf<'a> {
    pub fn new<I: IntoIterator<Item = &'a dyn VerificationPolicy>>(policies: I) -> Self {
        Self {
            children: policies.into_iter().collect(),
        }
    }
}

impl VerificationPolicy for AnyOf<'_> {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult {
        let ok = self
            .children
            .iter()
            .find(|policy| policy.verify(cert).is_ok());

        return if let Some(_) = ok {
            Ok(())
        } else {
            Err(VerificationError::PolicyFailure(format!(
                "0 of {} policies succeeded",
                self.children.len()
            )))
        };
    }
}

/// The "all of" policy, corresponding to a logical AND between child policies.
///
/// An empty list of child policies is considered trivially invalid.
pub struct AllOf<'a> {
    children: Vec<&'a dyn VerificationPolicy>,
}

impl<'a> AllOf<'a> {
    pub fn new<I: IntoIterator<Item = &'a dyn VerificationPolicy>>(policies: I) -> Self {
        Self {
            children: policies.into_iter().collect(),
        }
    }
}

impl VerificationPolicy for AllOf<'_> {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult {
        // Without this, we'd consider empty lists of child policies trivially valid.
        // This is almost certainly not what the user wants and is a potential
        // source of API misuse, so we explicitly disallow it.
        if self.children.len() < 1 {
            return Err(VerificationError::PolicyFailure(
                "no child policies to verify".into(),
            ));
        }

        let results = self.children.iter().map(|policy| policy.verify(cert));
        let failures: Vec<_> = results
            .filter_map(|result| result.err())
            .map(|err| err.to_string())
            .collect();

        if failures.len() == 0 {
            Ok(())
        } else {
            Err(VerificationError::PolicyFailure(format!(
                "{} of {} policies failed:\n- {}",
                failures.len(),
                self.children.len(),
                failures.join("\n- ")
            )))
        }
    }
}

pub(crate) struct UnsafeNoOp;

impl VerificationPolicy for UnsafeNoOp {
    fn verify(&self, _cert: &x509_cert::Certificate) -> VerificationResult {
        eprintln!("unsafe (no-op) verification policy used! no verification performed!");
        VerificationResult::Ok(())
    }
}

/// Verifies the certificate's "identity", corresponding to the X.509v3 SAN.
/// Identities are verified modulo an OIDC issuer, so the issuer's URI
/// is also required.
///
/// Supported SAN types include emails, URIs, and Sigstore-specific "other names".
pub struct Identity {
    identity: String,
    issuer: OIDCIssuer,
}

impl Identity {
    pub fn new<A, B>(identity: A, issuer: B) -> Self
    where
        A: AsRef<str>,
        B: AsRef<str>,
    {
        Self {
            identity: identity.as_ref().to_owned(),
            issuer: OIDCIssuer::new(issuer),
        }
    }
}

impl VerificationPolicy for Identity {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult {
        if let err @ Err(_) = self.issuer.verify(cert) {
            return err;
        }

        let (_, san): (bool, SubjectAltName) = match cert.tbs_certificate.get() {
            Ok(Some(result)) => result,
            _ => return Err(VerificationError::CertificateMalformed),
        };

        let names: Vec<_> = san
            .0
            .iter()
            .filter_map(|name| match name {
                GeneralName::Rfc822Name(name) => Some(name.as_str()),
                GeneralName::UniformResourceIdentifier(name) => Some(name.as_str()),
                GeneralName::OtherName(name) if name.type_id == OTHERNAME_OID => {
                    std::str::from_utf8(name.value.value()).ok()
                }
                _ => None,
            })
            .collect();

        if names.contains(&self.identity.as_str()) {
            Ok(())
        } else {
            Err(VerificationError::PolicyFailure(format!(
                "Certificate's SANs do not match {}; actual SANs: {}",
                self.identity,
                names.join(", ")
            )))
        }
    }
}
