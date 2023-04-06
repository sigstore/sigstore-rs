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

use crate::errors::SigstoreError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// `OciReference` provides a general type to represent any way of referencing images within an OCI registry.
#[derive(Debug, Clone, PartialEq)]
pub struct OciReference {
    pub(crate) oci_reference: oci_distribution::Reference,
}

impl FromStr for OciReference {
    type Err = SigstoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<oci_distribution::Reference>()
            .map_err(|_| SigstoreError::OciReferenceNotValidError {
                reference: s.to_string(),
            })
            .map(|oci_reference| OciReference { oci_reference })
    }
}

impl OciReference {
    /// Create a Reference with a registry, repository and tag.
    pub fn with_tag(registry: String, repository: String, tag: String) -> Self {
        OciReference {
            oci_reference: oci_distribution::Reference::with_tag(registry, repository, tag),
        }
    }

    /// Create a Reference with a registry, repository and digest.
    pub fn with_digest(registry: String, repository: String, digest: String) -> Self {
        OciReference {
            oci_reference: oci_distribution::Reference::with_digest(registry, repository, digest),
        }
    }

    /// Resolve the registry address of a given Reference.
    ///
    /// Some registries, such as docker.io, uses a different address for the actual
    /// registry. This function implements such redirection.
    pub fn resolve_registry(&self) -> &str {
        self.oci_reference.resolve_registry()
    }

    /// registry returns the name of the registry.
    pub fn registry(&self) -> &str {
        self.oci_reference.registry()
    }

    /// repository returns the name of the repository
    pub fn repository(&self) -> &str {
        self.oci_reference.repository()
    }

    /// digest returns the object's digest, if present.
    pub fn digest(&self) -> Option<&str> {
        self.oci_reference.digest()
    }

    /// tag returns the object's tag, if present.
    pub fn tag(&self) -> Option<&str> {
        self.oci_reference.tag()
    }

    /// whole returns the whole reference.
    pub fn whole(&self) -> String {
        self.oci_reference.whole()
    }
}

impl Display for OciReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.oci_reference.fmt(f)
    }
}
