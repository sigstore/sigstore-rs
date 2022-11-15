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

//! Structs that can be used to verify [`crate::cosign::SignatureLayer`]
//! with special business logic.
//!
//! This module provides already the most common kind of verification constraints:
//! * [`PublicKeyVerifier`]: ensure a signature has been produced by a specific
//!   cosign key
//! * [`CertSubjectEmailVerifier`]: ensure a signature has been produced in keyless mode,
//!   plus the email address associated with the signer matches a specific one
//! * [`CertSubjectUrlVerifier`]: ensure a signature has been produced in keyless mode,
//!   plus the certificate SAN has a specific URI inside of it. This can be used to verify
//!   signatures produced by GitHub Actions.
//!
//! Developers can define ad-hoc validation logic by creating a Struct that implements
//! the [`VerificationConstraintVec`] trait.

use super::signature_layers::SignatureLayer;
use crate::errors::Result;

/// A list of objects implementing the [`VerificationConstraint`] trait
pub type VerificationConstraintVec = Vec<Box<dyn VerificationConstraint>>;

/// A list of references to objects implementing the [`VerificationConstraint`] trait
pub type VerificationConstraintRefVec<'a> = Vec<&'a Box<dyn VerificationConstraint>>;

/// A trait that can be used to define verification constraints objects
/// that use a custom verification logic.
pub trait VerificationConstraint: std::fmt::Debug {
    /// Given the `signature_layer` object, return `true` if the verification
    /// check is satisfied.
    ///
    /// Developer can use the
    /// [`errors::SigstoreError::VerificationConstraintError`](crate::errors::SigstoreError::VerificationConstraintError)
    /// error when something goes wrong inside of the verification logic.
    ///
    /// ```
    /// use sigstore::{
    ///   cosign::verification_constraint::VerificationConstraint,
    ///   cosign::signature_layers::SignatureLayer,
    ///   errors::{SigstoreError, Result},
    /// };
    ///
    /// #[derive(Debug)]
    /// struct MyVerifier{}
    ///
    /// impl VerificationConstraint for MyVerifier {
    ///   fn verify(&self, _sl: &SignatureLayer) -> Result<bool> {
    ///     Err(SigstoreError::VerificationConstraintError(
    ///         "something went wrong!".to_string()))
    ///   }
    /// }
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool>;
}

pub mod certificate_verifier;
pub use certificate_verifier::CertificateVerifier;

pub mod public_key_verifier;
pub use public_key_verifier::PublicKeyVerifier;

pub mod cert_subject_email_verifier;
pub use cert_subject_email_verifier::CertSubjectEmailVerifier;

pub mod cert_subject_url_verifier;
pub use cert_subject_url_verifier::CertSubjectUrlVerifier;

pub mod annotation_verifier;
pub use annotation_verifier::AnnotationVerifier;
