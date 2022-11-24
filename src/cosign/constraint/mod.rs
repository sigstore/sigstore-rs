//
// Copyright 2022 The Sigstore Authors.
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

//! Structs that can be used to add constraints to [`crate::cosign::SignatureLayer`]
//! with special business logic.
//!
//! This module provides some common kinds of constraints:
//! * [`PrivateKeySigner`]: Attaching a signature
//! * [`AnnotationMarker`]: Adding extra annotations
//!
//! Developers can define ad-hoc constraint logic by creating a Struct that
//! implements the [`Constraint`] trait
//!
//! ## Warining
//! Because [`PrivateKeySigner`] will sign the whole data of a given
//! [`crate::cosign::SignatureLayer`], developers **must** ensure that
//! a [`PrivateKeySigner`] is the last constraint to be applied on a
//! [`crate::cosign::SignatureLayer`]. Before that, all constraints that
//! may modify the content of the [`crate::cosign::SignatureLayer`] should
//! have been applied already.

use super::SignatureLayer;
use crate::errors::Result;

pub type SignConstraintVec = Vec<Box<dyn Constraint>>;
pub type SignConstraintRefVec<'a> = Vec<&'a Box<dyn Constraint>>;

pub trait Constraint: std::fmt::Debug {
    /// Given a mutable reference of [`crate::cosign::SignatureLayer`], return
    /// `true` if the constraint is applied successfully.
    ///
    /// Developer can use the
    /// [`crate::errors::SigstoreError::ApplyConstraintError`] error
    /// when something goes wrong inside of the application logic.
    ///
    /// ```
    /// use sigstore::{
    ///   cosign::constraint::Constraint,
    ///   cosign::signature_layers::SignatureLayer,
    ///   errors::{SigstoreError, Result},
    /// };
    ///
    /// #[derive(Debug)]
    /// struct MyConstraint{}
    ///
    /// impl Constraint for MyConstraint {
    ///     fn add_constraint(&self, _sl: &mut SignatureLayer) -> Result<bool> {
    ///         Err(SigstoreError::ApplyConstraintError(
    ///         "something went wrong!".to_string()))
    ///     }
    /// }
    ///
    /// ```
    fn add_constraint(&self, signature_layer: &mut SignatureLayer) -> Result<bool>;
}

pub mod annotation;
pub use annotation::AnnotationMarker;

pub mod signature;
pub use self::signature::PrivateKeySigner;
