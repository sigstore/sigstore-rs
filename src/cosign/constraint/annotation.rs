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

use std::collections::HashMap;

use serde_json::Value;
use tracing::warn;

use crate::{cosign::SignatureLayer, errors::Result};

use super::Constraint;

/// Constraint for the annotations, which can be verified by [`crate::cosign::verification_constraint::AnnotationVerifier`]
///
/// The [`crate::cosign::payload::SimpleSigning`] object can be enriched by a signer
/// with more annotations.
///
/// A [`AnnotationMarker`] helps to add annotations to the [`crate::cosign::payload::SimpleSigning`]
/// of the given [`SignatureLayer`].
///
/// Warning: The signing step must not happen until all [`AnnotationMarker`]
/// have already performed `add_constraint`.
#[derive(Debug)]
pub struct AnnotationMarker {
    pub annotations: HashMap<String, String>,
}

impl AnnotationMarker {
    pub fn new(annotations: HashMap<String, String>) -> Self {
        Self { annotations }
    }
}

impl Constraint for AnnotationMarker {
    fn add_constraint(&self, signature_layer: &mut SignatureLayer) -> Result<bool> {
        let mut annotations = match &signature_layer.simple_signing.optional {
            Some(opt) => {
                warn!(optional = ?opt, "already has an annotation field");
                opt.extra.clone()
            }
            None => HashMap::new(),
        };

        for (k, v) in &self.annotations {
            if annotations.contains_key(k) && annotations[k] != *v {
                warn!(key = ?k, "extra field already has a value");
                return Ok(false);
            }
            annotations.insert(k.to_owned(), Value::String(v.into()));
        }

        let mut opt = signature_layer
            .simple_signing
            .optional
            .clone()
            .unwrap_or_default();
        opt.extra = annotations;
        signature_layer.simple_signing.optional = Some(opt);
        Ok(true)
    }
}
