// Copyright 2026 The Sigstore Authors.
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

//! Verification constraint for in-toto attestation content.

use super::VerificationConstraint;
use crate::cosign::signature_layers::SignatureLayer;
use crate::errors::Result;

/// Verification constraint that checks the in-toto attestation carried inside
/// a [`SignatureLayer`].
///
/// # Relationship to signature verification
///
/// This constraint is concerned solely with **content-level** policy on the
/// attestation (predicate type, predicate contents, etc.).  It does **not**
/// perform cryptographic signature verification itself.
///
/// Signature verification for attestations is split across two stages:
///
/// 1. **At `SignatureLayer` construction time**
///    ([`SignatureLayer::from_sigstore_bundle`]):
///    - The transparency log entry's Signed Entry Timestamp (SET) and
///      Merkle inclusion proof are verified against the Rekor public key.
///    - The tlog body is checked for consistency with the DSSE envelope
///      (envelope hash, payload hash, signature bytes, and signer
///      certificate must all match).
///    - The signing certificate is validated against the Fulcio certificate
///      pool (if provided), populating `certificate_signature`.
///
/// 2. **At constraint evaluation time** (via other
///    [`VerificationConstraint`] implementations):
///    - [`PublicKeyVerifier`](super::PublicKeyVerifier) or
///      [`CertificateVerifier`](super::CertificateVerifier) verify the
///      DSSE envelope signature against the signer's public key.
///
/// In a typical verification flow, `AttestationVerifier` is used
/// **alongside** a signature-checking constraint (e.g.
/// `CertificateVerifier`) so that both the cryptographic signature and the
/// attestation content are validated.
///
/// # Checks performed
///
/// 1. The [`SignatureLayer`] contains an attestation (i.e. it was produced from
///    a Sigstore Bundle with a DSSE envelope carrying an in-toto Statement v1).
/// 2. If [`predicate_type`](Self::predicate_type) is set, the attestation's
///    `predicateType` must match exactly.
/// 3. If a [`predicate_validator`](Self::predicate_validator) closure is set,
///    it is called with the attestation's `predicate` JSON value and must
///    return `true` for the constraint to be satisfied.
///
/// # Examples
///
/// ```rust,no_run
/// use sigstore::cosign::verification_constraint::AttestationVerifier;
///
/// // Require a SLSA provenance attestation with any predicate content.
/// let verifier = AttestationVerifier::new()
///     .with_predicate_type("https://slsa.dev/provenance/v1");
///
/// // Require a cosign sign attestation and validate the predicate.
/// let verifier = AttestationVerifier::new()
///     .with_predicate_type("https://sigstore.dev/cosign/sign/v1")
///     .with_predicate_validator(|predicate| {
///         // Custom validation logic on the predicate JSON value.
///         predicate.is_some()
///     });
/// ```
/// Type alias for the predicate validation closure.
type PredicateValidatorFn = Box<dyn Fn(Option<&serde_json::Value>) -> bool + Send + Sync>;

pub struct AttestationVerifier {
    /// If set, the attestation's `predicateType` must match this value.
    predicate_type: Option<String>,
    /// If set, this closure is called with the attestation's `predicate` field
    /// and must return `true` for the constraint to be satisfied.
    predicate_validator: Option<PredicateValidatorFn>,
}

impl std::fmt::Debug for AttestationVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Wrapper so that `Debug` prints without quotes around the value.
        struct OptionalClosure(bool);
        impl std::fmt::Debug for OptionalClosure {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if self.0 {
                    write!(f, "Some(<closure>)")
                } else {
                    write!(f, "None")
                }
            }
        }

        f.debug_struct("AttestationVerifier")
            .field("predicate_type", &self.predicate_type)
            .field(
                "predicate_validator",
                &OptionalClosure(self.predicate_validator.is_some()),
            )
            .finish()
    }
}

impl AttestationVerifier {
    /// Create a new `AttestationVerifier` with no additional constraints.
    ///
    /// By default this only checks that an attestation is present on the
    /// [`SignatureLayer`].
    pub fn new() -> Self {
        Self {
            predicate_type: None,
            predicate_validator: None,
        }
    }

    /// Require the attestation's `predicateType` to match `predicate_type`
    /// exactly.
    pub fn with_predicate_type(mut self, predicate_type: &str) -> Self {
        self.predicate_type = Some(predicate_type.to_string());
        self
    }

    /// Supply a closure that validates the attestation's `predicate` field.
    ///
    /// Per the [in-toto Statement v1 spec](https://in-toto.io/Statement/v1),
    /// the predicate is always a JSON object when present.  The closure
    /// receives `Option<&serde_json::Value>` — `None` when the statement
    /// omits the `predicate` field entirely, `Some(value)` otherwise.  It
    /// must return `true` for the constraint to be satisfied.
    pub fn with_predicate_validator<F>(mut self, f: F) -> Self
    where
        F: Fn(Option<&serde_json::Value>) -> bool + Send + Sync + 'static,
    {
        self.predicate_validator = Some(Box::new(f));
        self
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationConstraint for AttestationVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        let attestation = match &signature_layer.attestation {
            Some(a) => a,
            None => return Ok(false),
        };

        if let Some(expected) = &self.predicate_type
            && attestation.predicate_type != *expected
        {
            return Ok(false);
        }

        if let Some(validator) = &self.predicate_validator
            && !validator(attestation.predicate.as_ref())
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::intoto::{InTotoStatementV1, Subject};
    use crate::cosign::payload::simple_signing::SimpleSigning;
    use std::collections::BTreeMap;

    /// Helper to build a minimal `SignatureLayer` with an optional attestation.
    fn layer_with_attestation(attestation: Option<InTotoStatementV1>) -> SignatureLayer {
        SignatureLayer {
            simple_signing: SimpleSigning {
                critical: crate::cosign::payload::simple_signing::Critical {
                    identity: crate::cosign::payload::simple_signing::Identity {
                        docker_reference: String::new(),
                    },
                    image: crate::cosign::payload::simple_signing::Image {
                        docker_manifest_digest: String::new(),
                    },
                    type_name: String::new(),
                },
                optional: None,
            },
            attestation,
            oci_digest: String::new(),
            certificate_signature: None,
            bundle: None,
            signature: None,
            raw_data: Vec::new(),
        }
    }

    fn sample_attestation(
        predicate_type: &str,
        predicate: Option<serde_json::Value>,
    ) -> InTotoStatementV1 {
        InTotoStatementV1 {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: Some("artifact".to_string()),
                digest: BTreeMap::from([("sha256".to_string(), "abc".to_string())]),
                annotations: None,
            }],
            predicate_type: predicate_type.to_string(),
            predicate,
        }
    }

    #[test]
    fn rejects_layer_without_attestation() {
        let verifier = AttestationVerifier::new();
        let layer = layer_with_attestation(None);
        assert!(!verifier.verify(&layer).unwrap());
    }

    #[test]
    fn accepts_layer_with_any_attestation() {
        let verifier = AttestationVerifier::new();
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://sigstore.dev/cosign/sign/v1",
            None,
        )));
        assert!(verifier.verify(&layer).unwrap());
    }

    #[test]
    fn accepts_matching_predicate_type() {
        let verifier =
            AttestationVerifier::new().with_predicate_type("https://slsa.dev/provenance/v1");
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://slsa.dev/provenance/v1",
            None,
        )));
        assert!(verifier.verify(&layer).unwrap());
    }

    #[test]
    fn rejects_wrong_predicate_type() {
        let verifier =
            AttestationVerifier::new().with_predicate_type("https://slsa.dev/provenance/v1");
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://sigstore.dev/cosign/sign/v1",
            None,
        )));
        assert!(!verifier.verify(&layer).unwrap());
    }

    #[test]
    fn accepts_when_predicate_validator_returns_true() {
        let verifier = AttestationVerifier::new().with_predicate_validator(|p| p.is_some());
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://sigstore.dev/cosign/sign/v1",
            Some(serde_json::json!({"key": "value"})),
        )));
        assert!(verifier.verify(&layer).unwrap());
    }

    #[test]
    fn rejects_when_predicate_validator_returns_false() {
        let verifier = AttestationVerifier::new().with_predicate_validator(|p| p.is_some());
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://sigstore.dev/cosign/sign/v1",
            None,
        )));
        assert!(!verifier.verify(&layer).unwrap());
    }

    #[test]
    fn combined_predicate_type_and_validator() {
        let verifier = AttestationVerifier::new()
            .with_predicate_type("https://slsa.dev/provenance/v1")
            .with_predicate_validator(|p| p.and_then(|v| v.get("builder")).is_some());

        // Correct type + valid predicate → accepted
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://slsa.dev/provenance/v1",
            Some(serde_json::json!({"builder": {"id": "https://github.com/actions/runner"}})),
        )));
        assert!(verifier.verify(&layer).unwrap());

        // Correct type + invalid predicate → rejected
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://slsa.dev/provenance/v1",
            Some(serde_json::json!({"other": "field"})),
        )));
        assert!(!verifier.verify(&layer).unwrap());

        // Wrong type + valid predicate → rejected (type checked first)
        let layer = layer_with_attestation(Some(sample_attestation(
            "https://sigstore.dev/cosign/sign/v1",
            Some(serde_json::json!({"builder": {"id": "https://github.com/actions/runner"}})),
        )));
        assert!(!verifier.verify(&layer).unwrap());
    }
}
