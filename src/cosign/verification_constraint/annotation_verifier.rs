use std::collections::HashMap;

use super::VerificationConstraint;
use crate::cosign::signature_layers::SignatureLayer;
use crate::errors::Result;

/// Verification Constraint for the annotations added by `cosign sign`
///
/// The `SimpleSigning` object produced at signature time can be enriched by
/// signer with so called "anntoations".
///
/// This constraint ensures that all the annotations specified by the user are
/// found inside of the SignatureLayer.
///
/// It's perfectly find for the SignatureLayer to have additional annotations.
/// These will be simply be ignored by the verifier.
#[derive(Default, Debug)]
pub struct AnnotationVerifier {
    pub annotations: HashMap<String, String>,
}

impl VerificationConstraint for AnnotationVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        let verified = signature_layer
            .simple_signing
            .satisfies_annotations(&self.annotations);
        Ok(verified)
    }
}
