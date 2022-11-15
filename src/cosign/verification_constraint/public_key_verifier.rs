use super::VerificationConstraint;
use crate::cosign::signature_layers::SignatureLayer;
use crate::crypto::{CosignVerificationKey, SigningScheme};
use crate::errors::Result;

/// Verification Constraint for signatures produced with public/private keys
#[derive(Debug)]
pub struct PublicKeyVerifier {
    key: CosignVerificationKey,
}

impl PublicKeyVerifier {
    /// Create a new instance of `PublicKeyVerifier`.
    /// The `key_raw` variable holds a PEM encoded representation of the
    /// public key to be used at verification time.
    pub fn new(key_raw: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        let key = CosignVerificationKey::from_pem(key_raw, signing_scheme)?;
        Ok(PublicKeyVerifier { key })
    }

    /// Create a new instance of `PublicKeyVerifier`.
    /// The `key_raw` variable holds a PEM encoded representation of the
    /// public key to be used at verification time. The verification
    /// algorithm will be derived from the public key type:
    /// * `RSA public key`: `RSA_PKCS1_SHA256`
    /// * `EC public key with P-256 curve`: `ECDSA_P256_SHA256_ASN1`
    /// * `EC public key with P-384 curve`: `ECDSA_P384_SHA384_ASN1`
    /// * `Ed25519 public key`: `Ed25519`
    pub fn try_from(key_raw: &[u8]) -> Result<Self> {
        let key = CosignVerificationKey::try_from_pem(key_raw)?;
        Ok(PublicKeyVerifier { key })
    }
}

impl VerificationConstraint for PublicKeyVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        Ok(signature_layer.is_signed_by_key(&self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosign::signature_layers::tests::{
        build_correct_signature_layer_with_certificate,
        build_correct_signature_layer_without_bundle,
    };

    #[test]
    fn pub_key_verifier() {
        let (sl, key) = build_correct_signature_layer_without_bundle();

        let vc = PublicKeyVerifier { key };
        assert!(vc.verify(&sl).unwrap());

        let sl = build_correct_signature_layer_with_certificate();
        assert!(!vc.verify(&sl).unwrap());
    }
}
