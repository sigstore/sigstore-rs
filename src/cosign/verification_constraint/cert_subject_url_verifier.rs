use super::VerificationConstraint;
use crate::cosign::signature_layers::{CertificateSubject, SignatureLayer};
use crate::errors::Result;

/// Verification Constraint for signatures produced in keyless mode.
///
/// Keyless signatures have a x509 certificate associated to them. This
/// verifier ensures the SAN portion of the certificate has a URI
/// attribute that matches the one provided by the user.
///
/// The constraints needs also the `Issuer` to be provided, this is the name
/// of the identity provider that was used by the user to authenticate.
///
/// This verifier can be used to check keyless signatures produced in
/// non-interactive mode inside of GitHub Actions.
///
/// For example, `cosign` produces the following signature when the
/// OIDC token is extracted from the GITHUB_TOKEN:
///
/// ```hcl
/// {
///   "critical": {
///     // not relevant
///   },
///   "optional": {
///     "Bundle": {
///     // not relevant
///     },
///     "Issuer": "https://token.actions.githubusercontent.com",
///     "Subject": "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
///   }
/// }
/// ```
///
/// The following constraint would be able to enforce this signature to be
/// found:
///
/// ```rust
/// use sigstore::cosign::verification_constraint::CertSubjectUrlVerifier;
///
/// let vc = CertSubjectUrlVerifier{
///     url: String::from("https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"),
///     issuer: String::from("https://token.actions.githubusercontent.com"),
/// };
/// ```
#[derive(Default, Debug)]
pub struct CertSubjectUrlVerifier {
    pub url: String,
    pub issuer: String,
}

impl VerificationConstraint for CertSubjectUrlVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        let verified = match &signature_layer.certificate_signature {
            Some(signature) => {
                let url_matches = match &signature.subject {
                    CertificateSubject::Uri(u) => u == &self.url,
                    _ => false,
                };
                let issuer_matches = Some(self.issuer.clone()) == signature.issuer;

                url_matches && issuer_matches
            }
            _ => false,
        };
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosign::signature_layers::tests::{
        build_correct_signature_layer_with_certificate,
        build_correct_signature_layer_without_bundle,
    };
    use crate::cosign::verification_constraint::CertSubjectEmailVerifier;

    #[test]
    fn cert_subject_url_verifier() {
        let url = "https://sigstore.dev/test".to_string();
        let issuer = "the issuer".to_string();

        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let cert_subj = CertificateSubject::Uri(url.clone());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectUrlVerifier {
            url: url.clone(),
            issuer: issuer.clone(),
        };
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectUrlVerifier {
            url: "a different url".to_string(),
            issuer: issuer.clone(),
        };
        assert!(!vc.verify(&sl).unwrap());

        let vc = CertSubjectUrlVerifier {
            url,
            issuer: "a different issuer".to_string(),
        };
        assert!(!vc.verify(&sl).unwrap());

        // A Cert email verifier should also report a non match
        let vc = CertSubjectEmailVerifier {
            email: "alice@example.com".to_string(),
            issuer: Some(issuer),
        };
        assert!(!vc.verify(&sl).unwrap());
    }

    #[test]
    fn cert_subject_verifier_no_signature() {
        let (sl, _) = build_correct_signature_layer_without_bundle();

        let vc = CertSubjectUrlVerifier {
            url: "https://sigstore.dev/test".to_string(),
            issuer: "an issuer".to_string(),
        };
        assert!(!vc.verify(&sl).unwrap());
    }
}
