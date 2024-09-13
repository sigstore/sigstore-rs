use super::VerificationConstraint;
use crate::cosign::signature_layers::{CertificateSubject, SignatureLayer};
use crate::errors::Result;

/// Verification Constraint for signatures produced in keyless mode.
///
/// Keyless signatures have a x509 certificate associated to them. This
/// verifier ensures the SAN portion of the certificate has an email
/// attribute that matches the one provided by the user.
///
/// It's also possible to specify the `Issuer`, this is the name of the
/// identity provider that was used by the user to authenticate.
///
/// For example, `cosign` produces the following signature when the user
/// relies on GitHub to authenticate himself:
///
/// ```hcl
/// {
///   "critical": {
///      // not relevant
///   },
///   "optional": {
///     "Bundle": {
///       // not relevant
///     },
///     "Issuer": "https://github.com/login/oauth",
///     "Subject": "alice@example.com"
///   }
/// }
/// ```
///
/// The following constraints would be able to enforce this signature to be
/// found:
///
/// ```rust
/// use sigstore::cosign::verification_constraint::CertSubjectEmailVerifier;
///
/// // This looks only for the email address of the trusted user
/// let vc_email = CertSubjectEmailVerifier{
///     email: String::from("alice@example.com"),
///     ..Default::default()
/// };
///
/// // This ensures the user authenticated via GitHub (see the issuer value),
/// // plus the email associated to his GitHub account must be the one specified.
/// let vc_email_and_issuer = CertSubjectEmailVerifier{
///     email: String::from("alice@example.com"),
///     issuer: Some(String::from("https://github.com/login/oauth")),
/// };
/// ```
///
/// When `issuer` is `None`, the value found inside of the signature's certificate
/// is not checked.
///
/// For example, given the following constraint:
/// ```rust
/// use sigstore::cosign::verification_constraint::CertSubjectEmailVerifier;
///
/// let constraint = CertSubjectEmailVerifier{
///     email: String::from("alice@example.com"),
///     ..Default::default()
/// };
/// ```
///
/// Both these signatures would be trusted:
/// ```hcl
/// [
///   {
///     "critical": {
///        // not relevant
///     },
///     "optional": {
///       "Bundle": {
///         // not relevant
///       },
///       "Issuer": "https://github.com/login/oauth",
///       "Subject": "alice@example.com"
///     }
///   },
///   {
///     "critical": {
///        // not relevant
///     },
///     "optional": {
///       "Bundle": {
///         // not relevant
///       },
///       "Issuer": "https://example.com/login/oauth",
///       "Subject": "alice@example.com"
///     }
///   }
/// ]
/// ```
#[derive(Default, Debug)]
pub struct CertSubjectEmailVerifier {
    pub email: String,
    pub issuer: Option<String>,
}

impl VerificationConstraint for CertSubjectEmailVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        let verified = match &signature_layer.certificate_signature {
            Some(signature) => {
                let email_matches = match &signature.subject {
                    CertificateSubject::Email(e) => e == &self.email,
                    _ => false,
                };

                let issuer_matches = match self.issuer {
                    Some(_) => self.issuer == signature.issuer,
                    None => true,
                };

                email_matches && issuer_matches
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
    use crate::cosign::verification_constraint::CertSubjectUrlVerifier;

    #[test]
    fn cert_email_verifier_only_email() {
        let email = "alice@example.com".to_string();
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let cert_subj = CertificateSubject::Email(email.clone());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectEmailVerifier {
            email,
            issuer: None,
        };
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectEmailVerifier {
            email: "different@email.com".to_string(),
            issuer: None,
        };
        assert!(!vc.verify(&sl).unwrap());
    }

    #[test]
    fn cert_email_verifier_email_and_issuer() {
        let email = "alice@example.com".to_string();
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();

        // The cerificate subject doesn't have an issuer
        let cert_subj = CertificateSubject::Email(email.clone());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature.clone());

        // fail because the issuer we want doesn't exist
        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: Some("an issuer".to_string()),
        };
        assert!(!vc.verify(&sl).unwrap());

        // The cerificate subject has an issuer
        let issuer = "the issuer".to_string();
        let cert_subj = CertificateSubject::Email(email.clone());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectEmailVerifier {
            email: email.clone(),
            issuer: Some(issuer.clone()),
        };
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectEmailVerifier {
            email,
            issuer: Some("another issuer".to_string()),
        };
        assert!(!vc.verify(&sl).unwrap());

        // another verifier should fail
        let vc = CertSubjectUrlVerifier {
            url: "https://sigstore.dev/test".to_string(),
            issuer,
        };
        assert!(!vc.verify(&sl).unwrap());
    }

    #[test]
    fn cert_email_verifier_no_signature() {
        let (sl, _) = build_correct_signature_layer_without_bundle();

        let vc = CertSubjectEmailVerifier {
            email: "alice@example.com".to_string(),
            issuer: None,
        };
        assert!(!vc.verify(&sl).unwrap());
    }
}
