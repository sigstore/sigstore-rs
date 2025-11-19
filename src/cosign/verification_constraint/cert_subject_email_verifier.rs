use regex::Regex;
use std::fmt::Debug;

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
/// use regex::Regex;
/// use sigstore::cosign::verification_constraint::CertSubjectEmailVerifier;
/// use sigstore::cosign::verification_constraint::cert_subject_email_verifier::StringVerifier;
///
/// // This looks only for the email address of the trusted user
/// let vc_email = CertSubjectEmailVerifier{
///     email: StringVerifier::ExactMatch("alice@example.com".to_string()),
///     issuer: None,
/// };
///
/// // This looks only for emails matching the a pattern
/// let vc_email_regex = CertSubjectEmailVerifier{
///     email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
///     issuer: None,
/// };
///
/// // This ensures the user authenticated via GitHub (see the issuer value),
/// // plus the email associated to his GitHub account must be the one specified.
/// let vc_email_and_issuer = CertSubjectEmailVerifier{
///     email: StringVerifier::ExactMatch("alice@example.com".to_string()),
///     issuer: Some(StringVerifier::ExactMatch("https://github.com/login/oauth".to_string())),
/// };
///
/// // This ensures the user authenticated via a service that has a domain
/// // matching the regex, plus the email associated to account also matches
/// // the regex.
/// let vc_email_and_issuer_regex = CertSubjectEmailVerifier{
///     email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
///     issuer: Some(StringVerifier::Regex(Regex::new(r"https://github\.com/login/oauth|https://google\.com").unwrap())),
/// };
/// ```
///
/// When `issuer` is `None`, the value found inside of the signature's certificate
/// is not checked.
///
/// For example, given the following constraint:
/// ```rust
/// use sigstore::cosign::verification_constraint::CertSubjectEmailVerifier;
/// use sigstore::cosign::verification_constraint::cert_subject_email_verifier::StringVerifier;
///
/// let constraint = CertSubjectEmailVerifier{
///     email: StringVerifier::ExactMatch("alice@example.com".to_string()),
///     issuer: None,
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
pub struct CertSubjectEmailVerifier {
    pub email: StringVerifier,
    pub issuer: Option<StringVerifier>,
}

impl Debug for CertSubjectEmailVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut issuer_str = String::new();
        if let Some(issuer) = &self.issuer {
            issuer_str.push_str(&format!(" and {issuer}"));
        }
        f.write_fmt(format_args!(
            "email {}{}",
            &self.email.to_string(),
            issuer_str
        ))
    }
}

pub enum StringVerifier {
    ExactMatch(String),
    Regex(Regex),
}

impl StringVerifier {
    fn verify(&self, s: &str) -> bool {
        match self {
            StringVerifier::ExactMatch(s2) => s == *s2,
            StringVerifier::Regex(r) => r.is_match(s),
        }
    }
}

impl std::fmt::Display for StringVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringVerifier::ExactMatch(s) => f.write_fmt(format_args!("is exactly {s}")),
            StringVerifier::Regex(r) => f.write_fmt(format_args!("matches regular expression {r}")),
        }
    }
}

impl VerificationConstraint for CertSubjectEmailVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> Result<bool> {
        let verified = match &signature_layer.certificate_signature {
            Some(signature) => {
                let email_matches = match &signature.subject {
                    CertificateSubject::Email(e) => self.email.verify(e),
                    _ => false,
                };

                let issuer_matches = match &self.issuer {
                    Some(issuer) => {
                        if let Some(signature_issuer) = &signature.issuer {
                            issuer.verify(signature_issuer)
                        } else {
                            // if the issuer is not present in the signature, we
                            // consider it as a failed constriant
                            false
                        }
                    }
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
        let cert_subj = CertificateSubject::Email(email.to_string());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch(email),
            issuer: None,
        };
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch("different@email.com".to_string()),
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
            email: StringVerifier::ExactMatch(email.clone()),
            issuer: Some(StringVerifier::ExactMatch("an issuer".to_string())),
        };
        assert!(!vc.verify(&sl).unwrap());

        // The cerificate subject has an issuer
        let issuer = "the issuer".to_string();
        let cert_subj = CertificateSubject::Email(email.clone());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch(email.clone()),
            issuer: Some(StringVerifier::ExactMatch(issuer.clone())),
        };
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch(email),
            issuer: Some(StringVerifier::ExactMatch("another issuer".to_string())),
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
            email: StringVerifier::ExactMatch("alice@example.com".to_string()),
            issuer: None,
        };
        assert!(!vc.verify(&sl).unwrap());
    }

    #[test]
    fn cert_email_verifier_only_email_regex() {
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let cert_subj = CertificateSubject::Email("alice@example.com".to_string());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
            issuer: None,
        };
        assert!(vc.verify(&sl).unwrap());

        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let cert_subj = CertificateSubject::Email("bob@example.com".to_string());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);
        assert!(vc.verify(&sl).unwrap());

        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch("different@email.com".to_string()),
            issuer: None,
        };
        assert!(!vc.verify(&sl).unwrap());
    }

    #[test]
    fn cert_email_verifier_email_and_issuer_regex() {
        // The cerificate subject doesn't have an issuer
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let cert_subj = CertificateSubject::Email("alice@example.com".to_string());
        cert_signature.issuer = None;
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature.clone());

        // fail because the issuer we want doesn't exist
        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
            issuer: Some(StringVerifier::Regex(
                Regex::new(r#".*\.github.com"#).unwrap(),
            )),
        };
        assert!(!vc.verify(&sl).unwrap());

        // The cerificate subject has an issuer
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let issuer = "some-action.github.com".to_string();
        let cert_subj = CertificateSubject::Email("alice@example.com".to_string());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        // pass because the issuer matches the regex
        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
            issuer: Some(StringVerifier::Regex(
                Regex::new(r#".*\.github.com"#).unwrap(),
            )),
        };
        assert!(vc.verify(&sl).unwrap());

        // The cerificate subject has an incorrect issuer
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let issuer = "invalid issuer".to_string();
        let cert_subj = CertificateSubject::Email("alice@example.com".to_string());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        // fail because the issuer doesn't matches the regex
        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
            issuer: Some(StringVerifier::Regex(
                Regex::new(r#".*\.github.com"#).unwrap(),
            )),
        };
        assert!(!vc.verify(&sl).unwrap());

        // The cerificate subject has an invalid email
        let mut sl = build_correct_signature_layer_with_certificate();
        let mut cert_signature = sl.certificate_signature.unwrap();
        let issuer = "some-action.github.com".to_string();
        let cert_subj = CertificateSubject::Email("alice@somedomain.com".to_string());
        cert_signature.issuer = Some(issuer.clone());
        cert_signature.subject = cert_subj;
        sl.certificate_signature = Some(cert_signature);

        // fail because the email doesn't matches the regex
        let vc = CertSubjectEmailVerifier {
            email: StringVerifier::Regex(Regex::new(".*@example.com").unwrap()),
            issuer: Some(StringVerifier::Regex(
                Regex::new(r#".*\.github.com"#).unwrap(),
            )),
        };
        assert!(!vc.verify(&sl).unwrap());
    }
}
