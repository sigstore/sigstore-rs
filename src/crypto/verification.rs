use rustls_pki_types::CertificateDer;
use webpki::TrustAnchor;

/// Machinery for Sigstore end entity certificate verification.
struct CertificateVerificationContext<'a> {
    pub trust_anchors: Vec<TrustAnchor<'a>>,
    pub intermediate_certs: Vec<CertificateDer<'a>>,
}

impl CertificateVerificationContext<'_> {
    pub fn new() {}
}
