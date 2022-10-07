use sigstore::crypto::SigningScheme;
use sigstore::fulcio::oauth::OauthTokenProvider;
use sigstore::fulcio::{FulcioClient, TokenProvider, FULCIO_ROOT};
use url::Url;
use x509_parser::pem::Pem;

#[tokio::main]
async fn main() {
    let fulcio = FulcioClient::new(
        Url::parse(FULCIO_ROOT).unwrap(),
        TokenProvider::Oauth(OauthTokenProvider::default()),
    );

    if let Ok((_signer, cert)) = fulcio
        .request_cert(SigningScheme::ECDSA_P256_SHA256_ASN1)
        .await
    {
        println!("Received certificate chain");

        for cert in Pem::iter_from_buffer(cert.as_ref()) {
            if let Ok(cert) = cert {
                if let Ok(result) = cert.parse_x509() {
                    if let Ok(san) = result.subject_alternative_name() {
                        if let Some(san) = san {
                            let san = san.value;
                            for name in &san.general_names {
                                println!("SAN: {}", name);
                            }
                        }
                    }
                }
            }
        }
    }
}
