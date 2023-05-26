use pkcs8::der::Decode;
use sigstore::crypto::SigningScheme;
use sigstore::fulcio::oauth::OauthTokenProvider;
use sigstore::fulcio::{FulcioClient, TokenProvider, FULCIO_ROOT};
use url::Url;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

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

        let pems = pem::parse_many(cert.as_ref()).expect("parse pem failed");
        for pem in &pems {
            let cert = Certificate::from_der(pem.contents()).expect("parse certificate from der");

            let (_, san) = cert
                .tbs_certificate
                .get::<SubjectAltName>()
                .expect("get SAN failed")
                .expect("No SAN found");

            for name in &san.0 {
                println!("SAN: {name:?}");
            }
        }
    }
}
