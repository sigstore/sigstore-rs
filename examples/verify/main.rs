//
// Copyright 2021 The Sigstore Authors.
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

extern crate sigstore;
use sigstore::cosign::verification_constraint::{
    AnnotationVerifier, CertSubjectEmailVerifier, CertSubjectUrlVerifier, PublicKeyVerifier,
    VerificationConstraintVec,
};
use sigstore::cosign::CosignCapabilities;
use sigstore::cosign::SignatureLayer;
use sigstore::crypto::SignatureDigestAlgorithm;
use sigstore::tuf::SigstoreRepository;
use std::boxed::Box;
use std::convert::TryFrom;

extern crate anyhow;
use anyhow::anyhow;

extern crate clap;
use clap::Parser;

use std::{collections::HashMap, fs};
use tokio::task::spawn_blocking;

extern crate tracing_subscriber;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Verification key
    #[clap(short, long, required(false))]
    key: Option<String>,

    /// Digest algorithm to use when processing a signature
    #[clap(long, default_value = "sha256")]
    signature_digest_algorithm: String,

    /// Fetch Rekor and Fulcio data from Sigstore's TUF repository"
    #[clap(long)]
    use_sigstore_tuf_data: bool,

    /// File containing Rekor's public key (e.g.: ~/.sigstore/root/targets/rekor.pub)
    #[clap(long, required(false))]
    rekor_pub_key: Option<String>,

    /// File containing Fulcio's certificate (e.g.: ~/.sigstore/root/targets/fulcio.crt.pem)
    #[clap(long, required(false))]
    fulcio_cert: Option<String>,

    /// The issuer of the OIDC token used by the user to authenticate against Fulcio
    #[clap(long, required(false))]
    cert_issuer: Option<String>,

    /// The email expected in a valid fulcio cert
    #[clap(long, required(false))]
    cert_email: Option<String>,

    /// The URL expected in a valid fulcio cert
    #[clap(long, required(false))]
    cert_url: Option<String>,

    /// Annotations that have to be satisfied
    #[clap(
        short,
        long,
        parse(from_str),
        takes_value(true),
        required(false),
        multiple_occurrences(true)
    )]
    annotations: Vec<String>,

    /// Enable verbose mode
    #[clap(short, long)]
    verbose: bool,

    /// Name of the image to verify
    image: String,
}

async fn run_app() -> anyhow::Result<Vec<SignatureLayer>> {
    let cli = Cli::parse();

    // Note well: this a limitation deliberately introduced by this example.
    if cli.cert_email.is_some() && cli.cert_url.is_some() {
        return Err(anyhow!(
            "The 'cert-email' and 'cert-url' flags cannot be used at the same time"
        ));
    }

    // setup logging
    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let auth = &sigstore::registry::Auth::Anonymous;

    let rekor_pub_key: Option<String> = cli
        .rekor_pub_key
        .map(|path| {
            fs::read_to_string(path)
                .map_err(|e| anyhow!("Error reading rekor public key from disk: {}", e))
        })
        .transpose()?;

    let fulcio_cert: Option<Vec<u8>> = cli
        .fulcio_cert
        .map(|path| {
            fs::read(path).map_err(|e| anyhow!("Error reading fulcio certificate from disk: {}", e))
        })
        .transpose()?;

    let sigstore_repo: Option<SigstoreRepository> = if cli.use_sigstore_tuf_data {
        let repo: sigstore::errors::Result<SigstoreRepository> = spawn_blocking(|| {
            info!("Downloading data from Sigstore TUF repository");
            sigstore::tuf::SigstoreRepository::fetch(None)
        })
        .await
        .map_err(|e| anyhow!("Error spawining blocking task inside of tokio: {}", e))?;

        Some(repo?)
    } else {
        None
    };

    let mut client_builder = sigstore::cosign::ClientBuilder::default();

    if let Some(repo) = sigstore_repo {
        client_builder = client_builder.with_rekor_pub_key(repo.rekor_pub_key());
        client_builder = client_builder.with_fulcio_cert(repo.fulcio_cert());
    }

    // Set Rekor public key. Give higher precendece to the key specified by the user over the
    // one that can be obtained from Sigstore's TUF repository
    if let Some(key) = rekor_pub_key {
        client_builder = client_builder.with_rekor_pub_key(&key);
    }
    // Set Fulcio certificate. Give higher precendece to the certificate specified by the user over the
    // one that can be obtained from Sigstore's TUF repository
    if let Some(cert) = fulcio_cert {
        client_builder = client_builder.with_fulcio_cert(&cert);
    }

    let mut client = client_builder.build()?;

    // Build verification constraints
    let mut verification_constraint: VerificationConstraintVec = Vec::new();
    if let Some(cert_email) = cli.cert_email {
        let issuer = cli.cert_issuer.as_ref().map(|i| i.to_string());

        verification_constraint.push(Box::new(CertSubjectEmailVerifier {
            email: cert_email.to_string(),
            issuer,
        }));
    }
    if let Some(cert_url) = cli.cert_url {
        let issuer = cli.cert_issuer.as_ref().map(|i| i.to_string());
        if issuer.is_none() {
            return Err(anyhow!(
                "'cert-issuer' is required when 'cert-url' is specified"
            ));
        }

        verification_constraint.push(Box::new(CertSubjectUrlVerifier {
            url: cert_url.to_string(),
            issuer: issuer.unwrap(),
        }));
    }
    if let Some(path_to_key) = cli.key {
        let key = fs::read(path_to_key).map_err(|e| anyhow!("Cannot read key: {:?}", e))?;
        let signature_digest_algorithm =
            SignatureDigestAlgorithm::try_from(cli.signature_digest_algorithm.as_str())
                .map_err(anyhow::Error::msg)?;
        let verifier = PublicKeyVerifier::new(&key, signature_digest_algorithm)
            .map_err(|e| anyhow!("Cannot create public key verifier: {}", e))?;
        verification_constraint.push(Box::new(verifier));
    }

    if !cli.annotations.is_empty() {
        let mut values: HashMap<String, String> = HashMap::new();
        for annotation in &cli.annotations {
            let tmp: Vec<_> = annotation.splitn(2, "=").collect();
            if tmp.len() == 2 {
                values.insert(String::from(tmp[0]), String::from(tmp[1]));
            }
        }
        if !values.is_empty() {
            let annotations_verifier = AnnotationVerifier {
                annotations: values,
            };
            verification_constraint.push(Box::new(annotations_verifier));
        }
    }

    let image: &str = cli.image.as_str();

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;

    let trusted_layers = client
        .trusted_signature_layers(auth, &source_image_digest, &cosign_signature_image)
        .await?;

    sigstore::cosign::filter_signature_layers(&trusted_layers, verification_constraint)
        .map_err(|e| anyhow!("{}", e))
}

#[tokio::main]
pub async fn main() {
    let trusted_signatures: anyhow::Result<Vec<SignatureLayer>> = run_app().await;

    std::process::exit(match trusted_signatures {
        Ok(signatures) => {
            if signatures.is_empty() {
                eprintln!("Image verification failed: no matching signature found.");
                1
            } else {
                println!("Image successfully verified");
                serde_json::to_writer_pretty(std::io::stdout(), &signatures).unwrap();
                0
            }
        }
        Err(err) => {
            eprintln!("Image verification failed: {:?}", err);
            1
        }
    });
}
