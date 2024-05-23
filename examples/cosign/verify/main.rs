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
    AnnotationVerifier, CertSubjectEmailVerifier, CertSubjectUrlVerifier, CertificateVerifier,
    PublicKeyVerifier, VerificationConstraintVec,
};
use sigstore::cosign::{CosignCapabilities, SignatureLayer};
use sigstore::crypto::SigningScheme;
use sigstore::errors::SigstoreVerifyConstraintsError;
use sigstore::registry::{ClientConfig, ClientProtocol, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use std::time::Instant;

extern crate anyhow;
use anyhow::{anyhow, Result};

extern crate clap;
use clap::Parser;

use std::{collections::HashMap, fs};

extern crate tracing_subscriber;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Verification key
    #[clap(short, long, required(false))]
    key: Option<String>,

    /// Path to verification certificate
    #[clap(long, required(false))]
    cert: Option<String>,

    /// Path to certificate chain bundle file
    #[clap(long, required(false))]
    cert_chain: Option<String>,

    /// Signing scheme when signing and verifying
    #[clap(long, required(false))]
    signing_scheme: Option<String>,

    /// Fetch Rekor and Fulcio data from Sigstore's TUF repository"
    #[clap(long)]
    use_sigstore_tuf_data: bool,

    /// File containing Rekor's public key (e.g.: ~/.sigstore/root/targets/rekor.pub)
    #[clap(long, required(false))]
    rekor_pub_keys: Vec<String>,

    /// File containing Fulcio's certificate (e.g.: ~/.sigstore/root/targets/fulcio.crt.pem)
    #[clap(long, required(false))]
    fulcio_certs: Vec<String>,

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
    #[clap(short, long, required(false))]
    annotations: Vec<String>,

    /// Enable verbose mode
    #[clap(short, long)]
    verbose: bool,

    /// Enable caching of registry operations
    #[clap(long)]
    enable_registry_caching: bool,

    /// Number of loops to be done. Useful only for testing `enable-registry-caching`
    #[clap(long, default_value = "1")]
    loops: u32,

    /// Name of the image to verify
    image: OciReference,

    /// Whether the registry uses HTTP
    #[clap(long)]
    http: bool,
}

async fn run_app(
    cli: &Cli,
    frd: &dyn sigstore::trust::TrustRoot,
) -> anyhow::Result<(Vec<SignatureLayer>, VerificationConstraintVec)> {
    // Note well: this a limitation deliberately introduced by this example.
    if cli.cert_email.is_some() && cli.cert_url.is_some() {
        return Err(anyhow!(
            "The 'cert-email' and 'cert-url' flags cannot be used at the same time"
        ));
    }

    if cli.key.is_some() && cli.cert.is_some() {
        return Err(anyhow!("'key' and 'cert' cannot be used at the same time"));
    }

    let auth = &sigstore::registry::Auth::Anonymous;

    let mut oci_client_config = ClientConfig::default();
    match cli.http {
        false => oci_client_config.protocol = ClientProtocol::Https,
        true => oci_client_config.protocol = ClientProtocol::Http,
    }

    let mut client_builder =
        sigstore::cosign::ClientBuilder::default().with_oci_client_config(oci_client_config);
    client_builder = client_builder.with_trust_repository(frd)?;

    let cert_chain: Option<Vec<sigstore::registry::Certificate>> = match cli.cert_chain.as_ref() {
        None => None,
        Some(cert_chain_path) => Some(parse_cert_bundle(cert_chain_path)?),
    };

    if cli.enable_registry_caching {
        client_builder = client_builder.enable_registry_caching();
    }

    let mut client = client_builder.build()?;

    // Build verification constraints
    let mut verification_constraints: VerificationConstraintVec = Vec::new();
    if let Some(cert_email) = cli.cert_email.as_ref() {
        let issuer = cli.cert_issuer.as_ref().map(|i| i.to_string());

        verification_constraints.push(Box::new(CertSubjectEmailVerifier {
            email: cert_email.to_string(),
            issuer,
        }));
    }
    if let Some(cert_url) = cli.cert_url.as_ref() {
        let issuer = cli.cert_issuer.as_ref().map(|i| i.to_string());
        if issuer.is_none() {
            return Err(anyhow!(
                "'cert-issuer' is required when 'cert-url' is specified"
            ));
        }

        verification_constraints.push(Box::new(CertSubjectUrlVerifier {
            url: cert_url.to_string(),
            issuer: issuer.unwrap(),
        }));
    }
    if let Some(path_to_key) = cli.key.as_ref() {
        let key = fs::read(path_to_key).map_err(|e| anyhow!("Cannot read key: {:?}", e))?;

        let verifier = match &cli.signing_scheme {
            Some(scheme) => {
                let signing_scheme =
                    SigningScheme::try_from(&scheme[..]).map_err(anyhow::Error::msg)?;
                PublicKeyVerifier::new(&key, &signing_scheme)
                    .map_err(|e| anyhow!("Cannot create public key verifier: {}", e))?
            }
            None => PublicKeyVerifier::try_from(&key)
                .map_err(|e| anyhow!("Cannot create public key verifier: {}", e))?,
        };

        verification_constraints.push(Box::new(verifier));
    }
    if let Some(path_to_cert) = cli.cert.as_ref() {
        let cert = fs::read(path_to_cert).map_err(|e| anyhow!("Cannot read cert: {:?}", e))?;
        let require_rekor_bundle = if !frd.rekor_keys()?.is_empty() {
            true
        } else {
            warn!("certificate based verification is weaker when Rekor integration is disabled");
            false
        };

        let verifier =
            CertificateVerifier::from_pem(&cert, require_rekor_bundle, cert_chain.as_deref())
                .map_err(|e| anyhow!("Cannot create certificate verifier: {}", e))?;

        verification_constraints.push(Box::new(verifier));
    }

    if !cli.annotations.is_empty() {
        let mut values: HashMap<String, String> = HashMap::new();
        for annotation in &cli.annotations {
            let tmp: Vec<_> = annotation.splitn(2, '=').collect();
            if tmp.len() == 2 {
                values.insert(String::from(tmp[0]), String::from(tmp[1]));
            }
        }
        if !values.is_empty() {
            let annotations_verifier = AnnotationVerifier {
                annotations: values,
            };
            verification_constraints.push(Box::new(annotations_verifier));
        }
    }

    let image = &cli.image;

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;

    let trusted_layers = client
        .trusted_signature_layers(auth, &source_image_digest, &cosign_signature_image)
        .await?;

    Ok((trusted_layers, verification_constraints))
}

async fn fulcio_and_rekor_data(cli: &Cli) -> anyhow::Result<Box<dyn sigstore::trust::TrustRoot>> {
    if cli.use_sigstore_tuf_data {
        info!("Downloading data from Sigstore TUF repository");

        let repo: sigstore::errors::Result<SigstoreTrustRoot> = SigstoreTrustRoot::new(None).await;

        return Ok(Box::new(repo?));
    };

    let mut data = sigstore::trust::ManualTrustRoot::default();
    for path in cli.rekor_pub_keys.iter() {
        data.rekor_keys.push(
            fs::read(path)
                .map_err(|e| anyhow!("Error reading rekor public key from disk: {}", e))?,
        );
    }

    for path in cli.fulcio_certs.iter() {
        let cert_data = fs::read(path)
            .map_err(|e| anyhow!("Error reading fulcio certificate from disk: {}", e))?;

        let certificate = sigstore::registry::Certificate {
            encoding: sigstore::registry::CertificateEncoding::Pem,
            data: cert_data,
        };
        data.fulcio_certs.push(certificate.try_into()?);
    }

    Ok(Box::new(data))
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    // setup logging
    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let frd = match fulcio_and_rekor_data(&cli).await {
        Ok(sr) => sr,
        Err(e) => {
            eprintln!("Cannot build sigstore repo data: {}", e);
            std::process::exit(1);
        }
    };

    for n in 0..(cli.loops) {
        let now = Instant::now();
        if cli.loops != 1 {
            println!("Loop {}/{}", n + 1, cli.loops);
        }

        match run_app(&cli, frd.as_ref()).await {
            Ok((trusted_layers, verification_constraints)) => {
                let filter_result = sigstore::cosign::verify_constraints(
                    &trusted_layers,
                    verification_constraints.iter(),
                );

                match filter_result {
                    Ok(()) => {
                        println!("Image successfully verified");
                    }
                    Err(SigstoreVerifyConstraintsError {
                        unsatisfied_constraints,
                    }) => {
                        eprintln!("Image verification failed: not all constraints satisfied.");
                        eprintln!("{:?}", unsatisfied_constraints);
                    }
                }
            }
            Err(err) => {
                eprintln!("Image verification failed: {:?}", err);
            }
        }

        let elapsed = now.elapsed();

        if cli.loops != 1 {
            println!("Elapsed: {:.2?}", elapsed);
            println!("------");
        }
    }
}

fn parse_cert_bundle(bundle_path: &str) -> Result<Vec<sigstore::registry::Certificate>> {
    let data =
        fs::read(bundle_path).map_err(|e| anyhow!("Error reading {}: {}", bundle_path, e))?;
    let pems = pem::parse_many(data)?;

    Ok(pems
        .iter()
        .map(|pem| sigstore::registry::Certificate {
            encoding: sigstore::registry::CertificateEncoding::Der,
            data: pem.contents().to_vec(),
        })
        .collect())
}
