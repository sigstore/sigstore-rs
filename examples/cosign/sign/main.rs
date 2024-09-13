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

use docker_credential::{CredentialRetrievalError, DockerCredential};
use sigstore::cosign::constraint::{AnnotationMarker, PrivateKeySigner};
use sigstore::cosign::{Constraint, CosignCapabilities, SignatureLayer};
use sigstore::crypto::SigningScheme;
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
use tracing::{debug, warn};
use zeroize::Zeroizing;

extern crate anyhow;
use anyhow::anyhow;

extern crate clap;
use clap::Parser;

use std::{collections::HashMap, fs};

extern crate tracing_subscriber;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Verification key
    #[clap(short, long, required(false))]
    key: String,

    /// Signing scheme when signing and verifying
    #[clap(long, required(false))]
    signing_scheme: Option<String>,

    /// Password used to decrypt private key
    #[clap(long, required(false))]
    password: Option<String>,

    /// Annotations that have to be satisfied
    #[clap(short, long, required(false))]
    annotations: Vec<String>,

    /// Enable verbose mode
    #[clap(short, long)]
    verbose: bool,

    /// Name of the image to verify
    #[clap(short, long)]
    image: OciReference,

    /// Whether the registry uses HTTP
    #[clap(long)]
    http: bool,
}

async fn run_app(cli: &Cli) -> anyhow::Result<()> {
    let auth = &sigstore::registry::Auth::Anonymous;

    let mut oci_client_config = ClientConfig::default();
    match cli.http {
        false => oci_client_config.protocol = ClientProtocol::Https,
        true => oci_client_config.protocol = ClientProtocol::Http,
    }

    let client_builder =
        sigstore::cosign::ClientBuilder::default().with_oci_client_config(oci_client_config);
    let mut client = client_builder.build()?;

    let image = &cli.image;

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;
    debug!(cosign_signature_image= ?cosign_signature_image, source_image_digest= ?source_image_digest);

    let mut signature_layer = SignatureLayer::new_unsigned(image, &source_image_digest)?;

    let auth = build_auth(&cosign_signature_image);
    debug!(auth = ?auth, "use auth");

    if !cli.annotations.is_empty() {
        let mut values: HashMap<String, String> = HashMap::new();
        for annotation in &cli.annotations {
            let tmp: Vec<_> = annotation.splitn(2, '=').collect();
            if tmp.len() == 2 {
                values.insert(String::from(tmp[0]), String::from(tmp[1]));
            }
        }
        if !values.is_empty() {
            let annotations_marker = AnnotationMarker {
                annotations: values,
            };
            annotations_marker
                .add_constraint(&mut signature_layer)
                .expect("add annotations failed");
        }
    }

    let key = Zeroizing::new(fs::read(&cli.key).map_err(|e| anyhow!("Cannot read key: {:?}", e))?);

    let signing_scheme = if let Some(ss) = &cli.signing_scheme {
        &ss[..]
    } else {
        "ECDSA_P256_SHA256_ASN1"
    };
    let signing_scheme = SigningScheme::try_from(signing_scheme).map_err(anyhow::Error::msg)?;
    let password = Zeroizing::new(cli.password.clone().unwrap_or_default().as_bytes().to_vec());

    let signer = PrivateKeySigner::new_with_raw(key, password, &signing_scheme)
        .map_err(|e| anyhow!("Cannot create private key signer: {}", e))?;

    signer
        .add_constraint(&mut signature_layer)
        .expect("sign image failed");

    // Suppose there is only one SignatureLayer in the cosign image
    client
        .push_signature(None, &auth, &cosign_signature_image, vec![signature_layer])
        .await?;
    Ok(())
}

/// This function helps to get the auth of the given image reference.
/// Now only `UsernamePassword` and `Anonymous` is supported. If an
/// `IdentityToken` is found, this function will return an `Anonymous`
/// auth.
///
/// Any error will return an `Anonymous`.
fn build_auth(reference: &OciReference) -> Auth {
    let server = reference
        .resolve_registry()
        .strip_suffix('/')
        .unwrap_or_else(|| reference.resolve_registry());
    match docker_credential::get_credential(server) {
        Err(CredentialRetrievalError::ConfigNotFound) => Auth::Anonymous,
        Err(CredentialRetrievalError::NoCredentialConfigured) => Auth::Anonymous,
        Err(e) => {
            warn!("Error handling docker configuration file: {}", e);
            Auth::Anonymous
        }
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            debug!("Found docker credentials");
            Auth::Basic(username, password)
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            warn!("Cannot use contents of docker config, identity token not supported. Using anonymous auth");
            Auth::Anonymous
        }
    }
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

    match run_app(&cli).await {
        Ok(_) => println!("Costraints successfully applied"),
        Err(err) => {
            eprintln!("Image signing failed: {:?}", err);
        }
    }
}
