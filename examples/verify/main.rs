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
use sigstore::cosign::CosignCapabilities;
use sigstore::simple_signing::SimpleSigning;
use sigstore::tuf::SigstoreRepository;

extern crate anyhow;
use anyhow::anyhow;

extern crate clap;
use clap::{App, Arg};

use std::{collections::HashMap, fs};
use tokio::task::spawn_blocking;

extern crate tracing_subscriber;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

fn cli() -> App<'static, 'static> {
    App::new("verify")
        .about("verify a container image")
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("KEY")
                .help("Verification Key")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("use-sigstore-tuf-data")
                .long("use-sigstore-tuf-data")
                .help("Fetch Rekor and Fulcio data from Sigstore's TUF repository")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("rekor-pub-key")
                .long("rekor-pub-key")
                .value_name("KEY")
                .help("File containing Rekor's public key (e.g.: ~/.sigstore/root/targets/rekor.pub)")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("fulcio-crt")
                .long("fulcio-crt")
                .value_name("CERT")
                .help(
                    "File containing Fulcio's certificate (e.g.: ~/.sigstore/root/targets/fulcio.crt.pem)",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cert-email")
                .long("cert-email")
                .value_name("EMAIL")
                .help(
                    "The email expected in a valid fulcio cert",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("annotations")
                .short("a")
                .long("annotation")
                .value_name("PAIR")
                .help("Annotations that have to be satisfied")
                .required(false)
                .multiple(true)
                .number_of_values(1)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .help("Enable verbose mode"),
        )
        .arg(
            Arg::with_name("IMAGE")
                .help("Name of the image to use")
                .required(true)
                .index(1),
        )
}

async fn run_app() -> anyhow::Result<Vec<SimpleSigning>> {
    let matches = cli().get_matches();

    // setup logging
    let level_filter = if matches.is_present("verbose") {
        "debug"
    } else {
        "info"
    };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let auth = &sigstore::registry::Auth::Anonymous;

    let rekor_pub_key: Option<String> = matches
        .value_of("rekor-pub-key")
        .map(|path| {
            fs::read_to_string(path)
                .map_err(|e| anyhow!("Error reading rekor public key from disk: {}", e))
        })
        .transpose()?;

    let fulcio_cert: Option<Vec<u8>> = matches
        .value_of("fulcio-crt")
        .map(|path| {
            fs::read(path).map_err(|e| anyhow!("Error reading fulcio certificate from disk: {}", e))
        })
        .transpose()?;

    let sigstore_repo: Option<SigstoreRepository> = if matches.is_present("use-sigstore-tuf-data") {
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

    let mut client = client_builder
        .with_cert_email(matches.value_of("cert-email"))
        .build()?;

    let image: &str = matches.value_of("IMAGE").unwrap();

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;

    let pub_key = match matches.value_of("key") {
        Some(path) => {
            Some(fs::read_to_string(path).map_err(|e| anyhow!("Cannot read key: {:?}", e))?)
        }
        None => None,
    };

    let annotations: Option<HashMap<String, String>>;
    annotations = match matches.values_of("annotations") {
        None => None,
        Some(items) => {
            let mut values: HashMap<String, String> = HashMap::new();
            for item in items {
                let tmp: Vec<_> = item.splitn(2, "=").collect();
                if tmp.len() == 2 {
                    values.insert(String::from(tmp[0]), String::from(tmp[1]));
                }
            }
            if values.is_empty() {
                None
            } else {
                Some(values)
            }
        }
    };

    let matches = client
        .verify(
            auth,
            &source_image_digest,
            &cosign_signature_image,
            &pub_key,
            annotations,
        )
        .await?;

    Ok(matches)
}

#[tokio::main]
pub async fn main() {
    let satistied_simple_signatures: anyhow::Result<Vec<SimpleSigning>> = run_app().await;

    std::process::exit(match satistied_simple_signatures {
        Ok(signatures) => {
            if signatures.is_empty() {
                eprintln!("Image verification failed: no matching signature found.");
                1
            } else {
                println!("Image successfully verified");
                for signature in signatures {
                    println!("{}", signature);
                }
                0
            }
        }
        Err(err) => {
            eprintln!("Image verification failed: {:?}", err);
            1
        }
    });
}
