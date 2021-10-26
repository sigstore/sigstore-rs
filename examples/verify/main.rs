extern crate sigstore;
use sigstore::cosign::CosignCapabilities;
use sigstore::simple_signing::SimpleSigning;

extern crate anyhow;
use anyhow::Result;

use std::io::prelude::*;
use std::{collections::HashMap, fs::File};

extern crate clap;
use clap::{App, Arg};

extern crate tracing_subscriber;
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
                .required(true)
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

async fn run_app() -> Result<Vec<SimpleSigning>> {
    let matches = cli().get_matches();

    let auth = &sigstore::registry::Auth::Anonymous;
    let mut client = sigstore::cosign::Client::default();

    let image: &str = matches.value_of("IMAGE").unwrap();

    let (cosign_signature_image, source_image_digest) = client.triangulate(image, auth).await?;

    let mut pub_key_file = File::open(matches.value_of("key").unwrap())?;
    let mut pub_key = String::new();
    pub_key_file.read_to_string(&mut pub_key)?;

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

    client
        .verify(
            auth,
            &source_image_digest,
            &cosign_signature_image,
            &pub_key,
            annotations,
        )
        .await
}

#[tokio::main]
pub async fn main() {
    let satistied_simple_signatures: Result<Vec<SimpleSigning>> = run_app().await;

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
