extern crate sigstore;

extern crate anyhow;
use anyhow::Result;

extern crate oci_distribution;
use oci_distribution::{secrets::RegistryAuth, Reference};

use std::fs::File;
use std::io::prelude::*;

extern crate clap;
use clap::{App, Arg};

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
            Arg::with_name("IMAGE")
                .help("Name of the image to use")
                .required(true)
                .index(1),
        )
}

async fn run_app() -> Result<()> {
    let matches = cli().get_matches();

    let auth = &RegistryAuth::Anonymous;
    let mut client = oci_distribution::Client::default();

    let image: Reference = String::from(matches.value_of("IMAGE").unwrap()).parse()?;

    let (cosign_signature_image, source_image_digest) =
        sigstore::triangulate(&mut client, image, auth).await?;

    let mut pub_key_file = File::open(matches.value_of("key").unwrap())?;
    let mut pub_key = String::new();
    pub_key_file.read_to_string(&mut pub_key)?;

    sigstore::verify(
        &mut client,
        auth,
        source_image_digest,
        cosign_signature_image,
        pub_key,
    )
    .await
}

#[tokio::main]
pub async fn main() {
    std::process::exit(match run_app().await {
        Ok(_) => {
            println!("Image successfully verified");
            0
        }
        Err(err) => {
            eprintln!("Image verification failed: {:?}", err);
            1
        }
    });
}
