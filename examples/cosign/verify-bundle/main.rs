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

use clap::Parser;
use sigstore::cosign::bundle::SignedArtifactBundle;
use sigstore::cosign::client::Client;
use sigstore::cosign::CosignCapabilities;
use sigstore::crypto::{CosignVerificationKey, SigningScheme};
use std::fs;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Path to bundle file
    #[clap(short, long)]
    bundle: String,

    /// Path to artifact to be verified
    blob: String,

    /// File containing Rekor's public key (e.g.: ~/.sigstore/root/targets/rekor.pub)
    #[clap(long, required(false))]
    rekor_pub_key: String,

    /// Enable verbose mode
    #[clap(short, long)]
    verbose: bool,
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

    let rekor_pub_pem =
        fs::read_to_string(&cli.rekor_pub_key).expect("error reading rekor's public key");
    let rekor_pub_key =
        CosignVerificationKey::from_pem(rekor_pub_pem.as_bytes(), &SigningScheme::default())
            .expect("Cannot create Rekor verification key");
    let bundle_json = fs::read_to_string(&cli.bundle).expect("error reading bundle json file");
    let blob = fs::read(cli.blob.as_str()).expect("error reading blob file");

    let bundle = SignedArtifactBundle::new_verified(&bundle_json, &rekor_pub_key).unwrap();
    match Client::verify_blob(&bundle.cert, &bundle.base64_signature, &blob) {
        Ok(_) => println!("Verification succeeded"),
        Err(e) => eprintln!("Verification failed: {}", e),
    }
}
