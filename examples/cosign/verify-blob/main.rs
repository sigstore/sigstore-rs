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

extern crate clap;
extern crate sigstore;
use clap::Parser;
use sigstore::cosign::client::Client;
use sigstore::cosign::CosignCapabilities;

extern crate tracing_subscriber;
use std::fs;
use std::path::PathBuf;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// The certificate generate from the `cosign sign-blob` command
    #[clap(short, long)]
    certificate: PathBuf,

    /// The signature generated from the `cosign sign-blob` command
    #[clap(long, required(false))]
    signature: PathBuf,

    /// The blob to verify
    blob: String,

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

    let certificate = fs::read_to_string(&cli.certificate).expect("error reading certificate");
    let signature = fs::read_to_string(&cli.signature).expect("error reading signature");
    let blob = fs::read(cli.blob.as_str()).expect("error reading blob file");

    match Client::verify_blob(&certificate, &signature, &blob) {
        Ok(_) => println!("Verification succeeded"),
        Err(e) => eprintln!("Verification failed {:?}", e),
    }
}
