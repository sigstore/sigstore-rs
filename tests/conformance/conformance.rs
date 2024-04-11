//
// Copyright 2023 The Sigstore Authors.
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

// CLI implemented to specification:
// https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md

use std::{fs, process::exit};

use clap::{Parser, Subcommand};
use sigstore::{
    bundle::sign::SigningContext,
    bundle::verify::{blocking::Verifier, policy},
    oauth::IdentityToken,
};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Sign(Sign),
    SignBundle(SignBundle),
    Verify(Verify),
    VerifyBundle(VerifyBundle),
}

#[derive(Parser, Debug)]
struct Sign {
    // The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    // The path to write the signature to
    #[clap(long)]
    signature: String,

    // The path to write the signing certificate to
    #[clap(long)]
    certificate: String,

    // The artifact to sign
    artifact: String,
}

#[derive(Parser, Debug)]
struct SignBundle {
    // The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    // The path to write the bundle to
    #[clap(long)]
    bundle: String,

    // The artifact to sign
    artifact: String,
}

#[derive(Parser, Debug)]
struct Verify {
    // The path to the signature to verify
    #[clap(long)]
    signature: String,

    // The path to the signing certificate to verify
    #[clap(long)]
    certificate: String,

    // The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    // The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    // The path to the artifact to verify
    artifact: String,
}

#[derive(Parser, Debug)]
struct VerifyBundle {
    // The path to the Sigstore bundle to verify
    #[clap(long)]
    bundle: String,

    // The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    // The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    // The path to the artifact to verify
    artifact: String,
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::SignBundle(args) => sign_bundle(args),
        Commands::VerifyBundle(args) => verify_bundle(args),
        _ => unimplemented!("sig/cert commands"),
    };

    if let Err(error) = result {
        eprintln!("Operation failed:\n{error:?}");
        exit(-1);
    }

    eprintln!("Operation succeeded!");
}

fn sign_bundle(args: SignBundle) -> anyhow::Result<()> {
    let SignBundle {
        identity_token,
        bundle,
        artifact,
    } = args;
    let identity_token = IdentityToken::try_from(identity_token.as_str())?;
    let bundle = fs::File::create(bundle)?;
    let mut artifact = fs::File::open(artifact)?;

    let context = SigningContext::production()?;
    let signer = context.blocking_signer(identity_token);

    let signing_artifact = signer?.sign(&mut artifact)?;
    let bundle_data = signing_artifact.to_bundle();

    serde_json::to_writer(bundle, &bundle_data)?;

    Ok(())
}

fn verify_bundle(args: VerifyBundle) -> anyhow::Result<()> {
    let VerifyBundle {
        bundle,
        certificate_identity,
        certificate_oidc_issuer,
        artifact,
    } = args;
    let bundle = fs::File::open(bundle)?;
    let mut artifact = fs::File::open(artifact)?;

    let bundle: sigstore::bundle::Bundle = serde_json::from_reader(bundle)?;
    let verifier = Verifier::production()?;

    verifier.verify(
        &mut artifact,
        bundle,
        &policy::Identity::new(certificate_identity, certificate_oidc_issuer),
        true,
    )?;

    Ok(())
}
