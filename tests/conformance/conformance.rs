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

//! CLI implemented to specification:
//! <https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md>

use std::{path::Path, process::exit};

use clap::{Parser, Subcommand};
use sigstore::{
    bundle::{
        sign::SigningContext,
        verify::{policy, Verifier},
    },
    oauth::IdentityToken,
    protobuf_specs::dev::sigstore::trustroot::v1::TrustedRoot,
    trust::{
        sigstore::{Instance, TrustRootOptions},
        BundledTrustRoot, TrustConfig,
    },
};
use tokio::fs;
use tokio_util::io::SyncIoBridge;

#[derive(Parser, Debug)]
struct Cli {
    /// Presence indicates client should use Sigstore staging infrastructure
    #[clap(long, global(true))]
    staging: bool,

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

/// Sign with the signature and certificate flow
#[derive(Parser, Debug)]
struct Sign {
    /// The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    /// The path to write the signature to
    #[clap(long)]
    signature: String,

    /// The path to write the signing certificate to
    #[clap(long)]
    certificate: String,

    /// The artifact to sign
    artifact: String,
}

/// Sign with the bundle flow
#[derive(Parser, Debug)]
struct SignBundle {
    /// The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    /// The path to write the bundle to
    #[clap(long)]
    bundle: String,

    /// The artifact to sign
    artifact: String,
}

/// Verify with the signature and certificate flow
#[derive(Parser, Debug)]
struct Verify {
    /// The path to the signature to verify
    #[clap(long)]
    signature: String,

    /// The path to the signing certificate to verify
    #[clap(long)]
    certificate: String,

    /// The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    /// The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    /// The path of the custom trusted root to use to verify the bundle
    #[clap(long)]
    trusted_root: String,

    /// The path to the artifact to verify
    artifact: String,
}

/// Verify with the bundle flow
#[derive(Parser, Debug)]
struct VerifyBundle {
    /// The path to the Sigstore bundle to verify
    #[clap(long)]
    bundle: String,

    /// The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    /// The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    /// The path of the custom trusted root to use to verify the bundle
    #[clap(long)]
    trusted_root: Option<String>,

    /// The path to the artifact to verify
    artifact: String,
}

async fn read<P, T>(path: P) -> anyhow::Result<T>
where
    P: AsRef<Path>,
    T: for<'de> serde::Deserialize<'de> + Send + 'static,
{
    let file = fs::File::open(path.as_ref()).await?;

    Ok(tokio::task::spawn_blocking(move || -> _ {
        serde_json::from_reader(SyncIoBridge::new(file))
    })
    .await??)
}

async fn write<P, T>(path: P, data: T) -> anyhow::Result<()>
where
    T: serde::Serialize + Send + 'static,
    P: AsRef<Path>,
{
    let file = fs::File::create(path.as_ref()).await?;

    Ok(tokio::task::spawn_blocking(move || -> _ {
        serde_json::to_writer(SyncIoBridge::new(file), &data)
    })
    .await??)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let instance = if cli.staging {
        Instance::Staging
    } else {
        Instance::Prod
    };

    let trust = instance
        .trust_config(TrustRootOptions { cache_dir: None })
        .await
        .unwrap();

    let result = match cli.command {
        Commands::SignBundle(args) => sign_bundle(args, trust).await,
        Commands::VerifyBundle(args) => verify_bundle(args, trust).await,
        _ => unimplemented!("sig/cert commands"),
    };

    if let Err(error) = result {
        eprintln!("Operation failed:\n{error:?}");
        exit(-1);
    }

    eprintln!("Operation succeeded!");
}

async fn sign_bundle(args: SignBundle, trust: TrustConfig<BundledTrustRoot>) -> anyhow::Result<()> {
    let SignBundle {
        identity_token,
        bundle,
        artifact,
    } = args;
    let identity_token = IdentityToken::try_from(identity_token.as_str())?;
    let artifact = fs::File::open(artifact).await?;

    let context = SigningContext::new(trust).unwrap();
    let signer = context.signer(identity_token).await?;

    let signing_artifact = signer.sign(artifact).await?;
    let bundle_data = signing_artifact.to_bundle();

    write(bundle, bundle_data).await?;

    Ok(())
}

async fn verify_bundle(
    args: VerifyBundle,
    mut trust: TrustConfig<BundledTrustRoot>,
) -> anyhow::Result<()> {
    let VerifyBundle {
        bundle,
        certificate_identity,
        certificate_oidc_issuer,
        artifact,
        trusted_root,
    } = args;
    let mut artifact = fs::File::open(artifact).await?;

    let bundle: sigstore::bundle::Bundle = read(bundle).await?;

    if let Some(trusted_root) = trusted_root {
        let tr_bundle: TrustedRoot = read(trusted_root).await?;
        trust.trust_root = tr_bundle.into();
    }

    let verifier = Verifier::new(trust)?;
    let policy = policy::Identity::new(certificate_identity, certificate_oidc_issuer);

    verifier
        .verify(&mut artifact, bundle, &policy, true)
        .await?;

    Ok(())
}
