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

use clap::{Parser, Subcommand};

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

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
}
