// Copyright 2025 The Sigstore Authors.
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

//! Sigstore CLI - A cosign-compatible command-line tool for signing and attestation
//!
//! This CLI provides a `attest-blob` command that works like cosign's attest-blob,
//! producing Sigstore Bundle v0.3 with DSSE envelopes and in-toto statements.

use clap::{Parser, Subcommand};
use serde_json::json;
use sha2::{Digest, Sha256};
use sigstore::bundle::intoto::{StatementBuilder, Subject};
use sigstore::bundle::sign::SigningContext;
use sigstore::oauth;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sigstore-cli")]
#[command(about = "Sigstore CLI tool for signing and attestation", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Skip confirmation prompts
    #[arg(short = 'y', long, global = true)]
    yes: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Attest a blob with an in-toto statement (like cosign attest-blob)
    AttestBlob {
        /// Path to the blob (file) to attest
        blob: PathBuf,

        /// Path to the in-toto statement JSON file (predicate)
        #[arg(long)]
        statement: Option<PathBuf>,

        /// Predicate type URI (required if not using --statement)
        #[arg(long = "type")]
        predicate_type: Option<String>,

        /// Path to write the Sigstore bundle
        #[arg(long)]
        bundle: PathBuf,

        /// Use new bundle format (always true for v0.3)
        #[arg(long, default_value = "true")]
        new_bundle_format: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Set COSIGN_YES environment variable if -y flag is used
    if cli.yes {
        // SAFETY: This is safe because we're setting an environment variable for this process only
        // before any threads are spawned, and it's used to control interactive prompts.
        unsafe {
            env::set_var("COSIGN_YES", "true");
        }
    }

    match cli.command {
        Commands::AttestBlob {
            blob,
            statement,
            predicate_type,
            bundle,
            new_bundle_format: _,
        } => {
            attest_blob(blob, statement, predicate_type, bundle)?;
        }
    }

    Ok(())
}

fn attest_blob(
    blob_path: PathBuf,
    statement_path: Option<PathBuf>,
    predicate_type: Option<String>,
    bundle_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check that blob exists
    if !blob_path.exists() {
        eprintln!("Error: Blob file not found: {}", blob_path.display());
        std::process::exit(1);
    }

    println!("Signing blob: {}", blob_path.display());

    // Read and hash the blob
    let blob_bytes = fs::read(&blob_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&blob_bytes);
    let digest = hasher.finalize();
    let digest_hex = hex::encode(digest);

    println!("  SHA256: {}", digest_hex);

    // Create the subject
    let blob_name = blob_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let subject = Subject::new(blob_name, "sha256", &digest_hex);

    // Create the statement
    let statement = if let Some(statement_path) = statement_path {
        // Read existing statement and add subject
        println!("Reading statement from: {}", statement_path.display());

        if !statement_path.exists() {
            eprintln!("Error: Statement file not found: {}", statement_path.display());
            std::process::exit(1);
        }

        let statement_json = fs::read_to_string(&statement_path)?;
        let statement: serde_json::Value = serde_json::from_str(&statement_json)?;

        // Get predicate type and predicate
        let pred_type = statement
            .get("predicateType")
            .and_then(|v| v.as_str())
            .ok_or("Statement must have 'predicateType' field")?
            .to_string();

        let predicate = statement
            .get("predicate")
            .ok_or("Statement must have 'predicate' field")?
            .clone();

        // Check if statement already has subjects
        let has_subjects = statement
            .get("subject")
            .and_then(|v| v.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);

        if has_subjects {
            // Use existing statement as-is
            println!("Using existing statement with subjects");
            serde_json::from_value(statement)?
        } else {
            // Add the blob as subject
            println!("Adding blob as subject to statement");
            StatementBuilder::new()
                .subject(subject)
                .predicate_type(pred_type)
                .predicate(predicate)
                .build()
                .map_err(|e| format!("Failed to build statement: {}", e))?
        }
    } else if let Some(pred_type) = predicate_type {
        // Create minimal statement with just the predicate type
        // Validate that it looks like a URI
        if !pred_type.contains("://") && !pred_type.starts_with("https://") {
            eprintln!("Warning: Predicate type should be a valid URI (e.g., https://example.com/predicate/v1)");
            eprintln!("         Got: {}", pred_type);
        }

        println!("Creating statement with predicate type: {}", pred_type);
        StatementBuilder::new()
            .subject(subject)
            .predicate_type(pred_type)
            .predicate(json!({}))
            .build()
            .map_err(|e| format!("Failed to build statement: {}", e))?
    } else {
        eprintln!("Error: Either --statement or --type must be provided");
        std::process::exit(1);
    };

    println!("\nStatement created:");
    println!("  Type: {}", statement.statement_type);
    println!("  Predicate Type: {}", statement.predicate_type);
    println!("  Subjects: {}", statement.subject.len());

    // Get identity token
    println!("\nAuthenticating...");
    let token = get_identity_token()?;

    // Create signing context
    println!("Connecting to Sigstore...");
    let ctx = SigningContext::production()?;
    let signer = ctx.blocking_signer(token)?;

    // Sign the statement
    println!("Creating DSSE envelope and signing...");
    let artifact = signer.sign_dsse(&statement)?;

    // Create bundle
    println!("Creating Sigstore bundle...");
    let bundle = artifact.to_bundle();

    // Write bundle
    println!("Writing bundle to: {}", bundle_path.display());
    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    fs::write(&bundle_path, bundle_json)?;

    println!("\n✓ Successfully created attestation bundle");
    println!("  Bundle: {}", bundle_path.display());
    println!("  Format: {}", bundle.media_type);

    Ok(())
}

fn get_identity_token() -> Result<oauth::IdentityToken, Box<dyn std::error::Error>> {
    // Check for GitHub Actions OIDC token
    if let (Ok(token_url), Ok(request_token)) = (
        env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) {
        println!("  Using GitHub Actions OIDC token");

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(&format!("{}&audience=sigstore", token_url))
            .header("Authorization", format!("Bearer {}", request_token))
            .send()?;

        if !response.status().is_success() {
            return Err(format!(
                "Failed to get OIDC token from GitHub Actions: {}",
                response.status()
            )
            .into());
        }

        let token_response: serde_json::Value = response.json()?;
        let token_string = token_response["value"]
            .as_str()
            .ok_or("Missing 'value' field in token response")?;

        return Ok(token_string.try_into()?);
    }

    // Check for COSIGN_YES environment variable to skip interactive flow
    if env::var("COSIGN_YES").is_ok() {
        return Err("No OIDC token available and COSIGN_YES is set (non-interactive mode)".into());
    }

    // Fall back to interactive OAuth flow
    println!("  Using interactive OAuth flow...");
    println!("  A browser window will open for authentication");

    let oidc_url = oauth::openidflow::OpenIDAuthorize::new(
        "sigstore",
        "",
        "https://oauth2.sigstore.dev/auth",
        "http://localhost:8080",
    )
    .auth_url()?;

    println!("  Opening browser to: {}", oidc_url.0.as_ref());
    webbrowser::open(oidc_url.0.as_ref())?;

    println!("  Waiting for authentication...");

    let listener = oauth::openidflow::RedirectListener::new(
        "127.0.0.1:8080",
        oidc_url.1,
        oidc_url.2,
        oidc_url.3,
    );
    let (_, token) = listener.redirect_listener()?;
    Ok(oauth::IdentityToken::from(token))
}
