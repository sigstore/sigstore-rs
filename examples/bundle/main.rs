use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use sigstore::bundle::sign::SigningContext;
use sigstore::bundle::verify::{blocking::Verifier, policy};
use sigstore::oauth;

#[derive(Parser, Debug)]
#[clap(about = "Signing and verification example for sigstore::bundle module")]
struct Cli {
    /// Enable verbose mode
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify a signature for an artifact
    Verify(VerifyArgs),
    /// Create a signature for an artifact
    Sign(SignArgs),
}

#[derive(Parser, Debug)]
struct SignArgs {
    /// Path to the artifact to sign
    artifact: PathBuf,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    /// Path to the artifact to verify
    artifact: PathBuf,

    /// expected signing identity (email)
    #[arg(long, value_name = "EMAIL")]
    identity: String,

    /// expected signing identity issuer (URI)
    #[arg(long, value_name = "URI")]
    issuer: String,
}

pub fn main() {
    let cli = Cli::parse();

    // setup logging
    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    match cli.command {
        Commands::Sign(args) => sign(&args.artifact),
        Commands::Verify(args) => verify(&args.artifact, &args.identity, &args.issuer),
    }
}

fn sign(artifact_path: &PathBuf) {
    let filename = artifact_path
        .file_name()
        .and_then(|s| s.to_str())
        .expect("Failed to parse artifact filename");
    let mut artifact = fs::File::open(artifact_path)
        .unwrap_or_else(|_| panic!("Failed to read artifact {}", artifact_path.display()));

    let mut bundle_path = artifact_path.clone();
    bundle_path.set_file_name(format!("{}.sigstore.json", filename));
    let bundle = fs::File::create_new(&bundle_path).unwrap_or_else(|e| {
        println!(
            "Failed to create signature bundle {}: {}",
            bundle_path.display(),
            e
        );
        std::process::exit(1);
    });

    let token = authorize();
    let email = &token.unverified_claims().email.clone();
    debug!("Signing with {}", email);

    let signing_artifact = SigningContext::production().and_then(|ctx| {
        ctx.blocking_signer(token)
            .and_then(|session| session.sign(&mut artifact))
    });

    match signing_artifact {
        Ok(signing_artifact) => {
            serde_json::to_writer(bundle, &signing_artifact.to_bundle())
                .expect("Failed to write bundle to file");
        }
        Err(e) => {
            panic!("Failed to sign: {}", e);
        }
    }
    println!(
        "Created signature bundle {} with identity {}",
        bundle_path.display(),
        email
    );
}

fn verify(artifact_path: &PathBuf, identity: &str, issuer: &str) {
    let filename = artifact_path
        .file_name()
        .and_then(|s| s.to_str())
        .expect("Failed to parse artifact filename");
    let mut bundle_path = artifact_path.clone();
    bundle_path.set_file_name(format!("{}.sigstore.json", filename));

    let bundle = fs::File::open(&bundle_path)
        .unwrap_or_else(|_| panic!("Failed to open signature bundle {}", &bundle_path.display()));
    let mut artifact = fs::File::open(artifact_path)
        .unwrap_or_else(|_| panic!("Failed to read artifact {}", artifact_path.display()));

    let bundle: sigstore::bundle::Bundle =
        serde_json::from_reader(bundle).expect("Failed to parse the bundle");
    let verifier = Verifier::production().expect("Failed to create a verifier");

    debug!("Verifying with {} (issuer {})", identity, issuer);
    let id_policy = policy::Identity::new(identity, issuer);

    if let Err(e) = verifier.verify(&mut artifact, bundle, &id_policy, true) {
        println!("Failed to verify: {}", e);
        std::process::exit(1);
    }
    println!("Verified")
}

fn authorize() -> oauth::IdentityToken {
    let oidc_url = oauth::openidflow::OpenIDAuthorize::new(
        "sigstore",
        "",
        "https://oauth2.sigstore.dev/auth",
        "http://localhost:8080",
    )
    .auth_url()
    .expect("Failed to start OIDC authorization");

    webbrowser::open(oidc_url.0.as_ref()).expect("Failed to open browser");

    println!("Please authorize signing in web browser.");

    let listener = oauth::openidflow::RedirectListener::new(
        "127.0.0.1:8080",
        oidc_url.1, // client
        oidc_url.2, // nonce
        oidc_url.3, // pkce_verifier
    );
    let (_, token) = listener
        .redirect_listener()
        .expect("Failed to receive a token");
    oauth::IdentityToken::from(token)
}
