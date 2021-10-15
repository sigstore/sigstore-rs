//! This is an experimental crate to interact with [sigstore](https://sigstore.dev/).
//!
//! This is under high development, many features and probably checks are still missing.

mod crypto;
mod mock_client;

pub mod cosign;
pub mod registry;
pub mod simple_signing;
