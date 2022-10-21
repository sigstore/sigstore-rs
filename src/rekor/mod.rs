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

//! This crate aims to provide Rust API client for Rekor <https://github.com/sigstore/rekor> to Rust developers.
//!
//! Rekor is a cryptographically secure, immutable transparency log for signed software releases.
//!
//! **Warning:** this crate is still experimental. Its API can change at any time.
//!
//! # Security
//!
//! Should you discover any security issues, please refer to
//! Sigstore's [security process](https://github.com/sigstore/community/blob/main/SECURITY.md).
//!
//! # How to use this crate
//! The examples folder contains code that shows users how to make API calls.
//! It also provides a clean interface with step-by-step instructions that other developers can copy and paste.
//!
//! ```
//! use clap::{Arg, Command};
//! use sigstore::rekor::apis::{configuration::Configuration, entries_api};
//! use sigstore::rekor::models::log_entry::LogEntry;
//! use std::str::FromStr;
//! #[tokio::main]
//! async fn main() {
//!     /*
//!     Retrieves an entry and inclusion proof from the transparency log (if it exists) by index
//!     Example command :
//!     cargo run --example get_log_entry_by_index -- --log_index 99
//!     */
//!     let matches = Command::new("cmd").arg(
//!         Arg::new("log_index")
//!             .long("log_index")
//!             .num_args(1)
//!             .value_parser(clap::value_parser!(i32))
//!             .default_value("1")
//!             .help("log_index of the artifact"),
//!     );
//!
//!     let flags = matches.get_matches();
//!     let index: &i32 = flags.get_one("log_index").unwrap();
//!
//!     let configuration = Configuration::default();
//!
//!     let message: LogEntry = entries_api::get_log_entry_by_index(&configuration, *index)
//!         .await
//!         .unwrap();
//!     println!("{:#?}", message);
//! }
//! ```
//!
//! The following comment in the code tells the user how to provide the required values to the API calls using cli flags.
//!
//! In the example below, the user can retrieve different entries by inputting a different value for the log_index flag.
//!
//!
//!/*
//!Retrieves an entry and inclusion proof from the transparency log (if it exists) by index
//!Example command :
//!cargo run --example get_log_entry_by_index -- --log_index 99
//!*/
//!
//! # The example code is provided for the following API calls:
//!
//!- create_log_entry
//!- get_log_entry_by_index
//!- get_log_entry_by_uuid
//!- get_log_info
//!- get_log_proof
//!- get_public_key
//!- get_timestamp_cert_chain
//!- get_timestamp_response
//!- search_index
//!- search_log_query
//!

pub mod apis;
pub mod models;
type TreeSize = i64;
