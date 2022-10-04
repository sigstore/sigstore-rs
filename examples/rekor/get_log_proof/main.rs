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

use clap::{Arg, Command};
use sigstore::rekor::apis::{configuration::Configuration, tlog_api};
use sigstore::rekor::models::ConsistencyProof;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    /*

    Get information required to generate a consistency proof for the transparency log.
    Returns a list of hashes for specified tree sizes that can be used to confirm the consistency of the transparency log.

    Example command :
    cargo run --example get_log_proof -- --last_size 10
    cargo run --example get_log_proof -- --last_size 10 --first_size 1

    */
    let matches = Command::new("cmd")
    .arg(Arg::new("last_size")
             .long("last_size")
             .value_name("LAST_SIZE")
             .help("The size of the tree that you wish to prove consistency to"))
    .arg(Arg::new("first_size")
             .long("first_size")
             .value_name("FIRST_SIZE")
             .help("The size of the tree that you wish to prove consistency from (1 means the beginning of the log). Defaults to 1. To use the default value, do not input any value"))
    .arg(Arg::new("tree_id")
             .long("tree_id")
             .value_name("TREE_ID")
             .help("The tree ID of the tree that you wish to prove consistency for. To use the default value, do not input any value."));

    let configuration = Configuration::default();
    let flags = matches.get_matches();

    // The following default value will be used if the user does not input values using cli flags
    const LAST_SIZE: &str = "10";

    let log_proof: ConsistencyProof = tlog_api::get_log_proof(
        &configuration,
        i32::from_str(
            flags
                .get_one::<String>("last_size")
                .unwrap_or(&LAST_SIZE.to_string()),
        )
        .unwrap(),
        flags.get_one::<String>("first_size").map(|s| s.as_str()),
        flags.get_one::<String>("tree_id").map(|s| s.as_str()),
    )
    .await
    .unwrap();
    println!("{:#?}", log_proof);
}
