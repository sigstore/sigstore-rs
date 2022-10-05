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
use sigstore::rekor::apis::{configuration::Configuration, pubkey_api};

#[tokio::main]
async fn main() {
    /*
    Returns the public key that can be used to validate the signed tree head

    Example command :
    cargo run --example get_public_key
    */

    let matches = Command::new("cmd")
    .arg(Arg::new("tree_id")
             .long("tree_id")
             .value_name("TREE_ID")
             .help("The tree ID of the tree that you wish to prove consistency for. To use the default value, do not input any value."));

    let flags = matches.get_matches();
    let configuration = Configuration::default();
    let pubkey = pubkey_api::get_public_key(
        &configuration,
        flags.get_one::<String>("tree_id").map(|s| s.as_str()),
    )
    .await;
    println!("{:#?}", pubkey.unwrap());
}
