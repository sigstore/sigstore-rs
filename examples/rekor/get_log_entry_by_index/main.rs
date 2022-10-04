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
use sigstore::rekor::apis::{configuration::Configuration, entries_api};
use sigstore::rekor::models::log_entry::LogEntry;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    /*

    Retrieves an entry and inclusion proof from the transparency log (if it exists) by index

    Example command :
    cargo run --example get_log_entry_by_index -- --log_index 99

    */
    let matches = Command::new("cmd").arg(
        Arg::new("log_index")
            .long("log_index")
            .value_name("LOG_INDEX")
            .help("log_index of the artifact"),
    );

    // The following default value will be used if the user does not input values using cli flags
    const LOG_INDEX: &str = "1";

    let flags = matches.get_matches();
    let index = i32::from_str(
        flags
            .get_one::<String>("log_index")
            .unwrap_or(&LOG_INDEX.to_string()),
    )
    .unwrap();

    let configuration = Configuration::default();

    let message: LogEntry = entries_api::get_log_entry_by_index(&configuration, index)
        .await
        .unwrap();
    println!("{:#?}", message);
}
