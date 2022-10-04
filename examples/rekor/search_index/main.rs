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
use sigstore::rekor::apis::{configuration::Configuration, index_api};
use sigstore::rekor::models::{
    search_index_public_key, search_index_public_key::Format, SearchIndex,
};

#[tokio::main]
async fn main() {
    /*

    Searches index by entry metadata

    Example command:
    cargo run --example search_index -- \
    --hash e2535d638859bb63ea9ea5cf467562cba63b007eae1acd0d73a3f259c582561f \
    --public_key c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSVA3M2tuT0tKYVNyVEtEa2U2OEgvRlJoODRZWU5CU0tBN1hPVWRpWmJjeG8gdGVzdEByZWtvci5kZXYK \
    --key_format ssh \
    --email jpenumak@redhat.com

    cargo run --example search_index -- \
    --public_key c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSVA3M2tuT0tKYVNyVEtEa2U2OEgvRlJoODRZWU5CU0tBN1hPVWRpWmJjeG8gdGVzdEByZWtvci5kZXYK \
    --key_format ssh \
    --email jpenumak@redhat.com

    The server might return an error sometimes,
    this is because the result depends on the kind of rekor object that gets returned.

    */

    let matches = Command::new("cmd")
    .arg(Arg::new("hash")
             .long("hash")
             .value_name("HASH")
             .help("hash of the artifact"))
    .arg(Arg::new("url")
             .long("url")
             .value_name("URL")
             .help("url containing the contents of the artifact (raw github url)"))
    .arg(Arg::new("public_key")
             .long("public_key")
             .value_name("PUBLIC_KEY")
             .help("base64 encoded public_key. Look at https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/create_log_entry.md for more details on generating keys."))
    .arg(Arg::new("key_format")
             .long("key_format")
             .value_name("KEY_FORMAT")
             .help("Accepted formats are : pgp / x509 / minsign / ssh / tuf"))  
     .arg(Arg::new("email")
             .long("email")
             .value_name("EMAIL")
             .help("Author's email"));

    let flags = matches.get_matches();

    // The following default values will be used if the user does not input values using cli flags
    const HASH: &str = "c7ead87fa5c82d2b17feece1c2ee1bda8e94788f4b208de5057b3617a42b7413";
    const PUBLIC_KEY: &str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeEhUTWRSQk80ZThCcGZ3cG5KMlozT2JMRlVrVQpaUVp6WGxtKzdyd1lZKzhSMUZpRWhmS0JZclZraGpHL2lCUjZac2s3Z01iYWZPOG9FM01lUEVvWU93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
    const KEY_FORMAT: &str = "x509";
    const EMAIL: &str = "jpenumak@redhat.com";

    let key_format = match flags
        .get_one::<String>("key_format")
        .unwrap_or(&KEY_FORMAT.to_string())
        .as_str()
    {
        "pgp" => Format::Pgp,
        "x509" => Format::X509,
        "minisign" => Format::Minisign,
        "ssh" => Format::Ssh,
        _ => Format::Tuf,
    };

    let public_key = search_index_public_key::SearchIndexPublicKey {
        format: key_format,
        content: Some(
            flags
                .get_one::<String>("public_key")
                .unwrap_or(&PUBLIC_KEY.to_string())
                .to_owned(),
        ),
        url: None,
    };

    let query = SearchIndex {
        email: Some(
            flags
                .get_one::<String>("email")
                .unwrap_or(&EMAIL.to_string())
                .to_owned(),
        ),
        public_key: Some(public_key),
        hash: Some(
            flags
                .get_one("hash")
                .unwrap_or(&HASH.to_string())
                .to_owned(),
        ),
    };
    let configuration = Configuration::default();

    let uuid_vec = index_api::search_index(&configuration, query).await;
    println!("{:#?}", uuid_vec);
}
