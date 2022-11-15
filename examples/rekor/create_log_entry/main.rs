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

use sigstore::rekor::apis::{configuration::Configuration, entries_api};
use sigstore::rekor::models::{
    hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Signature, Spec},
    ProposedEntry,
};

use clap::{Arg, Command};

#[tokio::main]
async fn main() {
    /*

    Creates an entry in the transparency log for a detached signature, public key, and content.
    Items can be included in the request or fetched by the server when URLs are specified.

    Example command :
    cargo run --example create_log_entry -- \
     --hash c7ead87fa5c82d2b17feece1c2ee1bda8e94788f4b208de5057b3617a42b7413\
     --url https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/data\
     --public_key LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeEhUTWRSQk80ZThCcGZ3cG5KMlozT2JMRlVrVQpaUVp6WGxtKzdyd1lZKzhSMUZpRWhmS0JZclZraGpHL2lCUjZac2s3Z01iYWZPOG9FM01lUEVvWU93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\
     --signature MEUCIHWACbBnw+YkJCy2tVQd5i7VH6HgkdVBdP7HRV1IEsDuAiEA19iJNvmkE6We7iZGjHsTkjXV8QhK9iXu0ArUxvJF1N8=\
     --key_format x509\
     --api_version 0.0.1

    When the example code is run with the default values, the following error message gets returned:

    Err(
        ResponseError(
            ResponseContent {
                status: 409,
                content: "{\"code\":409,\"message\":\"An equivalent entry already exists in the transparency log with UUID aa7ba9f2eae2a0c9a40dab33c160ba41c80da877b0207b8f3243fdb4db5cf30c\"}\n",
                entity: Some(
                    Status400(
                        Error {
                            code: Some(
                                409,
                            ),
                            message: Some(
                                "An equivalent entry already exists in the transparency log with UUID aa7ba9f2eae2a0c9a40dab33c160ba41c80da877b0207b8f3243fdb4db5cf30c",
                            ),
                        },
                    ),
                ),
            },
        ),
    )

    This is because an equivalent entry with the provided meta data already exists in the transparency log.
    When you use the example code to create a new entry with fresh set of input values,
    you should be able to run the code without any errors.

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
    .arg(Arg::new("signature")
             .long("signature")
             .value_name("SIGNATURE")
             .help("base64 encoded signature of the artifact. Look at https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/create_log_entry.md for more details on generating keys."))
    .arg(Arg::new("api_version")
             .long("api_version")
             .value_name("API_VERSION")
             .help("Rekor-rs open api version"));

    let flags = matches.get_matches();

    let configuration = Configuration::default();

    // The following default values will be used if the user does not input values using cli flags
    const HASH: &str = "c7ead87fa5c82d2b17feece1c2ee1bda8e94788f4b208de5057b3617a42b7413";
    const URL: &str = "https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/data";
    const PUBLIC_KEY: &str = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeEhUTWRSQk80ZThCcGZ3cG5KMlozT2JMRlVrVQpaUVp6WGxtKzdyd1lZKzhSMUZpRWhmS0JZclZraGpHL2lCUjZac2s3Z01iYWZPOG9FM01lUEVvWU93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
    const SIGNATURE: &str = "MEUCIHWACbBnw+YkJCy2tVQd5i7VH6HgkdVBdP7HRV1IEsDuAiEA19iJNvmkE6We7iZGjHsTkjXV8QhK9iXu0ArUxvJF1N8=";
    const KEY_FORMAT: &str = "x509";
    const API_VERSION: &str = "0.0.1";

    let hash = Hash::new(
        AlgorithmKind::sha256,
        flags
            .get_one::<String>("hash")
            .unwrap_or(&HASH.to_string())
            .to_owned(),
    );
    let data = Data::new(hash);
    let public_key = PublicKey::new(
        flags
            .get_one::<String>("public_key")
            .unwrap_or(&PUBLIC_KEY.to_string())
            .to_owned(),
    );
    let signature = Signature::new(
        flags
            .get_one("signature")
            .unwrap_or(&SIGNATURE.to_string())
            .to_owned(),
        public_key,
    );
    let spec = Spec::new(signature, data);
    let proposed_entry = ProposedEntry::Hashedrekord {
        api_version: flags
            .get_one::<String>("api_version")
            .unwrap_or(&API_VERSION.to_string())
            .to_owned(),
        spec,
    };

    let log_entry = entries_api::create_log_entry(&configuration, proposed_entry).await;
    println!("{:#?}", log_entry);
}
