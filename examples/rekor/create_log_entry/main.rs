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

use base64::{engine::general_purpose, Engine as _};
use sha2::Digest;
use sha2::Sha256;
use sigstore::crypto::signing_key::SigStoreSigner;
use sigstore::crypto::SigningScheme;
use sigstore::rekor::apis::{configuration::Configuration, entries_api};
use sigstore::rekor::models::{
    hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Signature, Spec},
    ProposedEntry,
};

use clap::{Arg, Command};

async fn create_signer() -> SigStoreSigner {
    SigningScheme::ECDSA_P256_SHA256_ASN1
        .create_signer()
        .expect("cannot create sigstore signer")
}

// function to fetch data and generate the hash of it to be signed and upload to the transparency log
async fn get_file_sha256sum(url: String) -> Result<(Vec<u8>, String), reqwest::Error> {
    let body = reqwest::get(&url).await?.bytes().await?;
    let mut digester = Sha256::new();
    digester.update(body.clone());
    let digest = format!("{:x}", digester.finalize());
    Ok((body.to_vec(), digest))
}

#[tokio::main]
async fn main() {
    /*

    Creates an entry in the transparency log. If no command line arguments is provided,
    the program will generate a key pair, download the file available at URL constant, sign it
    and create an entry in the transparency log. In the other hand, if the user sets the
    command line flags, the program will use that info to create the entry. Therefore,
    if the user use information of an entry already present in the transparency log, this
    program can print an error. See an example:

    Example command :
    cargo run --example create_log_entry -- \
     --hash c7ead87fa5c82d2b17feece1c2ee1bda8e94788f4b208de5057b3617a42b7413\
     --url https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/data\
     --public_key LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFeEhUTWRSQk80ZThCcGZ3cG5KMlozT2JMRlVrVQpaUVp6WGxtKzdyd1lZKzhSMUZpRWhmS0JZclZraGpHL2lCUjZac2s3Z01iYWZPOG9FM01lUEVvWU93PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\
     --signature MEUCIHWACbBnw+YkJCy2tVQd5i7VH6HgkdVBdP7HRV1IEsDuAiEA19iJNvmkE6We7iZGjHsTkjXV8QhK9iXu0ArUxvJF1N8=\
     --api_version 0.0.1

    When the example code is run with the default values, the following error message gets returned:

    Err(
        ResponseError(
            ResponseContent {
                status: 409,
                content: "{\"code\":409,\"message\":\"An equivalent entry already exists in the transparency log with UUID 1377da9d9dbad451a5a8acdd28add750815d34e8205f1b8a35a67b8a27dae9bf\"}\n",
                entity: Some(
                    Status400(
                        Error {
                            code: Some(
                                409,
                            ),
                            message: Some(
                                "An equivalent entry already exists in the transparency log with UUID 1377da9d9dbad451a5a8acdd28add750815d34e8205f1b8a35a67b8a27dae9bf",
                            ),
                        },
                    ),
                ),
            },
        ),
    )

    This is because an equivalent entry with the provided meta data already exists in the transparency log.
    When you use the example code to create a new entry with fresh set of input values or leaving the program
    to generate the required data, you should be able to run the code without any errors. See an example:

    Example command :
    cargo run --example create_log_entry --

    The expected output will be something similar to:

    Ok(
        LogEntry {
            uuid: "24296fb24b8ad77afa01e2c1f5555326e4fc32a942b40a2d798ae72a8f10c801f6e8dee771dfbacc",
            attestation: None,
            body: "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJjN2VhZDg3ZmE1YzgyZDJiMTdmZWVjZTFjMmVlMWJkYThlOTQ3ODhmNGIyMDhkZTUwNTdiMzYxN2E0MmI3NDEzIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQWh4elhWZnRyMWpyS0k3dEluWW5iR1pNMDZybFhpQ1lUMTRJbFdFazF4QkFpRUE0SGllM2l4cTRyOG9tVVgwclRDV2o3UmducVhqUEFZTmlkaDlQVllrQXFVPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGYjNCRmJGTlJlbGRTTUM5Sk5raEJZbm9yV21sVmFsVlhWR051WlFvdlUwUndWV1ZOVUhGR04wUXlZbU5xV2tKRlYweGhiak5XTjB3cmVHNW5jVFJHYW1wRGVtdHlLMFkwYlc5bFNEaFJTbWhNYUV0SlQzWlJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=",
            integrated_time: 1675277501,
            log_i_d: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
            log_index: 12425816,
            verification: Verification {
                inclusion_proof: Some(
                    InclusionProof {
                        hashes: [
                            "a0b75928818e5fa302c3690a895e0385803a079391a79cf9f25b08a51eebc338",
                            "3a39532ac61bf4d3f9a982e38f1b3166a3222e9d8a081d31f67d0da745117dc5",
                            "96ff049c2d122233d7e44b49d5df16b0901dbf85523d90bd739a3a25d26a974c",
                            "09805d1e21e395d8b82e7269c7ddff2941564f925145196273a993c452059a85",
                            "37ca98bdb80bdc45768539d15117b2b57531b3ad1f051aaa4f58d030f868f86e",
                            "e81e08afa83961c36e2a6961f66859620c9ee4ed9be5631ace9f3c27c72f66fb",
                            "2f01e165e3758aba5fd53d0c03c88b84ccbed7334173d9159d87fed5930bfe03",
                            "d0509b1c0bde3ba0517efcc5d3e8d2007fe86e5e055cebd5e94307cd0394c22d",
                            "8a84151f9b8fbbf7b3e77cb658535ec46d27c1cdd1cab714558dc51114922e7a",
                            "5eb43eca7a763e2eaafb2bc2fc963e7802283cf1a9076638242177b1669942c0",
                            "5523cd019fea93d01834fc429f708b700aeb72c835a73161cdb9003f8f4e8072",
                            "4b6df664d9552bc24d48a4c7d5659a8270065e1fedbc39103b010ab235a87850",
                            "616429db6c7d20c5b0eff1a6e512ea57a0734b94ae0bc7c914679463e01a7fba",
                            "5a4ad1534b1e770f02bfde0de15008a6971cf1ffbfa963fc9c2a644973a8d2d1",
                        ],
                        log_index: 8262385,
                        root_hash: "41b3e1294d122b2190396de7de92731a378378ac2d7f620eb01d653838e88219",
                        tree_size: 8262387,
                    },
                ),
                signed_entry_timestamp: "MEUCIG/vIwjuQoiVZtxw48KSMYyxXlpHA/y8kxYTJh46qbejAiEAyFAP5oQjxT6xFK7wKYW33sa/5wFQvqtKsdTLnitrzWA=",
            },
        },
    )
    */

    const URL: &str = "https://raw.githubusercontent.com/jyotsna-penumaka/rekor-rs/rekor-functionality/test_data/data";
    const API_VERSION: &str = "0.0.1";

    let data_job = get_file_sha256sum(URL.to_string());
    let signer_job = create_signer();

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

    let (data_bytes, digest) = data_job.await.expect("Cannot get data digest");
    let signer = signer_job.await;
    let public_key_base64 = general_purpose::STANDARD.encode(
        signer
            .to_sigstore_keypair()
            .expect("Cannot get sigstore keypair")
            .public_key_to_pem()
            .expect("Cannot set public key"),
    );

    let sig = general_purpose::STANDARD.encode(signer.sign(&data_bytes).expect("Cannot sign data"));

    let hash = Hash::new(
        AlgorithmKind::sha256,
        flags
            .get_one::<String>("hash")
            .unwrap_or(&digest)
            .to_owned(),
    );
    let data = Data::new(hash);
    let public_key = PublicKey::new(
        flags
            .get_one::<String>("public_key")
            .unwrap_or(&public_key_base64)
            .to_owned(),
    );
    let signature = Signature::new(
        flags.get_one("signature").unwrap_or(&sig).to_owned(),
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
