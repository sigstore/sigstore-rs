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

use sigstore::rekor::apis::{configuration::Configuration, server_api};

/*
Gets the current version of the rekor server

Example command :
cargo run --example get_rekor_version
*/

#[tokio::main]
async fn main() {
    let configuration = Configuration::default();
    let rekor_version = server_api::get_rekor_version(&configuration).await;
    println!("{:#?}", rekor_version.unwrap());
}
