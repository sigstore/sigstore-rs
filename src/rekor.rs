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

//! Set of structs and enums used to define how to interact with the Rekor server

use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::error::Error;

/// Stores the Rekor object type, API version and the Spec struct
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub api_version: String,
    pub kind: String,
    pub spec: Spec,
}

/// Stores the Signature and Data struct
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub signature: Signature,
    pub data: Data,
}

/// Stores the signature format, signature of the artifact and the PublicKey struct
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub format: String,
    pub content: String,
    pub public_key: PublicKey,
}

/// Stores the public key used to sign the artifact
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub content: String,
}

/// Stores the Hash struct and location of the file
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub hash: Hash,
    pub url: String,
}

/// Stores the algorithm used to hash the artifact and the value of the hash
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash {
    pub algorithm: String,
    pub value: String,
}

/// Stores the response returned by Rekor after making a new entry
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Post {
    uuid: String,
    body: String,
    integrated_time: i64,
    log_i_d: String,
    log_index: i64,
    verification: Verification,
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    signed_entry_timestamp: String,
}

/// Creates an entry in the Rekor server
pub async fn rekor_upload(
    api_version_val: String,
    object_type: String,
    key_format: String,
    signature_val: String,
    pub_key_val: String,
    file_url: String,
    algorithm_name: String,
    hash_val: String,
) -> Result<Post, Box<dyn Error>> {
    // This is the body of the post request
    let body = Root {
        api_version: api_version_val,
        kind: object_type,
        spec: Spec {
            signature: Signature {
                format: key_format,
                content: signature_val,
                public_key: PublicKey {
                    content: pub_key_val,
                },
            },
            data: Data {
                url: file_url,
                hash: Hash {
                    algorithm: algorithm_name,
                    value: hash_val,
                },
            },
        },
    };

    /*
    (Not for testing)
    To make a post request to create an entry in the live Rekor server :

    let response = reqwest::Client::new()
        .post("https://rekor.sigstore.dev/api/v1/log/entries")
        .json(&body)
        .send()
        .await?
        .text()
        .await?;
    */

    // Let's create a mock Rekor Server for testing
    let server = httpmock::MockServer::start();
    server.mock(|when, then| {
        when.method("POST")
            .path("/api/v1/log/entries")
            .json_body_obj(&body);
        then.status(201)
            .body(
    "{\"9bf4f37447a48848c1f69b6463190cd6cef7728d6b86b7723f08aad0c54cb8d4\":{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI0NmJkMzE5ZDM1OTBkMmI0ZDdjN2EyN2M5OWQzMmY3ZWE2MGE4NTBlYzM4MDYzNTFlMDRkMTYxZDAxNGVjYzAxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlRVMGdnVTBsSFRrRlVWVkpGTFMwdExTMEtWVEZPU1ZVd2JFaEJRVUZCUVZGQlFVRkVUVUZCUVVGTVl6Tk9iMHhYVm10TmFsVXhUVlJyUVVGQlFXY3ZkbVZUWXpSdmJIQkxkRTF2VDFJM2NuZG1PQXBXUjBoNmFHaG5NRVpKYjBSMFl6VlNNa3BzZEhwSFowRkJRVUZGV20xc2MxcFJRVUZCUVVGQlFVRkJSMk15YUdoT1ZFVjVRVUZCUVZWM1FVRkJRWFI2Q21NeVozUmFWMUY1VGxSVmVFOVJRVUZCUlVKalEydDBaME14V1dwcmIzZEtkSEJzZVhCRFNEUTJhbkV5UW1Sb05tUjZhblIwZVd0SFpWRjVLMG8xZUhvS2RIRlVlbXRqUXpCWVNHRkZZWEZPZFdNMWNURnpUbEZNWTJRNFNEUjRNM0ZLU2xSRFFsRnZUd290TFMwdExVVk9SQ0JUVTBnZ1UwbEhUa0ZVVlZKRkxTMHRMUzBLIiwiZm9ybWF0Ijoic3NoIiwicHVibGljS2V5Ijp7ImNvbnRlbnQiOiJjM05vTFdWa01qVTFNVGtnUVVGQlFVTXpUbnBoUXpGc1drUkpNVTVVUlRWQlFVRkJTVkEzTTJ0dVQwdEtZVk55VkV0RWEyVTJPRWd2UmxKb09EUlpXVTVDVTB0Qk4xaFBWV1JwV21KamVHOEsifX19fQ==\",\"integratedTime\":1643749079,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\",\"logIndex\":1236200,\"verification\":{\"signedEntryTimestamp\":\"MEQCID3QHHXwGauKUfFvs0YCMKZ4e3BE1ZIhrJ5RHnoHGophAiA/R5cDc8JnSUq6F7U/8oTk8/mn7QCdDXI+NRT7qm78+Q==\"}}}\n"
            );
    });

    let response = reqwest::Client::new()
        .post(server.url("/api/v1/log/entries"))
        .json(&body)
        .send()
        .await?
        .text()
        .await?;

    // println!();
    // println!("{:#?}", response);
    // println!();

    /*
    We need to modify the response before we can read it into a Struct

    This is the response that is returned by Rekor:
    {
        "9bf4f37447a48848c1f69b6463190cd6cef7728d6b86b7723f08aad0c54cb8d4": {
            "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI0NmJkMzE5ZDM1OTBkMmI0ZDdjN2EyN2M5OWQzMmY3ZWE2MGE4NTBlYzM4MDYzNTFlMDRkMTYxZDAxNGVjYzAxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlRVMGdnVTBsSFRrRlVWVkpGTFMwdExTMEtWVEZPU1ZVd2JFaEJRVUZCUVZGQlFVRkVUVUZCUVVGTVl6Tk9iMHhYVm10TmFsVXhUVlJyUVVGQlFXY3ZkbVZUWXpSdmJIQkxkRTF2VDFJM2NuZG1PQXBXUjBoNmFHaG5NRVpKYjBSMFl6VlNNa3BzZEhwSFowRkJRVUZGV20xc2MxcFJRVUZCUVVGQlFVRkJSMk15YUdoT1ZFVjVRVUZCUVZWM1FVRkJRWFI2Q21NeVozUmFWMUY1VGxSVmVFOVJRVUZCUlVKalEydDBaME14V1dwcmIzZEtkSEJzZVhCRFNEUTJhbkV5UW1Sb05tUjZhblIwZVd0SFpWRjVLMG8xZUhvS2RIRlVlbXRqUXpCWVNHRkZZWEZPZFdNMWNURnpUbEZNWTJRNFNEUjRNM0ZLU2xSRFFsRnZUd290TFMwdExVVk9SQ0JUVTBnZ1UwbEhUa0ZVVlZKRkxTMHRMUzBLIiwiZm9ybWF0Ijoic3NoIiwicHVibGljS2V5Ijp7ImNvbnRlbnQiOiJjM05vTFdWa01qVTFNVGtnUVVGQlFVTXpUbnBoUXpGc1drUkpNVTVVUlRWQlFVRkJTVkEzTTJ0dVQwdEtZVk55VkV0RWEyVTJPRWd2UmxKb09EUlpXVTVDVTB0Qk4xaFBWV1JwV21KamVHOEsifX19fQ==",
            "integratedTime": 1643749079,
            "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
            "logIndex": 1236200,
            "verification": {
                "signedEntryTimestamp": "MEQCID3QHHXwGauKUfFvs0YCMKZ4e3BE1ZIhrJ5RHnoHGophAiA/R5cDc8JnSUq6F7U/8oTk8/mn7QCdDXI+NRT7qm78+Q=="
            }
        }
    }

    Since there is no member called "uuid" in the json body,
    we cannot read it into the Post struct.
    So we add "{\"uuid\": " to the returned response and make it a valid json
    */

    let uuid: &str = &response[1..67];
    let rest: &str = &response[69..response.len() - 2];
    let sum = "{\"uuid\": ".to_string() + &(uuid.to_owned()) + "," + rest;
    let v: Result<Post, serde_json::Error> = serde_json::from_str(&sum);
    v.or_else(|err| Err(Box::new(err) as Box<dyn std::error::Error>))
}

#[cfg(test)]
mod tests {

    use crate::rekor::rekor_upload;

    #[tokio::test]
    async fn verify_rekor_upload() -> Result<(), reqwest::Error> {
        let response = rekor_upload(
        "0.0.1".to_string(),
        "rekord".to_string(),
        "ssh".to_string(),
        "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWcvdmVTYzRvbHBLdE1vT1I3cndmOFZHSHpoaApnMEZJb0R0YzVSMkpsdHpHZ0FBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6YzJndFpXUXlOVFV4Ck9RQUFBRUR4VFg4dDMva0lvbEpYai9aZnJXQTAvNUg2cEhSTUhEeWNmWStPR3M0MUhXMCt0bkxESGFuQ3R3NGtsY3BpZk0KTHVLdk5LYXB6V0hiazh5d3NHRTVvTAotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K".to_string(),
        "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSVA3M2tuT0tKYVNyVEtEa2U2OEgvRlJoODRZWU5CU0tBN1hPVWRpWmJjeG8gdGVzdEByZWtvci5kZXYK".to_string(),
        "https://raw.githubusercontent.com/jyotsna-penumaka/integrate-rekor/main/README.md".to_string(),
        "sha256".to_string(),
        "58f7c1bab6fc37b4679abf5971898d0b61cd29c9afe153bfcfafabb23c256883".to_string()).await;
        assert!(response.is_ok());
        Ok(())
    }
}

/*
TO DO:
1. replace isach with request once you get it to work
2. Check if you can move httpmock = "0.6", isahc = "1.6.0" into dev-dependencies


*/
