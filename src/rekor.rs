use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::env;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub api_version: String,
    pub kind: String,
    pub spec: Spec,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub signature: Signature,
    pub data: Data,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub format: String,
    pub content: String,
    pub public_key: PublicKey,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub content: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub hash: Hash,
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash {
    pub algorithm: String,
    pub value: String,
}

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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    signed_entry_timestamp: String,
}

/*
This is the response, that gets structured into "Post"
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
*/

fn get_github_token() -> String {
    match env::var("GITHUB_AUTH_TOKEN") {
        Ok(val) => format!("Token {}", val),
        Err(_err) => ("").to_string(),
    }
}

async fn rekor_upload(
    api_version_val: String,
    object_type: String,
    key_format: String,
    signature_val: String,
    pub_key_val: String,
    file_url: String,
    algorithm_name: String,
    hash_val: String,
) -> Result<Post, serde_json::Error> {
    let new_post = Root {
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

    let new_post = reqwest::Client::new()
        .post("https://rekor.sigstore.dev/api/v1/log/entries")
        .header("Authorization", get_github_token())
        .json(&new_post)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    println!();
    println!("{:#?}", new_post);
    println!();

    if &new_post[..7] != "{\"code\"" {
        println!("Lets parse the response, there is no error :) ");
    } else {
        println!("There is an error! Cannot parse the response :( ");
    }
    println!();

    let post = new_post;
    let uuid: &str = &post[1..67];
    let rest: &str = &post[69..post.len() - 2];
    let sum = "{\"uuid\": ".to_string() + &(uuid.to_owned()) + "," + rest;
    let v: Result<Post, serde_json::Error> = serde_json::from_str(&sum);
    v
}

#[tokio::test]
async fn verify_rekor_upload() -> Result<(), reqwest::Error> {
    let new_post = rekor_upload(
        "0.0.1".to_string(),
        "rekord".to_string(),
        "ssh".to_string(),
        "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0KVTFOSVUwbEhBQUFBQVFBQUFETUFBQUFMYzNOb0xXVmtNalUxTVRrQUFBQWcvdmVTYzRvbHBLdE1vT1I3cndmOFZHSHpoaApnMEZJb0R0YzVSMkpsdHpHZ0FBQUFFWm1sc1pRQUFBQUFBQUFBR2MyaGhOVEV5QUFBQVV3QUFBQXR6YzJndFpXUXlOVFV4Ck9RQUFBRURQbGU5WEIzeE9NRUl5SytDRm5WK2xXK0hWYXJwZ05wRklyeG5mWlNRcC9YcFhocVE1SUlYYllQR2RKeHMydzAKZ0FFekREZlNuTUtUK2VHbE5oZWFRSwotLS0tLUVORCBTU0ggU0lHTkFUVVJFLS0tLS0K".to_string(),
        "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSVA3M2tuT0tKYVNyVEtEa2U2OEgvRlJoODRZWU5CU0tBN1hPVWRpWmJjeG8gdGVzdEByZWtvci5kZXYK".to_string(),
        "https://raw.githubusercontent.com/jyotsna-penumaka/integrate-rekor/main/README.md".to_string(),
        "sha256".to_string(),
        "8101640bcab37a0e486a35a3e4343f0de215f46205ab485929ccfd60077ee894".to_string()).await;

    //println!("{:#?}", new_post.unwrap());

    Ok(())
}
