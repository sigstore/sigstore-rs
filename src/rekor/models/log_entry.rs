//
// Copyright 2023 The Sigstore Authors.
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

use crate::errors::SigstoreError;
use crate::rekor::TreeSize;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD_ENGINE};

use crate::crypto::CosignVerificationKey;
use crate::errors::SigstoreError::UnexpectedError;
use crate::rekor::models::InclusionProof as InclusionProof2;
use crate::rekor::models::checkpoint::Checkpoint;
use serde::{Deserialize, Serialize};
use serde_json::{Error, Value, json};
use std::collections::HashMap;
use std::str::FromStr;

use super::{
    AlpineAllOf, HashedrekordAllOf, HelmAllOf, IntotoAllOf, JarAllOf, RekordAllOf, Rfc3161AllOf,
    RpmAllOf, TufAllOf,
};

/// Stores the response returned by Rekor after making a new entry
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    pub body: Body,
    pub integrated_time: i64,
    pub log_i_d: String,
    pub log_index: i64,
    pub verification: Verification,
}

impl FromStr for LogEntry {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut log_entry_map = serde_json::from_str::<HashMap<&str, Value>>(s)?;
        log_entry_map.entry("body").and_modify(|body| {
            let decoded_body = serde_json::to_value(
                decode_body(body.as_str().expect("Failed to parse Body"))
                    .expect("Failed to decode Body"),
            )
            .expect("Serialization failed");
            *body = json!(decoded_body);
        });
        let log_entry_str = serde_json::to_string(&log_entry_map)?;
        Ok(serde_json::from_str::<LogEntry>(&log_entry_str).expect("Serialization failed"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[allow(non_camel_case_types)]
pub enum Body {
    alpine(AlpineAllOf),
    helm(HelmAllOf),
    jar(JarAllOf),
    rfc3161(Rfc3161AllOf),
    rpm(RpmAllOf),
    tuf(TufAllOf),
    intoto(IntotoAllOf),
    hashedrekord(HashedrekordAllOf),
    rekord(RekordAllOf),
}

impl Default for Body {
    fn default() -> Self {
        Self::hashedrekord(Default::default())
    }
}

fn decode_body(s: &str) -> Result<Body, SigstoreError> {
    let decoded = BASE64_STD_ENGINE.decode(s)?;
    serde_json::from_slice(&decoded).map_err(SigstoreError::from)
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    // This field is just a place holder
    // Not sure what is stored inside the Attestation struct, it is empty for now
    #[serde(skip_serializing_if = "Option::is_none")]
    dummy: Option<String>,
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,
    pub signed_entry_timestamp: String,
}

impl LogEntry {
    /// Verifies that the log entry was included by a log in possession of `rekor_key`.
    ///
    /// Example:
    /// ```rust
    /// use sigstore::rekor::apis::configuration::Configuration;
    /// use sigstore::rekor::apis::pubkey_api::get_public_key;
    /// use sigstore::rekor::apis::tlog_api::get_log_info;
    /// use sigstore::crypto::{CosignVerificationKey, SigningScheme};
    /// #[tokio::main]
    /// async fn main() {
    ///     use sigstore::rekor::apis::entries_api::get_log_entry_by_index;
    ///     let rekor_config = Configuration::default();
    ///     // Important: in practice obtain the rekor key via TUF repo or another secure channel!
    ///     let rekor_key = get_public_key(&rekor_config, None)
    ///         .await
    ///         .expect("failed to fetch pubkey from remote log");
    ///     let rekor_key =  CosignVerificationKey::from_pem(
    ///         rekor_key.as_bytes(),
    ///         &SigningScheme::ECDSA_P256_SHA256_ASN1,
    ///     ).expect("failed to parse rekor key");
    ///
    ///     // fetch log info and then the most recent entry
    ///     let log_info = get_log_info(&rekor_config)
    ///         .await
    ///         .expect("failed to fetch log info");
    ///     let entry = get_log_entry_by_index(&rekor_config, (log_info.tree_size - 1) as i32)
    ///         .await.expect("failed to fetch log entry");
    ///     entry.verify_inclusion(&rekor_key)
    ///         .expect("failed to verify inclusion");
    /// }
    /// ```
    pub fn verify_inclusion(&self, rekor_key: &CosignVerificationKey) -> Result<(), SigstoreError> {
        self.verification
            .inclusion_proof
            .as_ref()
            .ok_or(UnexpectedError("missing inclusion proof".to_string()))
            .and_then(|proof| {
                Checkpoint::decode(&proof.checkpoint)
                    .map_err(|_| UnexpectedError("failed to parse checkpoint".to_string()))
                    .map(|checkpoint| {
                        InclusionProof2::new(
                            proof.log_index,
                            proof.root_hash.clone(),
                            proof.tree_size,
                            proof.hashes.clone(),
                            Some(checkpoint),
                        )
                    })
            })
            .and_then(|proof| {
                // encode as canonical JSON
                let buf = serde_json_canonicalizer::to_vec(&self.body).map_err(|e| {
                    SigstoreError::UnexpectedError(format!(
                        "Cannot create canonical JSON representation of body: {e:?}"
                    ))
                })?;
                proof.verify(&buf, rekor_key)
            })
    }
}

/// Stores the signature over the artifact's logID, logIndex, body and integratedTime.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    pub hashes: Vec<String>,
    pub log_index: i64,
    pub root_hash: String,
    pub tree_size: TreeSize,

    /// A snapshot of the transparency log's state at a specific point in time,
    /// in [Signed Note format].
    ///
    /// [Signed Note format]: https://github.com/transparency-dev/formats/blob/main/log/README.md
    pub checkpoint: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::crypto::{CosignVerificationKey, SigningScheme};

    use super::LogEntry;

    const LOG_ENTRY: &str = r#"
    {
        "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI0N2MxZGI5ZmI1ZmU3ZmY2NmUzZDdjMTViMmNhNWQzYTA0NmVlOGY0YWEwNDNkZWRkMzE3ZTQ2YjMyMWM0MzkwIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURVell6d3o4SEdhVXRXNUwvb0VNNGc1MFVvSUtzNXhuV1B0amFyeHRKckxBSWhBTzkwRTl2NGd5MmZUcytJbHM4OFczOXhldEUzS3NqRHN0cXF6NXNQMGVITSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTkRWRU5EUVdFclowRjNTVUpCWjBsSFFWbEhjMEZMUVhkTlFXOUhRME54UjFOTk5EbENRVTFEVFVOdmVFUlVRVXhDWjA1V1FrRk5UVUpJVW13S1l6TlJlRWRVUVZoQ1owNVdRa0Z2VFVWSVVteGpNMUZuV1RKV2VXUkhiRzFoVjA1b1pFZFZkMGhvWTA1TmFrbDNUbXBKTkUxcVFYbFBSRlY0VjJoalRncE5ha2wzVG1wSk5FMXFRVEJQUkZWNFYycEJjVTFSTUhkRGQxbEVWbEZSUkVSQlVqQmFXRTR3VFZKcmQwWjNXVVJXVVZGTFJFSkNNRnBZVGpCSlIwNXNDbU51VW5CYWJXeHFXVmhTYkUxR2EzZEZkMWxJUzI5YVNYcHFNRU5CVVZsSlMyOWFTWHBxTUVSQlVXTkVVV2RCUlVSQ1VISnBNMEp3VlhZNVRYRndVMlFLWlVoWlJXVjRZM3BqV0RKWmRHRkJXRGxDVjB4VVkyVm9Za2MxUnpkUFVGcHNVekZ2Y0hWRldXMVViVEJhY2pKTmNXcHBiV05xTHpjNFpFSTJNbUpFWWdwSlMwcDZTbUZQUW5kRVEwSjJWRUZrUW1kT1ZraFJORVZHWjFGVlFXcHBSMUJFUWsxSFNXSTFZVEp3YUhkeU1VVTJURXBtVTJGdmQwaDNXVVJXVWpCcUNrSkNaM2RHYjBGVldWTldPV1V5TjFKVmN6TTViRTg1VWsxTVlXaGtZVzV0V1VaM2QwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUpOUjBFeFZXUUtTbEZSVFUxQmIwZERRM05IUVZGVlJrSjNUVVJOUVhkSFFURlZaRVYzUlVJdmQxRkRUVUZCZDBkM1dVUldVakJTUVZGSUwwSkNSWGRFTkVWT1pFZFdlZ3BrUlVJd1dsaE9NRXh0VG5aaVZFRnlRbWR2Y2tKblJVVkJXVTh2VFVGRlFrSkNNVzlrU0ZKM1kzcHZka3d5V21oaE1sWm9XVEpPZG1SWE5UQmplVFV3Q2xwWVRqQk1iVTUyWWxSQlMwSm5aM0ZvYTJwUFVGRlJSRUZuVGtsQlJFSkdRV2xCVXpWTVZHeHlXak54Vm5aUGIyVjBibGh4V21JdmEzcEVURWRhYXpNS1MySkJTMGhMYmpkemFqQkZabEZKYUVGT05uTldVRTlyWlU1SlVYYzJlVEJNUVhNMVlrbGFXVkExUVVoTWFFUm9SRTlhZG1Od1lWUlhaek5xQ2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn19fX0=",
        "integratedTime": 1656448131,
        "logID": "d32f30a3c32d639c2b762205a21c7bb07788e68283a4ae6f42118723a1bea496",
        "logIndex": 1688,
        "verification": {
        "inclusionProof": {
            "hashes": [
            "810320ec3029914695826d60133c67021f66ee0cfb09a6f79eb267ed9f55de2c",
            "67e9d9f66f0ad388f7e1a20991e9a2ae3efad5cbf281e8b3d2aaf1ef99a4618c",
            "16a106400c53465f6e18c2475df6ba889ca30f5667bacf32b1a5661f14a5080c",
            "b4439e8d71edbc96271723cb7a969dd725e23e73d139361864a62ed76ce8dc11",
            "49b3e90806c7b63b5a86f5748e3ecb7d264ea0828eb74a45bc1a2cd7962408e8",
            "5059ad9b48fa50bd9adcbff0dd81c5a0dcb60f37e0716e723a33805a464f72f8",
            "6c2ce64219799e61d72996884eee9e19fb906e4d7fa04b71625fde4108f21762",
            "784f79c817abb78db3ae99b6c1ede640470bf4bb678673a05bf3a6b50aaaddd6",
            "c6d92ebf4e10cdba500ca410166cd0a8d8b312154d2f45bc4292d63dea6112f6",
            "1768732027401f6718b0df7769e2803127cfc099eb130a8ed7d913218f6a65f6",
            "0da021f68571b65e49e926e4c69024de3ac248a1319d254bc51a85a657b93c33",
            "bc8cf0c8497d5c24841de0c9bef598ec99bbd59d9538d58568340646fe289e9a",
            "be328fa737b8fa9461850b8034250f237ff5b0b590b9468e6223968df294872b",
            "6f06f4025d0346f04830352b23f65c8cd9e3ce4b8cb899877c35282521ddaf85"
            ],
            "logIndex": 1227,
            "rootHash": "effa4fa4575f72829016a64e584441203de533212f9470d63a56d1992e73465d",
            "treeSize": 14358,
            "checkpoint": "rekor.sigstage.dev - 108574341321668964\n14358\n7/pPpFdfcoKQFqZOWERBID3lMyEvlHDWOlbRmS5zRl0=\n\n— rekor.sigstage.dev 0y8wozBFAiB8OkuzdwlL6/rDEu2CsIfqmesaH/KLfmIMvlH3YTdIYgIhAPFZeXK6+b0vbWy4GSU/YZxiTpFrrzjsVOShN4LlPdZb\n"
        },
        "signedEntryTimestamp": "MEUCIQCO8dFvolJwFZDHkhkSdsW3Ny+07fG8CF7G32feG8NJMgIgd2qfJ5shezuXX8I1S6DsudvIZ8xN/+y95at/V5xHfEQ="
        }
    }
    "#;
    /// Pubkey for `rekor.sigstage.dev`.
    const REKOR_STAGING_KEY_PEM: &str = r#"
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9
        nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==
        -----END PUBLIC KEY-----
    "#;

    #[test]
    fn test_inclusion_proof_valid() {
        let entry = LogEntry::from_str(LOG_ENTRY).expect("failed to parse log entry");
        let rekor_key = CosignVerificationKey::from_pem(
            REKOR_STAGING_KEY_PEM.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("failed to parse Rekor key");
        entry
            .verify_inclusion(&rekor_key)
            .expect("rejected valid inclusion proof");
    }

    #[test]
    fn test_inclusion_proof_missing_proof() {
        let mut entry = LogEntry::from_str(LOG_ENTRY).expect("failed to parse log entry");
        entry.verification.inclusion_proof = None;
        let rekor_key = CosignVerificationKey::from_pem(
            REKOR_STAGING_KEY_PEM.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("failed to parse Rekor key");
        entry
            .verify_inclusion(&rekor_key)
            .expect_err("accepted invalid inclusion proof");
    }

    #[test]
    fn test_inclusion_proof_modified_proof() {
        let entry = LogEntry::from_str(LOG_ENTRY).expect("failed to parse log entry");
        let rekor_key = CosignVerificationKey::from_pem(
            REKOR_STAGING_KEY_PEM.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("failed to parse Rekor key");

        let mut test_cases = vec![];

        // swap upper and lower halves of a hash.
        let mut entry_modified_hashes = entry.clone();
        entry_modified_hashes
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .hashes[0] =
            "1f66ee0cfb09a6f79eb267ed9f55de2c810320ec3029914695826d60133c6702".to_string();
        test_cases.push((entry_modified_hashes, "modified hash"));

        // modify checkpoint.
        let mut entry_modified_checkpoint = entry.clone();
        entry_modified_checkpoint
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .checkpoint = "foo".to_string();
        test_cases.push((entry_modified_checkpoint, "modified checkpoint"));

        // modify log index.
        let mut entry_modified_log_index = entry.clone();
        entry_modified_log_index
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .log_index += 1;
        test_cases.push((entry_modified_log_index, "modified log index"));

        // modify root hash.
        let mut entry_modified_root_hash = entry.clone();
        entry_modified_root_hash
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .root_hash =
            "3de533212f9470d63a56d1992e73465deffa4fa4575f72829016a64e58444120".to_string();
        test_cases.push((entry_modified_root_hash, "modified root hash"));

        // modify tree size.
        let mut entry_modified_tree_size = entry.clone();
        entry_modified_tree_size
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .tree_size += 1;
        test_cases.push((entry_modified_tree_size, "modified tree size"));

        for (case, desc) in test_cases {
            let res = case.verify_inclusion(&rekor_key);
            assert!(res.is_err(), "accepted invalid proof: {desc}");
        }
    }
}
