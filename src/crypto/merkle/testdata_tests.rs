// Copyright 2025 The Sigstore Authors.
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

//! Tests using the official transparency-dev/merkle test vectors
//!
//! This test suite uses the comprehensive test vectors from the Go reference
//! implementation at https://github.com/transparency-dev/merkle

use super::proof_verification::MerkleProofVerifier;
use super::rfc6962::Rfc6269Default;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use digest::Output;
use rstest::rstest;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionProofTestVector {
    leaf_idx: u64,
    tree_size: u64,
    root: String,
    leaf_hash: String,
    proof: Option<Vec<String>>,
    desc: String,
    want_err: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsistencyProofTestVector {
    size1: u64,
    size2: u64,
    root1: String,
    root2: String,
    proof: Option<Vec<String>>,
    desc: String,
    want_err: bool,
}

fn decode_base64_hash(s: &str) -> Result<Output<Rfc6269Default>, String> {
    // Empty strings are invalid
    if s.is_empty() {
        return Err("Empty hash string".to_string());
    }

    let bytes = base64
        .decode(s)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Some test vectors intentionally have wrong-sized hashes to test error handling
    // Pad or truncate to 32 bytes
    let mut arr = [0u8; 32];
    let copy_len = bytes.len().min(32);
    arr[..copy_len].copy_from_slice(&bytes[..copy_len]);
    Ok(arr.into())
}

#[rstest]
fn test_inclusion_proof(#[files("tests/data/merkle/testdata/inclusion/**/*.json")] path: PathBuf) {
    let content =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read file: {:?}", path));
    let vector: InclusionProofTestVector = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {:?}: {}", path, e));

    // Try to decode - if any decoding fails and we expect an error, accept it
    let root_result = decode_base64_hash(&vector.root);
    let leaf_hash_result = decode_base64_hash(&vector.leaf_hash);
    let proof_result: Result<Vec<Output<Rfc6269Default>>, String> = vector
        .proof
        .as_ref()
        .map(|p| p.iter().map(|h| decode_base64_hash(h)).collect())
        .unwrap_or(Ok(Vec::new()));

    if (root_result.is_err() || leaf_hash_result.is_err() || proof_result.is_err())
        && vector.want_err
    {
        // Expected error due to invalid input
        return;
    }

    let root = root_result.unwrap();
    let leaf_hash = leaf_hash_result.unwrap();
    let proof = proof_result.unwrap();

    let result = Rfc6269Default::verify_inclusion(
        vector.leaf_idx,
        &leaf_hash,
        vector.tree_size,
        &proof,
        &root,
    );

    assert_eq!(
        result.is_err(),
        vector.want_err,
        "Test '{}' ({}): expected_error={}, got_error={}",
        vector.desc,
        path.display(),
        vector.want_err,
        result.is_err()
    );
}

#[rstest]
fn test_consistency_proof(
    #[files("tests/data/merkle/testdata/consistency/**/*.json")] path: PathBuf,
) {
    let content =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read file: {:?}", path));
    let vector: ConsistencyProofTestVector = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {:?}: {}", path, e));

    // Try to decode - if any decoding fails and we expect an error, accept it
    let root1_result = decode_base64_hash(&vector.root1);
    let root2_result = decode_base64_hash(&vector.root2);
    let proof_result: Result<Vec<Output<Rfc6269Default>>, String> = vector
        .proof
        .as_ref()
        .map(|p| p.iter().map(|h| decode_base64_hash(h)).collect())
        .unwrap_or(Ok(Vec::new()));

    if (root1_result.is_err() || root2_result.is_err() || proof_result.is_err()) && vector.want_err
    {
        // Expected error due to invalid input
        return;
    }

    let root1 = root1_result.unwrap();
    let root2 = root2_result.unwrap();
    let proof = proof_result.unwrap();

    let result =
        Rfc6269Default::verify_consistency(vector.size1, vector.size2, &proof, &root1, &root2);

    assert_eq!(
        result.is_err(),
        vector.want_err,
        "Test '{}' ({}): expected_error={}, got_error={}",
        vector.desc,
        path.display(),
        vector.want_err,
        result.is_err()
    );
}
