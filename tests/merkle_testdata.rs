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

//! Test vectors from transparency-dev/merkle
//!
//! These tests validate our Merkle tree implementation against the official
//! test vectors from https://github.com/transparency-dev/merkle
//!
//! Test data includes both positive and negative test cases for:
//! - Inclusion proof verification
//! - Consistency proof verification
//!
//! To run these tests, clone the transparency-dev/merkle repository and
//! place it in the `tests/data/merkle` directory relative to this file.
//!
//! git clone https://github.com/transparency-dev/merkle.git tests/data/merkle
//! cargo test --test merkle_testdata

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use rstest::rstest;
use serde::Deserialize;
use sigstore::crypto::merkle::{verify_consistency, verify_inclusion};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct InclusionTestCase {
    #[serde(rename = "leafIdx")]
    leaf_idx: u64,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    root: String,
    #[serde(rename = "leafHash")]
    leaf_hash: String,
    proof: Option<Vec<String>>,
    desc: String,
    #[serde(rename = "wantErr")]
    want_err: bool,
}

#[derive(Debug, Deserialize)]
struct ConsistencyTestCase {
    size1: u64,
    size2: u64,
    root1: String,
    root2: String,
    proof: Option<Vec<String>>,
    desc: String,
    #[serde(rename = "wantErr")]
    want_err: bool,
}

fn decode_base64(s: &str) -> Vec<u8> {
    base64.decode(s).expect("valid base64")
}

fn run_inclusion_test(test_file: &PathBuf) {
    let test_json = std::fs::read_to_string(test_file)
        .unwrap_or_else(|_| panic!("Failed to read test file: {:?}", test_file));
    let test: InclusionTestCase = serde_json::from_str(&test_json)
        .unwrap_or_else(|_| panic!("Failed to parse test file: {:?}", test_file));

    let root = decode_base64(&test.root);
    let leaf_hash = decode_base64(&test.leaf_hash);
    let proof: Vec<Vec<u8>> = test
        .proof
        .as_ref()
        .map(|p| p.iter().map(|s| decode_base64(s)).collect())
        .unwrap_or_default();

    let result = verify_inclusion(test.leaf_idx, test.tree_size, &leaf_hash, &proof, &root);

    if test.want_err {
        assert!(
            result.is_err(),
            "Test '{}' ({:?}): expected error but got success",
            test.desc,
            test_file
        );
    } else {
        assert!(
            result.is_ok(),
            "Test '{}' ({:?}): expected success but got error: {:?}",
            test.desc,
            test_file,
            result.err()
        );
    }
}

fn run_consistency_test(test_file: &PathBuf) {
    let test_json = std::fs::read_to_string(test_file)
        .unwrap_or_else(|_| panic!("Failed to read test file: {:?}", test_file));
    let test: ConsistencyTestCase = serde_json::from_str(&test_json)
        .unwrap_or_else(|_| panic!("Failed to parse test file: {:?}", test_file));

    let root1 = decode_base64(&test.root1);
    let root2 = decode_base64(&test.root2);
    let proof: Vec<Vec<u8>> = test
        .proof
        .as_ref()
        .map(|p| p.iter().map(|s| decode_base64(s)).collect())
        .unwrap_or_default();

    let result = verify_consistency(test.size1, test.size2, &proof, &root1, &root2);

    if test.want_err {
        assert!(
            result.is_err(),
            "Test '{}' ({:?}): expected error but got success",
            test.desc,
            test_file
        );
    } else {
        assert!(
            result.is_ok(),
            "Test '{}' ({:?}): expected success but got error: {:?}",
            test.desc,
            test_file,
            result.err()
        );
    }
}

#[rstest]
fn test_inclusion_vectors(
    #[files("tests/data/merkle/testdata/inclusion/**/*.json")] path: PathBuf,
) {
    run_inclusion_test(&path);
}

#[rstest]
fn test_consistency_vectors(
    #[files("tests/data/merkle/testdata/consistency/**/*.json")] path: PathBuf,
) {
    run_consistency_test(&path);
}

#[test]
fn test_inclusion_sample() {
    // Sample test case to verify basic functionality without requiring external files
    let test = InclusionTestCase {
        leaf_idx: 0,
        tree_size: 8,
        root: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=".to_string(),
        leaf_hash: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=".to_string(),
        proof: Some(vec![
            "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=".to_string(),
            "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=".to_string(),
            "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=".to_string(),
        ]),
        desc: "sample inclusion proof".to_string(),
        want_err: false,
    };

    let root = decode_base64(&test.root);
    let leaf_hash = decode_base64(&test.leaf_hash);
    let proof: Vec<Vec<u8>> = test
        .proof
        .unwrap()
        .iter()
        .map(|s| decode_base64(s))
        .collect();

    let result = verify_inclusion(test.leaf_idx, test.tree_size, &leaf_hash, &proof, &root);
    assert!(result.is_ok());
}

#[test]
fn test_consistency_sample() {
    // Sample test case to verify basic functionality without requiring external files
    let test = ConsistencyTestCase {
        size1: 6,
        size2: 8,
        root1: "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=".to_string(),
        root2: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=".to_string(),
        proof: Some(vec![
            "DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=".to_string(),
            "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=".to_string(),
            "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=".to_string(),
        ]),
        desc: "sample consistency proof".to_string(),
        want_err: false,
    };

    let root1 = decode_base64(&test.root1);
    let root2 = decode_base64(&test.root2);
    let proof: Vec<Vec<u8>> = test
        .proof
        .unwrap()
        .iter()
        .map(|s| decode_base64(s))
        .collect();

    let result = verify_consistency(test.size1, test.size2, &proof, &root1, &root2);
    assert!(result.is_ok());
}
