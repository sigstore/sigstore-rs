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

//! Merkle tree operations for transparency log verification.
//!
//! This module implements RFC 6962 (Certificate Transparency) Merkle tree
//! operations for verifying inclusion proofs from Rekor transparency logs.
//!
//! See: <https://datatracker.ietf.org/doc/html/rfc6962>

use sha2::{Digest, Sha256};

use crate::errors::{Result, SigstoreError};

/// Compute RFC 6962 leaf hash: SHA256(0x00 || data)
///
/// The leaf hash includes a 0x00 prefix byte to distinguish it from
/// internal node hashes.
///
/// # Example
///
/// ```
/// use sigstore::crypto::merkle::leaf_hash;
///
/// let data = b"hello world";
/// let hash = leaf_hash(data);
/// assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes
/// ```
pub fn leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]); // Leaf prefix
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute RFC 6962 node hash: SHA256(0x01 || left || right)
///
/// The node hash includes a 0x01 prefix byte to distinguish it from
/// leaf hashes. This prevents second-preimage attacks.
///
/// # Example
///
/// ```
/// use sigstore::crypto::merkle::node_hash;
///
/// let left = &[0u8; 32];
/// let right = &[1u8; 32];
/// let hash = node_hash(left, right);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]); // Node prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// Verify a Merkle tree inclusion proof.
///
/// This function verifies that a given leaf is included in a Merkle tree
/// at the specified index, using the provided inclusion proof.
///
/// # Arguments
///
/// * `leaf_index` - The index of the leaf in the tree (0-based)
/// * `tree_size` - The total number of leaves in the tree
/// * `leaf_hash` - The hash of the leaf being verified
/// * `proof_hashes` - The sibling hashes along the path from leaf to root
/// * `root_hash` - The expected root hash of the tree
///
/// # Returns
///
/// Returns `Ok(())` if the proof is valid, or an error if:
/// - The leaf index is >= tree size
/// - The computed root doesn't match the expected root
/// - Any hash is malformed
///
/// # Example
///
/// ```no_run
/// use sigstore::crypto::merkle::verify_inclusion;
///
/// let leaf_index = 5;
/// let tree_size = 8;
/// let leaf_hash = vec![0u8; 32];
/// let proof_hashes = vec![vec![1u8; 32], vec![2u8; 32]];
/// let root_hash = vec![3u8; 32];
///
/// verify_inclusion(leaf_index, tree_size, &leaf_hash, &proof_hashes, &root_hash).unwrap();
/// ```
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof_hashes: &[Vec<u8>],
    root_hash: &[u8],
) -> Result<()> {
    if leaf_index >= tree_size {
        return Err(SigstoreError::UnexpectedError(format!(
            "Merkle tree verification: leaf index {} >= tree size {}",
            leaf_index, tree_size
        )));
    }

    // Compute the root hash from the leaf and proof
    let computed_root = compute_root_from_proof(leaf_index, tree_size, leaf_hash, proof_hashes);

    // Compare with expected root hash
    if computed_root != root_hash {
        return Err(SigstoreError::UnexpectedError(
            "Merkle tree inclusion proof verification failed: computed root hash does not match expected root"
                .into(),
        ));
    }

    Ok(())
}

/// Compute the root hash from a leaf and its inclusion proof.
///
/// This implements the algorithm from RFC 6962 Section 2.1.1 for computing
/// the Merkle tree root from a leaf hash and the hashes along the path to the root.
///
/// The algorithm works by starting with the leaf hash and repeatedly combining
/// it with sibling hashes from the proof, moving up the tree until reaching the root.
///
/// # Arguments
///
/// * `leaf_index` - The index of the leaf (0-based)
/// * `tree_size` - The total size of the tree
/// * `leaf_hash` - The hash of the leaf
/// * `proof` - The sibling hashes along the path to the root
///
/// # Returns
///
/// The computed root hash as a vector of bytes.
fn compute_root_from_proof(
    mut index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof: &[Vec<u8>],
) -> Vec<u8> {
    let mut current_hash = leaf_hash.to_vec();
    let mut last_node = tree_size - 1;

    for sibling in proof {
        // Determine if we hash (sibling || current) or (current || sibling)
        // based on the index and tree structure
        //
        // If the index is odd, the sibling is on the left (we are the right child)
        // If the index equals last_node, we're at the rightmost position
        if index % 2 == 1 || index == last_node {
            // Sibling is on the left
            current_hash = node_hash(sibling, &current_hash);
        } else {
            // Sibling is on the right
            current_hash = node_hash(&current_hash, sibling);
        }

        index /= 2;
        last_node /= 2;
    }

    current_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash() {
        // Test that leaf hash includes the 0x00 prefix
        let data = b"test data";
        let hash = leaf_hash(data);

        // Should be SHA256 output (32 bytes)
        assert_eq!(hash.len(), 32);

        // Manually compute expected hash
        let mut hasher = Sha256::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        let expected = hasher.finalize();

        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_node_hash() {
        // Test that node hash includes the 0x01 prefix
        let left = vec![0x42; 32];
        let right = vec![0x43; 32];
        let hash = node_hash(&left, &right);

        // Should be SHA256 output (32 bytes)
        assert_eq!(hash.len(), 32);

        // Manually compute expected hash
        let mut hasher = Sha256::new();
        hasher.update(&[0x01]);
        hasher.update(&left);
        hasher.update(&right);
        let expected = hasher.finalize();

        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_leaf_and_node_hashes_differ() {
        // Ensure leaf and node hashes are different for the same input
        let data = vec![0x00; 32];
        let left = vec![0x00; 16];
        let right = vec![0x00; 16];

        let leaf = leaf_hash(&data);
        let node = node_hash(&left, &right);

        assert_ne!(leaf, node);
    }

    #[test]
    fn test_verify_inclusion_single_leaf() {
        // Tree with a single leaf - the leaf hash IS the root hash
        let leaf_data = b"single leaf";
        let leaf = leaf_hash(leaf_data);
        let root = leaf.clone();

        let result = verify_inclusion(0, 1, &leaf, &[], &root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_inclusion_two_leaves() {
        // Tree with two leaves
        let leaf0_data = b"leaf 0";
        let leaf1_data = b"leaf 1";

        let leaf0 = leaf_hash(leaf0_data);
        let leaf1 = leaf_hash(leaf1_data);

        // Root is hash(leaf0 || leaf1)
        let root = node_hash(&leaf0, &leaf1);

        // Verify leaf 0 with leaf 1 as proof
        let result = verify_inclusion(0, 2, &leaf0, &[leaf1.clone()], &root);
        assert!(result.is_ok());

        // Verify leaf 1 with leaf 0 as proof
        let result = verify_inclusion(1, 2, &leaf1, &[leaf0], &root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_inclusion_invalid_index() {
        let leaf = vec![0u8; 32];
        let root = vec![1u8; 32];

        // Leaf index >= tree size should fail
        let result = verify_inclusion(5, 5, &leaf, &[], &root);
        assert!(result.is_err());

        let result = verify_inclusion(10, 5, &leaf, &[], &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_inclusion_wrong_root() {
        let leaf = leaf_hash(b"test");
        let wrong_root = vec![0u8; 32];

        let result = verify_inclusion(0, 1, &leaf, &[], &wrong_root);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("computed root hash does not match"));
    }

    #[test]
    fn test_verify_inclusion_four_leaves() {
        // Build a tree with 4 leaves:
        //         root
        //        /    \
        //       h01   h23
        //      /  \   /  \
        //     l0  l1 l2  l3

        let leaf0 = leaf_hash(b"leaf 0");
        let leaf1 = leaf_hash(b"leaf 1");
        let leaf2 = leaf_hash(b"leaf 2");
        let leaf3 = leaf_hash(b"leaf 3");

        let h01 = node_hash(&leaf0, &leaf1);
        let h23 = node_hash(&leaf2, &leaf3);
        let root = node_hash(&h01, &h23);

        // Verify leaf 0: proof is [leaf1, h23]
        let result = verify_inclusion(0, 4, &leaf0, &[leaf1.clone(), h23.clone()], &root);
        assert!(result.is_ok());

        // Verify leaf 1: proof is [leaf0, h23]
        let result = verify_inclusion(1, 4, &leaf1, &[leaf0.clone(), h23.clone()], &root);
        assert!(result.is_ok());

        // Verify leaf 2: proof is [leaf3, h01]
        let result = verify_inclusion(2, 4, &leaf2, &[leaf3.clone(), h01.clone()], &root);
        assert!(result.is_ok());

        // Verify leaf 3: proof is [leaf2, h01]
        let result = verify_inclusion(3, 4, &leaf3, &[leaf2, h01], &root);
        assert!(result.is_ok());
    }
}
