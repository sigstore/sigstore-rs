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

/// Simple hex encoding helper (to avoid dependency on hex crate)
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

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
    hasher.update([0x00]); // Leaf prefix
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
    hasher.update([0x01]); // Node prefix
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

/// Verify a Merkle tree consistency proof.
///
/// This function verifies that a tree has grown consistently from `old_size` to `new_size`.
/// A consistency proof demonstrates that the tree at `old_size` is a prefix of the tree
/// at `new_size`, ensuring the tree has only been appended to.
///
/// # Arguments
///
/// * `old_size` - The size of the earlier tree version
/// * `new_size` - The size of the later tree version
/// * `proof_hashes` - The consistency proof hashes
/// * `old_root` - The root hash of the tree at `old_size`
/// * `new_root` - The root hash of the tree at `new_size`
///
/// # Returns
///
/// Returns `Ok(())` if the consistency proof is valid, or an error if:
/// - The new tree is smaller than the old tree (trees can only grow)
/// - The proof structure is invalid
/// - The computed roots don't match the provided roots
///
/// # Example
///
/// ```no_run
/// use sigstore::crypto::merkle::verify_consistency;
///
/// let old_size = 100;
/// let new_size = 150;
/// let proof_hashes = vec![vec![0u8; 32], vec![1u8; 32]];
/// let old_root = vec![2u8; 32];
/// let new_root = vec![3u8; 32];
///
/// verify_consistency(old_size, new_size, &proof_hashes, &old_root, &new_root).unwrap();
/// ```
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof_hashes: &[Vec<u8>],
    old_root: &[u8],
    new_root: &[u8],
) -> Result<()> {
    // Tree cannot shrink
    if new_size < old_size {
        return Err(SigstoreError::UnexpectedError(format!(
            "Merkle consistency proof: new tree size {} < old tree size {}",
            new_size, old_size
        )));
    }

    // If sizes are equal, roots must match and proof must be empty
    if old_size == new_size {
        if !proof_hashes.is_empty() {
            return Err(SigstoreError::UnexpectedError(
                "Merkle consistency proof: proof must be empty when tree sizes are equal".into(),
            ));
        }
        if old_root != new_root {
            return Err(SigstoreError::UnexpectedError(
                "Merkle consistency proof: roots must match when tree sizes are equal".into(),
            ));
        }
        return Ok(());
    }

    // If old tree is empty
    if old_size == 0 {
        if !proof_hashes.is_empty() {
            return Err(SigstoreError::UnexpectedError(
                "Merkle consistency proof: proof must be empty when old tree is empty".into(),
            ));
        }
        // Empty tree has a specific empty root - we just accept any old_root here
        return Ok(());
    }

    // Normal case: old_size > 0 and new_size > old_size
    if proof_hashes.is_empty() {
        return Err(SigstoreError::UnexpectedError(
            "Merkle consistency proof: proof cannot be empty for non-trivial consistency".into(),
        ));
    }

    // Find the largest power of 2 less than or equal to old_size
    let shift = (old_size as u64).trailing_zeros() as usize;
    let (inner, border) = decomp_inclusion_proof(old_size - 1, new_size);
    let inner = inner - shift;

    // The proof includes the root hash for the sub-tree of size 2^shift,
    // unless old_size is exactly 2^shift
    let (seed, start) = if old_size == (1 << shift) {
        (old_root, 0)
    } else {
        if proof_hashes.is_empty() {
            return Err(SigstoreError::UnexpectedError(
                "Merkle consistency proof: insufficient proof hashes".into(),
            ));
        }
        (&proof_hashes[0][..], 1)
    };

    let expected_proof_len = start + inner + border;
    if proof_hashes.len() != expected_proof_len {
        return Err(SigstoreError::UnexpectedError(format!(
            "Merkle consistency proof: wrong proof size (got {}, expected {})",
            proof_hashes.len(),
            expected_proof_len
        )));
    }

    let proof = &proof_hashes[start..];
    let mask = ((old_size - 1) >> shift) as u64;

    // Verify the old root is correct by chaining to the right
    let hash1 = chain_inner_right(seed, &proof[..inner], mask);
    let hash1 = chain_border_right(&hash1, &proof[inner..]);
    if hash1 != old_root {
        return Err(SigstoreError::UnexpectedError(format!(
            "Merkle consistency proof: old root mismatch (expected {}, got {})",
            encode_hex(old_root),
            encode_hex(&hash1)
        )));
    }

    // Verify the new root is correct
    let hash2 = chain_inner(seed, &proof[..inner], mask);
    let hash2 = chain_border_right(&hash2, &proof[inner..]);
    if hash2 != new_root {
        return Err(SigstoreError::UnexpectedError(format!(
            "Merkle consistency proof: new root mismatch (expected {}, got {})",
            encode_hex(new_root),
            encode_hex(&hash2)
        )));
    }

    Ok(())
}

/// Decompose an inclusion proof into inner and border components.
///
/// Returns (inner, border) where:
/// - inner: number of hashes along the path to the leaf
/// - border: number of hashes along the right border of the tree
fn decomp_inclusion_proof(index: u64, tree_size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, tree_size);
    let border = ((index >> inner).count_ones()) as usize;
    (inner, border)
}

/// Calculate the size of the inner proof component.
fn inner_proof_size(index: u64, tree_size: u64) -> usize {
    64 - ((index ^ (tree_size - 1)).leading_zeros() as usize)
}

/// Chain inner hashes for consistency proof verification.
///
/// Computes a subtree hash for a node on or below the tree's right border.
/// This is used when verifying the new tree root.
fn chain_inner(seed: &[u8], proof_hashes: &[Vec<u8>], index: u64) -> Vec<u8> {
    let mut current = seed.to_vec();
    for (i, hash) in proof_hashes.iter().enumerate() {
        let (left, right) = if ((index >> i) & 1) == 0 {
            (&current[..], &hash[..])
        } else {
            (&hash[..], &current[..])
        };
        current = node_hash(left, right);
    }
    current
}

/// Chain inner hashes to the right for consistency proof verification.
///
/// Computes a subtree hash like chain_inner, but only takes hashes to the left
/// from the path into consideration. This computes the hash of an earlier version
/// of the subtree and is used when verifying the old tree root.
fn chain_inner_right(seed: &[u8], proof_hashes: &[Vec<u8>], index: u64) -> Vec<u8> {
    let mut current = seed.to_vec();
    for (i, hash) in proof_hashes.iter().enumerate() {
        if ((index >> i) & 1) == 1 {
            current = node_hash(hash, &current);
        }
        // If bit is 0, we're on the right edge, so we don't hash
    }
    current
}

/// Chain border hashes to the right.
///
/// Chains proof hashes along tree borders. This differs from inner chaining
/// because the proof contains only left-side subtree hashes.
fn chain_border_right(seed: &[u8], proof_hashes: &[Vec<u8>]) -> Vec<u8> {
    let mut current = seed.to_vec();
    for hash in proof_hashes {
        current = node_hash(hash, &current);
    }
    current
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("computed root hash does not match")
        );
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

    #[test]
    fn test_verify_consistency_same_size() {
        // When sizes are equal, roots must match and proof must be empty
        let root = vec![0u8; 32];

        // Same size, same root, empty proof - should succeed
        let result = verify_consistency(5, 5, &[], &root, &root);
        assert!(result.is_ok());

        // Same size, different roots - should fail
        let different_root = vec![1u8; 32];
        let result = verify_consistency(5, 5, &[], &root, &different_root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("roots must match"));

        // Same size, non-empty proof - should fail
        let proof = vec![vec![2u8; 32]];
        let result = verify_consistency(5, 5, &proof, &root, &root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("proof must be empty"));
    }

    #[test]
    fn test_verify_consistency_empty_old_tree() {
        // When old tree is empty, proof must be empty
        let old_root = vec![0u8; 32];
        let new_root = vec![1u8; 32];

        // Empty old tree, empty proof - should succeed
        let result = verify_consistency(0, 5, &[], &old_root, &new_root);
        assert!(result.is_ok());

        // Empty old tree, non-empty proof - should fail
        let proof = vec![vec![2u8; 32]];
        let result = verify_consistency(0, 5, &proof, &old_root, &new_root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("proof must be empty"));
    }

    #[test]
    fn test_verify_consistency_tree_cannot_shrink() {
        // Tree cannot shrink: new_size < old_size should fail
        let old_root = vec![0u8; 32];
        let new_root = vec![1u8; 32];

        let result = verify_consistency(10, 5, &[], &old_root, &new_root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("new tree size"));
    }

    #[test]
    fn test_verify_consistency_empty_proof_non_trivial() {
        // For non-trivial consistency (old_size > 0 and new_size > old_size),
        // proof cannot be empty
        let old_root = vec![0u8; 32];
        let new_root = vec![1u8; 32];

        let result = verify_consistency(1, 2, &[], &old_root, &new_root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("proof cannot be empty"));
    }

    #[test]
    fn test_verify_consistency_simple_growth() {
        // Test consistency proof for tree growth from 1 to 2 leaves
        // Tree at size 1: just leaf0
        let leaf0 = leaf_hash(b"leaf 0");
        let root1 = leaf0.clone();

        // Tree at size 2: hash(leaf0 || leaf1)
        let leaf1 = leaf_hash(b"leaf 1");
        let root2 = node_hash(&leaf0, &leaf1);

        // Consistency proof from size 1 to 2 is just [leaf1]
        let proof = vec![leaf1.clone()];

        let result = verify_consistency(1, 2, &proof, &root1, &root2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_consistency_power_of_two() {
        // Test consistency for tree growing from size 2 (power of 2) to size 3
        let leaf0 = leaf_hash(b"leaf 0");
        let leaf1 = leaf_hash(b"leaf 1");
        let leaf2 = leaf_hash(b"leaf 2");

        // Root at size 2: hash(leaf0 || leaf1)
        let root2 = node_hash(&leaf0, &leaf1);

        // Root at size 3: hash(hash(leaf0 || leaf1) || leaf2)
        let root3 = node_hash(&root2, &leaf2);

        // Consistency proof from size 2 to 3: [leaf2]
        let proof = vec![leaf2.clone()];

        let result = verify_consistency(2, 3, &proof, &root2, &root3);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_consistency_wrong_proof() {
        // Test that consistency fails with wrong proof
        let leaf0 = leaf_hash(b"leaf 0");
        let leaf1 = leaf_hash(b"leaf 1");

        let root1 = leaf0.clone();
        let root2 = node_hash(&leaf0, &leaf1);

        // Wrong proof (random hash instead of leaf1)
        let wrong_proof = vec![vec![42u8; 32]];

        let result = verify_consistency(1, 2, &wrong_proof, &root1, &root2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("root mismatch"));
    }

    #[test]
    fn test_consistency_proof_helpers() {
        // Test that helper functions return reasonable values
        // These functions are used internally by verify_consistency

        // inner_proof_size should return non-negative values
        assert!(inner_proof_size(0, 1) < 64);
        assert!(inner_proof_size(1, 2) < 64);
        assert!(inner_proof_size(7, 8) < 64);

        // decomp_inclusion_proof should return reasonable values
        let (inner, border) = decomp_inclusion_proof(0, 1);
        assert!(inner < 64);
        assert!(border < 64);

        let (inner, border) = decomp_inclusion_proof(3, 8);
        assert!(inner < 64);
        assert!(border < 64);
    }

    #[test]
    fn test_chain_functions() {
        // Test chain_inner
        let seed = vec![1u8; 32];
        let proof = vec![vec![2u8; 32], vec![3u8; 32]];

        // Test with index 0 (binary: 00)
        let result = chain_inner(&seed, &proof, 0);
        assert_eq!(result.len(), 32);

        // Test chain_inner_right
        let result = chain_inner_right(&seed, &proof, 3);  // binary: 11
        assert_eq!(result.len(), 32);

        // Test chain_border_right
        let result = chain_border_right(&seed, &proof);
        assert_eq!(result.len(), 32);

        // Verify chain_border_right chains all hashes from left
        let expected = node_hash(&proof[0], &seed);
        let expected = node_hash(&proof[1], &expected);
        assert_eq!(result, expected);
    }

    // ========================================================================
    // Comprehensive test vectors from RFC 6962 / transparency-dev
    // These test vectors are from the sigstore-rs patch 285 which comes from
    // the transparency-dev Merkle implementation test suite.
    // ========================================================================

    /// Test data: leaf values to build the tree
    const LEAVES: &[&[u8]] = &[
        &[],                                                   // Empty leaf
        &[0x00],                                               // Single byte
        &[0x10],                                               // Another single byte
        &[0x20, 0x21],                                         // Two bytes
        &[0x30, 0x31],                                         // Two bytes
        &[0x40, 0x41, 0x42, 0x43],                            // Four bytes
        &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],   // Eight bytes
        &[0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,    // Sixteen bytes
          0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f],
    ];

    /// Pre-computed root hashes for trees of size 1-8
    /// These are the expected root hashes when building a tree with LEAVES[0..n]
    const ROOTS: [[u8; 32]; 8] = [
        // Root for tree with 1 leaf (LEAVES[0])
        [0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6,
         0xbb, 0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
         0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d],
        // Root for tree with 2 leaves
        [0xfa, 0xc5, 0x42, 0x03, 0xe7, 0xcc, 0x69, 0x6c, 0xf0, 0xdf, 0xcb, 0x42,
         0xc9, 0x2a, 0x1d, 0x9d, 0xba, 0xf7, 0x0a, 0xd9, 0xe6, 0x21, 0xf4, 0xbd,
         0x8d, 0x98, 0x66, 0x2f, 0x00, 0xe3, 0xc1, 0x25],
        // Root for tree with 3 leaves
        [0xae, 0xb6, 0xbc, 0xfe, 0x27, 0x4b, 0x70, 0xa1, 0x4f, 0xb0, 0x67, 0xa5,
         0xe5, 0x57, 0x82, 0x64, 0xdb, 0x0f, 0xa9, 0xb5, 0x1a, 0xf5, 0xe0, 0xba,
         0x15, 0x91, 0x58, 0xf3, 0x29, 0xe0, 0x6e, 0x77],
        // Root for tree with 4 leaves
        [0xd3, 0x7e, 0xe4, 0x18, 0x97, 0x6d, 0xd9, 0x57, 0x53, 0xc1, 0xc7, 0x38,
         0x62, 0xb9, 0x39, 0x8f, 0xa2, 0xa2, 0xcf, 0x9b, 0x4f, 0xf0, 0xfd, 0xfe,
         0x8b, 0x30, 0xcd, 0x95, 0x20, 0x96, 0x14, 0xb7],
        // Root for tree with 5 leaves
        [0x4e, 0x3b, 0xbb, 0x1f, 0x7b, 0x47, 0x8d, 0xcf, 0xe7, 0x1f, 0xb6, 0x31,
         0x63, 0x15, 0x19, 0xa3, 0xbc, 0xa1, 0x2c, 0x9a, 0xef, 0xca, 0x16, 0x12,
         0xbf, 0xce, 0x4c, 0x13, 0xa8, 0x62, 0x64, 0xd4],
        // Root for tree with 6 leaves
        [0x76, 0xe6, 0x7d, 0xad, 0xbc, 0xdf, 0x1e, 0x10, 0xe1, 0xb7, 0x4d, 0xdc,
         0x60, 0x8a, 0xbd, 0x2f, 0x98, 0xdf, 0xb1, 0x6f, 0xbc, 0xe7, 0x52, 0x77,
         0xb5, 0x23, 0x2a, 0x12, 0x7f, 0x20, 0x87, 0xef],
        // Root for tree with 7 leaves
        [0xdd, 0xb8, 0x9b, 0xe4, 0x03, 0x80, 0x9e, 0x32, 0x57, 0x50, 0xd3, 0xd2,
         0x63, 0xcd, 0x78, 0x92, 0x9c, 0x29, 0x42, 0xb7, 0x94, 0x2a, 0x34, 0xb7,
         0x7e, 0x12, 0x2c, 0x95, 0x94, 0xa7, 0x4c, 0x8c],
        // Root for tree with 8 leaves
        [0x5d, 0xc9, 0xda, 0x79, 0xa7, 0x06, 0x59, 0xa9, 0xad, 0x55, 0x9c, 0xb7,
         0x01, 0xde, 0xd9, 0xa2, 0xab, 0x9d, 0x82, 0x3a, 0xad, 0x2f, 0x49, 0x60,
         0xcf, 0xe3, 0x70, 0xef, 0xf4, 0x60, 0x43, 0x28],
    ];

    #[test]
    fn test_verify_inclusion_with_test_vectors() {
        // Test vector 1: leaf 1 in tree of size 1 (no proof needed)
        let hash = leaf_hash(LEAVES[0]);
        let result = verify_inclusion(0, 1, &hash, &[], &ROOTS[0]);
        assert!(result.is_ok(), "Failed for leaf 0, size 1");

        // Test vector 2: leaf 1 in tree of size 8
        let hash = leaf_hash(LEAVES[0]);
        let proof = vec![
            vec![0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3,
                 0x0f, 0x8a, 0x30, 0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e,
                 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09, 0xcf, 0xc7],
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0x6b, 0x47, 0xaa, 0xf2, 0x9e, 0xe3, 0xc2, 0xaf, 0x9a, 0xf8, 0x89, 0xbc,
                 0x1f, 0xb9, 0x25, 0x4d, 0xab, 0xd3, 0x11, 0x77, 0xf1, 0x62, 0x32, 0xdd,
                 0x6a, 0xab, 0x03, 0x5c, 0xa3, 0x9b, 0xf6, 0xe4],
        ];
        let result = verify_inclusion(0, 8, &hash, &proof, &ROOTS[7]);
        assert!(result.is_ok(), "Failed for leaf 0, size 8");

        // Test vector 3: leaf 6 in tree of size 8
        let hash = leaf_hash(LEAVES[5]);
        let proof = vec![
            vec![0xbc, 0x1a, 0x06, 0x43, 0xb1, 0x2e, 0x4d, 0x2d, 0x7c, 0x77, 0x91, 0x8f,
                 0x44, 0xe0, 0xf4, 0xf7, 0x9a, 0x83, 0x8b, 0x6c, 0xf9, 0xec, 0x5b, 0x5c,
                 0x28, 0x3e, 0x1f, 0x4d, 0x88, 0x59, 0x9e, 0x6b],
            vec![0xca, 0x85, 0x4e, 0xa1, 0x28, 0xed, 0x05, 0x0b, 0x41, 0xb3, 0x5f, 0xfc,
                 0x1b, 0x87, 0xb8, 0xeb, 0x2b, 0xde, 0x46, 0x1e, 0x9e, 0x3b, 0x55, 0x96,
                 0xec, 0xe6, 0xb9, 0xd5, 0x97, 0x5a, 0x0a, 0xe0],
            vec![0xd3, 0x7e, 0xe4, 0x18, 0x97, 0x6d, 0xd9, 0x57, 0x53, 0xc1, 0xc7, 0x38,
                 0x62, 0xb9, 0x39, 0x8f, 0xa2, 0xa2, 0xcf, 0x9b, 0x4f, 0xf0, 0xfd, 0xfe,
                 0x8b, 0x30, 0xcd, 0x95, 0x20, 0x96, 0x14, 0xb7],
        ];
        let result = verify_inclusion(5, 8, &hash, &proof, &ROOTS[7]);
        assert!(result.is_ok(), "Failed for leaf 5, size 8");

        // Test vector 4: leaf 3 in tree of size 3
        let hash = leaf_hash(LEAVES[2]);
        let proof = vec![
            vec![0xfa, 0xc5, 0x42, 0x03, 0xe7, 0xcc, 0x69, 0x6c, 0xf0, 0xdf, 0xcb, 0x42,
                 0xc9, 0x2a, 0x1d, 0x9d, 0xba, 0xf7, 0x0a, 0xd9, 0xe6, 0x21, 0xf4, 0xbd,
                 0x8d, 0x98, 0x66, 0x2f, 0x00, 0xe3, 0xc1, 0x25],
        ];
        let result = verify_inclusion(2, 3, &hash, &proof, &ROOTS[2]);
        assert!(result.is_ok(), "Failed for leaf 2, size 3");

        // Test vector 5: leaf 2 in tree of size 5
        let hash = leaf_hash(LEAVES[1]);
        let proof = vec![
            vec![0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6,
                 0xbb, 0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
                 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d],
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0xbc, 0x1a, 0x06, 0x43, 0xb1, 0x2e, 0x4d, 0x2d, 0x7c, 0x77, 0x91, 0x8f,
                 0x44, 0xe0, 0xf4, 0xf7, 0x9a, 0x83, 0x8b, 0x6c, 0xf9, 0xec, 0x5b, 0x5c,
                 0x28, 0x3e, 0x1f, 0x4d, 0x88, 0x59, 0x9e, 0x6b],
        ];
        let result = verify_inclusion(1, 5, &hash, &proof, &ROOTS[4]);
        assert!(result.is_ok(), "Failed for leaf 1, size 5");
    }

    #[test]
    fn test_verify_consistency_with_test_vectors() {
        // Test vector 1: size 1 to 1 (same size, empty proof)
        let result = verify_consistency(1, 1, &[], &ROOTS[0], &ROOTS[0]);
        assert!(result.is_ok(), "Failed for size 1 to 1");

        // Test vector 2: size 1 to 8
        let proof = vec![
            vec![0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3,
                 0x0f, 0x8a, 0x30, 0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e,
                 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09, 0xcf, 0xc7],
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0x6b, 0x47, 0xaa, 0xf2, 0x9e, 0xe3, 0xc2, 0xaf, 0x9a, 0xf8, 0x89, 0xbc,
                 0x1f, 0xb9, 0x25, 0x4d, 0xab, 0xd3, 0x11, 0x77, 0xf1, 0x62, 0x32, 0xdd,
                 0x6a, 0xab, 0x03, 0x5c, 0xa3, 0x9b, 0xf6, 0xe4],
        ];
        let result = verify_consistency(1, 8, &proof, &ROOTS[0], &ROOTS[7]);
        assert!(result.is_ok(), "Failed for size 1 to 8");

        // Test vector 3: size 6 to 8
        let proof = vec![
            vec![0x0e, 0xbc, 0x5d, 0x34, 0x37, 0xfb, 0xe2, 0xdb, 0x15, 0x8b, 0x9f, 0x12,
                 0x6a, 0x1d, 0x11, 0x8e, 0x30, 0x81, 0x81, 0x03, 0x1d, 0x0a, 0x94, 0x9f,
                 0x8d, 0xed, 0xed, 0xeb, 0xc5, 0x58, 0xef, 0x6a],
            vec![0xca, 0x85, 0x4e, 0xa1, 0x28, 0xed, 0x05, 0x0b, 0x41, 0xb3, 0x5f, 0xfc,
                 0x1b, 0x87, 0xb8, 0xeb, 0x2b, 0xde, 0x46, 0x1e, 0x9e, 0x3b, 0x55, 0x96,
                 0xec, 0xe6, 0xb9, 0xd5, 0x97, 0x5a, 0x0a, 0xe0],
            vec![0xd3, 0x7e, 0xe4, 0x18, 0x97, 0x6d, 0xd9, 0x57, 0x53, 0xc1, 0xc7, 0x38,
                 0x62, 0xb9, 0x39, 0x8f, 0xa2, 0xa2, 0xcf, 0x9b, 0x4f, 0xf0, 0xfd, 0xfe,
                 0x8b, 0x30, 0xcd, 0x95, 0x20, 0x96, 0x14, 0xb7],
        ];
        let result = verify_consistency(6, 8, &proof, &ROOTS[5], &ROOTS[7]);
        assert!(result.is_ok(), "Failed for size 6 to 8");

        // Test vector 4: size 2 to 5
        let proof = vec![
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0xbc, 0x1a, 0x06, 0x43, 0xb1, 0x2e, 0x4d, 0x2d, 0x7c, 0x77, 0x91, 0x8f,
                 0x44, 0xe0, 0xf4, 0xf7, 0x9a, 0x83, 0x8b, 0x6c, 0xf9, 0xec, 0x5b, 0x5c,
                 0x28, 0x3e, 0x1f, 0x4d, 0x88, 0x59, 0x9e, 0x6b],
        ];
        let result = verify_consistency(2, 5, &proof, &ROOTS[1], &ROOTS[4]);
        assert!(result.is_ok(), "Failed for size 2 to 5");

        // Test vector 5: size 6 to 7
        let proof = vec![
            vec![0x0e, 0xbc, 0x5d, 0x34, 0x37, 0xfb, 0xe2, 0xdb, 0x15, 0x8b, 0x9f, 0x12,
                 0x6a, 0x1d, 0x11, 0x8e, 0x30, 0x81, 0x81, 0x03, 0x1d, 0x0a, 0x94, 0x9f,
                 0x8d, 0xed, 0xed, 0xeb, 0xc5, 0x58, 0xef, 0x6a],
            vec![0xb0, 0x86, 0x93, 0xec, 0x2e, 0x72, 0x15, 0x97, 0x13, 0x06, 0x41, 0xe8,
                 0x21, 0x1e, 0x7e, 0xed, 0xcc, 0xb4, 0xc2, 0x64, 0x13, 0x96, 0x3e, 0xee,
                 0x6c, 0x1e, 0x2e, 0xd1, 0x6f, 0xfb, 0x1a, 0x5f],
            vec![0xd3, 0x7e, 0xe4, 0x18, 0x97, 0x6d, 0xd9, 0x57, 0x53, 0xc1, 0xc7, 0x38,
                 0x62, 0xb9, 0x39, 0x8f, 0xa2, 0xa2, 0xcf, 0x9b, 0x4f, 0xf0, 0xfd, 0xfe,
                 0x8b, 0x30, 0xcd, 0x95, 0x20, 0x96, 0x14, 0xb7],
        ];
        let result = verify_consistency(6, 7, &proof, &ROOTS[5], &ROOTS[6]);
        assert!(result.is_ok(), "Failed for size 6 to 7");
    }

    #[test]
    fn test_inclusion_proof_tamper_detection() {
        // Verify that tampering with inclusion proofs is detected
        let hash = leaf_hash(LEAVES[0]);

        // Correct proof for leaf 0, size 8
        let mut proof = vec![
            vec![0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3,
                 0x0f, 0x8a, 0x30, 0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e,
                 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09, 0xcf, 0xc7],
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0x6b, 0x47, 0xaa, 0xf2, 0x9e, 0xe3, 0xc2, 0xaf, 0x9a, 0xf8, 0x89, 0xbc,
                 0x1f, 0xb9, 0x25, 0x4d, 0xab, 0xd3, 0x11, 0x77, 0xf1, 0x62, 0x32, 0xdd,
                 0x6a, 0xab, 0x03, 0x5c, 0xa3, 0x9b, 0xf6, 0xe4],
        ];

        // Correct proof should succeed
        let result = verify_inclusion(0, 8, &hash, &proof, &ROOTS[7]);
        assert!(result.is_ok(), "Original proof should succeed");

        // Tamper with first proof hash - should fail
        proof[0][0] ^= 0x01;
        let result = verify_inclusion(0, 8, &hash, &proof, &ROOTS[7]);
        assert!(result.is_err(), "Tampered proof should fail");

        // Restore and tamper with wrong index - should fail
        proof[0][0] ^= 0x01;
        let result = verify_inclusion(1, 8, &hash, &proof, &ROOTS[7]);
        assert!(result.is_err(), "Wrong index should fail");

        // Wrong tree size should fail
        let result = verify_inclusion(0, 4, &hash, &proof, &ROOTS[7]);
        assert!(result.is_err(), "Wrong tree size should fail");

        // Wrong root should fail
        let result = verify_inclusion(0, 8, &hash, &proof, &ROOTS[6]);
        assert!(result.is_err(), "Wrong root should fail");
    }

    #[test]
    fn test_consistency_proof_tamper_detection() {
        // Verify that tampering with consistency proofs is detected
        let mut proof = vec![
            vec![0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3,
                 0x0f, 0x8a, 0x30, 0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e,
                 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09, 0xcf, 0xc7],
            vec![0x5f, 0x08, 0x3f, 0x0a, 0x1a, 0x33, 0xca, 0x07, 0x6a, 0x95, 0x27, 0x98,
                 0x32, 0x58, 0x0d, 0xb3, 0xe0, 0xef, 0x45, 0x84, 0xbd, 0xff, 0x1f, 0x54,
                 0xc8, 0xa3, 0x60, 0xf5, 0x0d, 0xe3, 0x03, 0x1e],
            vec![0x6b, 0x47, 0xaa, 0xf2, 0x9e, 0xe3, 0xc2, 0xaf, 0x9a, 0xf8, 0x89, 0xbc,
                 0x1f, 0xb9, 0x25, 0x4d, 0xab, 0xd3, 0x11, 0x77, 0xf1, 0x62, 0x32, 0xdd,
                 0x6a, 0xab, 0x03, 0x5c, 0xa3, 0x9b, 0xf6, 0xe4],
        ];

        // Correct proof (size 1 to 8) should succeed
        let result = verify_consistency(1, 8, &proof, &ROOTS[0], &ROOTS[7]);
        assert!(result.is_ok(), "Original consistency proof should succeed");

        // Tamper with proof hash - should fail
        proof[0][0] ^= 0x01;
        let result = verify_consistency(1, 8, &proof, &ROOTS[0], &ROOTS[7]);
        assert!(result.is_err(), "Tampered consistency proof should fail");

        // Restore and use wrong old root - should fail
        proof[0][0] ^= 0x01;
        let result = verify_consistency(1, 8, &proof, &ROOTS[1], &ROOTS[7]);
        assert!(result.is_err(), "Wrong old root should fail");

        // Wrong new root should fail
        let result = verify_consistency(1, 8, &proof, &ROOTS[0], &ROOTS[6]);
        assert!(result.is_err(), "Wrong new root should fail");

        // Wrong tree sizes should fail
        let result = verify_consistency(2, 8, &proof, &ROOTS[0], &ROOTS[7]);
        assert!(result.is_err(), "Wrong old size should fail");

        // Wrong new size with wrong root should fail
        let result = verify_consistency(1, 6, &proof, &ROOTS[0], &ROOTS[5]);
        assert!(result.is_err(), "Wrong new size should fail");
    }
}
