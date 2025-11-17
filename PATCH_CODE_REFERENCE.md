# Patch Code Reference Guide

This document provides quick references to key code sections from the patches that need to be ported.

---

## Consistency Proof Verification Algorithm

### Location: patches/285.patch.txt (Lines ~136-195)

The `verify_consistency` function validates that a transparency log has grown consistently from one state to another.

```rust
// PSEUDO-CODE STRUCTURE (refer to patches/285.patch.txt for exact implementation)
fn verify_consistency(
    old_size: usize,
    new_size: usize,
    proof_hashes: &[O],        // Proof of consistency
    old_root: &O,              // Root at old_size
    new_root: &O,              // Root at new_size
) -> Result<(), MerkleProofError> {
    // Check tree can only grow (old_size <= new_size)
    if old_size > new_size {
        return Err(NewTreeSmaller { new: new_size, old: old_size });
    }
    
    // Same size: roots must match exactly
    if old_size == new_size {
        return Self::verify_match(old_root, new_root)?;
    }
    
    // If old_size is 0, must be empty root
    if old_size == 0 {
        return Self::verify_match(old_root, &Self::empty_root())?;
    }
    
    // Complex proof decomposition and chaining
    // References helper functions:
    // - decomp_inclusion_proof()
    // - chain_inner_right()
    // - chain_border_right()
    
    Ok(())
}
```

### Key Helper Functions Needed

```rust
// From Patch 285 - calculate how many "inner" and "border" proof hashes
fn decomp_inclusion_proof(index: usize, tree_size: usize) -> (usize, usize) {
    // Returns (inner_count, border_count)
    // Used to verify correct proof structure
}

// From Patch 285 - chain hashes along inner nodes
fn chain_inner(seed: &O, proof_hashes: &[O], index: usize) -> O {
    // Progressively hash up the tree
}

// From Patch 285 - chain hashes for rightmost path
fn chain_inner_right(seed: &O, proof_hashes: &[O], index: usize) -> O {
    // Special handling for right edge of tree
}

// From Patch 285 - finalize with border hashes
fn chain_border_right(seed: &O, proof_hashes: &[O]) -> O {
    // Final hashing with remaining proofs
}

// From Patch 285 - empty tree hash
fn empty_root() -> O {
    // Hash of empty/zero tree for initialization
}
```

### Test Cases to Port

```rust
#[test]
fn test_verify_consistency() {
    // Test case from patch 285, lines ~868-920
    // Verifies multiple tree growth scenarios
    // Examples:
    // - 0 → 1 (empty to single leaf)
    // - 1 → 4 (linear growth)
    // - 4 → 8 (power of two growth)
    // - 4 → 7 (unbalanced growth)
}

#[test]
fn test_consistency_valid() {
    // Additional scenarios with valid proofs
}

#[test]
fn test_consistency_invalid() {
    // Error cases: wrong roots, tree shrinking, etc.
}

#[test]
fn test_consistency_edge_cases() {
    // Boundary conditions and special cases
}
```

---

## Checkpoint Marshaling

### Location: patches/285.patch.txt (Lines ~1080-1450)

Checkpoints need to be serializable to/from strings for round-trip verification.

```rust
// CHECKPOINT SERIALIZATION FORMAT
// Example from Rekor v2:
// ```
// log2025-alpha1.rekor.sigstage.dev
// 736
// rs1YPY0ydAV0lxgfrq5pE4oRpUJwo3syeps5+eGUTDI=
// 
// — log2025-alpha1.rekor.sigstage.dev 8w1amdbj1mjNN674dHAkD92+QZoEgBC7o0mXYSTRluDjQrOPjrps3zQB9ut+ShLepyZPsWBDi5IB3yXyjgjQT6OG9A8=
// ```

// Methods to implement on checkpoint structures:

trait CheckpointMarshal {
    // Serialize checkpoint to standard format
    fn marshal(&self) -> String {
        // Format: "origin\ntree_size\nroot_hash_base64\nmetadata_lines...\n"
        // Return just the checkpoint portion (not signatures)
    }
    
    // Parse checkpoint from string
    fn unmarshal(s: &str) -> Result<Self> {
        // Inverse of marshal()
        // Handle optional metadata lines
    }
}
```

### Integration with Note Format

```rust
// Checkpoint is part of SignedNote which has two sections:

// Section 1: Checkpoint (what marshal() produces)
// ============================================
origin_line
tree_size_line
root_hash_line
[optional metadata lines]

// Section 2: Signatures (separate from checkpoint)
// ==============================================
— signer_name signature_base64
— witness_name signature_base64

// marshal() should produce ONLY section 1
// SignedNote parsing handles combining both sections
```

### Test Cases to Port

```rust
#[test]
fn test_checkpoint_marshal() {
    // Serialize checkpoint to string
    // Verify format matches expected structure
}

#[test]
fn test_checkpoint_unmarshal_valid() {
    // Parse valid checkpoint string
    // Verify all fields extracted correctly
}

#[test]
fn test_checkpoint_unmarshal_invalid() {
    // Error cases: malformed input, missing fields, etc.
}

#[test]
fn test_checkpoint_roundtrip() {
    // Marshal → Unmarshal → Marshal
    // Verify produces identical string
}

#[test]
fn test_checkpoint_with_metadata() {
    // Handle optional metadata lines in checkpoint
}
```

---

## LogEntry Consistency Verification Method

### Location: patches/285.patch.txt (Lines ~1850-1880)

Add convenience method to LogEntry for verifying consistency proofs.

```rust
// Implementation pattern to follow:

impl LogEntry {
    /// Verify the consistency proof for this log entry
    pub fn verify_consistency(
        &self,
        old_size: usize,
        old_root: &[u8],
        proof: &ConsistencyProof,
        rekor_key: &CosignVerificationKey,
    ) -> Result<(), SigstoreError> {
        // 1. Extract proof hashes from proof_hashes field
        let proof_hashes = hex_to_hash_outputs(&proof.hashes)?;
        
        // 2. Get new root from self (current log entry)
        let new_root = hex_to_hash_output(&self.root_hash)?;
        let new_size = self.tree_size as usize;
        
        // 3. Call merkle::verify_consistency()
        merkle::verify_consistency(
            old_size,
            new_size,
            &proof_hashes,
            old_root,
            &new_root,
        )?;
        
        // 4. Verify proof signature if present
        self.verify_consistency_signature(&proof, rekor_key)?;
        
        Ok(())
    }
}
```

### Usage in Examples

```rust
// From examples in patch 285:

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Fetch current log info
    let rekor_config = Configuration::default();
    let log_info = get_log_info(&rekor_config).await?;
    
    // Fetch proof between old and new tree state
    let proof = get_log_proof(
        &rekor_config,
        log_info.tree_size as _,
        Some(&args.old_size.to_string()),
        None,
    ).await?;
    
    // Verify consistency
    log_info.verify_consistency(
        args.old_size,
        &args.old_root,
        &proof,
        &rekor_key,
    )?;
    
    println!("Successfully verified consistency");
    Ok(())
}
```

---

## Merkle Proof Examples Structure

### Location: patches/285.patch.txt (Lines ~1810-1900)

Two example programs demonstrating merkle proof verification.

```rust
// INCLUSION PROOF EXAMPLE (examples/rekor/merkle_proofs/inclusion.rs)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse(); // log_index, rekor_key
    
    let rekor_config = Configuration::default();
    let log_entry = get_log_entry_by_index(&rekor_config, args.log_index).await?;
    
    // The LogEntry contains inclusion_proof with hashes and root
    // Verify the entry is in the tree
    log_entry.verify_inclusion(&rekor_key)?;
    
    println!("Successfully verified inclusion");
    Ok(())
}
```

```rust
// CONSISTENCY PROOF EXAMPLE (examples/rekor/merkle_proofs/consistency.rs)

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse(); // old_root, old_size, rekor_key
    
    let rekor_config = Configuration::default();
    
    // Get current log state
    let log_info = get_log_info(&rekor_config).await?;
    
    // Get proof of consistency between old_size and current size
    let proof = get_log_proof(
        &rekor_config,
        log_info.tree_size as _,
        Some(&args.old_size.to_string()),
        args.tree_id.as_deref(),
    ).await?;
    
    // Verify the two states are consistent
    log_info.verify_consistency(
        args.old_size,
        &args.old_root,
        &proof,
        &rekor_key,
    )?;
    
    println!("Successfully verified consistency");
    Ok(())
}
```

---

## Current Implementation Reference Points

### Existing Merkle Functions (for understanding)

Location: `/Users/wolfv/Programs/sigstore-rs/src/crypto/merkle.rs`

```rust
// Existing functions to understand the pattern:

pub fn leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // Leaf prefix
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // Node prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof_hashes: &[Vec<u8>],
    root_hash: &[u8],
) -> Result<()> {
    // Already implemented
}
```

### Existing Note Parsing (for reference)

Location: `/Users/wolfv/Programs/sigstore-rs/src/crypto/note.rs`

```rust
// Already implemented and working:

impl LogCheckpoint {
    pub fn from_text(text: &str) -> Result<Self, NoteError> {
        // Parses: origin\ntree_size\nroot_hash\nmetadata...
    }
}

impl SignedNote {
    pub fn from_text(text: &str) -> Result<Self, NoteError> {
        // Parses complete: checkpoint\n\nsignatures
    }
    
    pub fn verify_root_hash(&self, expected_root_hash: &[u8]) -> Result<(), NoteError> {
        // Already checks root hash matches
    }
}
```

---

## Error Handling Reference

### From Patch 285 - MerkleProofError Variants

```rust
// Reference: patches/285.patch.txt around line ~67-75

#[derive(Debug)]
pub enum MerkleProofError {
    MismatchedRoot { expected: String, got: String },
    IndexGtTreeSize,
    UnexpectedNonEmptyProof,
    UnexpectedEmptyProof,
    NewTreeSmaller { new: usize, old: usize },
    WrongProofSize { got: usize, want: usize },
    WrongEmptyTreeHash,
}
```

These should be integrated into existing error handling or new specific error type.

---

## Integration Points

### Where consistency proof would be used

```
1. LogEntry::verify_consistency() method
   └─ calls merkle::verify_consistency()
   
2. LogInfo::verify_consistency() method  
   └─ calls merkle::verify_consistency()
   
3. Bundle verification flow
   └─ Potentially used for advanced verification scenarios
```

### Where checkpoint marshaling is needed

```
1. Round-trip testing (marshal → unmarshal → marshal)
2. Signature verification (need to reconstruct signed bytes)
3. Checkpoint comparison operations
4. Fixture-based testing
```

---

## Quick Lookup: Patch Line Numbers

| Feature | Patch 285 Lines | Patch 354 Lines | Patch 315 Lines |
|---------|-----------------|-----------------|-----------------|
| Consistency proof | 136-195 | - | - |
| Checkpoint marshal | 1080-1230 | - | - |
| Checkpoint parsing | 1300-1450 | - | - |
| Inclusion example | 1862-1900 | - | - |
| Consistency example | 1810-1860 | - | - |
| LogEntry methods | 1698-1880 | - | - |
| SCT validation | - | 21-410 | - |
| Keyring impl | - | 186-365 | - |
| Transparency.rs | - | 380-810 | - |
| Bundle verify | - | 127-295 | - |
| Full signing | - | - | 656-986 |
| Verify impl | - | - | (various) |

