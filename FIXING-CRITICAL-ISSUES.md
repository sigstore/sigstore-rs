# Fixing Critical Security Issues in sigstore-rs

This document provides a detailed implementation plan for fixing two critical security issues identified in the codebase.

---

## Issue 1: Missing Merkle Inclusion Proof and SET Verification

### Background

**Location**: `src/bundle/verify/verifier.rs:164, 168`

**Current State**: Two critical verification steps are commented out as TODOs:
```rust
// 5) Verify the inclusion proof supplied by Rekor for this artifact,
//    if we're doing online verification.
// TODO(tnytown): Merkle inclusion; sigstore-rs#285

// 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
//    artifact.
// TODO(tnytown) SET verification; sigstore-rs#285
```

### What These Verifications Do

1. **Merkle Inclusion Proof**: Proves that an entry exists in the Rekor transparency log at a specific index without revealing the entire log. Uses a Merkle tree to cryptographically verify the entry is part of the tree.

2. **Signed Entry Timestamp (SET)**: A signature from Rekor over the log entry's metadata (body, integratedTime, logIndex, logID) that proves Rekor witnessed the entry at a specific time.

### Data Structures Available

The Rust code already has the necessary data structures:
```rust
// From src/rekor/models/log_entry.rs
pub struct Verification {
    pub inclusion_proof: Option<InclusionProof>,
    pub signed_entry_timestamp: String, // base64-encoded signature
}

pub struct InclusionProof {
    pub hashes: Vec<String>,      // hex-encoded hashes for the proof path
    pub log_index: i64,            // index in the log
    pub root_hash: String,         // hex-encoded root hash
    pub tree_size: TreeSize,       // size of the tree
    pub checkpoint: String,        // signed checkpoint
}
```

### Implementation Plan for Merkle Inclusion Proof

Based on the Go implementation in `rekor/pkg/verify/verify.go:141-170`:

```rust
// Add to src/bundle/verify/verifier.rs or create new module

use sha2::{Digest, Sha256};

fn verify_inclusion_proof(
    log_entry: &TransparencyLogEntry,
    canonicalized_body: &[u8],
) -> Result<()> {
    let inclusion_proof = log_entry
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| SigstoreError::VerificationError("inclusion proof not provided".into()))?;

    // 1. Decode all hashes from the proof
    let hashes: Result<Vec<Vec<u8>>> = inclusion_proof
        .hashes
        .iter()
        .map(|h| hex::decode(h).map_err(|e| SigstoreError::VerificationError(format!("invalid hash in inclusion proof: {}", e))))
        .collect();
    let hashes = hashes?;

    // 2. Decode root hash
    let root_hash = hex::decode(&inclusion_proof.root_hash)
        .map_err(|e| SigstoreError::VerificationError(format!("invalid root hash: {}", e)))?;

    // 3. Compute leaf hash using RFC 6962 format
    // Leaf hash = SHA256(0x00 || leaf_data)
    let leaf_hash = rfc6962_leaf_hash(canonicalized_body);

    // 4. Verify the inclusion proof
    verify_merkle_inclusion(
        inclusion_proof.log_index as u64,
        inclusion_proof.tree_size as u64,
        &leaf_hash,
        &hashes,
        &root_hash,
    )?;

    Ok(())
}

/// Compute RFC 6962 leaf hash: SHA256(0x00 || data)
fn rfc6962_leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]); // Leaf prefix
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Verify Merkle tree inclusion proof
fn verify_merkle_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof_hashes: &[Vec<u8>],
    root_hash: &[u8],
) -> Result<()> {
    if leaf_index >= tree_size {
        return Err(SigstoreError::VerificationError(
            "leaf index >= tree size".into(),
        ));
    }

    // Compute the root hash from the leaf and proof
    let computed_root = compute_root_from_proof(leaf_index, tree_size, leaf_hash, proof_hashes);

    // Compare with expected root hash
    if computed_root != root_hash {
        return Err(SigstoreError::VerificationError(
            "inclusion proof verification failed: root hash mismatch".into(),
        ));
    }

    Ok(())
}

/// Compute root hash from leaf and inclusion proof
/// Algorithm from RFC 6962 Section 2.1.1
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
        // based on the index bit
        if index % 2 == 1 || index == last_node {
            // Sibling is on the left
            current_hash = rfc6962_node_hash(sibling, &current_hash);
        } else {
            // Sibling is on the right
            current_hash = rfc6962_node_hash(&current_hash, sibling);
        }

        index /= 2;
        last_node /= 2;
    }

    current_hash
}

/// Compute RFC 6962 node hash: SHA256(0x01 || left || right)
fn rfc6962_node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]); // Node prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}
```

### Implementation Plan for SET Verification

Based on the Go implementation in `rekor/pkg/verify/verify.go:172-211`:

```rust
// Add to src/bundle/verify/verifier.rs

use serde_json::json;

fn verify_signed_entry_timestamp(
    log_entry: &TransparencyLogEntry,
    rekor_public_key: &CosignVerificationKey,
) -> Result<()> {
    // 1. Get the SET from inclusion_promise
    let set_signature = log_entry
        .inclusion_promise
        .as_ref()
        .and_then(|p| Some(&p.signed_entry_timestamp))
        .ok_or_else(|| SigstoreError::VerificationError("signed entry timestamp not provided".into()))?;

    // 2. Reconstruct the payload that was signed
    // The SET is a signature over: {body, integratedTime, logIndex, logID}
    let bundle_payload = json!({
        "body": log_entry.canonicalized_body,
        "integratedTime": log_entry.integrated_time,
        "logIndex": log_entry.log_index,
        "logID": log_entry.log_id.as_ref().map(|id| hex::encode(&id.key_id)),
    });

    // 3. Canonicalize JSON (must be RFC 8785 canonical JSON)
    let payload_json = serde_json::to_vec(&bundle_payload)?;
    let canonicalized = canonicalize_json(&payload_json)?;

    // 4. Verify the signature using Rekor's public key
    rekor_public_key.verify_signature(
        Signature::Raw(set_signature),
        &canonicalized,
    )?;

    Ok(())
}

/// Canonicalize JSON using RFC 8785
/// Consider using a crate like `jcs` or `olpc-cjson`
fn canonicalize_json(json_bytes: &[u8]) -> Result<Vec<u8>> {
    // Use olpc-cjson crate which is already in dependencies
    use olpc_cjson::CanonicalFormatter;

    let value: serde_json::Value = serde_json::from_slice(json_bytes)?;
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}
```

### Integration into Verifier

Update `src/bundle/verify/verifier.rs` around line 164:

```rust
// 5) Verify the inclusion proof supplied by Rekor for this artifact
if materials.tlog_entry.inclusion_proof.is_some() {
    verify_inclusion_proof(&materials.tlog_entry, &materials.canonicalized_body)?;
    debug!("inclusion proof verified successfully");
}

// 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor
if let Some(rekor_key) = rekor_public_key {
    verify_signed_entry_timestamp(&materials.tlog_entry, rekor_key)?;
    debug!("signed entry timestamp verified successfully");
}
```

### Dependencies Needed

Check if these are already in `Cargo.toml`:
- `hex` - already present
- `sha2` - already present
- `serde_json` - already present
- `olpc-cjson` - already present ✓

No new dependencies needed!

### Test Cases from Other Implementations

**From Go implementation** (`sigstore-go/pkg/verify/tlog_test.go`):
```go
// Test vectors with known good inclusion proofs
```

**From Python implementation** (`sigstore-python/test/unit/internal/rekor/`):
```python
# Test cases for merkle tree verification
```

### Recommended Testing Strategy

1. **Unit tests** for the Merkle tree functions:
   - Test `rfc6962_leaf_hash` with known inputs/outputs
   - Test `rfc6962_node_hash` with known inputs/outputs
   - Test `compute_root_from_proof` with small trees

2. **Integration tests** using real Rekor data:
   - Fetch a real log entry from Rekor
   - Verify the inclusion proof
   - Verify the SET

3. **Test vectors** from Go/Python:
   - Port test cases from sigstore-go
   - Port test cases from sigstore-python

---

## Issue 2: Ed25519 Prehash Verification Panic

### Background

**Location**: `src/crypto/verification_key.rs:391`

**Current State**:
```rust
CosignVerificationKey::ED25519(_) => {
    unimplemented!("Ed25519 doesn't implement verify_prehash")
}
```

### Why This Is a Problem

1. **Will panic at runtime** if Ed25519 keys are used with prehashed verification
2. **Violates library safety** - library code should never panic on valid inputs
3. **Security concern** - could be used for DoS

### Analysis: When is verify_prehash Called?

Looking at `src/bundle/verify/verifier.rs:149`:
```rust
// Regular verification: verify against prehashed input digest
signing_key.verify_prehash(Signature::Raw(&materials.signature), &input_digest)
```

This is called for **non-DSSE bundles** where the signature is over a pre-computed digest.

### Ed25519 and Prehashing

**The core issue**: Ed25519 (RFC 8032) **does not support** prehashed message signing by design. The Ed25519 signature algorithm includes its own internal hashing step (SHA-512) as part of the signature generation.

From RFC 8032:
> Ed25519 is a signature scheme that uses EdDSA with SHA-512 and Curve25519.
> The signature is computed over the message itself, not a hash of the message.

There **is** a variant called **Ed25519ph** (pre-hash) that supports signing pre-hashed messages, but it's a different algorithm with different signatures.

### Solution Options

#### Option 1: Return Proper Error (Recommended)

```rust
CosignVerificationKey::ED25519(_) => {
    Err(SigstoreError::UnsupportedAlgorithm(
        "Ed25519 does not support prehashed message verification. \
         Ed25519 signatures must be verified against the original message, \
         not a pre-computed digest.".into()
    ))
}
```

**Pros**:
- Correct behavior
- Clear error message
- No panics
- Follows Ed25519 spec

**Cons**:
- Won't work with Ed25519 + non-DSSE bundles (but this combination shouldn't exist)

#### Option 2: Hash the Input and Verify

This is **INCORRECT** and would break security, but documenting for completeness:

```rust
// ❌ WRONG - DO NOT DO THIS
// This would verify a signature over hash(hash(message))
// which is NOT what Ed25519 produces
```

#### Option 3: Implement Ed25519ph Support

If Ed25519ph (pre-hash variant) is needed:

```rust
CosignVerificationKey::ED25519(inner) => {
    // Ed25519ph: hash = SHA-512(msg)
    // Then sign/verify the hash using Ed25519ph algorithm
    // This requires ed25519-dalek with ph feature
    Err(SigstoreError::UnsupportedAlgorithm(
        "Ed25519ph (pre-hash variant) is not yet implemented. \
         If you need this, please file an issue.".into()
    ))
}
```

### Recommended Implementation

**Step 1**: Add proper error type to `src/errors.rs`:
```rust
#[error("unsupported cryptographic algorithm: {0}")]
UnsupportedAlgorithm(String),
```

**Step 2**: Replace unimplemented! with proper error in `src/crypto/verification_key.rs:391`:
```rust
CosignVerificationKey::ED25519(_) => {
    Err(SigstoreError::UnsupportedAlgorithm(
        "Ed25519 does not support prehashed message verification. \
         Ed25519 signatures are computed over the full message, not a digest. \
         This combination (Ed25519 + prehashed verification) should not occur \
         in valid Sigstore bundles.".to_string()
    ))
}
```

**Step 3**: Add test to verify the error is returned:
```rust
#[test]
fn test_ed25519_prehash_returns_error() {
    let key = CosignVerificationKey::ED25519(/* test key */);
    let sig = /* test signature */;
    let digest = /* test digest */;

    let result = key.verify_prehash(Signature::Raw(&sig), &digest);

    assert!(matches!(
        result,
        Err(SigstoreError::UnsupportedAlgorithm(_))
    ));
}
```

**Step 4**: Document in rustdoc:
```rust
/// Verify the signature provided has been actually generated by the given key
/// when signing the provided prehashed message.
///
/// # Ed25519 Limitation
///
/// **Note**: Ed25519 keys do not support prehashed verification. If you attempt
/// to verify a prehashed message with an Ed25519 key, this will return an error.
/// Ed25519 signatures must be verified against the full original message using
/// [`verify_signature`] instead.
///
/// This limitation is by design in the Ed25519 specification (RFC 8032), which
/// includes internal hashing as part of the signature algorithm.
pub(crate) fn verify_prehash(&self, signature: Signature, msg: &[u8]) -> Result<()> {
    // ...
}
```

### Testing Strategy

1. **Negative test**: Verify Ed25519 + prehash returns error (not panic)
2. **Positive test**: Verify Ed25519 + full message still works
3. **Integration test**: Ensure real Ed25519 bundles verify correctly

### Follow-up Investigation

Check if any real-world Sigstore bundles use Ed25519 with prehashed verification:
- Search test data for Ed25519 bundles
- Check what verification path they take
- Confirm this code path is actually unused

If Ed25519 + prehash is needed, we need to implement Ed25519ph properly.

---

## Getting Test Cases from Other Implementations

### From sigstore-go

**Location**: `sigstore-go/pkg/verify/tlog_test.go`

```bash
# Copy test vectors
cd sigstore-rs
cp ../sigstore-go/pkg/verify/tlog_test.go tests/fixtures/

# Extract test cases and port to Rust
```

Key test cases to port:
1. `TestVerifyInclusion` - Merkle tree verification
2. `TestVerifySignedEntryTimestamp` - SET verification
3. `TestVerifyCheckpointSignature` - Checkpoint verification

### From sigstore-python

**Location**: `sigstore-python/test/unit/internal/rekor/`

```bash
# Copy test data
cd sigstore-rs
mkdir -p tests/fixtures/rekor
cp -r ../sigstore-python/test/unit/internal/rekor/*.py tests/fixtures/
```

### From Rekor itself

**Location**: `rekor/pkg/verify/verify_test.go`

This has the most comprehensive test cases including:
- Various tree sizes
- Edge cases (single node trees, etc.)
- Invalid proofs
- Malformed data

### Test Data Format

Create `tests/fixtures/merkle_test_vectors.json`:
```json
{
  "test_cases": [
    {
      "name": "valid_inclusion_proof",
      "leaf_hash": "abc123...",
      "tree_size": 100,
      "leaf_index": 42,
      "proof_hashes": ["hash1", "hash2", ...],
      "root_hash": "root...",
      "expected": "valid"
    },
    {
      "name": "invalid_root_hash",
      "leaf_hash": "abc123...",
      "tree_size": 100,
      "leaf_index": 42,
      "proof_hashes": ["hash1", "hash2", ...],
      "root_hash": "wrong_root...",
      "expected": "invalid"
    }
  ]
}
```

---

## Implementation Timeline

### Phase 1: Fix Ed25519 (Easy - 1 day)
- [ ] Add UnsupportedAlgorithm error type
- [ ] Replace unimplemented! with proper error
- [ ] Add rustdoc warnings
- [ ] Add negative test
- [ ] Submit PR

### Phase 2: Implement Merkle Inclusion (Medium - 2-3 days)
- [ ] Implement RFC 6962 hashing functions
- [ ] Implement Merkle tree verification
- [ ] Add unit tests
- [ ] Integrate into verifier
- [ ] Test with real data

### Phase 3: Implement SET Verification (Medium - 2-3 days)
- [ ] Implement JSON canonicalization helper
- [ ] Implement SET verification function
- [ ] Integrate into verifier
- [ ] Test with real data

### Phase 4: Integration & Testing (2 days)
- [ ] Port test cases from Go/Python
- [ ] Add integration tests
- [ ] Test with live Rekor data
- [ ] Update documentation
- [ ] Submit PR

**Total Estimated Time**: 7-9 days

---

## References

- RFC 6962 (Certificate Transparency): https://datatracker.ietf.org/doc/html/rfc6962
- RFC 8032 (Ed25519): https://datatracker.ietf.org/doc/html/rfc8032
- RFC 8785 (JSON Canonicalization): https://datatracker.ietf.org/doc/html/rfc8785
- Sigstore Bundle Spec: https://github.com/sigstore/protobuf-specs
- Rekor Verification: https://github.com/sigstore/rekor/blob/main/pkg/verify/verify.go
- Sigstore-Go: https://github.com/sigstore/sigstore-go
- Sigstore-Python: https://github.com/sigstore/sigstore-python
