# Nonce Generation Tests

**Added:** 2025-11-10
**File:** [src/crypto/tsa.rs](src/crypto/tsa.rs)

## Summary

Refactored the TSA nonce generation into a dedicated helper function `generate_positive_nonce_bytes()` and added comprehensive tests to catch the common DER encoding mistakes.

## Changes

### 1. Extracted Helper Function

Created `generate_positive_nonce_bytes()` function at [src/crypto/tsa.rs:37-52](src/crypto/tsa.rs#L37-L52):

```rust
/// Generates a random nonce suitable for RFC 3161 timestamp requests.
///
/// The nonce is generated as 8 random bytes and encoded as a positive INTEGER
/// according to DER rules:
/// - If the high bit is clear (0x00-0x7F), no padding is needed
/// - If the high bit is set (0x80-0xFF), prepend 0x00 to indicate positive
///
/// This ensures the nonce is always interpreted as a positive integer,
/// which is required by RFC 3161.
fn generate_positive_nonce_bytes() -> Vec<u8>
```

### 2. Refactored Usage

Simplified the nonce generation in `request_timestamp()` at [src/crypto/tsa.rs:137-142](src/crypto/tsa.rs#L137-L142):

**Before (19 lines):**
```rust
// Generate a random nonce for replay protection
// IMPORTANT: The nonce must be a positive INTEGER in DER encoding.
// Per DER rules, we should only prepend 0x00 if the high bit is set.
use rand::Rng;
let mut rng = rand::thread_rng();
let nonce_random: [u8; 8] = rng.r#gen();

// Only prepend 0x00 if the high bit is set (to avoid negative number)
let nonce_bytes = if nonce_random[0] & 0x80 != 0 {
    // High bit set, need 0x00 padding
    let mut padded = vec![0x00];
    padded.extend_from_slice(&nonce_random);
    padded
} else {
    // High bit clear, no padding needed
    nonce_random.to_vec()
};

let nonce = x509_cert::der::asn1::Int::new(&nonce_bytes).map_err(|e| {
    SigstoreError::UnexpectedError(format!("failed to create nonce: {}", e))
})?;
```

**After (6 lines):**
```rust
// Generate a random nonce for replay protection
// The nonce must be a positive INTEGER in DER encoding
let nonce_bytes = generate_positive_nonce_bytes();
let nonce = x509_cert::der::asn1::Int::new(&nonce_bytes).map_err(|e| {
    SigstoreError::UnexpectedError(format!("failed to create nonce: {}", e))
})?;
```

### 3. Added Comprehensive Tests

Added 5 test functions at [src/crypto/tsa.rs:228-391](src/crypto/tsa.rs#L228-L391):

#### Test 1: `test_generate_positive_nonce_bytes_length`
- Verifies nonce is always 8-9 bytes
- Runs 1000 iterations to catch edge cases

#### Test 2: `test_generate_positive_nonce_bytes_always_positive`
- **Critical test**: Verifies nonce is ALWAYS positive
- Checks that padding is added exactly when needed
- Tests the core bug we fixed

#### Test 3: `test_generate_positive_nonce_bytes_canonical_encoding`
- Verifies canonical DER encoding rules:
  - No unnecessary leading zeros
  - Only pad with 0x00 when high bit is set
- Ensures compliance with DER specification

#### Test 4: `test_nonce_with_high_bit_set`
- Manually tests high-bit case (0x80-0xFF)
- Demonstrates the difference between buggy and fixed encoding
- Shows that without padding, the value is interpreted as negative

#### Test 5: `test_nonce_with_high_bit_clear`
- Manually tests clear-bit case (0x00-0x7F)
- Verifies no padding is added unnecessarily
- Checks exact DER encoding format

## Test Results

```
running 6 tests
test crypto::tsa::tests::test_timestamp_request ... ignored
test crypto::tsa::tests::test_nonce_with_high_bit_set ... ok
test crypto::tsa::tests::test_nonce_with_high_bit_clear ... ok
test crypto::tsa::tests::test_generate_positive_nonce_bytes_length ... ok
test crypto::tsa::tests::test_generate_positive_nonce_bytes_canonical_encoding ... ok
test crypto::tsa::tests::test_generate_positive_nonce_bytes_always_positive ... ok

test result: ok. 5 passed; 0 failed; 1 ignored
```

## Why This Matters

### Common Mistake
Multiple independent RFC 3161 implementations have made this mistake:
1. **Python's rfc3161_client** - Fixed in Oct 2024 (see patch in conversation)
2. **Our sigstore-rs** - Fixed in Nov 2025 (TIMESTAMP_FIX_SUMMARY.md)
3. **Third implementation found** - Still has the bug!

### The Bug Pattern
```rust
// ❌ WRONG: Can create negative nonces
let random: [u8; 8] = rng.gen();
let nonce = Int::new(&random)?;  // BUG: Negative when random[0] >= 0x80
```

### The Fix Pattern
```rust
// ✅ CORRECT: Always positive
let random: [u8; 8] = rng.gen();
let bytes = if random[0] & 0x80 != 0 {
    [vec![0x00], random.to_vec()].concat()
} else {
    random.to_vec()
};
let nonce = Int::new(&bytes)?;
```

## Benefits

1. **Reusability**: Helper function can be used anywhere nonces are needed
2. **Testability**: Logic is isolated and thoroughly tested
3. **Documentation**: Clear explanation of DER encoding rules
4. **Regression Prevention**: Tests catch if someone reverts to buggy implementation
5. **Learning Tool**: Tests demonstrate correct vs incorrect encoding

## Related Files

- [TIMESTAMP_FIX_SUMMARY.md](TIMESTAMP_FIX_SUMMARY.md) - Original bug fix documentation
- [src/crypto/tsa.rs](src/crypto/tsa.rs) - Implementation and tests
- Python rfc3161_client patch - Shows same fix in another implementation

## DER INTEGER Encoding Rules (Reference)

For positive integers:
- **High bit clear (0x00-0x7F)**: Use as-is, no padding
  - Example: `0x3A` → `02 01 3A` (3 bytes DER)
- **High bit set (0x80-0xFF)**: Prepend 0x00
  - Example: `0x8F` → `02 02 00 8F` (4 bytes DER)

For negative integers (not used for nonces):
- Use two's complement representation
- Example: `-1` → `02 01 FF`

**Canonical DER Rule**: No unnecessary leading zeros are allowed.

---

*Generated: 2025-11-10*
