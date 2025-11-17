# Conformance Test Fixes

This document summarizes the changes made to fix Sigstore conformance test failures.

## Problem

Conformance tests were failing with:
```
WARN sigstore::crypto::keyring: Failed to load key: KeyMalformed(...)
Operation failed: failed to verify SCT
```

The test was trying to use a custom trusted root from the staging environment, but:
1. The `--trusted-root` CLI argument was being ignored during signing
2. The staging TUF repository contains a deprecated PKCS#1 RSA key that our code couldn't parse
3. SCT verification during signing was too strict (required exactly one SCT to verify)

## Root Cause

The Sigstore **staging** environment (`tuf-repo-cdn.sigstage.dev`) has:
- 1 RSA 4096-bit CTFE key in **PKCS#1 format** (deprecated)
- 2 ECDSA P256 CTFE keys in **SPKI format** (standard)

When Fulcio issues certificates during signing, it may include an SCT signed by the RSA CTFE log. Without RSA support, SCT verification fails, and signing fails.

### Why PKCS#1 Instead of SPKI?

According to sigstore-go's codebase:
> "This key format is deprecated, but currently in use for Sigstore staging instance"

Both sigstore-python and sigstore-go explicitly support PKCS#1 RSA keys for staging compatibility.

## Solutions Implemented

### 1. Custom Trust Root Support for Signing

**Files Modified:**
- `src/trust/sigstore/mod.rs`: Added `from_file_unchecked()` method
- `src/bundle/sign.rs`: Added `SigningContext::from_trust_root()` method
- `tests/conformance/conformance.rs`: Updated CLI to load and use custom trust roots

**What Changed:**
```rust
// New method to create signing context with custom trust root
pub fn from_trust_root(trust_root: SigstoreTrustRoot) -> SigstoreResult<Self>

// CLI now loads custom trust root when provided
if let Some(trusted_root_path) = trusted_root {
    let trust_root = SigstoreTrustRoot::from_file_unchecked(Path::new(&trusted_root_path))?;
    SigningContext::from_trust_root(trust_root)?
} else {
    SigningContext::production()?
}
```

### 2. Multi-SCT Verification for Signing

**Files Modified:**
- `src/crypto/transparency.rs`: Added `CertificateEmbeddedSCTs::new()` method
- `src/bundle/sign.rs`: Updated to use threshold-based SCT verification

**What Changed:**
```rust
// OLD: Required exactly one SCT to verify
let sct = CertificateEmbeddedSCT::new(&self.certs.cert, &self.certs.chain)?;
verify_sct(&sct, &self.context.ctfe_keyring)?;

// NEW: Threshold-based verification (at least 1 must succeed)
let scts = CertificateEmbeddedSCTs::new(&self.certs.cert, &self.certs.chain)?;
verify_scts(&scts, &self.context.ctfe_keyring, 1)?;
```

This allows signing to succeed even if some CTFE keys are missing or malformed, as long as at least one SCT can be verified.

### 3. RSA CTFE Key Support (Critical Fix)

**Files Modified:**
- `src/crypto/keyring.rs`: Added support for both SPKI RSA and PKCS#1 RSA keys

**What Changed:**

#### SPKI RSA Support
```rust
// RSA keys have NULL parameters in SPKI format
if spki.algorithm.oid == RSA_ENCRYPTION && params == &der::Any::null() {
    return Ok(Key {
        inner: UnparsedPublicKey::new(
            &aws_lc_rs_signature::RSA_PKCS1_2048_8192_SHA256,
            spki.subject_public_key.raw_bytes().to_owned(),
        ),
        fingerprint,
    });
}
```

#### PKCS#1 RSA Fallback (Critical Fix - Moved to Key::new())
The initial implementation placed PKCS#1 detection in `Key::new_with_id()`, but it was never reached because `Key::new()` failed at SPKI parsing first. The fix was to detect PKCS#1 format **before** attempting SPKI parsing:

```rust
// In Key::new() - BEFORE SPKI parsing
pub fn new(spki_bytes: &[u8]) -> Result<Self> {
    // Check for PKCS#1 format FIRST (before SPKI parsing fails)
    if spki_bytes.len() >= 4 && spki_bytes[0] == 0x30 && spki_bytes[4] == 0x02 {
        tracing::debug!("Detected PKCS#1 RSA key format (deprecated, used in staging) in Key::new()");
        // For PKCS#1 keys, compute fingerprint from the raw bytes
        let fingerprint = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(spki_bytes);
            hasher.finalize().into()
        };
        return Self::new_with_id(spki_bytes, fingerprint);
    }

    // Normal SPKI path (only reached if not PKCS#1)
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_bytes)?;
    // ...
}
```

This ensures PKCS#1 keys are detected and handled before the SPKI parser rejects them.

**However, there was still another critical issue**: The `SigningContext::from_trust_root()` method was using `Keyring::new()` which computes RFC 6962-style key IDs from the SPKI. For PKCS#1 keys, this computed a different key ID than what the trust root provided, causing SCT verification to fail because the keyring lookup used the wrong key ID.

**Final Fix**: Use `Keyring::new_with_ids()` instead to preserve the exact key IDs from the trust root:

```rust
// In SigningContext::from_trust_root()
pub fn from_trust_root(trust_root: SigstoreTrustRoot) -> SigstoreResult<Self> {
    let ctfe_keys = trust_root.ctfe_keys()?;
    let keys_with_ids: Vec<([u8; 32], &[u8])> = ctfe_keys
        .iter()
        .filter_map(|(key_id_hex, key_bytes)| {
            let key_id_vec = hex::decode(key_id_hex).ok()?;
            let key_id: [u8; 32] = key_id_vec.try_into().ok()?;
            Some((key_id, *key_bytes))
        })
        .collect();

    // Use new_with_ids() to preserve trust root key IDs
    Keyring::new_with_ids(keys_with_ids.iter().map(|(id, bytes)| (id, *bytes)))?
}
```

## Test Coverage

### New Tests Added

1. **`test_pkcs1_rsa_key_from_staging_tuf()`**
   - Loads the actual PKCS#1 RSA key from staging TUF root
   - Verifies it can be parsed and added to a keyring
   - Located in `src/crypto/keyring.rs`

2. **`test_load_staging_trusted_root_with_pkcs1_rsa()`**
   - End-to-end test loading the complete staging trusted root
   - Verifies all 3 CTFE keys load correctly (1 RSA + 2 ECDSA)
   - Tests mixed key format handling
   - Located in `src/crypto/keyring.rs`

### Test Data Files

- `tests/data/keys/ctfe_rsa_pkcs1_staging.der`: Extracted RSA key from staging
- `tests/data/keys/staging_trusted_root.json`: Complete staging trust root
- `tests/data/keys/README.md`: Documentation of test data

## Compatibility Matrix

| Implementation | SPKI RSA | PKCS#1 RSA | Notes |
|---------------|----------|------------|-------|
| **sigstore-rs** (this PR) | ✅ | ✅ | Full support |
| **sigstore-python** | ✅ | ✅ | Uses cryptography lib |
| **sigstore-go** | ✅ | ✅ | Explicit PKCS#1 handling |
| **Production TUF** | ✅ | ❌ | Only SPKI keys |
| **Staging TUF** | ✅ | ✅ | Has 1 PKCS#1 key |

## Expected Test Results

After these changes, conformance tests should:
- ✅ Pass 109/109 tests (up from 108/109)
- ✅ Successfully sign with staging trust root
- ✅ Handle RSA CTFE keys from staging environment
- ✅ Work with both production and staging infrastructure

## References

- [RFC 8017 - PKCS #1: RSA Cryptography Specifications](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 5280 - SubjectPublicKeyInfo](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
- [sigstore-go trusted_root.go](https://github.com/sigstore/sigstore-go/blob/main/pkg/root/trusted_root.go)
- [sigstore-python trust.py](https://github.com/sigstore/sigstore-python/blob/main/sigstore/_internal/trust.py)
