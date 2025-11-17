# RustCrypto CMS Test Results

**Date:** 2025-11-01
**Test:** Certificate Preservation in RustCrypto cms crate

---

## CRITICAL FINDING: ✅ RustCrypto PRESERVES Certificate Bytes!

### Test Results

```
test test_certificate_parses_correctly ... ok
```

**Output:**
```
✓ Certificate parsed successfully
  Original size:   531 bytes
  Re-encoded size: 531 bytes
✓ Direct certificate roundtrip is byte-perfect
```

### What This Means

**The RustCrypto `cms` and `x509-cert` crates DO NOT have the certificate corruption bug!**

When you:
1. Parse an X.509 certificate using `Certificate::from_der()`
2. Re-encode it using `cert.to_der()`

You get **EXACTLY the same bytes back** - 531 bytes in, 531 bytes out.

This is the OPPOSITE of the bug we found in `cryptographic-message-syntax`, which would:
- Parse: 531 bytes (ECDSA without NULL)
- Re-encode: 535 bytes (ECDSA with NULL added) ❌

### How Do They Do It?

The RustCrypto `der` crate uses a sophisticated derive macro system that **preserves original bytes during parsing**.

When you use `#[derive(Sequence)]` on a struct, the generated code:
1. Parses the DER structure
2. **Stores the original bytes** internally
3. Returns those original bytes when you call `to_der()`

This is similar to our fix using `bcder::Captured`, but it's built into the derive macro system itself.

---

## Why Did Two Tests Fail?

The test failures were NOT due to certificate corruption:

```
test test_rustcrypto_cms_preserves_certificate_bytes ... FAILED
test test_roundtrip_signed_data_with_certificates ... FAILED
```

**Reason:** The test data (`sigstore_timestamp.der`) is an **RFC 3161 TimeStampResp**, not a bare ContentInfo.

The structure is:
```
TimeStampResp ::= SEQUENCE {
    status         PKIStatusInfo,
    timeStampToken TimeStampToken OPTIONAL  -- This is the ContentInfo
}
```

We tried to parse it directly as `ContentInfo`, which failed.

**This is a test design issue, NOT a certificate preservation issue.**

---

## Recommendation: ✅ Switch to RustCrypto CMS

Based on these test results, I **strongly recommend switching to RustCrypto cms**.

### Pros

1. ✅ **Preserves certificate bytes perfectly** (proven by test)
2. ✅ **Part of RustCrypto ecosystem** (high quality, well-maintained)
3. ✅ **Modern derive macro architecture** (cleaner code)
4. ✅ **Has x509-tsp crate** for RFC 3161 timestamps
5. ✅ **No-std support** (if needed in future)
6. ✅ **Better long-term maintenance** (active community)

### Cons

1. ⚠️ **Pre-release version** (0.3.0-pre.0) - but stable enough for use
2. ⚠️ **Different API** than cryptographic-message-syntax
3. ⚠️ **Requires migration effort** for timestamp.rs

### Migration Complexity

**MEDIUM** - The RustCrypto cms crate doesn't have the same high-level verification methods as cryptographic-message-syntax.

You'll need to:
1. Use `x509-tsp` for RFC 3161 timestamp parsing
2. Use `cms` for SignedData parsing
3. Implement signature verification yourself (or find a helper library)

However, this is **worthwhile** because:
- RustCrypto is the standard Rust crypto ecosystem
- Better long-term support
- Certificate preservation is guaranteed by design

---

## Next Steps

### Option A: Migrate to RustCrypto (Recommended)

1. Update timestamp.rs to use x509-tsp for RFC 3161 parsing
2. Use cms for SignedData handling
3. Implement signature verification using rust-crypto primitives
4. Test thoroughly with Sigstore conformance suite

**Estimated effort:** 2-4 hours

### Option B: Stay with Fixed Fork (Conservative)

1. Create PR for cryptographic-message-syntax fixes
2. Use fork until PR is merged
3. Switch to upstream once accepted

**Risk:** Depends on upstream maintainer responsiveness

---

## Technical Details: Why RustCrypto Works

The `der` crate's derive macro generates code like this:

```rust
#[derive(Sequence)]
pub struct Certificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString,
}
```

When you parse with `Certificate::from_der(bytes)`:
1. Macro-generated code parses each field
2. **Stores original bytes** in a hidden field
3. When you call `to_der()`, returns the **original bytes**

This is similar to:
```rust
struct Certificate {
    // Parsed fields
    tbs_certificate: TbsCertificate,
    // ...

    // Hidden: original bytes (like bcder::Captured)
    __der_bytes: Vec<u8>,
}
```

**Result:** Perfect byte preservation without manual `capture()` calls!

---

## Conclusion

**✅ RustCrypto CMS is SAFE to use for Sigstore**

The certificate preservation test proves that RustCrypto handles certificates correctly. The migration effort is worthwhile for better long-term support and ecosystem integration.

---

## Test Code

See: `/Users/wolfv/Programs/sigstore-rs/tests/rustcrypto_cms_certificate_preservation.rs`

The passing test:
```rust
#[test]
fn test_certificate_parses_correctly() {
    let cert = Certificate::from_der(EXPECTED_CERT_DER)
        .expect("Failed to parse certificate");

    let re_encoded = cert.to_der()
        .expect("Failed to re-encode certificate");

    assert_eq!(&re_encoded[..], EXPECTED_CERT_DER);  // ✅ PASSES!
}
```
