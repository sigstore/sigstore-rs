# CMS Crate Comparison for Sigstore-RS

**Date:** 2025-11-01
**Purpose:** Evaluate alternatives for CMS parsing in sigstore-rs

---

## Options Evaluated

1. **cryptographic-message-syntax** (indygreg/cryptography-rs) - Currently used
2. **cms** (RustCrypto/formats) - New alternative
3. **Custom minimal parser** - Written for evaluation

---

## 1. cryptographic-message-syntax (indygreg)

**Repository:** https://github.com/indygreg/cryptography-rs
**Crate:** cryptographic-message-syntax
**Parser:** bcder (BER/DER parser)

### Pros
- ✓ Comprehensive implementation (~2000 lines)
- ✓ Supports both parsing and creation
- ✓ Well-tested with production use
- ✓ **We've already fixed the certificate corruption bug**
- ✓ Actively maintained
- ✓ Uses `bcder` which has explicit `capture()` API for preserving bytes

### Cons
- ✗ **Had critical certificate corruption bug** (now fixed in our fork)
- ✗ **Had 4 DoS vulnerabilities** (now fixed in our fork)
- ✗ Larger codebase means more potential issues
- ✗ Not part of RustCrypto ecosystem
- ✗ Fixes not yet merged upstream (PR pending)

### Certificate Handling

**BEFORE our fix:**
```rust
// BUG: Re-encodes certificate, adding NULL parameters
CertificateChoices::Certificate(Box::new(cert_asn1))
```

**AFTER our fix:**
```rust
// Preserves original bytes using bcder::capture()
CertificateChoices::Certificate {
    parsed: Box::new(cert_asn1),
    original: bcder::Captured,  // ✓ PRESERVES EXACT BYTES
}
```

### Status
- ✓ **Working correctly** in our fork
- ⏳ PR pending for upstream
- ✓ Already integrated in sigstore-rs

---

## 2. cms (RustCrypto)

**Repository:** https://github.com/RustCrypto/formats
**Crate:** cms (version 0.3.0-pre.0)
**Parser:** der (DER parser with derive macros)

### Pros
- ✓ Part of the **RustCrypto ecosystem** (high quality, well-maintained)
- ✓ Uses modern `der` crate with derive macros
- ✓ Has **test showing byte-perfect re-encoding** (line 75 in signed_data.rs)
- ✓ Supports multiple CMS content types (SignedData, EnvelopedData, etc.)
- ✓ No-std support
- ✓ Uses x509-cert 0.3.0 (modern version)

### Cons
- ⚠️ **Pre-release version** (0.3.0-pre.0)
- ⚠️ **UNKNOWN: Does it preserve certificate bytes correctly?** (needs testing)
- ⚠️ Uses x509-cert which may have same NULL parameter issue
- ⚠️ Edition 2024 / Rust 1.85 required
- ⚠️ Less battle-tested than cryptographic-message-syntax

### Certificate Handling

**Current implementation:**
```rust
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertificateChoices {
    Certificate(Certificate),  // ⚠️ DOES THIS RE-ENCODE?
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Other(OtherCertificateFormat),
}
```

**Key question:** Does the `der` crate's derive macro preserve original bytes, or does it re-encode like the old cryptographic-message-syntax?

### Test Evidence

From `tests/signed_data.rs:75`:
```rust
// parse as SignedData then re-encode
let sd = SignedData::from_der(bytes.as_slice()).unwrap();
let reencoded_signed_data = sd.to_der().unwrap();

// should match the original
assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
```

This test **passes**, suggesting that re-encoding produces identical bytes. This could mean:

1. ✓ **Best case:** The `der` crate preserves original bytes (similar to our fix)
2. ⚠️ **Uncertain:** The test data doesn't include ECDSA certs with/without NULL parameters
3. ✗ **Worst case:** The test passes by luck (e.g., RSA certs that re-encode identically)

**WE NEED TO TEST WITH SIGSTORE DATA TO KNOW FOR SURE**

---

## 3. Custom Minimal Parser

**Location:** `/Users/wolfv/Programs/sigstore-rs/src/crypto/cms_minimal.rs`
**Size:** ~400 lines
**Parser:** bcder (same as cryptographic-message-syntax)

### Pros
- ✓ **Extremely minimal** - only what Sigstore needs
- ✓ **Guaranteed to preserve bytes** - we control the implementation
- ✓ Read-only (no signing complexity)
- ✓ Well-documented with our fix built-in
- ✓ No external dependencies beyond bcder

### Cons
- ✗ **We have to maintain it** forever
- ✗ Not RFC 5652 compliant (subset only)
- ✗ No community review/testing
- ✗ Reinventing the wheel
- ✗ If we need more CMS features later, we'd have to add them

### Certificate Handling

```rust
pub struct Certificate {
    /// The original DER bytes - NEVER re-encode these!
    original: bcder::Captured,
}

impl Certificate {
    fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>> {
        // CRITICAL: Use capture() to preserve original bytes!
        let captured_result = cons.capture(|capture_cons| {
            // ... parse without storing parsed structure
        });
        Ok(Some(Certificate { original: captured_result }))
    }
}
```

**Certainty:** 100% - we built the fix ourselves

---

## Key Technical Question: How Does `der` Crate Work?

The RustCrypto `der` crate uses **derive macros** to generate parsing code:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedData {
    // ...
    pub certificates: Option<CertificateSet>,
    // ...
}
```

**Critical question:** Does this derive macro:
1. Parse → Store parsed structure → Re-encode when you call `to_der()`? (**BAD - re-encodes**)
2. Parse → Store original bytes → Return original bytes? (**GOOD - preserves**)

**How to find out:**
- Read the `der` crate source code for `Sequence` derive macro
- Test with Sigstore TSA certificate data
- Check if re-encoding a certificate changes its bytes

---

## Testing Strategy

To determine if RustCrypto's `cms` crate preserves certificate bytes:

```rust
#[test]
fn test_rustcrypto_cms_certificate_preservation() {
    // Use the SAME Sigstore TSA timestamp that exposed the bug
    let timestamp_der = include_bytes!("test_data/sigstore_timestamp.der");
    let expected_cert = include_bytes!("test_data/sigstore_tsa_cert.der"); // 531 bytes

    // Parse using RustCrypto cms
    let content_info = ContentInfo::from_der(timestamp_der).unwrap();
    let signed_data = SignedData::from_der(content_info.content.to_der().unwrap()).unwrap();

    let certs = signed_data.certificates.as_ref().unwrap();
    let cert = &certs.0[0];

    // Re-encode the certificate
    let re_encoded = cert.to_der().unwrap();

    // CRITICAL TEST: Does it match the original?
    assert_eq!(re_encoded.len(), 531); // Not 535!
    assert_eq!(&re_encoded[..], expected_cert);
}
```

**If this test passes:** RustCrypto cms is safe to use
**If this test fails:** RustCrypto cms has the same bug

---

## Recommendations

### Option A: Stay with cryptographic-message-syntax (SAFEST)

**Rationale:**
- ✓ We've already fixed the bugs
- ✓ We know it works with Sigstore data
- ✓ Production-tested
- ✓ Just need to get PR merged upstream

**Action items:**
1. Create PR for upstream cryptography-rs
2. Use our fork until PR is merged
3. Switch to upstream once fixes are accepted

**Risk:** Low - we control the fixes

---

### Option B: Switch to RustCrypto cms (NEEDS TESTING)

**Rationale:**
- ✓ Part of trusted RustCrypto ecosystem
- ✓ Modern architecture with derive macros
- ✓ Better long-term maintenance

**Action items:**
1. **CRITICAL:** Test with Sigstore TSA data (test above)
2. If test passes → evaluate migration effort
3. If test fails → investigate if `der` crate can be fixed

**Risk:** Medium - unknown if it preserves bytes correctly

---

### Option C: Use minimal custom parser (NOT RECOMMENDED)

**Rationale:**
- Only if both other options fail
- Maintenance burden on sigstore-rs team
- Reinventing the wheel

**Risk:** High - long-term maintenance burden

---

## Immediate Next Steps

1. **Test RustCrypto cms** with Sigstore TSA certificate data
2. **Investigate `der` crate** source code to understand byte preservation
3. **Make decision** based on test results:
   - If RustCrypto preserves bytes → strong candidate for migration
   - If RustCrypto corrupts bytes → stay with our fixed fork

---

## Technical Deep Dive: Why This Matters

### The Core Problem

X.509 certificates are **signed over their exact bytes**:

```
Certificate = {
    TBSCertificate (to-be-signed data)
    SignatureAlgorithm
    SignatureValue = sign(hash(TBSCertificate))
}
```

If you change **even one byte** in TBSCertificate, the signature becomes invalid.

### The Bug

Different libraries encode ECDSA algorithms differently:

**OpenSSL/Go (compact):**
```
SEQUENCE (10 bytes) {
    OBJECT IDENTIFIER ecdsaWithSHA256
}
```

**Rust x509-certificate (verbose):**
```
SEQUENCE (12 bytes) {
    OBJECT IDENTIFIER ecdsaWithSHA256
    NULL
}
```

Both are valid per RFC 5480, but:
- Original cert: 531 bytes, compact encoding, **valid signature**
- Re-encoded cert: 535 bytes, verbose encoding, **INVALID signature**

### The Solution

**Never re-encode certificates**. Instead:
1. Parse the certificate structure
2. **Also store the original DER bytes**
3. When you need to output the certificate, return the **original bytes**

This is what `bcder::capture()` does, and **hopefully** what `der` crate does too.

---

## References

- [RFC 5652: Cryptographic Message Syntax](https://www.rfc-editor.org/rfc/rfc5652.html)
- [RFC 5480: Elliptic Curve Cryptography Subject Public Key Information](https://www.rfc-editor.org/rfc/rfc5480.html)
- [RustCrypto formats repository](https://github.com/RustCrypto/formats)
- [bcder documentation](https://docs.rs/bcder/)
- [der crate documentation](https://docs.rs/der/)
