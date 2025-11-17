# Certificate Corruption Bug - Issue & Request for Comments

## Summary

`CertificateChoices` in the `cryptographic-message-syntax` crate corrupts X.509 certificates during extraction from CMS SignedData by re-encoding them, which adds NULL parameters to ECDSA signature algorithms where there were none originally.

## Impact

- Extracted certificates differ from originals (535 bytes vs 531 bytes)
- webpki rejects the corrupted certificates
- OpenSSL reports "certificate signature failure"
- Blocks X.509 chain validation in sigstore-rs
- Affects Sigstore TSA validation

## Reproduction

**Test case**: See attached test file `sigstore_certificate_preservation.rs`

Using real Sigstore conformance test data:
1. Parse timestamp response with embedded TSA certificate
2. Extract certificate using `CertificateChoices`
3. Re-encode using `encode_ref()`
4. Result: 535 bytes (should be 531 bytes)
5. Hex analysis shows NULL parameters added at offset 0x20

**Expected** (531 bytes, correct):
```
00000020: 037c a730 0a06 082a 8648 ce3d 0403 0330
                 ^^
            SEQUENCE(10) - just OID
```

**Actual** (535 bytes, corrupted):
```
00000020: 037c a730 0c06 082a 8648 ce3d 0403 0305
                 ^^                        ^^^^
            SEQUENCE(12)              NULL added!
```

## Root Cause

In `src/asn1/rfc5652.rs`, line 1204:

```rust
pub enum CertificateChoices {
    Certificate(Box<Certificate>),  // Stores parsed cert
    // ...
}

impl CertificateChoices {
    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Certificate(cert) => cert.encode_ref(),  // ← BUG: Re-encodes!
            // ...
        }
    }
}
```

The `cert.encode_ref()` call **re-encodes** the certificate using `x509-certificate::Certificate::encode_ref()`, which adds NULL parameters that weren't in the original DER encoding.

## Proposed Solution

**Store both the parsed certificate AND the original DER bytes**:

```rust
pub enum CertificateChoices {
    Certificate {
        parsed: Box<Certificate>,
        original: Captured,  // ← Preserve original DER bytes
    },
    // ...
}

impl CertificateChoices {
    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Certificate { original, .. } => {
                // Return original bytes, don't re-encode
                encode::slice(original.as_slice())
            }
            // ...
        }
    }
}
```

## Challenge: Capturing Original Bytes During Parsing

The difficulty is **how to capture the original DER bytes** while parsing in `take_opt_from`:

**Current parsing** (line 1194):
```rust
cons.take_opt_constructed(|_, cons| Certificate::from_sequence(cons))?
```

This gives us the parsed `Certificate` but not the original bytes.

**What we need**: Access to both:
1. The original DER bytes (as `Captured` or `Content`)
2. The parsed `Certificate`

## Request for Guidance

We need help from bcder/CMS maintainers on the **best way to capture original bytes during parsing**.

### Options we've considered:

**Option A**: Use `take_opt_value` to get `Content`, then parse
```rust
cons.take_opt_value(|tag, content| {
    let original = content.clone();  // Capture original
    // How to parse Certificate from Content?
    let cert = ??? // Need help here
    Ok(Some((cert, original)))
})
```

**Question**: How do we parse a `Certificate` from `Content`? The API requires `Constructed`.

**Option B**: Use some bcder capture API
```rust
// Is there a way to do this?
let (cert, captured) = cons.capture_one(|cons| {
    cons.take_opt_constructed(|_, c| Certificate::from_sequence(c))
})?;
```

**Question**: Does bcder have a capture API for this use case?

**Option C**: Modify `Certificate::from_sequence` to return both
- Could x509-certificate provide a method that returns `(Certificate, Captured)`?
- Or should CMS handle this differently?

## Files & Test Case

We've prepared:
- Comprehensive test case demonstrating the bug
- Real test data from Sigstore conformance suite
- Hex dumps showing the exact corruption
- Comparison with Go/OpenSSL (which extract correctly)

See: https://github.com/sigstore/sigstore-rs/tree/main/examples

Test files:
- `test_data/sigstore_timestamp.der` - Real timestamp with embedded cert
- `test_data/sigstore_tsa_cert.der` - Expected cert (531 bytes, correct)
- `tests/sigstore_certificate_preservation.rs` - Failing test

## Breaking Change Note

Yes, changing `CertificateChoices` from `Certificate(Box<Certificate>)` to `Certificate { parsed, original }` is a **breaking change**.

**Migration**:
```rust
// Old code:
match choice {
    CertificateChoices::Certificate(cert) => { /* use cert */ }
}

// New code:
match choice {
    CertificateChoices::Certificate { parsed, .. } => { /* use parsed */ }
}

// Or use accessor:
if let Some(cert) = choice.as_certificate() {
    // use cert
}
```

**Version bump**: Requires minor version bump (0.28.0 → 0.29.0)

## Request

1. **Confirm this analysis is correct**
2. **Advise on best way to capture original bytes** during parsing with bcder
3. **Guide on preferred implementation approach**
4. We're happy to implement and submit PR once we understand the right pattern!

## Why This Matters

- Sigstore ecosystem relies on TSA validation
- Affects production security (corrupted certificates)
- Other projects using this crate may have same issue
- Reference implementations (Go/Python) preserve original bytes correctly

## Contact

- Reporter: @wolfv (sigstore-rs contributor)
- Project: https://github.com/sigstore/sigstore-rs
- Context: Rekor v2 bundle TSA validation

We're eager to help fix this properly with maintainer guidance!
