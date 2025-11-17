# Bug Report for cryptographic-message-syntax

## Summary

`CertificateChoices::encode_ref()` re-encodes certificates instead of preserving original DER bytes, which corrupts the certificate by adding NULL parameters to ECDSA signature algorithms.

## Description

When extracting X.509 certificates from CMS `SignedData` structures, the `cryptographic-message-syntax` crate is re-encoding the certificates during extraction rather than preserving the original DER bytes. This causes the extracted certificate to differ from the original, specifically by adding NULL parameters to the signature algorithm where there were none.

## Impact

- Extracted certificates have different bytes than the original
- Signature verification fails (OpenSSL reports "certificate signature failure")
- webpki rejects the certificates due to NULL parameters in ECDSA algorithms
- Cannot perform X.509 chain validation on embedded TSA certificates

## Reproduction

### Test Data

Using the Sigstore conformance test bundle:
`sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json`

### Steps

1. Extract timestamp from bundle
2. Parse `TimeStampResp` → `SignedData`
3. Extract certificate using `CertificateChoices::encode_ref()`
4. Compare with original cert in CMS

### Expected Behavior

Certificate extracted: **531 bytes**
```
Signature algorithm (offset 0x20):
30 0a 06 08 2a 86 48 ce 3d 04 03 03 30
^^                                   ^^
SEQUENCE(10) - just OID, no params   next field
```

### Actual Behavior

Certificate extracted: **535 bytes (+4 bytes!)**
```
Signature algorithm (offset 0x20):
30 0c 06 08 2a 86 48 ce 3d 04 03 03 05 00 30
^^                                ^^^^^ ^^
SEQUENCE(12) - OID + NULL params      next field
```

The NULL parameters (`05 00`) were **added during extraction**.

## Root Cause Analysis

When `CertificateChoices::encode_ref()` is called, it:
1. Matches on `Self::Certificate(cert)`
2. Calls `cert.encode_ref()`
3. This re-encodes the certificate using `x509-certificate` crate
4. The re-encoding adds NULL parameters that weren't in the original

**The issue**: We need the **original bytes** from the CMS, not a re-encoded version.

## Proposed Solution

### Option A: Store Original Bytes (Preferred)

Modify `CertificateChoices` to store the original DER bytes:

```rust
pub enum CertificateChoices {
    Certificate {
        parsed: Box<Certificate>,
        original_der: Vec<u8>,  // Store original bytes
    },
    // ...
}
```

Then in `encode_ref()`:
```rust
Self::Certificate { original_der, .. } => {
    // Return original bytes, don't re-encode
    encode::slice(original_der)
}
```

### Option B: Use Captured Type

Similar to how `ContentInfo` uses `Captured`, certificates could be stored as `Captured` to preserve original DER:

```rust
pub enum CertificateChoices {
    Certificate(Captured),  // Store as Captured DER
    // ...
}
```

### Option C: Fix x509-certificate Encoding

If the issue is in `x509-certificate::Certificate::encode_ref()` adding NULL parameters, fix it there to preserve original encoding.

## Test Case

### Standalone Reproducer

See `examples/isolate_cert_corruption.rs` in sigstore-rs:

```bash
git clone https://github.com/sigstore/sigstore-rs.git
cd sigstore-rs
git submodule update --init --recursive
cargo run --example isolate_cert_corruption --features verify
```

This demonstrates:
1. Certificate in CMS: 531 bytes, no NULL parameter
2. After extraction: 535 bytes, NULL parameter added
3. The corruption happens in `encode_ref()`

### Verification with OpenSSL

```bash
# Extract cert directly from CMS using OpenSSL
openssl asn1parse -in bundle.der -strparse 251 -out cert_openssl.der

# Extract using Rust cryptographic-message-syntax
# (via our test code)
cargo run --example debug_cert_extraction --features verify

# Compare
diff cert_openssl.der /tmp/cert_raw_asn1.der
# Shows 4-byte difference (NULL parameters added)

# Verify OpenSSL rejects the corrupted cert
openssl verify -CAfile root.pem cert_from_rust.pem
# FAILS: "certificate signature failure"

openssl verify -CAfile root.pem cert_from_openssl.der
# WORKS: cert validates correctly
```

## Additional Context

### Why This Matters

1. **Sigstore ecosystem**: TSA validation in sigstore-rs is blocked by this
2. **Security**: Using corrupted certificates is dangerous
3. **Compliance**: Some security frameworks require original certificates
4. **Interoperability**: Go and Python implementations extract correctly

### Comparison with Other Libraries

- **Go** (`github.com/digitorus/timestamp`): Extracts 531 bytes, no NULL
- **OpenSSL**: Extracts 531 bytes, no NULL
- **Rust** (`cryptographic-message-syntax`): Extracts 535 bytes, adds NULL

### RFC 5652 Expectation

Per RFC 5652, `CertificateChoices` is a CHOICE that contains the certificate. The certificate bytes should be **preserved as-is**, not re-encoded.

## Files

All test files and analysis available at:
https://github.com/sigstore/sigstore-rs

Key files:
- `examples/isolate_cert_corruption.rs` - Minimal reproducer
- `examples/debug_cert_extraction.rs` - Detailed extraction test
- `examples/compare_with_sigstore_go.sh` - Compares with Go
- `CRITICAL_BUG_FOUND.md` - Complete analysis

## Environment

- `cryptographic-message-syntax`: 0.28.0
- `x509-certificate`: 0.25.0
- `bcder`: 0.7.6
- Rust: 1.85 (or current stable)

## Request

We'd like to:
1. Confirm this analysis is correct
2. Determine the best fix (Option A, B, C, or other)
3. Help implement and test the fix
4. Submit a PR if welcomed

This is blocking full X.509 chain validation in sigstore-rs, and we're eager to help get it fixed!

## Contact

- Issue author: @wolfv (sigstore-rs contributor)
- Project: https://github.com/sigstore/sigstore-rs
- Context: TSA certificate validation for Rekor v2 bundles
