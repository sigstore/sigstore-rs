# CRITICAL BUG: Certificate Corruption During CMS Extraction

## Discovery

While investigating the webpki NULL parameter issue, we discovered a **more serious bug**:
The Rust code is **corrupting certificates** during extraction from CMS SignedData structures.

## Evidence

### What's in the CMS (correct):
```
Certificate size: 531 bytes
Signature algorithm: SEQUENCE of 10 bytes
  - OID: ecdsa-with-SHA384 (8 bytes)
  - Parameters: (none)
```

### What Rust extracts (corrupted):
```
Certificate size: 535 bytes (+4 bytes!)
Signature algorithm: SEQUENCE of 12 bytes
  - OID: ecdsa-with-SHA384 (8 bytes)
  - Parameters: NULL (2 bytes) ← INCORRECTLY ADDED
```

### Hex Comparison

**Original (from OpenSSL/Go)**:
```
00000020: 037c a730 0a06 082a 8648 ce3d 0403 0330
                 ^^^^                          ^^
                 SEQUENCE(10)                  next field
```

**Rust extraction**:
```
00000020: 037c a730 0c06 082a 8648 ce3d 0403 0305
                 ^^^^                       ^^^^^
                 SEQUENCE(12)               NULL + next
00000030: 0030 39
         ^^
         (continued)
```

## Impact

1. **Corrupted certificates**: The extracted certificate is invalid
2. **Signature verification fails**: OpenSSL reports "certificate signature failure"
3. **webpki rejects it**: Due to the incorrectly added NULL parameter
4. **Security risk**: We're using corrupted certificates for validation

## Root Cause

The bug is in one of these components:
- `cryptographic-message-syntax` crate's certificate extraction
- `x509-certificate` crate's `CapturedX509Certificate`
- The interaction between bcder parsing and x509 re-encoding

When extracting the certificate via:
```rust
let cert_der = cert.constructed_data().to_vec()
```

The certificate is being **re-encoded** rather than preserving the original DER bytes, and the re-encoding adds NULL parameters that weren't in the original.

## Verification Steps

Run these commands to verify:

```bash
# Extract with Rust
cargo run --example debug_cert_extraction --features verify

# Extract with Go
cd sigstore-go
go run /tmp/extract_cert.go

# Compare
diff /tmp/cert_0_constructed.der /tmp/sigstore_go_cert.der
# Shows difference

# Verify with OpenSSL
openssl x509 -in /tmp/sigstore_go_cert.der -inform DER -noout -text
# Works

openssl verify -CAfile /tmp/trusted_root_cert.pem /tmp/sigstore_go_cert.pem
# Works (after converting to PEM)

openssl x509 -in /tmp/cert_0_constructed.der -inform DER -noout -text
# Works (parses)

openssl verify -CAfile /tmp/trusted_root_cert.pem /tmp/embedded_cert.pem
# FAILS with "certificate signature failure"
```

## Implications for Original Investigation

The original TODO about webpki was investigating the wrong problem:

**We thought**: webpki rejects valid certificates with NULL parameters
**Actually**: The certificates don't have NULL parameters originally, but we're adding them during extraction

**We thought**: Full chain validation is disabled due to webpki limitations
**Actually**: Full chain validation fails because we're corrupting the certificates

## Immediate Actions Required

### 1. File Bug in cryptographic-message-syntax

Report to: https://github.com/indygreg/cryptographic-message-syntax

Details:
- Certificate extraction adds NULL parameters to signature algorithms
- Use our test case as reproduction
- Link to this analysis

### 2. Workaround in sigstore-rs

Instead of using `cert.constructed_data()`, we need to:

**Option A**: Extract the raw DER directly from the ASN.1 structure without going through x509-certificate parsing

**Option B**: Use the certificate from the trusted root (like sigstore-go does) instead of extracting from CMS

**Option C**: Fix the underlying crate

### 3. Re-evaluate Current Validation

The current code at [src/crypto/timestamp.rs] compares:
- Embedded cert (corrupted, 535 bytes)
- Trusted cert (correct, 531 bytes)

They will NEVER match byte-for-byte because the embedded cert is corrupted!

However, the identity comparison (subject/issuer/serial) still works because those fields aren't corrupted, just the signature algorithm encoding.

## Recommended Fix

**Short-term** (this week):
1. Use certificate from trusted root for validation (not embedded)
2. This matches what sigstore-go does
3. File upstream bug

**Medium-term** (weeks):
1. Help fix cryptographic-message-syntax crate
2. Or find way to extract raw DER without re-encoding

**Long-term**:
1. Once fixed, can re-enable embedded cert validation
2. But using trusted root is still the correct approach per spec

## Files for Reference

- `/tmp/cert_from_openssl.der` - Correct cert (531 bytes, no NULL)
- `/tmp/sigstore_go_cert.der` - Correct cert from Go (531 bytes, no NULL)
- `/tmp/cert_0_constructed.der` - Corrupted cert from Rust (535 bytes, has NULL)

## Test to Demonstrate

```bash
# Shows the corruption
cargo run --example debug_cert_extraction --features verify

# Shows OpenSSL rejects the corrupted cert
./examples/openssl_tsa_concept.sh
```

## Conclusion

Your colleague identified a real issue, but it's even more serious than we thought:

- ✓ webpki DOES reject NULL parameters
- ✓ The embedded cert extraction DOES fail
- ✗ BUT the original cert doesn't have NULL parameters
- ✗ WE ARE ADDING THEM during extraction
- ✗ This corrupts the certificate signature

**This is a critical bug that needs immediate attention.**

The current validation works by accident (comparing identity fields that aren't corrupted), but using corrupted certificates is dangerous and incorrect.

**Action**: Use certificates from trusted root, not from CMS embedded certificates, and file upstream bug.
