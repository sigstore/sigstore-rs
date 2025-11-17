# webpki TSA Certificate Chain Validation Issue

> **For a quick summary for experts, see [README_FOR_EXPERT.md](README_FOR_EXPERT.md)**

## Summary

We're implementing TSA (Time-Stamp Authority) certificate chain validation for sigstore-rs using rustls-webpki 0.103.8. We've encountered an `UnsupportedSignatureAlgorithmContext` error in production code, but the same validation works in a standalone test.

## The Problem

When validating TSA certificate chains, we get this error:

```
UnsupportedSignatureAlgorithmContext {
    signature_algorithm_id: [6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 5, 0],
    supported_algorithms: [0x06082a8648ce3d040303, ...]
}
```

The algorithm ID `[6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 5, 0]` breaks down as:
- `06 08 2a 86 48 ce 3d 04 03 03` - OID for ECDSA-with-SHA384 (1.2.840.10045.4.3.3)
- `05 00` - NULL parameter

The supported algorithms list includes `0x06082a8648ce3d040303` (without NULL), suggesting webpki expects the algorithm without NULL parameters.

However, when we inspect the certificates with OpenSSL, they DON'T have NULL parameters - they use the standard encoding.

## Reproducers

We've created two standalone examples to demonstrate the issue:

### 1. Simple Test (WORKS ✓)

```bash
cargo run --example webpki_tsa_simple --features verify
```

This demonstrates that webpki CAN successfully validate the same TSA certificate chain when used directly. This proves the certificates are valid and webpki supports the algorithm.

**Result:** ✓ Certificate chain validation SUCCEEDED!

### 2. Detailed Test (for investigation)

```bash
cargo run --example webpki_tsa_validation --features verify
```

This shows more details about the certificates including subject/issuer names and attempts to extract embedded certificates from the timestamp.

## Key Findings

1. **Standalone validation WORKS**: Direct use of webpki with these certificates succeeds
2. **Production code FAILS**: The same validation in [src/crypto/timestamp.rs:476](../src/crypto/timestamp.rs#L476) fails
3. **Certificate encoding is correct**: OpenSSL shows no NULL parameters in the certificates
4. **The difference**: Production code uses certificates embedded in CMS SignedData, while the test uses certificates from the trusted root

## Theory

The embedded certificate in the SignedData structure might have different encoding than the certificate in the trusted root. Specifically:
- Trusted root certificate: ECDSA-SHA384 without NULL parameter ✓
- Embedded certificate: ECDSA-SHA384 with NULL parameter? ✗

However, we can't easily verify this because the cryptographic-message-syntax crate's API makes it difficult to extract the raw DER bytes of embedded certificates.

## Files to Examine

### Test Certificates

```
sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/
├── bundle.sigstore.json          # Contains SignedData with embedded cert
└── trusted_root.json              # Contains TSA cert chain (leaf + root)
```

### Source Code

- [src/crypto/timestamp.rs](../src/crypto/timestamp.rs) - TSA validation logic (line 395+)
- [src/trust/sigstore/mod.rs](../src/trust/sigstore/mod.rs) - TSA root cert extraction (line 304+)
- [examples/webpki_tsa_simple.rs](webpki_tsa_simple.rs) - Working standalone test

## Questions for the Expert

1. Why does webpki validation succeed in the standalone test but fail in production code?
2. Is there a way to inspect/normalize the algorithm encoding in embedded certificates?
3. Could the `cryptographic-message-syntax` crate be adding NULL parameters when extracting certificates?
4. Is there a webpki API to handle both algorithm encodings (with and without NULL)?

## Environment

- rustls-webpki: 0.103.8
- Certificate algorithm: ECDSA-with-SHA384 (OID 1.2.840.10045.4.3.3)
- Source: Sigstore staging TSA

## How to Help

Run the reproducer examples and compare the results. The key question is: why does the same certificate validate successfully in one context but fail in another?

```bash
# This works:
cargo run --example webpki_tsa_simple --features verify

# This fails (via production code):
cargo build --release --features verify
cd tests/conformance
./target/release/sigstore verify-bundle \
  --bundle ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
  --certificate-identity "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --trusted-root ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json \
  "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
```
