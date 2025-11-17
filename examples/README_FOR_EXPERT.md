# TSA Certificate Chain Validation Issue - For Your Expert Friend

## TL;DR

webpki validation works standalone but fails in production code. We need help figuring out why.

## Working Example

Run this - it WORKS:

```bash
cargo run --example webpki_tsa_simple --features verify
```

Output: ✓ Certificate chain validation SUCCEEDED!

## Failing Production Code

But the exact same certificates fail in the production code:

```bash
cargo build --release --features verify
cd tests/conformance
./target/release/sigstore verify-bundle \
  --bundle ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
  --certificate-identity "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --trusted-root ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json \
  "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
```

Output:
```
ERROR TSA certificate chain validation failed: UnsupportedSignatureAlgorithmContext {
  signature_algorithm_id: [6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 5, 0],
  ...
}
```

## The Error

The bytes `[6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 5, 0]` are:
- `06 08 2a 86 48 ce 3d 04 03 03` - ECDSA-with-SHA384 OID
- `05 00` - NULL parameter

But when we inspect the certificates with OpenSSL, they don't have NULL parameters!

## Key Difference

- **Working test**: Uses certificates directly from `trusted_root.json`
- **Failing code**: Uses certificates embedded in CMS SignedData structure within the timestamp

Theory: The `cryptographic-message-syntax` crate might be adding NULL parameters when extracting certificates, or the embedded certificates are encoded differently.

## Source Code to Check

The validation code is in [src/crypto/timestamp.rs](../src/crypto/timestamp.rs) starting at line 395.

Key section:
```rust
// Extract embedded certificate from SignedData
let cert = parsed_signed_data.certificates().next().unwrap();
let cert_der = cert.constructed_data().to_vec();  // ← This might have NULL parameter added?

// Validate with webpki
let end_entity_cert = EndEntityCert::try_from(&cert_der)?;
end_entity_cert.verify_for_usage(...)  // ← Fails here
```

## Questions

1. Could `constructed_data().to_vec()` be changing the certificate encoding?
2. Is there a way to normalize the algorithm encoding before passing to webpki?
3. Should we strip NULL parameters from algorithm IDs?
4. Is this a known issue with the `cryptographic-message-syntax` crate?

## Files

All test data is in:
```
sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/
├── bundle.sigstore.json   # Contains timestamp with embedded cert
└── trusted_root.json      # Contains TSA cert chain
```

##Dependencies

- rustls-webpki: 0.103.8
- cryptographic-message-syntax: 0.28.0
- x509-certificate: 0.25.0

Thanks for any help you can provide!
