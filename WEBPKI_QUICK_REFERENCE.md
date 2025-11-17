# webpki TSA Validation - Quick Reference

## TL;DR

✓ **Your colleague's findings are correct** - webpki rejects certificates with NULL parameters
✓ **Current implementation is secure** - conformance suite passes, identity validation works
✓ **Full chain validation would be better** - but not critical for security
✗ **Missing**: Revocation checking and CA constraint validation

**Recommendation**: Document the limitation now, fix webpki upstream later.

---

## Run Tests to See the Issue

```bash
# All tests from the repo root
cd /Users/wolfv/Programs/sigstore-rs

# 1. Simple test - shows webpki CAN validate (uses trusted root cert without NULL)
cargo run --example webpki_tsa_simple --features verify

# 2. Exact reproducer - shows the failure (uses embedded cert with NULL)
cargo run --example webpki_tsa_reproduce_exact --features verify -- \
  --bundle sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
  --trusted-root sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json

# 3. Comprehensive demo - compares both certificates side-by-side
cargo run --example webpki_issue_demo --features verify

# 4. Minimal test - clean test case for webpki upstream PR
cargo run --example webpki_upstream_test --features verify

# 5. OpenSSL demo - shows OpenSSL accepts the certificate
./examples/openssl_tsa_concept.sh
```

---

## The Problem in One Image

```
Trusted Root Cert (from JSON):          Embedded Cert (from CMS):
┌───────────────────────────┐          ┌───────────────────────────┐
│ ECDSA-with-SHA384         │          │ ECDSA-with-SHA384         │
│ OID: 1.2.840.10045.4.3.3  │          │ OID: 1.2.840.10045.4.3.3  │
│ Parameters: (none)        │          │ Parameters: NULL          │
│                           │          │                           │
│ 10 bytes total            │          │ 12 bytes total            │
│                           │          │                           │
│ webpki: ✓ ACCEPTS         │          │ webpki: ✗ REJECTS         │
└───────────────────────────┘          └───────────────────────────┘
         Same certificate, different encoding
```

---

## Security Analysis

### What IS Validated ✓

| Check | Status | Security Value |
|-------|--------|----------------|
| CMS Signature | ✓ | Prevents tampering |
| Certificate Identity | ✓ | Prevents untrusted TSAs |
| Timestamp Validity | ✓ | Prevents expired timestamps |
| Certificate Validity | ✓ | Prevents expired certificates |

### What Is NOT Validated ✗

| Check | Status | Security Impact | Risk Level |
|-------|--------|-----------------|------------|
| X.509 Chain to Root | ✗ | Missing path validation | LOW |
| Certificate Revocation | ✗ | Revoked certs accepted | MEDIUM |
| CA Constraints | ✗ | Policy/name constraints ignored | LOW |

**Overall Risk**: **LOW to MEDIUM** - Core security is solid, missing defense-in-depth

---

## Solution Decision Tree

```
Do you need full chain validation?
│
├─ No, conformance suite passing is enough
│  └─ ✓ Use current implementation
│     └─ Action: Document limitation (see below)
│
├─ Yes, but can wait for upstream fix
│  └─ ✓ Fix webpki upstream
│     └─ Action: File issue + PR at rustls/webpki
│
└─ Yes, need it now
   └─ ✓ Add OpenSSL feature flag
      └─ Action: Implement Option B (see analysis doc)
```

---

## Recommended Actions by Timeline

### This Week (Documentation)

1. **Update the TODO comment** in [src/crypto/timestamp.rs:449-460]:
   ```rust
   // Full chain validation disabled due to webpki NULL parameter issue
   //
   // ISSUE: webpki rejects ECDSA certificates with NULL algorithm parameters,
   // even though RFC 5480 allows them. The embedded TSA certificate in the
   // CMS SignedData has this encoding.
   //
   // CURRENT APPROACH: We validate certificate identity (subject/issuer/serial)
   // against the trusted TSA certificate. This prevents accepting timestamps
   // from untrusted TSAs while avoiding the webpki encoding issue.
   //
   // MISSING: Full X.509 chain validation, revocation checking, CA constraints
   //
   // SECURITY: LOW-MEDIUM risk. Core security (identity + signature) is solid.
   // See: WEBPKI_TSA_ANALYSIS.md for details
   //
   // TRACKING: https://github.com/sigstore/sigstore-rs/issues/XXX
   // UPSTREAM: https://github.com/rustls/webpki/issues/XXX (when filed)
   //
   // TODO: Re-enable when webpki accepts NULL parameters OR add OpenSSL option
   ```

2. **File tracking issue** in sigstore-rs repo

3. **Add module documentation** explaining the approach

### Next Month (Upstream Engagement)

1. **Research webpki**:
   - Search for existing issues about NULL parameters
   - Review their security policy
   - Check PR acceptance criteria

2. **File webpki issue**:
   - Title: "Support NULL parameters in ECDSA signature algorithms per RFC 5480"
   - Use `webpki_upstream_test.rs` as reproduction
   - Reference Sigstore ecosystem impact
   - Link to RFC 5480 section 2.1.1

3. **Submit PR** (if welcomed):
   - Modify algorithm matching to accept both encodings
   - Add comprehensive tests
   - Document security implications

### In 3-6 Months (Re-evaluation)

**If webpki merged the fix**:
- Update webpki dependency
- Re-enable chain validation code
- Run conformance tests
- Update documentation

**If webpki rejected the fix**:
- Consider OpenSSL feature flag
- Or document as permanent limitation
- Ensure conformance suite still passes

---

## Files Reference

| File | Purpose |
|------|---------|
| `WEBPKI_SUMMARY.md` | This file - quick overview |
| `WEBPKI_TSA_ANALYSIS.md` | Deep dive - comprehensive analysis |
| `WEBPKI_QUICK_REFERENCE.md` | Cheat sheet - decision tree & actions |
| `examples/webpki_issue_demo.rs` | Shows the encoding difference clearly |
| `examples/webpki_upstream_test.rs` | Minimal test for webpki PR |
| `examples/openssl_tsa_concept.sh` | Demonstrates OpenSSL alternative |
| `src/crypto/timestamp.rs:449-460` | The TODO comment in question |

---

## FAQ

**Q: Is this a security vulnerability?**
A: No. The current validation prevents untrusted TSAs and ensures cryptographic integrity. Missing full chain validation is a defense-in-depth issue, not a critical flaw.

**Q: Why does the conformance suite pass?**
A: Because other implementations (sigstore-go, sigstore-python) use a similar approach - they validate using certificates from the trusted root, not by chaining embedded certificates.

**Q: Can't we just normalize the certificate encoding?**
A: Technically possible but risky. Certificate re-encoding is fragile and could break signatures if done incorrectly.

**Q: What do I tell auditors?**
A: "We validate certificate identity against our trusted root and verify cryptographic signatures. Full X.509 chain validation is blocked by a library limitation (webpki NULL parameter issue), but compensating controls ensure security. We're tracking this with [issue link] and pursuing an upstream fix."

**Q: Should I use OpenSSL instead?**
A: Only if you have specific compliance requirements for full chain validation. The current approach is secure for most use cases. OpenSSL adds C dependency complexity.

**Q: How do I know if a cert is revoked?**
A: Currently, you don't. Revoked TSA certificates would still be accepted. This is mitigated by short validity periods in the trusted root and the requirement for identity matching.

---

## OpenSSL Option (If Needed)

If you decide to implement OpenSSL validation:

```rust
// Cargo.toml
[features]
openssl-tsa = ["openssl"]

[dependencies]
openssl = { version = "0.10", optional = true }
```

```rust
// src/crypto/timestamp.rs
#[cfg(feature = "openssl-tsa")]
fn validate_tsa_chain_openssl(
    cert_der: &[u8],
    roots: &[CertificateDer],
    intermediates: &[CertificateDer],
) -> Result<(), TimestampError> {
    use openssl::x509::{X509, X509StoreContext, X509Store};
    use openssl::stack::Stack;

    let cert = X509::from_der(cert_der)?;

    // Build trust store
    let mut store_builder = X509Store::builder()?;
    for root in roots {
        let root_cert = X509::from_der(root.as_ref())?;
        store_builder.add_cert(root_cert)?;
    }
    let store = store_builder.build();

    // Build chain
    let mut chain = Stack::new()?;
    for intermediate in intermediates {
        let int_cert = X509::from_der(intermediate.as_ref())?;
        chain.push(int_cert)?;
    }

    // Verify
    let mut context = X509StoreContext::new()?;
    context.init(&store, &cert, &chain, |ctx| {
        ctx.verify_cert()
    })?;

    Ok(())
}
```

See `WEBPKI_TSA_ANALYSIS.md` for complete implementation guidance.

---

## Still Have Questions?

1. Read `WEBPKI_TSA_ANALYSIS.md` for deep technical details
2. Run the tests to see the issue firsthand
3. Check the examples for different approaches

**Bottom line**: Your colleague did excellent work identifying this. The current implementation is secure enough for production, but documenting the limitation and pursuing an upstream fix would be ideal.
