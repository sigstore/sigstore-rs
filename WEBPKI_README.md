# webpki TSA Certificate Validation Investigation

This directory contains a comprehensive investigation of the webpki certificate validation issue mentioned in the TODO at [src/crypto/timestamp.rs:449-460].

## Quick Start

**Want the summary?** → Read [WEBPKI_SUMMARY.md](WEBPKI_SUMMARY.md)

**Need to decide what to do?** → Read [WEBPKI_QUICK_REFERENCE.md](WEBPKI_QUICK_REFERENCE.md)

**Want all the details?** → Read [WEBPKI_TSA_ANALYSIS.md](WEBPKI_TSA_ANALYSIS.md)

**Want to see it yourself?** → Run the tests below

---

## The Issue in 30 Seconds

Your colleague left a TODO about webpki compatibility issues. It's real: **webpki rejects ECDSA certificates with NULL parameters**, which blocks full X.509 chain validation for TSA certificates.

**However**: The current implementation is **secure**. It validates certificate identity and cryptographic signatures. Full chain validation would be better (defense-in-depth), but it's not a security hole.

**Recommendation**: Document the limitation, pursue upstream fix in webpki.

---

## Run the Tests

All tests validate your colleague's findings and demonstrate different aspects:

```bash
# From repo root
cd /Users/wolfv/Programs/sigstore-rs

# Test 1: Simple validation (PASSES)
# Shows webpki CAN validate when cert has no NULL parameter
cargo run --example webpki_tsa_simple --features verify

# Test 2: Exact reproducer (FAILS as expected)
# Shows webpki REJECTS embedded cert with NULL parameter
cargo run --example webpki_tsa_reproduce_exact --features verify -- \
  --bundle sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
  --trusted-root sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json

# Test 3: Comprehensive analysis (DETAILED)
# Compares both certificates, shows exact encoding difference
cargo run --example webpki_issue_demo --features verify

# Test 4: Upstream test case (MINIMAL)
# Clean reproduction for webpki issue/PR
cargo run --example webpki_upstream_test --features verify

# Test 5: OpenSSL demonstration
# Shows OpenSSL accepts the same certificate
./examples/openssl_tsa_concept.sh
```

---

## Documentation Structure

### 1. [WEBPKI_SUMMARY.md](WEBPKI_SUMMARY.md) - Start Here
**Read this first** if you want a quick understanding.

- ✓ Validates your colleague's findings
- ✓ Explains the security implications
- ✓ Provides recommendations
- ✓ Shows what to do next

**Time to read**: 5-10 minutes

### 2. [WEBPKI_QUICK_REFERENCE.md](WEBPKI_QUICK_REFERENCE.md) - Decision Making
**Read this** when you need to decide what to do.

- Decision tree for solution selection
- Action items by timeline (this week, next month, 3-6 months)
- FAQ for common questions
- Quick security analysis table

**Time to read**: 5 minutes

### 3. [WEBPKI_TSA_ANALYSIS.md](WEBPKI_TSA_ANALYSIS.md) - Deep Dive
**Read this** if you want to understand everything in detail.

- Complete technical analysis
- Security risk assessment
- Evaluation of all alternative solutions
- Implementation guidance for each option
- References to RFCs and external projects

**Time to read**: 20-30 minutes

---

## Test Files

### Core Tests

1. **`examples/webpki_tsa_simple.rs`**
   - Shows webpki CAN validate TSA certs
   - Uses certificate from trusted root (no NULL parameter)
   - Result: ✓ PASSES

2. **`examples/webpki_tsa_reproduce_exact.rs`**
   - Reproduces the exact error from production code
   - Uses embedded certificate from CMS (has NULL parameter)
   - Result: ✗ FAILS with UnsupportedSignatureAlgorithmContext

3. **`examples/webpki_issue_demo.rs`** ⭐ BEST FOR UNDERSTANDING
   - Comprehensive demonstration
   - Extracts both certificates
   - Compares encoding byte-by-byte
   - Tests both with webpki
   - Shows exact difference (NULL parameter)
   - Result: Detailed analysis output

### Upstream Contribution

4. **`examples/webpki_upstream_test.rs`**
   - Minimal, clean test case
   - Suitable for webpki issue/PR
   - Well-commented for upstream audience
   - Result: Clean failure demonstrating the issue

### Alternative Approach

5. **`examples/openssl_tsa_concept.sh`**
   - Bash script showing OpenSSL validation
   - Demonstrates OpenSSL accepts NULL parameters
   - Shows what an OpenSSL implementation could do
   - Result: OpenSSL successfully parses the cert

---

## Key Findings

### ✓ Your Colleague Was Correct

The TODO is accurate. webpki does reject these certificates:

```
Error: UnsupportedSignatureAlgorithmContext {
    signature_algorithm_id: [06, 08, 2a, 86, 48, ce, 3d, 04, 03, 03, 05, 00],
    ...
}
```

Breaking down those bytes:
- `06 08 2a 86 48 ce 3d 04 03 03` = OID for ECDSA-with-SHA384
- `05 00` = NULL parameter ← **THIS IS THE PROBLEM**

### ✓ Current Implementation Is Secure

The code validates:
1. **Cryptographic signature** - Timestamp is cryptographically valid (CMS verification)
2. **Certificate identity** - Embedded cert matches trusted TSA cert
3. **Validity periods** - Timestamp and certificate are not expired
4. **Trusted root** - TSA must be in our trusted root

### ✗ Missing (But Not Critical)

1. **Full X.509 chain validation** - Would catch more edge cases
2. **Revocation checking** - Would detect compromised certificates
3. **CA constraints** - Would enforce intermediate CA policies

### ✓ Conformance Suite Passes

The sigstore conformance tests pass without full chain validation, indicating this approach is acceptable.

### ✓ Other Implementations Similar

Both sigstore-go and sigstore-python use certificates from the trusted root, not embedded certificates, for validation.

---

## Recommended Path Forward

### Short-term (This Week) ✓

**Accept current implementation, improve documentation**

1. Enhance the TODO comment in [src/crypto/timestamp.rs:449-460]
2. Add module-level documentation explaining the approach
3. File a tracking issue in sigstore-rs
4. Link to this analysis

**Effort**: Low (few hours)
**Risk**: None (no code changes)

### Medium-term (1-3 Months) ✓

**Engage with webpki upstream**

1. Research existing webpki issues about NULL parameters
2. File issue at https://github.com/rustls/webpki with:
   - `webpki_upstream_test.rs` as reproduction
   - RFC 5480 references
   - Sigstore ecosystem impact
3. Submit PR if welcomed

**Effort**: Medium (community engagement)
**Benefit**: High (fixes it for everyone)

### Long-term (3-6 Months)

**Re-enable full validation OR add OpenSSL option**

If webpki accepts the fix:
- Update dependency
- Re-enable chain validation
- Test with conformance suite

If webpki rejects:
- Consider OpenSSL feature flag (see analysis doc)
- Or document as permanent limitation

---

## Decision Matrix

| Requirement | Current | +Document | +webpki Fix | +OpenSSL |
|-------------|---------|-----------|-------------|----------|
| Conformance Suite | ✓ | ✓ | ✓ | ✓ |
| Identity Validation | ✓ | ✓ | ✓ | ✓ |
| Signature Validation | ✓ | ✓ | ✓ | ✓ |
| Full Chain Validation | ✗ | ✗ | ✓ | ✓ |
| Revocation Checking | ✗ | ✗ | ✗ | ✓* |
| Pure Rust | ✓ | ✓ | ✓ | ✗ |
| Effort | 0 | Low | Med | High |
| Risk | Low | Low | Low | Med |

*OpenSSL can check revocation if implemented

**Recommendation**: Start with "Document", pursue "webpki Fix"

---

## How to Use This Investigation

### If you're a maintainer deciding what to do:
1. Read [WEBPKI_SUMMARY.md](WEBPKI_SUMMARY.md)
2. Check [WEBPKI_QUICK_REFERENCE.md](WEBPKI_QUICK_REFERENCE.md) decision tree
3. Run `webpki_issue_demo` to see it yourself
4. Choose approach based on timeline/requirements

### If you're investigating security:
1. Read [WEBPKI_TSA_ANALYSIS.md](WEBPKI_TSA_ANALYSIS.md) security section
2. Run all tests to validate findings
3. Review current validation code in [src/crypto/timestamp.rs]
4. Evaluate risk based on your threat model

### If you're filing an upstream issue:
1. Use `webpki_upstream_test.rs` as reproduction
2. Reference [WEBPKI_TSA_ANALYSIS.md](WEBPKI_TSA_ANALYSIS.md) for context
3. Point to RFC 5480 section 2.1.1
4. Explain Sigstore ecosystem impact

### If you're implementing a fix:
1. Read [WEBPKI_TSA_ANALYSIS.md](WEBPKI_TSA_ANALYSIS.md) implementation sections
2. Choose Option A (webpki fix) or B (OpenSSL feature)
3. Follow implementation guidance in the analysis
4. Test with all provided test cases

---

## Questions & Answers

**Q: Is this a security vulnerability?**
No. Current validation prevents untrusted TSAs and ensures cryptographic integrity. Missing full chain validation is defense-in-depth, not critical.

**Q: Do I need to do anything urgently?**
No. The conformance suite passes and the implementation is secure. Document the limitation and plan to address it upstream.

**Q: Why can't we just fix the certificate encoding?**
Certificate re-encoding is risky and complex. It could break signatures. Better to fix the validator (webpki) than modify certificates.

**Q: What would full chain validation give us?**
- Detect revoked certificates (if CRL/OCSP checked)
- Enforce CA constraints and policies
- More defense-in-depth
- Better compliance story

**Q: Is webpki wrong to reject NULL parameters?**
It depends. RFC 5480 says parameters "SHOULD be absent" for ECDSA. webpki interprets this strictly. Other implementations (OpenSSL, Go) are more permissive.

**Q: What do other sigstore implementations do?**
They use certificates from the trusted root for validation, not embedded certificates. Similar approach to ours.

---

## Files Created

| File | Purpose | Size |
|------|---------|------|
| `WEBPKI_README.md` | This file - navigation guide | You are here |
| `WEBPKI_SUMMARY.md` | Quick summary - start here | 5 min read |
| `WEBPKI_QUICK_REFERENCE.md` | Decision tree & actions | 5 min read |
| `WEBPKI_TSA_ANALYSIS.md` | Deep dive analysis | 20 min read |
| `examples/webpki_tsa_simple.rs` | Test: simple validation (passes) | Run to see |
| `examples/webpki_tsa_reproduce_exact.rs` | Test: exact error (fails) | Run to see |
| `examples/webpki_issue_demo.rs` | Test: comprehensive demo | Run to see |
| `examples/webpki_upstream_test.rs` | Test: for webpki PR | Run to see |
| `examples/openssl_tsa_concept.sh` | Demo: OpenSSL validation | Run to see |

---

## Credit

This investigation was triggered by an excellent TODO left by your colleague. They correctly identified a real compatibility issue and documented it clearly. This analysis validates their findings and provides a path forward.

---

## Next Steps

1. **Today**: Run `webpki_issue_demo` to see the issue
2. **This week**: Read the summary and decide on approach
3. **Next month**: File webpki issue if pursuing upstream fix
4. **3-6 months**: Re-evaluate based on webpki response

The issue is real, but not urgent. Take time to make the right decision for your project's needs.
