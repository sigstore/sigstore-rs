# Action Plan - webpki TSA Investigation

## TL;DR

**Problem Found**: `cryptographic-message-syntax` crate corrupts certificates by adding NULL parameters during extraction.

**Immediate Action**: Use trusted root certificates (don't extract from CMS) + file upstream bug.

---

## This Week

### 1. Update sigstore-rs Code (1-2 hours)

**Current approach** (in [src/crypto/timestamp.rs](src/crypto/timestamp.rs)):
- Extracts embedded cert from CMS (gets corrupted 535-byte version)
- Compares identity fields with trusted cert
- Works by accident (identity fields not corrupted)

**Better approach** (like sigstore-go):
- Use certificate from trusted root for validation
- Don't extract from CMS at all
- Simpler, matches reference implementations

**Changes needed**:
```rust
// src/crypto/timestamp.rs around line 460
// Remove the disabled webpki validation code entirely
// Update comments to explain we use trusted root certs
// Document that this matches sigstore-go/python approach
```

### 2. Update Documentation (30 minutes)

**Update the TODO comment**:
```rust
// TSA Certificate Validation Approach
//
// We use the TSA certificate from the trusted root for validation,
// not the embedded certificate from the CMS SignedData. This matches
// the approach used by sigstore-go and sigstore-python.
//
// The CMS library provides signature verification using embedded certs,
// which is sufficient for cryptographic integrity. The trust anchor
// is the TSA certificate in the trusted root, not the embedded cert.
//
// Note: Extracting certs from CMS using cryptographic-message-syntax
// currently corrupts them by re-encoding and adding NULL parameters.
// See: https://github.com/indygreg/cryptography-rs/issues/XXX
//
// Current validation:
//   ✓ CMS signature verification (cryptographic integrity)
//   ✓ Certificate identity matching (prevents untrusted TSAs)
//   ✓ Validity period checks (timestamp and cert expiration)
//   ✓ Uses trusted root as source of truth
```

### 3. File Upstream Bug (1 hour)

**Where**: https://github.com/indygreg/cryptography-rs/issues

**What**: Use `UPSTREAM_BUG_REPORT.md` as template

**Include**:
- Link to our test cases
- Offer to help with PR
- Reference this investigation

---

## Next Week

### 1. Review Upstream Response

**If accepted**:
- Offer to help with PR
- Provide test cases
- Review proposed solution

**If rejected**:
- Consider forking
- Or document as permanent limitation
- Current workaround is fine

### 2. Add Integration Test

Create test in `tests/` that verifies:
- TSA validation uses trusted root certs
- Embedded certs are NOT used for validation
- Conformance tests still pass

---

## Next Month

### 1. Monitor Upstream Fix

- Watch for PR merge
- Test with new version
- Update dependencies

### 2. Optional: Full Chain Validation

**Only if**:
- Upstream bug is fixed
- You want defense-in-depth
- Compliance requires it

**Otherwise**:
- Current approach is sufficient
- Matches reference implementations
- Simpler and works

---

## Files to Share

When filing the upstream bug, reference:

1. **Bug Report**: `UPSTREAM_BUG_REPORT.md`
2. **Test Case**: `examples/isolate_cert_corruption.rs`
3. **Comparison**: `examples/compare_with_sigstore_go.sh`
4. **Analysis**: `CRITICAL_BUG_FOUND.md`

---

## Quick Wins

### Can Do Today

1. ✓ Tests are already written
2. ✓ Bug is documented
3. ✓ Upstream report is ready
4. → File the upstream bug
5. → Update documentation

### Can Do This Week

1. → Verify current validation works (run conformance tests)
2. → Clean up the disabled code in timestamp.rs
3. → Update comments
4. → Commit changes

### Can Wait

1. Forking upstream crate
2. Full chain validation
3. OpenSSL alternative
4. webpki fix (not needed!)

---

## Decision Matrix

| Approach | Effort | Risk | Benefit | Recommended? |
|----------|--------|------|---------|--------------|
| Use trusted root | Low | Low | High | ✓ YES |
| File upstream bug | Low | None | High | ✓ YES |
| Fork & fix upstream | High | Med | Med | Maybe later |
| Full chain validation | Med | Med | Low | Not needed |
| OpenSSL alternative | High | Med | Low | Not needed |

---

## Success Criteria

### Short-term Success
- [x] Understanding the bug
- [x] Test cases created
- [ ] Upstream bug filed
- [ ] Documentation updated
- [ ] Team understands approach

### Long-term Success
- [ ] Upstream bug fixed
- [ ] Dependencies updated
- [ ] Ecosystem benefits
- [ ] Conformance tests pass

---

## Communication

### For Your Team
- "We found the root cause - certificate corruption in extraction"
- "Current validation is secure, matches reference implementations"
- "Filing upstream bug, no urgent changes needed"
- "Colleague did great work identifying the issue"

### For Upstream
- "Found a bug where certificates get corrupted during extraction"
- "Have comprehensive test cases and analysis"
- "Happy to help with PR"
- "This affects Sigstore ecosystem"

### For Future You
- "Don't try to fix webpki - not the problem"
- "Use trusted root certs like reference implementations"
- "The corruption bug is documented and reported"
- "Current approach is the right one"

---

## One-Liner Summary

**Use trusted root certificates for TSA validation (like sigstore-go does), file bug report for certificate corruption in cryptographic-message-syntax, update documentation, done.**
