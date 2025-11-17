# Remaining Work for Full Conformance

## Current Status

**94 passed, 10 failed** out of 104 conformance tests

## Failures (Tests that should fail but pass)

### 1. Checkpoint Validation (6 tests) - MEDIUM PRIORITY

Tests:
- `checkpoint-bad-keyhint_fail`
- `checkpoint-wrong-roothash_fail`
- `invalid-checkpoint-signature_fail`

**Issue**: These tests don't have `trusted_root.json` files - they use production trusted root. Our CLI requires an explicit trusted root file.

**What needs to be done**:
1. Add support for loading production trusted root when no `--trusted-root` is specified
2. The checkpoint validation code already exists and should work correctly
3. Once production trusted root is loaded, these tests should pass

**Code locations**:
- Checkpoint validation: `src/bundle/verify/verifier.rs:286-400` (already implemented)
- Need to add: Production trusted root loading in CLI

### 2. TSA Timestamp vs Signing Certificate Validity (2 tests) - LOW PRIORITY

Tests:
- `intoto-tsa-timestamp-outside-cert-validity_fail`

**Issue**: We validate that timestamps are within TSA certificate validity, but not that they're within the **signing certificate** validity period.

**What needs to be done**:
1. After getting timestamp from TSA, verify it falls within signing cert's notBefore/notAfter
2. This ensures the signing cert was valid when the signature was created

**Code location**:
- Add check in `src/bundle/verify/verifier.rs` after timestamp verification
- Check timestamp against `cert.tbs_certificate.validity`

### 3. Untrusted TSA (2 tests) - UNCLEAR

Tests:
- `rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail`

**Issue**: Unclear how this should fail. Reference implementations (sigstore-go, sigstore-python) don't validate embedded certificates against trusted roots - they use TSA certs from trusted root.

**What needs to be done**:
1. Investigate what "untrusted TSA" means in this context
2. Check sigstore-go/python to see how they handle this
3. Might be related to production trusted root issue (test has no trusted_root.json)

**Needs investigation**.

## Summary

The main blocker is **production trusted root support**. Once that's added:
- 6 checkpoint tests should automatically pass
- 2 untrusted TSA tests might pass
- Leaves only 2 intoto tests needing timestamp-vs-signing-cert validation

## Priority Order

1. **HIGH**: Add production trusted root loading (fixes 6-8 tests)
2. **LOW**: Add timestamp-vs-signing-cert validity check (fixes 2 tests)
3. **INVESTIGATE**: Understand untrusted TSA requirement

With these fixes, we should achieve 100% conformance test pass rate!
