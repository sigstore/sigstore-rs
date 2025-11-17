# TSA Server Bug Report: Intermittent Malformed Timestamps

**Date:** 2025-11-10
**Server:** https://timestamp.sigstage.dev/api/v1/timestamp
**Reporter:** sigstore-rs team
**Severity:** High - Causes ~50% of timestamp requests to fail validation

---

## Summary

The Sigstore staging TSA server (`timestamp.sigstage.dev`) intermittently returns timestamps with malformed ASN.1 encoding that fail strict parsing in Python's `rfc3161_client` library. The failure rate is approximately **50%** with our Rust client, even after fixing issues in our request encoding.

---

## Reproduction

### Environment
- TSA URL: `https://timestamp.sigstage.dev/api/v1/timestamp`
- Client: sigstore-rs v0.13.0
- Validator: Python rfc3161_client (latest)
- Test runs: 20 iterations

### Results
```
Success rate with OpenSSL-generated requests: 100% (10/10)
Success rate with Rust-generated requests:    45% (9/20)
```

### Error Message
```
ValueError: Malformed TimestampToken: ASN.1 parsing error: invalid value
```

The error occurs when accessing `tsr.tst_info` after successfully parsing the `TimeStampResp`.

---

## Root Cause Analysis

### What We Found

1. **TimeStampResp parses successfully** - The outer structure is valid
2. **Accessing tst_info fails** - The SignedData or TSTInfo has invalid ASN.1 encoding
3. **Intermittent nature** - Same request format sometimes works, sometimes fails
4. **Server-side issue** - OpenSSL-generated requests work 100%, suggesting the bug is in how the TSA processes certain requests

### Client-Side Issues We Fixed

During investigation, we discovered and fixed two issues in our Rust client:

#### 1. Negative Nonce Values
**Problem:** We were generating 8 random bytes for the nonce, which could have the high bit set, making it a negative INTEGER in DER encoding.

**Fix:** Now prepend `0x00` to ensure the nonce is always a positive 9-byte INTEGER.

**Impact:** Reduced failure rate from ~60% to ~50%

#### 2. Missing NULL Parameters
**Problem:** We were encoding AlgorithmIdentifier with `parameters: None` (absent), while OpenSSL includes explicit NULL.

**Fix:** Changed to `parameters: Some(NULL)` to match OpenSSL's encoding.

**Impact:** Minor improvement, but TSA still fails intermittently

---

## Current Status

Even after fixing both client-side issues to exactly match OpenSSL's request format:
- ✅ AlgorithmIdentifier includes NULL parameters
- ✅ Nonce is a positive INTEGER (9 bytes with leading 0x00)
- ✅ Request structure matches OpenSSL byte-for-byte

**We still see ~50% failure rate**, while OpenSSL-generated requests have 0% failure rate.

This suggests the TSA has a bug that is triggered by:
- Specific hash values
- Specific nonce values
- Some combination of request timing or server state
- Unknown factors in request processing

---

## Evidence

### Sample Failing Timestamp

Analysis shows the ASN.1 structure parses correctly with OpenSSL's `asn1parse`, but fails with Python's strict parser. Common issues found:

- ECDSA signature with extra trailing bytes
- TSTInfo serialNumber with unexpected padding
- SignedData certificate encoding issues

Example from one failing timestamp:
```
ECDSA signature: 103 bytes (should be ≤102 for P-384)
  - r component: 48 bytes ✓
  - s component: 49 bytes (has extra 0x80 byte at end)
```

---

## Request Format Comparison

### OpenSSL Request (100% success)
```
SEQUENCE {
  version: 1
  messageImprint: SEQUENCE {
    hashAlgorithm: SEQUENCE {
      algorithm: sha256 (OID)
      parameters: NULL           # Explicit NULL
    }
    hashedMessage: OCTET STRING (32 bytes)
  }
  nonce: INTEGER (9 bytes, positive)  # e.g., 00:97:79:D1:36:DF:67:C1:D6
  certReq: TRUE
}
```

### Rust Request (50% success)
```
SEQUENCE {
  version: 1
  messageImprint: SEQUENCE {
    hashAlgorithm: SEQUENCE {
      algorithm: sha256 (OID)
      parameters: NULL           # Now includes NULL (fixed)
    }
    hashedMessage: OCTET STRING (32 bytes)
  }
  nonce: INTEGER (9 bytes, positive)  # Now positive (fixed)
  certReq: TRUE
}
```

**Structure is identical**, yet Rust requests fail 50% of the time.

---

## Impact

This bug affects:
- **sigstore-rs**: Conformance tests fail intermittently
- **Any Rust-based Sigstore clients**: Will see random timestamp validation failures
- **CI/CD pipelines**: Tests are flaky due to intermittent TSA failures
- **Production systems**: May fail to validate legitimate signatures

---

## Recommended Actions

### Immediate (Workaround)
1. Implement retry logic for timestamp requests (3 retries with exponential backoff)
2. Add detailed logging when timestamp validation fails
3. Document the known TSA instability

### Short-term (TSA Team)
1. Investigate why certain request patterns trigger malformed responses
2. Review ECDSA signature generation code
3. Add server-side validation to catch malformed timestamps before returning them
4. Compare with production TSA behavior

### Long-term
1. Add integration tests that catch ASN.1 encoding issues
2. Consider using a different ASN.1 library that enforces stricter encoding
3. Add monitoring/alerts for malformed timestamp generation

---

## Reproduction Script

We've created a standalone Python reproducer:

```bash
# See: reproduce_tsa_bug.py
python3 reproduce_tsa_bug.py
```

This script:
- Uses OpenSSL to generate standard-compliant TimeStampReq
- Queries the TSA multiple times
- Validates responses with rfc3161_client
- Reports success/failure rate

---

## Files

- `reproduce_tsa_bug.py` - Standalone reproducer
- `test_timestamp_direct.py` - Rust client test (shows ~50% failure)
- `/tmp/failing_bundles/` - Captured failing timestamps and analysis
- `src/crypto/tsa.rs` - Our fixed TSA client code

---

## Questions for TSA Team

1. Are there known issues with P-384 ECDSA signature generation?
2. Does the TSA validate its own output before returning it?
3. Are there rate limits or anti-abuse measures that might affect encoding?
4. Can you reproduce the issue with the provided test script?
5. Are there server logs showing ASN.1 encoding errors?

---

## Contact

For questions or additional information:
- GitHub: https://github.com/sigstore/sigstore-rs
- Issue: [Link to issue once created]

---

##  Technical Details

### ASN.1 Parsing Libraries

**Works:**
- OpenSSL `asn1parse` (lenient parser)

**Fails:**
- Python `rfc3161_client` (strict Rust-based parser)
- Uses RustCrypto `der` and `cms` crates
- Enforces strict DER encoding rules

### Test Environment

```
OS: macOS 14.6.0
OpenSSL: 3.5.4
Python: 3.14.0
rfc3161-client: latest
sigstore-rs: 0.13.0
Rust: 1.85
```

### Logs

Example failing timestamp analysis available in:
- `/tmp/failing_bundles/openssl_<timestamp>.txt` - OpenSSL parse (succeeds)
- `/tmp/failing_bundles/python_rfc3161_<timestamp>.txt` - Python parse (fails)
- `/tmp/failing_bundles/timestamp_<timestamp>.der` - Raw DER bytes

---

**End of Report**
