# Timestamp Token Analysis

## Issue
Python's `rfc3161_client` fails to parse timestamp tokens created by our Rust implementation with error:
```
ValueError: Malformed TimestampToken: ASN.1 parsing error: invalid value
```

## Fix Applied
Changed `AlgorithmIdentifier` parameters from `Some(Null)` to `None` in [src/crypto/tsa.rs:85](src/crypto/tsa.rs#L85):

```rust
// Before (BROKEN):
hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ID_SHA_256,
    parameters: Some(x509_cert::der::asn1::Null.into()),
},

// After (FIXED):
hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ID_SHA_256,
    parameters: None,  // Absent, not NULL
},
```

## Root Cause
According to RFC 4055 section 2.1, the `AlgorithmIdentifier` parameters for SHA-256 **SHOULD** be either:
1. Absent (None)
2. Present with value NULL

While both are technically valid, setting `parameters: Some(Null)` causes the TSA at `timestamp.sigstage.dev` to return a malformed response that Python's `rfc3161_client` cannot parse.

## How We Store Timestamps
In [src/bundle/sign.rs:724-733](src/bundle/sign.rs#L724-L733), we store the raw TimeStampResp bytes from the TSA:

```rust
let timestamp_verification_data =
    self.tsa_timestamp
        .map(|timestamp_bytes| TimestampVerificationData {
            rfc3161_timestamps: vec![
            sigstore_protobuf_specs::dev::sigstore::common::v1::Rfc3161SignedTimestamp {
                signed_timestamp: timestamp_bytes,  // Raw DER-encoded TimeStampResp
            },
        ],
        });
```

The `timestamp_bytes` come from [src/crypto/tsa.rs:179](src/crypto/tsa.rs#L179) which returns the full HTTP response body from the TSA (DER-encoded `TimeStampResp`).

## Working Example
A working timestamp from `tests/data/dsse_bundle.sigstore.json`:
- Length: 1259 bytes
- Structure: Complete `TimeStampResp` with status + `TimeStampToken`
- First bytes: `308204e73003020100308204de...`

## Verification
After applying the fix and doing a clean rebuild:
```bash
cargo clean --manifest-path=tests/conformance/Cargo.toml
cargo build --manifest-path=tests/conformance/Cargo.toml --release
sh test-conformance.sh -k test_sign_verify_rekor2
```

Result: ✅ PASSED

## Files Modified
1. [src/crypto/tsa.rs](src/crypto/tsa.rs#L79-L95) - Changed `parameters` from `Some(Null)` to `None`
2. [src/crypto/tsa.rs](src/crypto/tsa.rs#L150-L177) - Added validation for TimeStampResp status and token presence

## To Extract and Compare Timestamps

Use the provided `extract_timestamp.py` script:
```bash
python3 extract_timestamp.py <bundle.sigstore.json>
```

This will:
1. Extract the base64-encoded timestamp
2. Decode to DER format
3. Write to `/tmp/timestamp_N.der`
4. Parse with OpenSSL for inspection
