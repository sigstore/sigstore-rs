# Debug Code Cleanup Guide

This guide shows all debug code that was added during DSSE troubleshooting and needs to be removed.

## Summary of Changes

- ✅ **Fixed**: DSSE envelope now stores raw payload bytes instead of base64 string
- ✅ **Fixed**: Added `dsse` variant to Rekor log entry Body enum
- ❌ **TODO**: Remove 54+ debug statements added during troubleshooting

## Files to Clean

### 1. src/bundle/sign.rs (PRIORITY: HIGH)

**Lines to Remove:** All `eprintln!()` and `std::fs::write(/tmp/...)` calls

#### Section 1: materials() function (lines ~118-160)
Remove all debug logging that validates public key matching.

**KEEP:**
```rust
let cert_req = builder.build::<p256::ecdsa::DerSignature>()?;
let certs = fulcio.request_cert_v2(cert_req, token).await?;
Ok((private_key, certs))
```

**REMOVE:** All eprintln! statements between these lines

#### Section 2: sign_dsse() function (lines ~253-430)
This has the most debug code. Remove all:
- `eprintln!("[1]...` through `eprintln!("[7]...` statements
- `std::fs::write("/tmp/rust-statement.json", ...)`
- `std::fs::write("/tmp/rust-pae-bytes.bin", ...)`
- `std::fs::write("/tmp/rust-cert-debug.pem", ...)`
- Debug PAE verification section
- Debug error handling in the catch block

**KEEP this core logic:**
```rust
// Create the DSSE envelope
let mut envelope = dsse::create_envelope(statement)
    .map_err(|e| SigstoreError::UnexpectedError(format!("Failed to create DSSE envelope: {}", e)))?;

// Compute the PAE
let pae_bytes = dsse::pae(&envelope);

// Sign the PAE
let pae_signature: p256::ecdsa::Signature = self.private_key.sign(&pae_bytes);
let signature_bytes = pae_signature.to_der().as_bytes().to_owned();

// Add signature to envelope
dsse::add_signature(&mut envelope, signature_bytes.clone(), String::new());

let cert = &self.certs.cert;
let cert_pem = cert.to_pem(pkcs8::LineEnding::LF)?;
let cert_base64 = base64.encode(cert_pem.as_bytes());

// Build the DSSE envelope JSON for Rekor v0.0.1
let envelope_json = serde_json::json!({
    "payload": base64.encode(&envelope.payload),
    "payloadType": envelope.payload_type.clone(),
    "signatures": envelope.signatures.iter().map(|sig| {
        serde_json::json!({
            "sig": base64.encode(&sig.sig),
        })
    }).collect::<Vec_>(),
});

let envelope_json_string = serde_json::to_string(&envelope_json)
    .map_err(|e| SigstoreError::UnexpectedError(format!("Failed to serialize envelope: {}", e)))?;

// Use "dsse" kind with v0.0.1 API
let proposed_entry = ProposedLogEntry::Dsse {
    api_version: "0.0.1".to_owned(),
    spec: serde_json::json!({
        "proposedContent": {
            "envelope": envelope_json_string,
            "verifiers": [cert_base64],
        },
    }),
};

let log_entry = create_log_entry(&self.context.rekor_config, proposed_entry).await?;
```

**REMOVE:** Lines with computed but unused variables:
```rust
let _rekor_signatures = ...  // Line ~332 - not used
let pae_hash = Sha256::digest(&pae_bytes);  // Line ~296 - only for debug
let test_pae = dsse::pae(&envelope);  // Line ~400 - duplicate PAE computation
```

### 2. src/bundle/dsse.rs (PRIORITY: MEDIUM)

**Line 22:** Remove unused imports
```diff
-use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
```

The base64 encoding is now done in sign.rs when creating the JSON, not in dsse.rs.

### 3. src/bin/sigstore-cli.rs (PRIORITY: LOW)

Search for any `eprintln!` with "DEBUG" or debug output and remove them.

### 4. cosign/cmd/cosign/cli/attest/attest_blob.go (PRIORITY: MEDIUM)

**Line ~67:** Remove debug marker
```diff
-fmt.Fprintln(os.Stderr, ">>>>>>>>>> DEBUG BUILD OF COSIGN <<<<<<<<<<")
```

### 5. cosign/cmd/cosign/cli/signcommon/common.go (PRIORITY: HIGH)

**Lines ~484-514:** Remove all debug output from `WriteNewBundleWithSigningConfig`

```diff
-fmt.Fprintln(os.Stderr, "\n>>>>>>>>>> INSIDE WriteNewBundleWithSigningConfig <<<<<<<<<<")
-fmt.Fprintln(os.Stderr, "========== COSIGN DEBUG: WriteNewBundleWithSigningConfig ==========")
-fmt.Fprintf(os.Stderr, "[1] Statement JSON (payload) length: %d bytes\n", len(payload))
-fmt.Fprintf(os.Stderr, "[1] Statement JSON content:\n%s\n", string(payload))
-fmt.Fprintf(os.Stderr, "[1] Payload hex (FULL): %x\n", payload)
-os.WriteFile("/tmp/cosign-statement.json", payload, 0644)
-fmt.Fprintln(os.Stderr, "[1] Written to /tmp/cosign-statement.json")
-fmt.Fprintln(os.Stderr, "[2] About to call cbundle.SignData")
-fmt.Fprintln(os.Stderr, "[3] SignData completed successfully")
-fmt.Fprintf(os.Stderr, "[3] Bundle length: %d bytes\n", len(bundle))
-fmt.Fprintf(os.Stderr, "[3] Bundle content (first 500 chars):\n%s\n", string(bundle[:min(500, len(bundle))]))
-os.WriteFile("/tmp/cosign-bundle-raw.json", bundle, 0644)
-fmt.Fprintln(os.Stderr, "[3] Written to /tmp/cosign-bundle-raw.json")
-fmt.Fprintln(os.Stderr, "==========================================================\n")
```

**Lines ~527-546:** Remove debug output from `GetBundleComponents`

```diff
-fmt.Fprintln(os.Stderr, "\n>>>>>>>>>> INSIDE GetBundleComponents <<<<<<<<<<")
-fmt.Fprintln(os.Stderr, "========== COSIGN DEBUG: GetBundleComponents ==========")
-fmt.Fprintf(os.Stderr, "[1] Statement JSON (payload) length: %d bytes\n", len(payload))
-fmt.Fprintf(os.Stderr, "[1] Statement JSON content:\n%s\n", string(payload))
-fmt.Fprintf(os.Stderr, "[1] Payload hex (FULL): %x\n", payload)
-os.WriteFile("/tmp/cosign-statement.json", payload, 0644)
-fmt.Fprintln(os.Stderr, "[1] Written to /tmp/cosign-statement.json")
-fmt.Fprintln(os.Stderr, ">>>>>>>>>> ABOUT TO CALL wrapped.SignMessage <<<<<<<<<<")
-fmt.Fprintln(os.Stderr, "[2] SignedPayload (DSSE envelope) length: %d bytes\n", len(bc.SignedPayload))
-fmt.Fprintf(os.Stderr, "[2] SignedPayload content:\n%s\n", string(bc.SignedPayload))
-os.WriteFile("/tmp/cosign-envelope.json", bc.SignedPayload, 0644)
-fmt.Fprintln(os.Stderr, "[2] Written to /tmp/cosign-envelope.json")
-fmt.Fprintln(os.Stderr, "==========================================================\n\n")
```

### 6. cosign/internal/pkg/cosign/payload/attestor.go (PRIORITY: LOW)

This file might not actually be used by attest-blob, but if it has debug output, remove:
- All `fmt.Fprintf(os.Stderr, "...")` lines
- `os.WriteFile("/tmp/cosign-pae-bytes.bin", ...)` line

## Quick Cleanup Commands

### For Rust files:
```bash
# Backup first!
cp src/bundle/sign.rs src/bundle/sign.rs.backup

# Remove debug lines (be careful with this!)
sed -i.bak '/eprintln!/d; /std::fs::write.*\/tmp\//d' src/bundle/sign.rs

# Remove unused imports
sed -i.bak '/use base64::{Engine as _, engine::general_purpose::STANDARD as base64};/d' src/bundle/dsse.rs

# Check for any remaining debug in CLI
grep -n "eprintln.*DEBUG" src/bin/sigstore-cli.rs
```

### For Go files:
```bash
# Backup first!
cp cosign/cmd/cosign/cli/attest/attest_blob.go cosign/cmd/cosign/cli/attest/attest_blob.go.backup
cp cosign/cmd/cosign/cli/signcommon/common.go cosign/cmd/cosign/cli/signcommon/common.go.backup

# Remove debug marker from attest_blob.go
sed -i.bak '/>>>>>>>>>> DEBUG BUILD OF COSIGN <<<<<<<<<<</ d' cosign/cmd/cosign/cli/attest/attest_blob.go

# For common.go, manual editing is recommended due to complexity
```

## Verification After Cleanup

1. **Compile and test Rust:**
   ```bash
   cargo build --features="sign,full,clap,sigstore-trust-root"
   cargo test
   ```

2. **Compile and test cosign:**
   ```bash
   cd cosign && make cosign
   ```

3. **Run a test attestation:**
   ```bash
   cargo r --bin sigstore-cli --features="sign,full,clap,sigstore-trust-root" -- attest-blob README.md --type https://example.com/predicate/v1 --bundle /tmp/test.json
   ```

4. **Verify no debug output** in stderr (should only see normal user-facing messages)

## Important Notes

- The core DSSE fix (raw bytes vs base64) should remain
- The `dsse` variant in log_entry.rs Body enum should remain
- Only remove debug/instrumentation code added during troubleshooting
- Test thoroughly after cleanup to ensure functionality wasn't broken

## Summary of What to KEEP

These are the actual fixes, not debug code:

1. **src/bundle/dsse.rs:82-88** - Store raw payload bytes (not base64)
2. **src/bundle/sign.rs:400** - Base64 encode only when creating JSON
3. **src/rekor/models/log_entry.rs:72** - `dsse(IntotoAllOf)` variant
4. **TODO-rekor-v2.md** - V2 API implementation guide
