# Rekor v2 Implementation - Handoff Document

## Current Status

### What's Been Done ✅

1. **Investigation Complete**
   - Analyzed sigstore-python's Rekor v2 implementation
   - Analyzed sigstore-go's Rekor v2 implementation
   - Created comprehensive implementation plan
   - Identified the root cause of conformance test failure

2. **Quick Fix Attempted (NEEDS REVERTING)**
   - Added URL-based version detection in `src/bundle/sign.rs`
   - **This is WRONG and should be reverted!**
   - Neither Python nor Go use URL patterns - they use `major_api_version` from config

3. **Conformance CLI Updates (PARTIAL)**
   - Added support for `--signing-config` parameter
   - Upgraded `sigstore_protobuf_specs` to 0.5.0
   - Added parsing of signing config to extract Fulcio URL
   - **Still needs**: Parse `rekor_tlog_urls[].major_api_version`

4. **Test Added**
   - Created unit test for signing config v0.2 parsing
   - Test passes: `test_load_signing_config_v02`

### What's Stashed 📦

The stash contains:
- **Incorrect** URL-based version detection in `src/bundle/sign.rs`
- This should be **replaced** with proper implementation, not restored

### What Needs to Be Done 🚧

**IMPORTANT**: The stashed change is the WRONG approach. Start fresh following the proper plan.

## Implementation Checklist

### Phase 1: Revert Bad Change
- [ ] Revert the URL-based version detection in `src/bundle/sign.rs`
- [ ] Understand that version MUST come from `major_api_version` field

### Phase 2: Foundation (1-2 days)
- [ ] Create `src/rekor/client.rs` with `RekorClient` trait
- [ ] Add `async-trait` dependency to Cargo.toml
- [ ] Update `src/rekor/mod.rs` to expose new modules

### Phase 3: V1 Client Refactor (1 day)
- [ ] Create `src/rekor/client_v1.rs`
- [ ] Implement `RekorV1Client` wrapping existing `entries_api`
- [ ] Verify v1 client works identically to current implementation

### Phase 4: V2 Client Implementation (2-3 days)
- [ ] Create `src/rekor/client_v2.rs`
- [ ] Implement V2 API request format with protobuf
- [ ] **CRITICAL**: Implement key algorithm details extraction
- [ ] Add integration tests against staging Rekor v2

### Phase 5: SigningContext Integration (1-2 days)
- [ ] Update `SigningContext` to use `Box<dyn RekorClient>`
- [ ] Modify `from_trust_root_and_fulcio()` to accept tlog service info
- [ ] Implement client selection based on `major_api_version`

### Phase 6: Conformance CLI Updates (1 day)
- [ ] Parse `rekor_tlog_urls` from signing config
- [ ] Extract `major_api_version` from first tlog service
- [ ] Pass tlog service to `SigningContext::from_trust_root_and_fulcio()`

### Phase 7: Testing & Verification (1-2 days)
- [ ] Run conformance tests
- [ ] Verify `test_sign_verify_rekor2` passes with v0.0.2 entries
- [ ] Verify all 109 tests pass
- [ ] Update documentation

## Key Resources

### Documentation Created
1. **[REKOR_V2_IMPLEMENTATION_PLAN.md](REKOR_V2_IMPLEMENTATION_PLAN.md)**
   - Comprehensive implementation plan
   - Based on sigstore-python architecture
   - Includes code examples, testing strategy, timeline

2. **[SIGSTORE_GO_REKOR_V2_ANALYSIS.md](SIGSTORE_GO_REKOR_V2_ANALYSIS.md)**
   - Detailed analysis of sigstore-go implementation
   - Request/response format comparisons
   - Critical findings about version detection
   - Algorithm details extraction requirements

### Code References
- Python v2 client: `sigstore-python/sigstore/_internal/rekor/client_v2.py`
- Go v2 implementation: `sigstore-go/pkg/sign/transparency.go` (lines 124-206)
- Current conformance CLI: `tests/conformance/conformance.rs`

## Critical Insights

### 1. Version Detection (MOST IMPORTANT!)
```rust
// ❌ WRONG - Do NOT detect from URL
let api_version = if rekor_url.contains("2025") {
    "0.0.2"
} else {
    "0.0.1"
};

// ✅ CORRECT - Use major_api_version from signing config
let rekor_client: Box<dyn RekorClient> = if tlog.major_api_version == 2 {
    Box::new(RekorV2Client::new(tlog.url.clone()))
} else {
    Box::new(RekorV1Client::new(tlog.url.clone()))
};
```

### 2. V2 API is Different, Not Just a Version Number
- V1: POST to `/api/v1/log/entries` with JSON `{"apiVersion": "0.0.1", ...}`
- V2: POST to `/api/v2/log/entries` with protobuf `HashedRekordRequestV002 {...}`

You **cannot** just change the version string and use v1 API!

### 3. Algorithm Details Required for V2
The v2 API requires explicit key algorithm details:
```rust
// Must extract from certificate:
KeyDetails {
    details: EcdsaVerifyingKey {
        curve: NIST_P256,
        sha2_hash: SHA256,
    }
}
```

This is the most complex part of the implementation.

### 4. Test Data Available
- Staging config: `tests/data/signing_config.v0.2.json`
- Test already parses it: `test_load_signing_config_v02` in conformance.rs
- Just need to extract `major_api_version` field

## Quick Start Guide

### Step 1: Understand the Architecture
Read both:
1. [REKOR_V2_IMPLEMENTATION_PLAN.md](REKOR_V2_IMPLEMENTATION_PLAN.md) - overall plan
2. [SIGSTORE_GO_REKOR_V2_ANALYSIS.md](SIGSTORE_GO_REKOR_V2_ANALYSIS.md) - how it really works

### Step 2: Revert the Wrong Change
```bash
# Don't restore the stash! It's the wrong approach.
git checkout src/bundle/sign.rs
```

### Step 3: Start with Foundation
Create the trait structure first:
```rust
// src/rekor/client.rs
#[async_trait]
pub trait RekorClient: Send + Sync {
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry>;
    fn base_url(&self) -> &str;
    fn api_version(&self) -> u32;
}
```

### Step 4: Implement V1 (Easy)
Wrap existing code in trait implementation - should be straightforward.

### Step 5: Tackle V2 (Hard)
Focus on:
1. Protobuf request format
2. Algorithm details extraction (hardest part)
3. Testing against staging

## Testing Commands

```bash
# Build conformance binary
cargo build --release

# Run specific test
cd tests/conformance
cargo test test_load_signing_config_v02

# Run full conformance suite (when ready)
./test-conformance.sh
```

## Success Criteria

1. ✅ `test_sign_verify_rekor2` passes
2. ✅ All 109 conformance tests pass
3. ✅ Can sign with both v1 (production) and v2 (staging) Rekor instances
4. ✅ Client automatically selects correct version based on `major_api_version`
5. ✅ No breaking changes to existing public API

## Common Pitfalls to Avoid

1. **Don't use URL patterns** for version detection
2. **Don't try to use v1 API** with `api_version: "0.0.2"` - it won't work
3. **Don't forget algorithm details** - v2 API requires them
4. **Don't skip the trait structure** - it's critical for clean architecture
5. **Don't forget to test** against real staging Rekor v2 instance

## Questions? Check These First

- **Q: Why not just change the version string?**
  A: V2 uses completely different API (different endpoint, different request format)

- **Q: How do I know which version to use?**
  A: Check `major_api_version` field in signing config's `rekor_tlog_urls[0]`

- **Q: What if URL doesn't contain "2025"?**
  A: That's exactly the problem! Don't use URL patterns. Use `major_api_version`.

- **Q: Can I test locally?**
  A: Yes, use staging config at `tests/data/signing_config.v0.2.json`

## Timeline Estimate

- **Minimum**: 7 days (if everything goes smoothly)
- **Realistic**: 10-12 days (accounting for debugging, testing)
- **Comfortable**: 14 days (with buffer for unknowns)

The algorithm details extraction is the biggest unknown and could add 1-3 days.

## Final Notes

This is a **medium-to-large** refactoring that requires:
- Understanding Rekor APIs (v1 and v2)
- Trait-based architecture in Rust
- Protobuf serialization
- Certificate parsing and algorithm extraction
- Thorough testing

**Do NOT rush this.** Take time to understand the architecture before coding.

The documentation is comprehensive - use it!

Good luck! 🚀
