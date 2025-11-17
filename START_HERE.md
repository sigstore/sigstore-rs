# Rekor v2 Implementation - Start Here! 🚀

## TL;DR

Your task: Implement Rekor v2 API support so the conformance test `test_sign_verify_rekor2` passes.

**Current status**: 108/109 tests pass. The failing test expects `hashedrekord` v0.0.2 entries but we create v0.0.1.

**Why it fails**: We only support Rekor v1 API. Staging uses Rekor v2 which requires different API calls.

## Read These Documents IN ORDER

### 1. [REKOR_V2_HANDOFF.md](REKOR_V2_HANDOFF.md) ⭐ START HERE
- Current status and what's been done
- Implementation checklist
- Critical insights
- Common pitfalls to avoid

### 2. [SIGSTORE_GO_REKOR_V2_ANALYSIS.md](SIGSTORE_GO_REKOR_V2_ANALYSIS.md) 📖 ESSENTIAL
- How sigstore-go actually implements v2
- **Critical**: Version detection from `major_api_version`, NOT URL!
- Request/response format differences
- Algorithm details extraction requirements

### 3. [REKOR_V2_IMPLEMENTATION_PLAN.md](REKOR_V2_IMPLEMENTATION_PLAN.md) 🗺️ ROADMAP
- Detailed implementation plan
- Code examples and architecture
- Testing strategy
- Timeline estimates

## The One Thing You Must Know

```rust
// ❌ WRONG - The stashed code does this (DO NOT USE!)
let version = if url.contains("2025") { "0.0.2" } else { "0.0.1" };

// ✅ CORRECT - What you need to implement
let client = if tlog.major_api_version == 2 {
    RekorV2Client::new(tlog.url)  // Uses /api/v2 endpoint with protobuf
} else {
    RekorV1Client::new(tlog.url)  // Uses /api/v1 endpoint
};
```

## Quick Start

```bash
# 1. Read the handoff document
cat REKOR_V2_HANDOFF.md

# 2. Read the analysis
cat SIGSTORE_GO_REKOR_V2_ANALYSIS.md

# 3. Read the implementation plan
cat REKOR_V2_IMPLEMENTATION_PLAN.md

# 4. Verify current state (should be clean now)
git status

# 5. Start implementing following Phase 1 in the handoff
```

## Important Files

- `src/bundle/sign.rs` - Where signing happens (needs RekorClient trait)
- `tests/conformance/conformance.rs` - CLI that needs to pass `major_api_version`
- `tests/data/signing_config.v0.2.json` - Test config with v2 Rekor URLs

## The Stash

There's a stash with **incorrect code** that tries to detect version from URL.

**DO NOT RESTORE IT!** It's there as reference for what NOT to do.

```bash
# DON'T DO THIS:
git stash pop  # ❌ Don't restore the bad code!

# If you're curious what it was:
git stash show stash@{0}  # ✅ Just look, don't apply
```

## Test Command

```bash
# This is your target - make it pass!
cd sigstore-conformance
pytest test/test_bundle.py::test_sign_verify_rekor2 -v
```

## Success = All Green

When you're done:
- ✅ `test_sign_verify_rekor2` passes (creates v0.0.2 entries)
- ✅ All other 108 tests still pass (v0.0.1 for production)
- ✅ Code is clean and well-tested

## Estimated Time

- **Minimum**: 7 days
- **Realistic**: 10-12 days
- **Safe**: 14 days

Don't rush it! This is proper API integration work.

## Help & Resources

- **Sigstore-Python v2**: `sigstore-python/sigstore/_internal/rekor/client_v2.py`
- **Sigstore-Go v2**: `sigstore-go/pkg/sign/transparency.go` (line 124+)
- **Protobuf specs**: Already upgraded to 0.5.0 in conformance tests
- **Staging Rekor**: `https://log2025-alpha3.rekor.sigstage.dev`

## Questions?

Check [REKOR_V2_HANDOFF.md](REKOR_V2_HANDOFF.md) first - it has a FAQ section.

Good luck! 🎉
