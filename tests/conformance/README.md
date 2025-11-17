# Sigstore Conformance Tests

This directory contains the conformance test suite for the Rust sigstore implementation.

## Overview

The conformance tests verify that our implementation correctly handles:
- Bundle verification (both Rekor v1 and v2)
- Checkpoint validation and signature verification
- TSA (Timestamp Authority) certificate validation
- Certificate validity checking
- Transparency log verification

## Running the Tests

### Quick Start

1. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Build the conformance binary**:
   ```bash
   cargo build --release --manifest-path tests/conformance/Cargo.toml
   ```

3. **Clone the conformance suite** (if not already present):
   ```bash
   git clone https://github.com/sigstore/sigstore-conformance.git
   ```

4. **Run the tests** (uv handles all Python dependencies automatically):
   ```bash
   cd sigstore-conformance
   uv run pytest test/test_bundle.py::test_verify \
       --entrypoint="$(pwd)/../tests/conformance/target/release/sigstore" \
       --skip-signing \
       -v
   ```

## GitHub Actions

The conformance tests run automatically on:
- Push to `main` or `experiments` branches
- Pull requests to `main`
- Manual workflow dispatch

See [.github/workflows/conformance-tests.yml](../../.github/workflows/conformance-tests.yml) for the workflow configuration.

## Test Structure

The conformance suite tests various scenarios including:

### Passing Tests (Expected to succeed)
- Valid bundle signatures
- Rekor v1 and v2 entries
- Various checkpoint formats
- TSA timestamps with valid certificates

### Failing Tests (Expected to fail)
- Invalid checkpoint signatures
- Wrong checkpoint root hashes
- Bad checkpoint key hints
- Untrusted TSA certificates
- Timestamps outside certificate validity

## Current Status

✅ **All 104 conformance tests passing** (100% pass rate)

Key features validated:
- ✅ Checkpoint root hash & tree size validation
- ✅ Rekor v1 STH signature verification
- ✅ Checkpoint keyhint validation
- ✅ Timestamp vs signing certificate validity
- ✅ TSA embedded certificate validation

## Debugging Failed Tests

If tests fail, you can run individual tests with more verbose output:

```bash
# Run a specific test with debug output
pytest test/test_bundle.py::test_verify[PATH-specific-test-name] -v

# Enable Rust logging
RUST_LOG=debug pytest test/test_bundle.py::test_verify
```

## Binary Interface

The conformance binary (`sigstore`) implements the Sigstore conformance CLI protocol:

```bash
# Verify a bundle
sigstore verify-bundle \
    --bundle path/to/bundle.sigstore.json \
    --certificate-identity <identity> \
    --certificate-oidc-issuer <issuer> \
    [--trusted-root path/to/trusted_root.json] \
    <artifact-path-or-digest>
```

## Contributing

When adding new verification features:

1. Ensure all conformance tests still pass
2. Check if new test cases are needed in sigstore-conformance
3. Update this README if the test structure changes

## References

- [Sigstore Conformance Suite](https://github.com/sigstore/sigstore-conformance)
- [Sigstore Specification](https://github.com/sigstore/protobuf-specs)
- [Bundle Format v0.3](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
