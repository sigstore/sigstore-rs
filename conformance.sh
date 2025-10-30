#!/bin/bash
set -e

# Get the absolute path to the repository root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building conformance test binary..."
cargo build --release --manifest-path "$REPO_ROOT/tests/conformance/Cargo.toml"

echo "Running conformance tests..."
cd "$REPO_ROOT/sigstore-conformance"

# Use uv if available, otherwise use python directly
if command -v uv &> /dev/null; then
    uv run pytest test/test_bundle.py::test_verify \
        --entrypoint="$REPO_ROOT/tests/conformance/target/release/sigstore" \
        --skip-signing
else
    pytest test/test_bundle.py::test_verify \
        --entrypoint="$REPO_ROOT/tests/conformance/target/release/sigstore" \
        --skip-signing
fi