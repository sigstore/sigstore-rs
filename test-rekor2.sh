#!/bin/bash
set -e

cd /Users/wolfv/Programs/sigstore-rs/tests/conformance

echo "Building conformance binary..."
cargo build --release 2>&1 | tail -3

echo ""
echo "Running Rekor v2 test..."
export RUST_LOG=sigstore=info
./target/release/sigstore verify-bundle \
  --bundle ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json \
  --certificate-identity "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --trusted-root ../../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json \
  "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"

echo ""
echo "Test completed!"
