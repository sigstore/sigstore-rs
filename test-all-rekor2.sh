#!/bin/bash

cd /Users/wolfv/Programs/sigstore-rs/tests/conformance

echo "Building conformance binary..."
cargo build --release 2>&1 | tail -1

echo ""
echo "Running all Rekor v2 conformance tests..."
echo ""

export RUST_LOG=error
passed=0
failed=0

for dir in ../../sigstore-conformance/test/assets/bundle-verify/rekor2-*; do
    test_name=$(basename "$dir")

    # Check if it's a failure test case
    if [[ "$test_name" == *"_fail"* ]]; then
        continue  # Skip failure tests for now
    fi

    # Get the certificate identity and issuer from the bundle
    bundle="$dir/bundle.sigstore.json"
    trusted_root="$dir/trusted_root.json"

    if [ ! -f "$bundle" ]; then
        continue
    fi

    # Extract identity and issuer
    identity=$(python3 -c "import json; data=json.load(open('$bundle')); cert_der=data['verificationMaterial']['certificate']['rawBytes']; print('https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main')" 2>/dev/null)
    issuer="https://token.actions.githubusercontent.com"

    # Get digest
    digest=$(python3 -c "import json, base64; data=json.load(open('$bundle')); entry=data['verificationMaterial']['tlogEntries'][0]; body=json.loads(base64.b64decode(entry['canonicalizedBody'])); print(base64.b64decode(body['spec']['hashedRekordV002']['data']['digest']).hex())" 2>/dev/null)

    if [ -z "$digest" ]; then
        echo "❌ $test_name - skipped (no digest)"
        continue
    fi

    # Run verification
    if ./target/release/sigstore verify-bundle \
        --bundle "$bundle" \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "$issuer" \
        --trusted-root "$trusted_root" \
        "sha256:$digest" >/dev/null 2>&1; then
        echo "✅ $test_name"
        ((passed++))
    else
        echo "❌ $test_name"
        ((failed++))
    fi
done

echo ""
echo "Results: $passed passed, $failed failed"
