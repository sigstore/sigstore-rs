#!/bin/bash
# Script to capture failing bundles for debugging Python parsing issues

set -e

BUNDLE_DIR="/tmp/failing_bundles"
mkdir -p "$BUNDLE_DIR"

echo "Running conformance test and capturing Python verification failures..."
echo "Failed bundles will be saved to: $BUNDLE_DIR"

# Run the test multiple times to catch intermittent failures
for i in {1..10}; do
    echo ""
    echo "=== Test run $i ==="

    # Run test and capture output
    if sh test-conformance.sh -k test_sign_verify_rekor2 > /tmp/test_output.log 2>&1; then
        echo "✅ PASSED"
    else
        echo "❌ FAILED - Python verification error"

        # Check if it's the ASN.1 parsing error we're looking for
        if grep -q "Malformed TimestampToken: ASN.1 parsing error" /tmp/test_output.log; then
            TIMESTAMP=$(date +%Y%m%d_%H%M%S)
            echo "   Found ASN.1 parsing error!"

            # Save the test output
            cp /tmp/test_output.log "$BUNDLE_DIR/test_output_${TIMESTAMP}.log"
            echo "   Saved test output to: $BUNDLE_DIR/test_output_${TIMESTAMP}.log"

            # Try to find the bundle that was created
            # It's in a temp directory, so we need to find it before it's cleaned up
            BUNDLE_FILE=$(find /tmp /var/tmp ~/.cache -name "a.txt.sigstore.json" -type f -mmin -1 2>/dev/null | head -1)
            if [ -z "$BUNDLE_FILE" ]; then
                # Try the conformance test directory
                BUNDLE_FILE=$(find sigstore-conformance -name "*.sigstore.json" -type f -mmin -1 2>/dev/null | head -1)
            fi

            if [ -n "$BUNDLE_FILE" ] && [ -f "$BUNDLE_FILE" ]; then
                echo "   Found bundle: $BUNDLE_FILE"
                cp "$BUNDLE_FILE" "$BUNDLE_DIR/bundle_${TIMESTAMP}.sigstore.json"
                echo "   Saved bundle to: $BUNDLE_DIR/bundle_${TIMESTAMP}.sigstore.json"

                # Extract the timestamp from the bundle
                echo "   Extracting timestamp from bundle..."
                python3 extract_timestamp.py "$BUNDLE_DIR/bundle_${TIMESTAMP}.sigstore.json" \
                    > "$BUNDLE_DIR/timestamp_analysis_${TIMESTAMP}.txt" 2>&1 || true

                # The extract script saves to /tmp/timestamp_0.der, so copy it
                if [ -f /tmp/timestamp_0.der ]; then
                    cp /tmp/timestamp_0.der "$BUNDLE_DIR/timestamp_${TIMESTAMP}.der"
                    echo "   Saved timestamp DER to: $BUNDLE_DIR/timestamp_${TIMESTAMP}.der"

                    # Try to parse with Python rfc3161_client to reproduce the error
                    echo "   Attempting to parse with Python rfc3161_client..."
                    python3 << EOF > "$BUNDLE_DIR/python_parse_${TIMESTAMP}.txt" 2>&1 || true
import sys
sys.path.insert(0, 'rfc3161-client/src')
try:
    from rfc3161_client import decode_timestamp_response
    with open('$BUNDLE_DIR/timestamp_${TIMESTAMP}.der', 'rb') as f:
        data = f.read()
    print(f"Timestamp size: {len(data)} bytes")
    tsr = decode_timestamp_response(data)
    print("✓ Parsed successfully")
    tst_info = tsr.tst_info
    print(f"✓ Accessed tst_info: {tst_info.message_imprint.hash_algorithm}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
EOF
                    cat "$BUNDLE_DIR/python_parse_${TIMESTAMP}.txt"
                fi

                echo ""
                echo "   📁 Captured failure files:"
                echo "      - Bundle: $BUNDLE_DIR/bundle_${TIMESTAMP}.sigstore.json"
                echo "      - Timestamp: $BUNDLE_DIR/timestamp_${TIMESTAMP}.der"
                echo "      - Analysis: $BUNDLE_DIR/timestamp_analysis_${TIMESTAMP}.txt"
                echo "      - Python parse: $BUNDLE_DIR/python_parse_${TIMESTAMP}.txt"
                echo "      - Test log: $BUNDLE_DIR/test_output_${TIMESTAMP}.log"
                echo ""
                echo "   To analyze: python3 extract_timestamp.py $BUNDLE_DIR/bundle_${TIMESTAMP}.sigstore.json"
            else
                echo "   WARNING: Could not find bundle file"
            fi
        else
            echo "   Different error type (not ASN.1 parsing)"
        fi
    fi

    rm -f /tmp/test_output.log
    sleep 1
done

echo ""
echo "=== Summary ==="
echo "Check $BUNDLE_DIR for any captured failing bundles"
ls -lht "$BUNDLE_DIR" 2>/dev/null | head -20 || echo "No failures captured"
