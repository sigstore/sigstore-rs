#!/usr/bin/env python3
"""
Wrapper script that runs the conformance test and captures failing bundles.
This catches the bundle BEFORE Python verification fails.
"""

import subprocess
import sys
import os
import json
import shutil
import base64
from pathlib import Path
from datetime import datetime

BUNDLE_DIR = Path("/tmp/failing_bundles")
BUNDLE_DIR.mkdir(exist_ok=True)

def extract_timestamp_from_bundle(bundle_path, output_path):
    """Extract timestamp from bundle to DER file."""
    with open(bundle_path, 'r') as f:
        bundle = json.load(f)

    vm = bundle.get('verificationMaterial', {})
    tvd = vm.get('timestampVerificationData', {})
    timestamps = tvd.get('rfc3161Timestamps', [])

    if timestamps:
        timestamp_b64 = timestamps[0]['signedTimestamp']
        timestamp_der = base64.b64decode(timestamp_b64)
        with open(output_path, 'wb') as f:
            f.write(timestamp_der)
        return len(timestamp_der)
    return 0

def analyze_with_python(timestamp_der_path):
    """Try to parse with Python rfc3161_client."""
    result = subprocess.run([
        'python3', '-c', f'''
import sys
sys.path.insert(0, "rfc3161-client/src")
from rfc3161_client import decode_timestamp_response

with open("{timestamp_der_path}", "rb") as f:
    data = f.read()

print(f"Timestamp size: {{len(data)}} bytes")
print(f"First 100 bytes: {{data[:100].hex()}}")

try:
    tsr = decode_timestamp_response(data)
    print("✓ Parsed TimeStampResponse")
    tst_info = tsr.tst_info
    print(f"✓ Accessed tst_info")
    print(f"✓ Hash algorithm: {{tst_info.message_imprint.hash_algorithm}}")
except Exception as e:
    print(f"✗ Error: {{e}}")
    import traceback
    traceback.print_exc()
'''
    ], capture_output=True, text=True, cwd=os.getcwd())

    return result.stdout + result.stderr

print("🔍 Running conformance test and watching for failures...")
print(f"📁 Failing bundles will be saved to: {BUNDLE_DIR}")
print()

# Run test multiple times
success_count = 0
failure_count = 0

for i in range(1, 11):
    print(f"=== Test run {i}/10 ===")

    result = subprocess.run(
        ['sh', 'test-conformance.sh', '-k', 'test_sign_verify_rekor2'],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✅ PASSED")
        success_count += 1
    else:
        print("❌ FAILED")
        failure_count += 1

        # Check if it's the ASN.1 error
        output = result.stdout + result.stderr
        if "Malformed TimestampToken: ASN.1 parsing error" in output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            print(f"   🐛 Found ASN.1 parsing error!")

            # Save test output
            test_log = BUNDLE_DIR / f"test_output_{timestamp}.log"
            with open(test_log, 'w') as f:
                f.write(output)
            print(f"   💾 Test log: {test_log}")

            # Check if conftest saved the bundle to the known location
            latest_bundle = BUNDLE_DIR / "bundle_latest_failed.sigstore.json"
            bundle_src = None

            if latest_bundle.exists():
                print(f"   ✓ Found bundle saved by conftest.py")
                bundle_src = latest_bundle
            else:
                # Fallback: Look in common temp locations
                print(f"   Looking for bundle in temp locations...")
                for search_path in ['/tmp', str(Path.home() / '.cache'), 'sigstore-conformance']:
                    bundles = list(Path(search_path).rglob("a.txt.sigstore.json"))
                    # Filter to recent files (last 2 minutes)
                    import time
                    recent_bundles = [b for b in bundles if time.time() - b.stat().st_mtime < 120]

                    if recent_bundles:
                        bundle_src = recent_bundles[0]
                        print(f"   ✓ Found bundle at: {bundle_src}")
                        break

            if bundle_src:
                bundle_dst = BUNDLE_DIR / f"bundle_{timestamp}.sigstore.json"
                shutil.copy(bundle_src, bundle_dst)
                print(f"   💾 Bundle: {bundle_dst}")

                # Extract timestamp
                timestamp_der = BUNDLE_DIR / f"timestamp_{timestamp}.der"
                size = extract_timestamp_from_bundle(bundle_dst, timestamp_der)
                if size > 0:
                    print(f"   💾 Timestamp DER ({size} bytes): {timestamp_der}")

                    # Analyze with OpenSSL
                    asn1_analysis = BUNDLE_DIR / f"openssl_asn1_{timestamp}.txt"
                    result = subprocess.run(
                        ['openssl', 'asn1parse', '-inform', 'DER', '-in', str(timestamp_der)],
                        capture_output=True,
                        text=True
                    )
                    with open(asn1_analysis, 'w') as f:
                        f.write(result.stdout + result.stderr)
                    print(f"   💾 OpenSSL ASN.1: {asn1_analysis}")

                    # Try Python parsing
                    python_analysis = BUNDLE_DIR / f"python_parse_{timestamp}.txt"
                    analysis = analyze_with_python(timestamp_der)
                    with open(python_analysis, 'w') as f:
                        f.write(analysis)
                    print(f"   💾 Python parse: {python_analysis}")

                    # Show key info
                    if "✗ Error:" in analysis:
                        print(f"   ⚠️  Python parsing failed (as expected)")
                        print(f"      Error: {[line for line in analysis.split(chr(10)) if 'Error:' in line][0]}")
            else:
                print(f"   ⚠️  Could not find bundle file")
        else:
            print(f"   Different error (not ASN.1 parsing)")

print()
print("=" * 60)
print(f"📊 Results: {success_count} passed, {failure_count} failed")
print(f"📁 Captured files in: {BUNDLE_DIR}")

if failure_count > 0:
    print()
    print("To analyze a failing bundle:")
    print(f"  python3 extract_timestamp.py {BUNDLE_DIR}/bundle_<timestamp>.sigstore.json")
    print()
    print("Files in bundle dir:")
    subprocess.run(['ls', '-lht', str(BUNDLE_DIR)])
