#!/usr/bin/env python3
"""
Direct test of timestamp creation and verification without pytest.
Creates bundles, analyzes them, and tries to verify with Python.
"""

import subprocess
import json
import base64
import sys
import os
from pathlib import Path
from datetime import datetime

# Paths
BUNDLE_DIR = Path("/tmp/failing_bundles")
BUNDLE_DIR.mkdir(exist_ok=True)

# Use the staging config from the cache (like the test does)
TRUSTED_ROOT = Path.home() / "Library/Caches/sigstore-python/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json"
SIGNING_CONFIG = Path.home() / "Library/Caches/sigstore-python/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/signing_config.v0.2.json"

# Fallback to tests/data if cache doesn't exist
if not TRUSTED_ROOT.exists():
    TRUSTED_ROOT = Path("tests/data/trusted_root.json")
if not SIGNING_CONFIG.exists():
    SIGNING_CONFIG = Path("tests/data/signing_config.v0.2.json")

SIGSTORE_BIN = Path("tests/conformance/target/release/sigstore")
IDENTITY_TOKEN_FILE = Path(".github/workflows/token.txt")
TEST_FILE = Path("tests/data/a.txt")

def get_identity_token():
    """Get identity token from file or fetch from OIDC beacon."""
    # Try local file first
    if IDENTITY_TOKEN_FILE.exists():
        with open(IDENTITY_TOKEN_FILE) as f:
            token = f.read().strip()
            if token:
                return token

    # Fetch from extremely-dangerous-public-oidc-beacon
    print("📥 Fetching identity token from OIDC beacon...")
    import tempfile

    GIT_URL = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon.git"

    with tempfile.TemporaryDirectory() as tempdir:
        try:
            subprocess.run(
                ["git", "clone", "--quiet", "--branch", "current-token", "--depth", "1", GIT_URL, tempdir],
                check=True,
                capture_output=True
            )

            token_file = Path(tempdir) / "oidc-token.txt"
            with open(token_file) as f:
                token = f.read().strip()

            print(f"✅ Got identity token")
            return token

        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to fetch token: {e}")
            print(f"   You can manually save a token to: {IDENTITY_TOKEN_FILE}")
            sys.exit(1)

def create_bundle(output_path):
    """Create a bundle using our Rust tool."""
    token = get_identity_token()

    # Ensure output directory exists
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Verify all required files exist
    if not SIGSTORE_BIN.exists():
        print(f"❌ Sigstore binary not found: {SIGSTORE_BIN}")
        print(f"   Run: cargo build --manifest-path=tests/conformance/Cargo.toml --release")
        return False

    if not TRUSTED_ROOT.exists():
        print(f"❌ Trusted root not found: {TRUSTED_ROOT}")
        return False

    if not SIGNING_CONFIG.exists():
        print(f"❌ Signing config not found: {SIGNING_CONFIG}")
        return False

    if not TEST_FILE.exists():
        print(f"❌ Test file not found: {TEST_FILE}")
        print(f"   Creating it...")
        TEST_FILE.write_text("test content for signing\n")

    cmd = [
        str(SIGSTORE_BIN),
        "sign-bundle",
        "--identity-token", token,
        "--bundle", str(output_path),
        "--trusted-root", str(TRUSTED_ROOT),
        "--signing-config", str(SIGNING_CONFIG),
        str(TEST_FILE)
    ]

    print(f"Creating bundle...")
    print(f"  Command: {' '.join(cmd[:3])} ... {' '.join(cmd[-4:])}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"❌ Failed to create bundle:")
        print(result.stderr)
        return False

    print(f"✅ Bundle created: {output_path}")
    return True

def extract_timestamp(bundle_path):
    """Extract timestamp from bundle."""
    with open(bundle_path) as f:
        bundle = json.load(f)

    vm = bundle.get('verificationMaterial', {})
    tvd = vm.get('timestampVerificationData', {})
    timestamps = tvd.get('rfc3161Timestamps', [])

    if not timestamps:
        print("❌ No timestamps in bundle")
        return None

    timestamp_b64 = timestamps[0]['signedTimestamp']
    timestamp_der = base64.b64decode(timestamp_b64)

    return timestamp_der

def analyze_with_openssl(timestamp_der, output_file):
    """Analyze timestamp with OpenSSL."""
    result = subprocess.run(
        ['openssl', 'asn1parse', '-inform', 'DER'],
        input=timestamp_der,
        capture_output=True
    )

    analysis = result.stdout.decode('utf-8', errors='replace')

    with open(output_file, 'w') as f:
        f.write(analysis)

    return analysis

def verify_with_python_rfc3161(timestamp_der):
    """Try to verify with Python rfc3161_client."""
    # Write to temp file
    temp_der = BUNDLE_DIR / "temp_timestamp.der"
    with open(temp_der, 'wb') as f:
        f.write(timestamp_der)

    # Try to parse
    code = f'''
import sys
sys.path.insert(0, "rfc3161-client/src")

try:
    from rfc3161_client import decode_timestamp_response

    with open("{temp_der}", "rb") as f:
        data = f.read()

    print(f"Timestamp size: {{len(data)}} bytes")
    print(f"First 100 bytes: {{data[:100].hex()}}")

    tsr = decode_timestamp_response(data)
    print("✓ Parsed TimeStampResponse successfully")

    # This is where it fails
    tst_info = tsr.tst_info
    print("✓ Accessed tst_info successfully")
    print(f"✓ Hash algorithm: {{tst_info.message_imprint.hash_algorithm}}")
    print("✓ Gen time: {{tst_info.gen_time}}")

except Exception as e:
    print(f"✗ Error: {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''

    result = subprocess.run(
        ['python3', '-c', code],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )

    return result.returncode == 0, result.stdout + result.stderr

def verify_with_sigstore_python(bundle_path):
    """Try to verify bundle with sigstore-python."""
    # Find sigstore-python-conformance
    sigstore_python = Path("sigstore-conformance/sigstore-python-conformance")
    if not sigstore_python.exists():
        return None, "sigstore-python-conformance not found"

    cmd = [
        str(sigstore_python),
        "verify-bundle",
        "--bundle", str(bundle_path),
        "--certificate-identity", "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--trusted-root", str(TRUSTED_ROOT),
        str(TEST_FILE)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    return result.returncode == 0, result.stdout + result.stderr

# Main test loop
print("=" * 70)
print("Direct Timestamp Test - No Pytest")
print("=" * 70)
print()

success_count = 0
failure_count = 0

for run in range(1, 21):
    print(f"\n{'=' * 70}")
    print(f"Test Run {run}/20")
    print('=' * 70)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_path = BUNDLE_DIR / f"bundle_{timestamp}.sigstore.json"

    # Create bundle
    if not create_bundle(bundle_path):
        print("❌ Skipping this run")
        failure_count += 1
        continue

    # Extract timestamp
    print("\n📦 Extracting timestamp...")
    timestamp_der = extract_timestamp(bundle_path)
    if timestamp_der is None:
        print("❌ No timestamp found")
        failure_count += 1
        continue

    print(f"✅ Extracted {len(timestamp_der)} bytes")

    # Save timestamp DER
    timestamp_der_path = BUNDLE_DIR / f"timestamp_{timestamp}.der"
    with open(timestamp_der_path, 'wb') as f:
        f.write(timestamp_der)
    print(f"   Saved to: {timestamp_der_path}")

    # Analyze with OpenSSL
    print("\n🔍 Analyzing with OpenSSL...")
    openssl_file = BUNDLE_DIR / f"openssl_{timestamp}.txt"
    openssl_output = analyze_with_openssl(timestamp_der, openssl_file)
    print(f"   Analysis saved to: {openssl_file}")
    print(f"   First line: {openssl_output.split(chr(10))[0] if openssl_output else 'empty'}")

    # Try Python rfc3161_client
    print("\n🐍 Testing with Python rfc3161_client...")
    python_ok, python_output = verify_with_python_rfc3161(timestamp_der)

    python_file = BUNDLE_DIR / f"python_rfc3161_{timestamp}.txt"
    with open(python_file, 'w') as f:
        f.write(python_output)
    print(f"   Output saved to: {python_file}")

    if python_ok:
        print("   ✅ Python rfc3161_client PASSED")
    else:
        print("   ❌ Python rfc3161_client FAILED")
        if "Malformed TimestampToken" in python_output:
            print("   🐛 Found the ASN.1 parsing error!")
            print(f"      Bundle: {bundle_path}")
            print(f"      Timestamp: {timestamp_der_path}")

    # Try full sigstore-python verification
    print("\n🔐 Testing with sigstore-python verification...")
    verify_ok, verify_output = verify_with_sigstore_python(bundle_path)

    verify_file = BUNDLE_DIR / f"verify_{timestamp}.txt"
    with open(verify_file, 'w') as f:
        f.write(verify_output)
    print(f"   Output saved to: {verify_file}")

    if verify_ok is None:
        print("   ⚠️  Sigstore-python not available")
    elif verify_ok:
        print("   ✅ Full verification PASSED")
        success_count += 1
    else:
        print("   ❌ Full verification FAILED")
        failure_count += 1
        if "Malformed TimestampToken" in verify_output:
            print("   🐛 ASN.1 parsing error in verification")

    print(f"\n📊 Current results: {success_count} passed, {failure_count} failed")

print("\n" + "=" * 70)
print(f"Final Results: {success_count} passed, {failure_count} failed out of 20 runs")
print(f"All files saved to: {BUNDLE_DIR}")
print("=" * 70)

if failure_count > 0:
    print("\nTo analyze a failing bundle:")
    print(f"  ls -lt {BUNDLE_DIR}")
    print(f"  python3 extract_timestamp.py {BUNDLE_DIR}/bundle_<timestamp>.sigstore.json")
