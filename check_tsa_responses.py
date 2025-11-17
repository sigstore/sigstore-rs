#!/usr/bin/env python3
"""
Query the TSA server multiple times and analyze the responses.
Check for inconsistencies or malformed timestamps.
"""

import subprocess
import sys
import json
import hashlib
import base64
from pathlib import Path
from datetime import datetime

# Add paths
sys.path.insert(0, 'rfc3161-client/src')

TSA_URL = "https://timestamp.sigstage.dev/api/v1/timestamp"
OUTPUT_DIR = Path("/tmp/tsa_responses")
OUTPUT_DIR.mkdir(exist_ok=True)

def create_timestamp_request():
    """Create a TimeStampReq DER-encoded request."""
    # We'll use Python's cryptography library to create a proper request
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import oid
    from cryptography import x509

    # Create a message to hash
    message = b"test message for timestamp " + datetime.now().isoformat().encode()
    digest = hashlib.sha256(message).digest()

    # Build TSReq manually using ASN.1
    # For simplicity, we'll use openssl command

    # Write digest to temp file
    temp_digest = OUTPUT_DIR / "temp_digest.bin"
    with open(temp_digest, 'wb') as f:
        f.write(digest)

    # Create TSReq using openssl (need to pass hex digest)
    temp_req = OUTPUT_DIR / "temp_req.der"
    digest_hex = digest.hex()
    result = subprocess.run([
        'openssl', 'ts', '-query',
        '-data', str(temp_digest),
        '-sha256',
        '-cert',  # Request cert in response
        '-out', str(temp_req)
    ], capture_output=True)

    if result.returncode != 0:
        print(f"Failed to create TSReq: {result.stderr.decode()}")
        return None

    with open(temp_req, 'rb') as f:
        return f.read()

def query_tsa(request_der):
    """Send TSReq to TSA and get TSResp."""
    # Write request to temp file
    temp_req = OUTPUT_DIR / "temp_request.der"
    with open(temp_req, 'wb') as f:
        f.write(request_der)

    # Use curl to send request
    temp_resp = OUTPUT_DIR / "temp_response.der"
    result = subprocess.run([
        'curl', '-s', '-X', 'POST',
        '-H', 'Content-Type: application/timestamp-query',
        '--data-binary', f'@{temp_req}',
        '-o', str(temp_resp),
        TSA_URL
    ], capture_output=True)

    if result.returncode != 0:
        print(f"curl failed: {result.stderr.decode()}")
        return None

    with open(temp_resp, 'rb') as f:
        return f.read()

def analyze_response(response_der, run_num):
    """Analyze a TSResp."""
    timestamp_file = OUTPUT_DIR / f"response_{run_num}.der"
    with open(timestamp_file, 'wb') as f:
        f.write(response_der)

    print(f"\n=== Response {run_num} ===")
    print(f"  Size: {len(response_der)} bytes")
    print(f"  Saved to: {timestamp_file}")

    # Parse with OpenSSL
    openssl_file = OUTPUT_DIR / f"response_{run_num}_openssl.txt"
    result = subprocess.run(
        ['openssl', 'asn1parse', '-inform', 'DER', '-in', str(timestamp_file)],
        capture_output=True,
        text=True
    )
    with open(openssl_file, 'w') as f:
        f.write(result.stdout)

    # Extract key info
    lines = result.stdout.split('\n')

    # Find TSTInfo size
    tstinfo_line = [l for l in lines if 'id-smime-ct-TSTInfo' in l and 'OCTET STRING' in l]
    if tstinfo_line:
        # Next line should have the OCTET STRING with TSTInfo
        for i, l in enumerate(lines):
            if 'id-smime-ct-TSTInfo' in l:
                # Look ahead for OCTET STRING
                for j in range(i+1, min(i+5, len(lines))):
                    if 'OCTET STRING' in lines[j] and 'HEX DUMP' in lines[j]:
                        # Extract length
                        parts = lines[j].split()
                        for k, part in enumerate(parts):
                            if part.startswith('l='):
                                tstinfo_len = part[2:]
                                print(f"  TSTInfo size: {tstinfo_len} bytes")
                                break
                        break

    # Find signature size
    sig_lines = [l for l in lines if 'd=6' in l and 'OCTET STRING' in l]
    if sig_lines:
        last_sig = sig_lines[-1]  # Last OCTET STRING at depth 6 is usually the signature
        parts = last_sig.split()
        for k, part in enumerate(parts):
            if part.startswith('l='):
                sig_len = part[2:]
                print(f"  Signature size: {sig_len} bytes")
                break

    # Try parsing with Python rfc3161_client
    try:
        from rfc3161_client import decode_timestamp_response

        tsr = decode_timestamp_response(response_der)
        print(f"  ✓ Python parsed TimeStampResp")

        # Try to access tst_info
        try:
            tst_info = tsr.tst_info
            print(f"  ✓ Python accessed tst_info")
            # serial_number might be int or bytes
            serial = tst_info.serial_number
            if isinstance(serial, bytes):
                print(f"    Serial: {serial.hex()[:40]}...")
            else:
                print(f"    Serial: {hex(serial)[:40]}...")
            return True
        except Exception as e:
            print(f"  ✗ Python failed on tst_info: {e}")
            return False

    except Exception as e:
        print(f"  ✗ Python failed to parse: {e}")
        return False

print("=" * 70)
print("TSA Response Checker")
print("=" * 70)
print(f"TSA URL: {TSA_URL}")
print(f"Output: {OUTPUT_DIR}")
print()

# Create a request
print("Creating TimeStampReq...")
request_der = create_timestamp_request()
if request_der is None:
    print("Failed to create request")
    sys.exit(1)

print(f"Request size: {len(request_der)} bytes")
print()

# Query TSA multiple times
success_count = 0
failure_count = 0

for run in range(1, 11):
    try:
        print(f"Query {run}/10...", end=" ", flush=True)

        response_der = query_tsa(request_der)
        if response_der is None:
            print("FAILED")
            failure_count += 1
            continue

        print(f"OK ({len(response_der)} bytes)")

        # Analyze
        if analyze_response(response_der, run):
            success_count += 1
        else:
            failure_count += 1
            print(f"  🐛 FOUND FAILING RESPONSE!")

    except Exception as e:
        print(f"ERROR: {e}")
        failure_count += 1

print()
print("=" * 70)
print(f"Results: {success_count} passed, {failure_count} failed")
print(f"All responses saved to: {OUTPUT_DIR}")
print("=" * 70)

if failure_count > 0:
    print()
    print("To compare responses:")
    print(f"  ls -lh {OUTPUT_DIR}/response_*.der")
    print(f"  diff {OUTPUT_DIR}/response_1_openssl.txt {OUTPUT_DIR}/response_2_openssl.txt")
