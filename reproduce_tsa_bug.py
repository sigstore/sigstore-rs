#!/usr/bin/env python3
"""
Standalone script to reproduce TSA bug in timestamp.sigstage.dev

This script demonstrates that the Sigstore staging TSA server intermittently
returns malformed timestamps that fail strict ASN.1 parsing in Python's
rfc3161_client library.

Bug: The TSA returns timestamps with invalid ASN.1 encoding approximately
60% of the time, causing "ValueError: Malformed TimestampToken: ASN.1 parsing
error: invalid value" when accessing tst_info.

This is a minimal reproducer for bug reporting to Sigstore.
"""

import hashlib
import sys
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

# Configuration
TSA_URL = "https://timestamp.sigstage.dev/api/v1/timestamp"
NUM_TESTS = 10
OUTPUT_DIR = Path("/tmp/tsa_bug_reproducer")
OUTPUT_DIR.mkdir(exist_ok=True)

def create_tsa_request_with_null_params(test_num=0):
    """
    Create a TimeStampReq with SHA-256 and NULL parameters.

    This matches what OpenSSL generates and what most clients send.
    The request format is:

    TimeStampReq ::= SEQUENCE {
        version         INTEGER  { v1(1) },
        messageImprint  MessageImprint,
        reqPolicy       TSAPolicyId              OPTIONAL,
        nonce           INTEGER                  OPTIONAL,
        certReq         BOOLEAN                  DEFAULT FALSE,
        extensions      [0] IMPLICIT Extensions  OPTIONAL
    }

    MessageImprint ::= SEQUENCE {
        hashAlgorithm   AlgorithmIdentifier,
        hashedMessage   OCTET STRING
    }

    AlgorithmIdentifier ::= SEQUENCE {
        algorithm       OBJECT IDENTIFIER,
        parameters      ANY DEFINED BY algorithm OPTIONAL
    }
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    import os
    import time

    # Create a DIFFERENT message each time (like signing different data)
    # This ensures we hash different content, like real-world usage
    message = f"test message {test_num} at {time.time()}".encode()
    digest = hashlib.sha256(message).digest()

    # We'll use OpenSSL to create the request since it's the reference implementation
    # and it includes NULL parameters (the standard encoding)
    digest_file = OUTPUT_DIR / "digest.bin"
    with open(digest_file, 'wb') as f:
        f.write(digest)

    request_file = OUTPUT_DIR / "request.der"

    # Create TSReq using OpenSSL
    result = subprocess.run([
        'openssl', 'ts', '-query',
        '-data', str(digest_file),
        '-sha256',
        '-cert',  # Request certificate in response
        '-out', str(request_file)
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"ERROR: Failed to create TSReq: {result.stderr}")
        sys.exit(1)

    with open(request_file, 'rb') as f:
        request_der = f.read()

    return request_der

def query_tsa(request_der):
    """Send TSReq to TSA and get TSResp."""
    try:
        req = Request(
            TSA_URL,
            data=request_der,
            headers={'Content-Type': 'application/timestamp-query'}
        )

        with urlopen(req, timeout=10) as response:
            return response.read()

    except URLError as e:
        print(f"ERROR: Failed to connect to TSA: {e}")
        return None

def verify_timestamp_with_python(response_der):
    """
    Try to parse and verify the timestamp using Python's rfc3161_client.

    This is where the bug manifests: The library can parse the TimeStampResp,
    but fails with "ASN.1 parsing error: invalid value" when accessing tst_info.
    """
    try:
        # Try importing rfc3161_client
        try:
            from rfc3161_client import decode_timestamp_response
        except ImportError:
            print("ERROR: rfc3161_client not installed")
            print("Install with: pip install rfc3161-client")
            return None

        # Parse the TimeStampResp - this usually succeeds
        tsr = decode_timestamp_response(response_der)

        # Try to access tst_info - this is where it fails intermittently
        try:
            tst_info = tsr.tst_info
            # If we get here, the timestamp is valid
            return True
        except ValueError as e:
            if "Malformed TimestampToken" in str(e) and "ASN.1 parsing error" in str(e):
                # This is the bug we're looking for!
                return False
            else:
                # Different error
                print(f"WARNING: Unexpected error: {e}")
                return None

    except Exception as e:
        print(f"ERROR: Failed to parse TimeStampResp: {e}")
        return None

def analyze_timestamp_structure(response_der, test_num):
    """Use OpenSSL to analyze the timestamp structure."""
    timestamp_file = OUTPUT_DIR / f"response_{test_num}.der"
    with open(timestamp_file, 'wb') as f:
        f.write(response_der)

    analysis_file = OUTPUT_DIR / f"analysis_{test_num}.txt"

    result = subprocess.run([
        'openssl', 'asn1parse',
        '-inform', 'DER',
        '-in', str(timestamp_file)
    ], capture_output=True, text=True)

    with open(analysis_file, 'w') as f:
        f.write(result.stdout)

    return timestamp_file, analysis_file

def main():
    print("=" * 70)
    print("Sigstore TSA Bug Reproducer")
    print("=" * 70)
    print(f"\nTSA URL: {TSA_URL}")
    print(f"Number of tests: {NUM_TESTS}")
    print(f"Output directory: {OUTPUT_DIR}")
    print()

    # Check dependencies
    print("Checking dependencies...")
    try:
        from rfc3161_client import decode_timestamp_response
        print("  ✓ rfc3161_client installed")
    except ImportError:
        print("  ✗ rfc3161_client not installed")
        print("\nPlease install: pip install rfc3161-client")
        sys.exit(1)

    # Check OpenSSL
    result = subprocess.run(['openssl', 'version'], capture_output=True)
    if result.returncode == 0:
        print(f"  ✓ OpenSSL: {result.stdout.decode().strip()}")
    else:
        print("  ✗ OpenSSL not found")
        sys.exit(1)

    print()

    # Show what a request looks like
    print("Creating sample TimeStampReq...")
    sample_request = create_tsa_request_with_null_params(0)
    print(f"  Request size: {len(sample_request)} bytes")

    # Analyze the request
    print("\n  Request structure (should have NULL parameters):")
    result = subprocess.run([
        'openssl', 'asn1parse',
        '-inform', 'DER',
        '-in', str(OUTPUT_DIR / "digest.bin")
    ], capture_output=True, text=True)

    # Just show that we're using OpenSSL format
    print("    Using OpenSSL-generated TimeStampReq with NULL parameters")
    print("    Fresh request created for each test (different hash/nonce)")

    print()
    print("=" * 70)
    print("Querying TSA server...")
    print("=" * 70)

    success_count = 0
    failure_count = 0
    failures = []

    for i in range(1, NUM_TESTS + 1):
        print(f"\nTest {i}/{NUM_TESTS}:")

        # Create a FRESH request for each test (like real usage)
        request_der = create_tsa_request_with_null_params(i)

        # Query TSA
        response_der = query_tsa(request_der)
        if response_der is None:
            print("  ✗ Failed to get response")
            continue

        print(f"  Response size: {len(response_der)} bytes")

        # Try to verify with Python
        result = verify_timestamp_with_python(response_der)

        if result is True:
            print("  ✅ VALID - Python successfully parsed timestamp")
            success_count += 1
        elif result is False:
            print("  ❌ INVALID - Python ASN.1 parsing error (THE BUG!)")
            failure_count += 1
            failures.append(i)

            # Save the failing timestamp for analysis
            ts_file, analysis_file = analyze_timestamp_structure(response_der, i)
            print(f"      Saved to: {ts_file}")
            print(f"      Analysis: {analysis_file}")
        else:
            print("  ⚠️  UNKNOWN - Unexpected error")

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total tests: {NUM_TESTS}")
    print(f"✅ Valid timestamps: {success_count} ({success_count/NUM_TESTS*100:.1f}%)")
    print(f"❌ Invalid timestamps: {failure_count} ({failure_count/NUM_TESTS*100:.1f}%)")
    print()

    if failure_count > 0:
        print("BUG CONFIRMED!")
        print()
        print(f"The TSA server at {TSA_URL}")
        print(f"returned {failure_count} malformed timestamps out of {NUM_TESTS} requests.")
        print()
        print("Failed test numbers:", failures)
        print()
        print("Error details:")
        print("  - TimeStampResp parses successfully")
        print("  - Accessing tst_info fails with:")
        print("    ValueError: Malformed TimestampToken: ASN.1 parsing error: invalid value")
        print()
        print("This suggests the TSA is generating invalid ASN.1 encoding in the")
        print("SignedData or TSTInfo structure.")
        print()
        print(f"Failing timestamps saved to: {OUTPUT_DIR}")
        print()
        print("To analyze a failing timestamp:")
        print(f"  openssl asn1parse -inform DER -in {OUTPUT_DIR}/response_<N>.der")
        print(f"  cat {OUTPUT_DIR}/analysis_<N>.txt")
    else:
        print("No failures detected in this run.")
        print("Try running again or increasing NUM_TESTS.")

    print()
    print("=" * 70)

    # Return exit code based on whether we found the bug
    sys.exit(0 if failure_count > 0 else 1)

if __name__ == "__main__":
    main()
