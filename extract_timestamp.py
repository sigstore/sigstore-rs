#!/usr/bin/env python3
"""Extract and analyze timestamp from Sigstore bundle."""

import json
import base64
import sys
from pathlib import Path

def analyze_timestamp(bundle_path):
    """Extract and analyze timestamp from bundle."""
    with open(bundle_path, 'r') as f:
        bundle = json.load(f)

    if 'verificationMaterial' not in bundle:
        print("No verificationMaterial in bundle")
        return

    vm = bundle['verificationMaterial']
    if 'timestampVerificationData' not in vm:
        print("No timestampVerificationData in bundle")
        return

    tvd = vm['timestampVerificationData']
    if 'rfc3161Timestamps' not in tvd or len(tvd['rfc3161Timestamps']) == 0:
        print("No RFC3161 timestamps in bundle")
        return

    for i, ts in enumerate(tvd['rfc3161Timestamps']):
        print(f"\n=== Timestamp {i} ===")
        timestamp_b64 = ts['signedTimestamp']
        timestamp_der = base64.b64decode(timestamp_b64)

        print(f"Length: {len(timestamp_der)} bytes")
        print(f"Base64 (first 100 chars): {timestamp_b64[:100]}")
        print(f"Hex (first 200 bytes): {timestamp_der[:200].hex()}")

        # Write to file for further analysis
        output_file = f"/tmp/timestamp_{i}.der"
        with open(output_file, 'wb') as f:
            f.write(timestamp_der)
        print(f"Written to: {output_file}")

        # Try to parse with openssl
        print(f"\nOpenSSL ASN.1 parse:")
        import subprocess
        result = subprocess.run(
            ['openssl', 'asn1parse', '-inform', 'DER', '-in', output_file],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(result.stdout[:1000])  # First 1000 chars
        else:
            print(f"Error: {result.stderr}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: extract_timestamp.py <bundle.sigstore.json>")
        sys.exit(1)

    analyze_timestamp(sys.argv[1])
