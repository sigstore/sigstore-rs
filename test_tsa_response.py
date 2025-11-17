#!/usr/bin/env python3
"""Test script to examine TSA responses from Rust sigstore client."""

import json
import subprocess
import base64
import sys
from pathlib import Path

# Run the conformance test to generate a bundle
result = subprocess.run(
    ["./tests/conformance/target/release/sigstore", "sign-bundle",
     "--identity-token", "-",
     "--signing-config", "tests/data/signing_config.v0.2.json",
     "--trusted-root", "tests/data/trusted_root.json",
     "tests/data/a.txt"],
    input=open(".github/workflows/token.txt").read() if Path(".github/workflows/token.txt").exists() else "",
    capture_output=True,
    text=True,
)

if result.returncode != 0:
    print(f"Failed to create bundle: {result.stderr}", file=sys.stderr)
    sys.exit(1)

# Parse the bundle
bundle = json.loads(result.stdout)

# Check if there are RFC3161 timestamps
if "verificationMaterial" in bundle:
    vm = bundle["verificationMaterial"]
    if "timestampVerificationData" in vm:
        tvd = vm["timestampVerificationData"]
        if "rfc3161Timestamps" in tvd and len(tvd["rfc3161Timestamps"]) > 0:
            for i, ts in enumerate(tvd["rfc3161Timestamps"]):
                timestamp_b64 = ts["signedTimestamp"]
                timestamp_der = base64.b64decode(timestamp_b64)

                print(f"Timestamp {i}:")
                print(f"  Length: {len(timestamp_der)} bytes")
                print(f"  First 100 bytes (hex): {timestamp_der[:100].hex()}")

                # Try to parse with rfc3161_client
                try:
                    from rfc3161_client import decode_timestamp_response
                    tsr = decode_timestamp_response(timestamp_der)
                    print(f"  ✓ Parsed successfully")
                    print(f"  TST Info gen_time: {tsr.tst_info.gen_time}")
                except Exception as e:
                    print(f"  ✗ Failed to parse: {e}")
                    sys.exit(1)
        else:
            print("No RFC3161 timestamps found in bundle")
    else:
        print("No timestampVerificationData in bundle")
else:
    print("No verificationMaterial in bundle")
