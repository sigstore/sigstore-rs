#!/usr/bin/env python3
"""
Test how the Rust x509-tsp crate encodes AlgorithmIdentifier.
Compare with what OpenSSL generates.
"""

import subprocess
import hashlib
from pathlib import Path

OUTPUT_DIR = Path("/tmp/tsa_test")
OUTPUT_DIR.mkdir(exist_ok=True)

# Create a message
message = b"test message"
digest = hashlib.sha256(message).digest()

# Write digest
digest_file = OUTPUT_DIR / "digest.bin"
with open(digest_file, 'wb') as f:
    f.write(digest)

# Create TSReq with OpenSSL
openssl_req = OUTPUT_DIR / "openssl_request.der"
result = subprocess.run([
    'openssl', 'ts', '-query',
    '-data', str(digest_file),
    '-sha256',
    '-cert',
    '-out', str(openssl_req)
], capture_output=True)

if result.returncode != 0:
    print("OpenSSL failed:", result.stderr.decode())
    exit(1)

print("OpenSSL request created")
openssl_bytes = openssl_req.read_bytes()
print(f"  Size: {len(openssl_bytes)} bytes")

# Parse to see structure
result = subprocess.run([
    'openssl', 'asn1parse', '-inform', 'DER', '-in', str(openssl_req)
], capture_output=True, text=True)

print("\nOpenSSL TSReq structure:")
for line in result.stdout.split('\n')[:20]:  # First 20 lines
    print(f"  {line}")

# Look for the AlgorithmIdentifier
print("\nLooking for AlgorithmIdentifier (sha256):")
for line in result.stdout.split('\n'):
    if 'sha256' in line.lower() or 'OBJECT' in line and '2.16.840' in line:
        print(f"  {line}")
        # Get the next line too (might be NULL parameter)
        idx = result.stdout.split('\n').index(line)
        if idx + 1 < len(result.stdout.split('\n')):
            next_line = result.stdout.split('\n')[idx + 1]
            if 'NULL' in next_line or 'prim' in next_line:
                print(f"  {next_line}")

# Extract the MessageImprint SEQUENCE
print("\n\nLooking for MessageImprint:")
lines = result.stdout.split('\n')
for i, line in enumerate(lines):
    if 'SEQUENCE' in line and i > 5:  # Skip the outer SEQUENCE
        # This might be the MessageImprint
        # It should contain: AlgorithmIdentifier + OCTET STRING
        print(f"  {line}")
        for j in range(i+1, min(i+5, len(lines))):
            print(f"  {lines[j]}")
        break

print(f"\n\nOpenSSL request hex (first 100 bytes):")
print(f"  {openssl_bytes[:100].hex()}")

# Now we need to create a request with Rust and compare
# For now, let's just document what OpenSSL creates
print("\n" + "="*60)
print("To compare with Rust:")
print(f"1. Run our Rust tool to create a timestamp")
print(f"2. Extract the TSReq that was sent (add debug logging)")
print(f"3. Compare the AlgorithmIdentifier encoding")
print("="*60)
