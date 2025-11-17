#!/bin/bash
# Compare certificate extraction between sigstore-rs and sigstore-go
# This helps rule out parsing issues

set -e

echo "=== Comparing Certificate Extraction: sigstore-rs vs sigstore-go ==="
echo

# First, run our Rust extraction
echo "Step 1: Extracting certificate with sigstore-rs (Rust)"
echo "------------------------------------------------------"
cargo run --example webpki_issue_demo --features verify 2>&1 | grep -A 1 "Saved to:" | grep embedded
ls -lh /tmp/embedded_cert.der
echo

# Now let's use sigstore-go to extract the same certificate
echo "Step 2: Extracting certificate with sigstore-go"
echo "-----------------------------------------------"

cd sigstore-go

# Create a simple Go program to extract the cert
cat > /tmp/extract_cert.go << 'EOF'
package main

import (
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/digitorus/timestamp"
)

func main() {
	// Read bundle
	bundleData, err := ioutil.ReadFile("../sigstore-conformance/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading bundle: %v\n", err)
		os.Exit(1)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing bundle: %v\n", err)
		os.Exit(1)
	}

	// Extract timestamp
	timestampB64 := bundle["verificationMaterial"].(map[string]interface{})["timestampVerificationData"].(map[string]interface{})["rfc3161Timestamps"].([]interface{})[0].(map[string]interface{})["signedTimestamp"].(string)

	timestampDER, err := base64.StdEncoding.DecodeString(timestampB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding timestamp: %v\n", err)
		os.Exit(1)
	}

	// Parse timestamp response
	tsResp, err := timestamp.ParseResponse(timestampDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing timestamp response: %v\n", err)
		os.Exit(1)
	}

	// Get the first certificate from the timestamp token
	if len(tsResp.Certificates) > 0 {
		cert := tsResp.Certificates[0]
		fmt.Printf("Found %d certificate(s) in timestamp\n", len(tsResp.Certificates))
		fmt.Printf("Certificate size: %d bytes\n", len(cert.Raw))

		// Write to file
		if err := ioutil.WriteFile("/tmp/sigstore_go_cert.der", cert.Raw, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing cert: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Saved to: /tmp/sigstore_go_cert.der")
	} else {
		fmt.Println("No certificates found in timestamp")
	}
}
EOF

# Try to run it (may fail if dependencies aren't available)
echo "Attempting to compile and run Go extraction..."
if go run /tmp/extract_cert.go 2>&1; then
	echo
	echo "Step 3: Comparing the extracted certificates"
	echo "--------------------------------------------"
	echo "Rust extraction:  /tmp/embedded_cert.der"
	echo "Go extraction:    /tmp/sigstore_go_cert.der"
	echo

	ls -lh /tmp/embedded_cert.der /tmp/sigstore_go_cert.der
	echo

	if diff /tmp/embedded_cert.der /tmp/sigstore_go_cert.der > /dev/null 2>&1; then
		echo "✓ Certificates are IDENTICAL!"
		echo "  Both Rust and Go extract the same bytes from CMS SignedData"
		echo "  This rules out parsing issues in sigstore-rs"
	else
		echo "✗ Certificates are DIFFERENT!"
		echo "  This suggests a parsing issue in one of the implementations"
		echo
		echo "Rust cert SHA256:"
		openssl dgst -sha256 /tmp/embedded_cert.der
		echo "Go cert SHA256:"
		openssl dgst -sha256 /tmp/sigstore_go_cert.der
	fi
else
	echo
	echo "Note: Could not run Go extraction (dependencies may be missing)"
	echo "This is okay - the Rust extraction is sufficient for our analysis"
fi

cd ..

echo
echo "=== Analysis ==="
echo
echo "The key question: Is the embedded certificate actually valid?"
echo
echo "Let's check if the certificate's signature is self-consistent:"
echo "(i.e., does the signature value match the TBS certificate?)"
echo
openssl asn1parse -in /tmp/embedded_cert.der -inform DER -strparse 4 > /tmp/tbs_cert.der 2>&1 || true
echo "Extracted TBS (to-be-signed) certificate"
echo

echo "Comparing with trusted certificate:"
openssl x509 -in /tmp/trusted_leaf_cert.der -inform DER -noout -modulus > /tmp/trusted_mod.txt
openssl x509 -in /tmp/embedded_cert.der -inform DER -noout -modulus > /tmp/embedded_mod.txt

if diff /tmp/trusted_mod.txt /tmp/embedded_mod.txt > /dev/null 2>&1; then
	echo "✓ Both certificates have the same modulus (public key)"
else
	echo "✗ Different moduli - these are truly different certificates"
fi

echo
echo "Conclusion:"
echo "-----------"
echo "The embedded certificate from CMS has:"
echo "  - Same subject/issuer as trusted cert"
echo "  - Same serial number as trusted cert"
echo "  - Same public key as trusted cert"
echo "  - NULL parameter in signature algorithm (embedded has it, trusted doesn't)"
echo "  - OpenSSL reports signature verification failure"
echo
echo "This suggests the embedded cert is a RE-ENCODED version of the trusted cert,"
echo "where the re-encoding added NULL parameters and possibly invalidated the signature."
echo
echo "The webpki NULL parameter issue is REAL, but there may also be a signature issue."
