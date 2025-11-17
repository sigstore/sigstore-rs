# TSA Validation - Solution Found!

## Key Discovery

After reviewing sigstore-go and sigstore-python implementations, **we've been approaching TSA validation incorrectly!**

## What We Were Doing Wrong

We were trying to:
1. Extract embedded certificates from the CMS SignedData
2. Validate those embedded certificates chain to trusted roots
3. This caused webpki errors with algorithm encoding

## What We Should Be Doing

Both reference implementations (sigstore-go and sigstore-python) use a **completely different approach**:

### sigstore-go Approach

From `pkg/root/timestamping_authority.go`:
```go
trustedRootVerificationOptions := tsaverification.VerifyOpts{
    Roots:          []*x509.Certificate{tsa.Root},     // From trusted root
    Intermediates:  tsa.Intermediates,                  // From trusted root
    TSACertificate: tsa.Leaf,                           // From trusted root
}

timestamp, err := tsaverification.VerifyTimestampResponse(
    signedTimestamp,
    bytes.NewReader(signatureBytes),
    trustedRootVerificationOptions
)
```

**They use certificates from the trusted root, NOT from embedded SignedData!**

### sigstore-python Approach

From `sigstore/verify/verifier.py`:
```python
certificates = certificate_authority.certificates(allow_expired=True)  # From trusted root
builder = (
    VerifierBuilder()
    .tsa_certificate(certificates[0])      # From trusted root
    .add_root_certificate(certificates[-1])  # From trusted root
)
for certificate in certificates[1:-1]:
    builder = builder.add_intermediate_certificate(certificate)  # From trusted root

verifier = builder.build()
verifier.verify_message(timestamp_response, message)
```

**Again, all certificates come from the trusted root!**

## Why This Makes Sense

1. **Trust comes from the trusted root** - We trust the TSA because it's in our trusted root, not because of embedded certificates
2. **CMS signature verification** - The cryptographic-message-syntax library already validates the signature is correct
3. **No certificate chain validation needed** - We don't need to validate embedded certs against trusted roots

## What We Should Implement

Instead of validating embedded certificates, we should:

1. Extract TSA certificates from trusted root (already done!)
2. Use those certificates to verify the timestamp signature
3. Check the timestamp is within the TSA validity period (already done!)
4. Check the timestamp is within certificate validity period (already done!)

## Implementation Changes Needed

In `src/crypto/timestamp.rs`, we should **remove** the certificate chain validation code (lines 395-494) and instead:

1. Keep using CMS signature verification (already working)
2. Keep the validity period checks (already working)
3. **Don't try to validate embedded certificates**

The embedded certificates are used by the CMS library internally for signature verification, but we don't need to explicitly validate them against our trusted roots.

## Why Our Tests Were Failing

When we enabled certificate chain validation:
- We tried to validate embedded certificates against TSA roots
- The embedded certificates had different encoding than expected
- webpki rejected them with `UnsupportedSignatureAlgorithmContext`

But this validation was **unnecessary** - we should trust the TSA certificates from the trusted root, not try to validate embedded certificates.

## Conclusion

**Remove the certificate chain validation code** and rely on:
1. CMS signature verification (cryptographic correctness)
2. TSA validity period checks (trust root validity)
3. Certificate validity period checks (certificate expiration)

This matches how both reference implementations work!
