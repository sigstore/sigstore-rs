# Test Cryptographic Keys

This directory contains cryptographic key material used for testing.

## ctfe_rsa_pkcs1_staging.der

**Source**: Sigstore Staging TUF Repository
**URL**: https://tuf-repo-cdn.sigstage.dev
**Path**: `ctlogs[0].publicKey.rawBytes` from `trusted_root.json`
**Format**: PKCS#1 RSAPublicKey (DER-encoded)
**Key Type**: RSA 4096-bit
**Key Details**: `PKCS1_RSA_PKCS1V5`
**Log ID**: `1b7c142a4e992ba7df1e1fc574245413...`

### Description

This is a CTFE (Certificate Transparency Front End) public key from the Sigstore staging environment.

**Important**: This key uses the deprecated PKCS#1 format instead of the standard SPKI (SubjectPublicKeyInfo) format. According to sigstore-go's codebase:

> "This key format is deprecated, but currently in use for Sigstore staging instance"

The key structure is:
```
SEQUENCE {
  INTEGER (modulus - 4096 bits)
  INTEGER (public exponent - typically 65537)
}
```

Instead of the proper SPKI format:
```
SEQUENCE {
  SEQUENCE {                    -- AlgorithmIdentifier
    OBJECT IDENTIFIER (rsaEncryption)
    NULL
  }
  BIT STRING {                  -- subjectPublicKey
    SEQUENCE {
      INTEGER (modulus)
      INTEGER (exponent)
    }
  }
}
```

### Usage in Tests

This key is used to verify that our keyring implementation correctly handles:
1. PKCS#1 RSA keys (for staging compatibility)
2. Proper SPKI RSA keys (for production)
3. Graceful fallback when SPKI parsing fails

### References

- [RFC 8017 - PKCS #1: RSA Cryptography Specifications](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 5280 - SubjectPublicKeyInfo](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
- [sigstore-go trust root handling](https://github.com/sigstore/sigstore-go/blob/main/pkg/root/trusted_root.go)

---

## staging_trusted_root.json

**Source**: Sigstore Staging TUF Repository
**URL**: https://tuf-repo-cdn.sigstage.dev
**File**: `trusted_root.json`
**Format**: JSON (Sigstore TrustedRoot protobuf as JSON)

### Description

This is the complete trusted root from the Sigstore staging environment. It contains:

- **3 CTFE (Certificate Transparency) logs**:
  - 1 RSA 4096-bit key in PKCS#1 format (deprecated)
  - 2 ECDSA P256 keys in SPKI format
- **3 Transparency logs (Rekor)**:
  - Mixed ECDSA and Ed25519 keys
- **Certificate Authorities (Fulcio)**
- **Timestamp Authorities (TSA)**

### Usage in Tests

This file is used to verify that our implementation can:
1. Load complete trusted roots from JSON files
2. Handle mixed key formats (PKCS#1 and SPKI)
3. Extract and use all key types (RSA, ECDSA, Ed25519)
4. Work with the actual staging infrastructure used by conformance tests

### Key Differences from Production

The staging trusted root differs from production in:
1. Contains a deprecated PKCS#1 RSA key (production uses only SPKI)
2. Uses staging URLs (tuf-repo-cdn.sigstage.dev)
3. May have different certificate authorities and validity periods
