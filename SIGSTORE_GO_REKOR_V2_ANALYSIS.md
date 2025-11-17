# Sigstore-Go Rekor v2 Implementation Analysis

## Overview
This document analyzes how sigstore-go implements Rekor v1 and v2 API support, to inform our Rust implementation.

## Key Findings

### 1. Interface-Based Design

Sigstore-go uses two separate interfaces for v1 and v2 clients:

```go
// V1 Client Interface (uses existing Rekor v1 API)
type RekorClient interface {
    CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error)
}

// V2 Client Interface (uses rekor-tiles v2 API)
type RekorV2Client interface {
    Add(ctx context.Context, entry any) (*protorekor.TransparencyLogEntry, error)
}

// Higher-level interface for transparency operations
type Transparency interface {
    GetTransparencyLogEntry(context.Context, []byte, *protobundle.Bundle) error
}
```

### 2. Single Rekor Type with Version Switch

Unlike Python's separate `RekorClient` and `RekorV2Client` classes, Go uses a **single `Rekor` struct** with a version field:

```go
type Rekor struct {
    options *RekorOptions
}

type RekorOptions struct {
    BaseURL  string
    Timeout  time.Duration
    Retries  uint
    Client   RekorClient    // V1 client
    ClientV2 RekorV2Client  // V2 client
    Version  uint32         // 1 or 2
}

const (
    rekorV1 = iota + 1  // = 1
    rekorV2             // = 2
)

func NewRekor(opts *RekorOptions) *Rekor {
    if opts.Version == 0 {
        opts.Version = rekorV1  // Default to v1
    }
    return &Rekor{options: opts}
}
```

### 3. Version-Based Dispatch

The `GetTransparencyLogEntry` method switches based on version:

```go
func (r *Rekor) GetTransparencyLogEntry(ctx context.Context, keyOrCertPEM []byte, b *protobundle.Bundle) error {
    var tlogEntry *protorekor.TransparencyLogEntry

    switch r.options.Version {
    case rekorV1:
        tlogEntry, err = r.getRekorV1TLE(ctx, keyOrCertPEM, b)
    case rekorV2:
        tlogEntry, err = r.getRekorV2TLE(ctx, keyOrCertPEM, b)
    default:
        return fmt.Errorf("unknown rekor version: %d", r.options.Version)
    }

    // Add to bundle
    b.VerificationMaterial.TlogEntries = append(
        b.VerificationMaterial.TlogEntries,
        tlogEntry
    )

    return nil
}
```

### 4. V1 Implementation (Traditional API)

V1 uses the traditional Rekor API with `ProposedEntry`:

```go
func (r *Rekor) getRekorV1TLE(ctx context.Context, keyOrCertPEM []byte, b *protobundle.Bundle) (*protorekor.TransparencyLogEntry, error) {
    // Build artifact properties
    artifactProperties := types.ArtifactProperties{
        PublicKeyBytes: [][]byte{keyOrCertPEM},
    }

    var proposedEntry models.ProposedEntry

    if messageSignature != nil {
        // Create hashedrekord entry
        hashedrekordType := hashedrekord.New()
        hexDigest := hex.EncodeToString(messageSignature.MessageDigest.Digest)

        artifactProperties.PKIFormat = string(pki.X509)
        artifactProperties.SignatureBytes = messageSignature.Signature
        artifactProperties.ArtifactHash = rekorUtil.PrefixSHA(hexDigest)

        // CreateProposedEntry with empty version string defaults to "0.0.1"
        proposedEntry, err = hashedrekordType.CreateProposedEntry(ctx, "", artifactProperties)
    }

    // Submit to /api/v1/log/entries
    params := entries.NewCreateLogEntryParams()
    params.SetProposedEntry(proposedEntry)

    resp, err := r.options.Client.CreateLogEntry(params)

    // Convert response to TransparencyLogEntry
    entry := resp.Payload[resp.ETag]
    tlogEntry, err := tle.GenerateTransparencyLogEntry(entry)

    return tlogEntry, nil
}
```

**Key Points**:
- Uses `hashedrekord.New().CreateProposedEntry(ctx, "", artifactProperties)`
- Empty version string defaults to "0.0.1"
- Submits to `/api/v1/log/entries`
- Returns entry with `kind_version: {kind: "hashedrekord", version: "0.0.1"}`

### 5. V2 Implementation (New Rekor-Tiles API)

V2 uses the new rekor-tiles API with protobuf messages:

```go
func (r *Rekor) getRekorV2TLE(ctx context.Context, keyOrCertPEM []byte, b *protobundle.Bundle) (*protorekor.TransparencyLogEntry, error) {
    // Parse certificate/key
    block, _ := pem.Decode(keyOrCertPEM)
    keyOrCertDER := block.Bytes

    // Extract public key for algorithm details
    var pubKey crypto.PublicKey
    switch block.Type {
    case "CERTIFICATE":
        c, _ := x509.ParseCertificate(block.Bytes)
        pubKey = c.PublicKey
    case "PUBLIC KEY":
        pubKey, _ = x509.ParsePKIXPublicKey(block.Bytes)
    }

    // Get algorithm details (CRITICAL for v2)
    algoDetails, err := signature.GetDefaultAlgorithmDetails(pubKey, opts...)

    // Build Verifier with key details
    verifier := &rekortilespb.Verifier{
        KeyDetails: algoDetails.GetSignatureAlgorithm(),
    }

    if bundleCertificate != nil {
        verifier.Verifier = &rekortilespb.Verifier_X509Certificate{
            X509Certificate: &protocommon.X509Certificate{
                RawBytes: keyOrCertDER,
            },
        }
    }

    // Build v2 request based on content type
    var req any
    if messageSignature != nil {
        req = &rekortilespb.HashedRekordRequestV002{
            Signature: &rekortilespb.Signature{
                Content:  messageSignature.Signature,
                Verifier: verifier,
            },
            Digest: messageSignature.MessageDigest.Digest,
        }
    }

    // Create v2 client if needed
    if r.options.ClientV2 == nil {
        client, err := write.NewWriter(r.options.BaseURL, ...)
        r.options.ClientV2 = client
    }

    // Submit to /api/v2/log/entries via rekor-tiles client
    tle, err := r.options.ClientV2.Add(ctx, req)

    return tle, nil
}
```

**Key Differences from V1**:
1. **No `api_version` field**: The request structure itself indicates v0.0.2
2. **`HashedRekordRequestV002`**: Different protobuf message type
3. **Key Details Required**: Must extract and include algorithm details
4. **Verifier Structure**: Uses nested protobuf message with certificate/key + algorithm
5. **rekor-tiles Client**: Uses `github.com/sigstore/rekor-tiles/v2/pkg/client/write`
6. **Server Returns v0.0.2**: The response `TransparencyLogEntry` has `kind_version.version = "0.0.2"`

### 6. Request Structure Comparison

#### V1 Hashedrekord Request
```json
{
  "kind": "hashedrekord",
  "apiVersion": "0.0.1",
  "spec": {
    "signature": {
      "content": "<base64-signature>",
      "publicKey": {
        "content": "<PEM-cert>"
      }
    },
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "<hex-digest>"
      }
    }
  }
}
```

#### V2 Hashedrekord Request
```protobuf
HashedRekordRequestV002 {
  signature: Signature {
    content: <bytes>,
    verifier: Verifier {
      key_details: SignatureAlgorithm {  // ECDSA_P256_SHA256, etc.
        details: ...
      },
      verifier: X509Certificate {
        raw_bytes: <DER-cert>
      }
    }
  },
  digest: <sha256-bytes>
}
```

### 7. Algorithm Details Extraction

V2 requires extracting algorithm details from the public key:

```go
// From signature package
algoDetails, err := signature.GetDefaultAlgorithmDetails(pubKey, opts...)

// Returns something like:
SignatureAlgorithm {
  details: EcdsaVerifyingKey {
    curve: ECDSA_CURVE_NIST_P256,
    sha2_hash: SHA2_256
  }
}
```

This is **critical** - the v2 API won't work without proper key algorithm details.

### 8. Version Selection

**Important Discovery**: The code doesn't automatically select version based on URL or trust root!

The version must be **explicitly set** in `RekorOptions.Version`. The caller is responsible for:
1. Reading trust root or signing config
2. Checking `tlog.major_api_version`
3. Setting `RekorOptions.Version = 2` if needed

Example usage (from tests):
```go
opts := &RekorOptions{
    Retries: 1,
    ClientV2: &mockRekorV2{},
    Version: rekorV2,  // Explicitly set
}
rekor := NewRekor(opts)
```

### 9. Rekor-Tiles Client

V2 uses a separate client library:
```go
import rekortilesclient "github.com/sigstore/rekor-tiles/v2/pkg/client"
import "github.com/sigstore/rekor-tiles/v2/pkg/client/write"

client, err := write.NewWriter(baseURL, rekortilesclient.WithUserAgent(...))
```

This client:
- Implements `RekorV2Client` interface (`Add` method)
- Handles `/api/v2/log/entries` endpoint
- Works with protobuf messages directly
- Returns `*protorekor.TransparencyLogEntry` with v0.0.2 entries

## Key Takeaways for Rust Implementation

### 1. Architecture Choice
Go uses a **single struct with version field**, not separate types. This is simpler but requires runtime dispatch.

For Rust, we have two options:
- **Option A**: Trait-based (like Python) - more type-safe, clearer separation
- **Option B**: Enum-based (like Go) - simpler, single type

**Recommendation**: **Go with trait-based** (Option A) because:
- Rust's trait system provides compile-time guarantees
- Clearer separation of concerns
- Easier to test independently
- More idiomatic Rust

### 2. Version Detection
**Neither Python nor Go automatically detects version from URL!**

Both require explicit version information from:
- Trust root's `tlog.major_api_version` field
- Signing config's `rekorTlogUrls[].majorApiVersion` field

Our current URL-based detection (`if url.contains("2025")`) is **NOT how the reference implementations do it**.

**Action Required**: Update our implementation to use `major_api_version` from signing config.

### 3. V2 API Requirements

Critical elements for v2:
1. **Different endpoint**: `/api/v2/log/entries` (not `/api/v1`)
2. **Different request structure**: `HashedRekordRequestV002` protobuf
3. **Key algorithm details**: Must extract from certificate (ECDSA curve, hash algorithm)
4. **DER encoding**: Certificate as raw DER bytes, not PEM
5. **No api_version field**: The request type itself indicates version

### 4. Algorithm Details Extraction

Need to implement equivalent of Go's `signature.GetDefaultAlgorithmDetails`:
```rust
fn extract_key_details(cert: &Certificate) -> SigstoreResult<KeyDetails> {
    // Parse certificate
    // Extract public key
    // Determine algorithm (ECDSA P-256, RSA, etc.)
    // Return structured key details for v2 API
}
```

### 5. Client Libraries

Go uses `rekor-tiles/v2` for v2 API. For Rust:
- **Option A**: Generate Rust client from protobuf specs
- **Option B**: Use reqwest directly with protobuf serialization
- **Option C**: Wait for official Rust rekor-tiles client

**Recommendation**: **Option B** (reqwest + protobuf) for now:
- Full control over implementation
- Easier to debug
- Can switch to official client when available

## Implementation Differences

### Python vs Go vs Our Plan

| Aspect | Python | Go | Rust (Proposed) |
|--------|--------|----|----|
| **Architecture** | Separate classes | Single struct + version field | Trait-based |
| **Version Detection** | From `major_api_version` | From `major_api_version` | From `major_api_version` |
| **V1 Client** | `RekorClient` class | `RekorClient` interface | `RekorV1Client` impl |
| **V2 Client** | `RekorV2Client` class | `RekorV2Client` interface | `RekorV2Client` impl |
| **Dispatch** | Different class instances | Switch statement | Trait method dispatch |
| **Request Format** | Protobuf models | Protobuf messages | Protobuf (prost) |
| **Algorithm Details** | `_get_key_details()` | `GetDefaultAlgorithmDetails()` | Custom extraction |

## Updated Implementation Plan

Based on this analysis, here are the key updates needed to our plan:

### 1. Version Detection (CRITICAL FIX)
```rust
// NOT THIS:
let api_version = if rekor_url.contains("2025") || rekor_url.contains("/v2/") {
    "0.0.2"
} else {
    "0.0.1"
};

// DO THIS:
let rekor_client: Box<dyn RekorClient> = if tlog.major_api_version == 2 {
    Box::new(RekorV2Client::new(tlog.url.clone()))
} else {
    Box::new(RekorV1Client::new(tlog.url.clone()))
};
```

### 2. V2 Request Structure
Need to use protobuf messages like Go, not convert v1 to v2 format:

```rust
// For v2, build protobuf directly:
let verifier = Verifier {
    key_details: Some(extract_key_details(&cert)?),
    verifier: Some(verifier::Verifier::X509Certificate(
        X509Certificate {
            raw_bytes: cert.to_der()?,
        }
    )),
};

let request = HashedRekordRequestV002 {
    signature: Some(Signature {
        content: signature_bytes,
        verifier: Some(verifier),
    }),
    digest: message_digest,
};
```

### 3. Add Protobuf Dependencies
```toml
[dependencies]
prost = "0.12"
prost-types = "0.12"
# Or use sigstore_protobuf_specs if it includes v2 types
```

### 4. Implement Key Algorithm Details
This is the most complex part - need to determine:
- Key type (ECDSA, RSA, Ed25519)
- For ECDSA: curve (P-256, P-384, P-521)
- Hash algorithm (SHA256, SHA384, SHA512)

```rust
fn extract_key_details(cert: &Certificate) -> SigstoreResult<KeyDetails> {
    let public_key = cert.tbs_certificate.subject_public_key_info;

    match public_key.algorithm.oid {
        // ECDSA with P-256
        ECDSA_P256_OID => Ok(KeyDetails {
            details: Some(key_details::Details::EcdsaVerifyingKey(
                EcdsaVerifyingKey {
                    curve: EcdsaCurve::NistP256,
                    sha2_hash: Sha2Hash::Sha256,
                }
            ))
        }),
        // ... other algorithms
    }
}
```

## Testing Strategy

### 1. Test Against Real Rekor v2 Instance
Use staging: `https://log2025-alpha3.rekor.sigstage.dev`

### 2. Verify Response Format
Check that server returns:
```json
{
  "kindVersion": {
    "kind": "hashedrekord",
    "version": "0.0.2"  // Not 0.0.1!
  }
}
```

### 3. Test Algorithm Details
Ensure key details are correctly extracted for:
- ECDSA P-256 (most common)
- RSA 2048/4096
- Ed25519 (if supported)

## Conclusion

Sigstore-go's implementation is **more similar to our proposed Rust approach** than Python's:
- Uses interfaces for polymorphism (like Rust traits)
- Single package with version-specific code paths
- Explicit version selection based on `major_api_version`

Key learnings:
1. **Don't detect version from URL** - use `major_api_version` field
2. **V2 requires algorithm details** - must implement key detail extraction
3. **Different request structures** - v2 uses protobuf, not JSON with api_version
4. **Server determines entry version** - v2 server returns v0.0.2 entries

Our trait-based approach is the right choice for Rust, combining the best of both implementations.
