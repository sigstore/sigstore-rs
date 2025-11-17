# TODO: Add Rekor v2 API Support

## Background

Rekor v2 API is under development via the `rekor-tiles` project. While Rekor v1 API is currently the production standard used by cosign and sigstore-go, v2 offers improvements to API usability, deployment simplification, and enhanced privacy features.

**Current Status:**
- ✅ We successfully implemented DSSE v0.0.1 with Rekor v1 API
- ✅ Verified working with cosign verification
- ❌ Rekor v2 API not yet implemented

## When to Implement

Wait until:
1. The ecosystem starts migrating (cosign/sigstore-go add v2 support)
2. The v2 API is fully stabilized and documented
3. There's a clear migration path documented by Sigstore team

## Implementation Plan

### 1. Add v2 Request/Response Models (~100 lines)

Based on the Rekor v2 Swagger spec, create new types:

```rust
// src/rekor/models_v2.rs (new file)

#[derive(Serialize, Deserialize)]
pub struct CreateEntryRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashed_rekord_request_v002: Option<HashedRekordRequestV002>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsse_request_v002: Option<DSSERequestV002>,
}

#[derive(Serialize, Deserialize)]
pub struct DSSERequestV002 {
    pub envelope: IntotoEnvelope,
    pub verifiers: Vec<Verifier>,
}

#[derive(Serialize, Deserialize)]
pub struct Verifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<X509Certificate>,
    pub key_details: PublicKeyDetails,
}

// ... other types from swagger spec
```

### 2. Add v2 API Client (~50 lines)

```rust
// src/rekor/client_v2.rs (new file)

pub async fn create_entry_v2(
    config: &RekorConfiguration,
    request: CreateEntryRequest,
) -> Result<TransparencyLogEntry, Error> {
    let url = format!("{}/api/v2/log/entries", config.base_url);

    // POST request with v2 format
    // Parse v2 response
    // Return TransparencyLogEntry (same as v1)
}
```

### 3. Update sign.rs to Support Both APIs (~50 lines)

Add configuration option:

```rust
pub enum RekorApiVersion {
    V1,  // Current implementation
    V2,  // New implementation
}

impl SigningSession {
    pub async fn sign_dsse_with_api(
        &self,
        statement: &Statement,
        api_version: RekorApiVersion
    ) -> SigstoreResult<SigningArtifact> {
        // ... existing DSSE signing logic ...

        match api_version {
            RekorApiVersion::V1 => {
                // Current implementation (DSSE v0.0.1)
                let proposed_entry = ProposedLogEntry::Dsse { ... };
                create_log_entry(&self.context.rekor_config, proposed_entry).await
            }
            RekorApiVersion::V2 => {
                // New implementation (DSSE v0.0.2 format for v2 API)
                let request = CreateEntryRequest {
                    dsse_request_v002: Some(DSSERequestV002 {
                        envelope: envelope,
                        verifiers: vec![Verifier { ... }],
                    }),
                    ..Default::default()
                };
                create_entry_v2(&self.context.rekor_config, request).await
            }
        }
    }
}
```

### 4. Add CLI Flag (~10 lines)

```rust
// src/bin/sigstore-cli.rs

#[derive(Parser)]
struct AttestBlobArgs {
    // ... existing fields ...

    /// Use Rekor v2 API instead of v1
    #[clap(long)]
    rekor_v2: bool,
}
```

### 5. Add Tests (~100 lines)

- Unit tests for v2 models serialization/deserialization
- Integration test comparing v1 vs v2 submissions
- Test that both APIs produce valid bundles

## Estimated Effort

- **Total LOC:** ~300 lines
- **Time:** 4-6 hours for implementation + testing
- **Complexity:** Moderate (mainly adding parallel code path)

## Key Differences: v1 vs v2

| Aspect | v1 API | v2 API |
|--------|--------|--------|
| Endpoint | `/api/v1/log/entries` | `/api/v2/log/entries` |
| Request Format | `ProposedLogEntry` with `kind`/`apiVersion` | `CreateEntryRequest` with typed variants |
| DSSE Format | String envelope in `proposedContent` | Structured `DSSERequestV002` |
| Verifier Format | Base64 PEM string array | Structured `Verifier` objects with `key_details` |
| Response | Legacy format with base64 body | Standard `TransparencyLogEntry` |

## References

- [Rekor v2 Swagger Spec](https://rekor.sigstore.dev/api/v2/swagger.json)
- [rekor-tiles GitHub](https://github.com/sigstore/rekor-tiles)
- [SigstoreCon 2024 Presentation](https://openssf.org/blog/2024/12/16/sigstorecon-2024-advancing-software-supply-chain-security/)

## Notes

- The DSSE signing logic itself doesn't change - we just fixed the PAE computation bug
- v2 API uses the same DSSE envelope structure, just different submission format
- Both APIs should produce v0.3 bundles that verify the same way
- Keep v1 as default until ecosystem migrates
