# Rekor v2 API Support Implementation Plan

## Overview
This document outlines the plan to add Rekor v2 API support to sigstore-rs, following the pattern established by sigstore-python's implementation.

## Current State

### What We Have
- Rekor v1 API client at `src/rekor/apis/entries_api.rs`
- Hardcoded to `/api/v1/log/entries` endpoint
- Uses `ProposedLogEntry::Hashedrekord` with `api_version: "0.0.1"`
- Single `RekorConfiguration` type from `src/rekor/apis/configuration.rs`

### The Problem
- Conformance tests expect `hashedrekord` v0.0.2 entries when using staging Rekor v2 instances
- We currently create v0.0.1 entries regardless of the Rekor instance version
- Rekor v2 instances (URLs like `https://log2025-alpha3.rekor.sigstage.dev`) require different API interactions

## Architecture (Based on sigstore-python)

### Python's Approach
```python
# Abstract base class
class RekorLogSubmitter(ABC):
    @abstractmethod
    def create_entry(self, request: EntryRequestBody) -> TransparencyLogEntry

    @abstractmethod
    def _build_hashed_rekord_request(...)

    @abstractmethod
    def _build_dsse_request(...)

# V1 Implementation
class RekorClient(RekorLogSubmitter):
    def __init__(self, url: str):
        self.url = f"{url}/api/v1"

    def _build_hashed_rekord_request(...):
        # Uses rekor_types.hashedrekord.HashedrekordV001Schema
        # Returns dict with "apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {...}

# V2 Implementation
class RekorV2Client(RekorLogSubmitter):
    def __init__(self, url: str):
        self.url = f"{url}/api/v2"

    def _build_hashed_rekord_request(...):
        # Uses rekor_v2.hashedrekord.HashedRekordRequestV002
        # Different request structure, no apiVersion field
        # Server returns entries marked as v0.0.2

# Selection logic (in models.py)
for tlog in trust_root.tlogs:
    if tlog.major_api_version == 1:
        clients.append(RekorClient(tlog.url))
    elif tlog.major_api_version == 2:
        clients.append(RekorV2Client(tlog.url))
```

## Proposed Rust Implementation

### Phase 1: Trait-Based Architecture

#### 1.1 Create `RekorClient` Trait
**File**: `src/rekor/client.rs` (new file)

```rust
use crate::bundle::Bundle;
use crate::errors::SigstoreResult;
use crate::rekor::models::log_entry::LogEntry;
use crate::rekor::models::proposed_entry::ProposedEntry;
use async_trait::async_trait;

/// Trait for Rekor transparency log clients.
///
/// This trait abstracts over Rekor v1 and v2 API differences.
#[async_trait]
pub trait RekorClient: Send + Sync {
    /// Submit a log entry to Rekor and return the integrated entry.
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry>;

    /// Get the base URL of this Rekor instance.
    fn base_url(&self) -> &str;

    /// Get the major API version (1 or 2).
    fn api_version(&self) -> u32;
}
```

#### 1.2 Implement Rekor V1 Client
**File**: `src/rekor/client_v1.rs` (new file)

```rust
use super::client::RekorClient;
use super::apis::configuration::Configuration;
use super::apis::entries_api;
use async_trait::async_trait;

pub struct RekorV1Client {
    config: Configuration,
    base_url: String,
}

impl RekorV1Client {
    pub fn new(base_url: String) -> Self {
        let mut config = Configuration::default();
        config.base_path = base_url.clone();

        Self {
            config,
            base_url,
        }
    }
}

#[async_trait]
impl RekorClient for RekorV1Client {
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry> {
        // Use existing entries_api::create_log_entry
        // Maps to /api/v1/log/entries
        entries_api::create_log_entry(&self.config, entry)
            .await
            .map_err(|e| SigstoreError::RekorClientError(e.to_string()))
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn api_version(&self) -> u32 {
        1
    }
}
```

#### 1.3 Implement Rekor V2 Client
**File**: `src/rekor/client_v2.rs` (new file)

```rust
use super::client::RekorClient;
use async_trait::async_trait;
use reqwest;
use serde_json::json;

pub struct RekorV2Client {
    base_url: String,
    client: reqwest::Client,
}

impl RekorV2Client {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl RekorClient for RekorV2Client {
    async fn create_entry(&self, entry: ProposedEntry) -> SigstoreResult<LogEntry> {
        // Convert ProposedEntry to v2 request format
        let v2_request = self.build_v2_request(entry)?;

        // POST to /api/v2/log/entries
        let url = format!("{}/api/v2/log/entries", self.base_url);
        let response = self.client
            .post(&url)
            .json(&v2_request)
            .send()
            .await
            .map_err(|e| SigstoreError::RekorClientError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SigstoreError::RekorClientError(
                format!("Rekor v2 API error: {}", response.status())
            ));
        }

        // Parse response into LogEntry
        let entry: LogEntry = response.json()
            .await
            .map_err(|e| SigstoreError::RekorClientError(e.to_string()))?;

        Ok(entry)
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn api_version(&self) -> u32 {
        2
    }
}

impl RekorV2Client {
    fn build_v2_request(&self, entry: ProposedEntry) -> SigstoreResult<serde_json::Value> {
        match entry {
            ProposedEntry::Hashedrekord { api_version: _, spec } => {
                // Convert v1 hashedrekord spec to v2 format
                // V2 format: HashedRekordRequestV002
                Ok(json!({
                    "hashedRekordRequestV002": {
                        "digest": spec.data.hash.value, // base64 encoded
                        "signature": {
                            "content": spec.signature.content, // base64 encoded
                            "verifier": {
                                "x509Certificate": {
                                    "rawBytes": spec.signature.public_key.content // base64 DER cert
                                },
                                "keyDetails": self.extract_key_details(&spec.signature.public_key)?
                            }
                        }
                    }
                }))
            },
            ProposedEntry::Dsse { api_version: _, spec } => {
                // Convert v1 dsse spec to v2 format
                // V2 format: DSSERequestV002
                Ok(json!({
                    "dsseRequestV002": {
                        "envelope": spec.envelope,
                        "verifiers": spec.verifiers.iter().map(|v| {
                            json!({
                                "x509Certificate": {
                                    "rawBytes": v.content
                                },
                                "keyDetails": self.extract_key_details(v)?
                            })
                        }).collect::<Result<Vec<_>, _>>()?
                    }
                }))
            },
            _ => Err(SigstoreError::UnexpectedError(
                "Unsupported entry type for Rekor v2".into()
            ))
        }
    }

    fn extract_key_details(&self, cert: &PublicKey) -> SigstoreResult<serde_json::Value> {
        // Parse certificate and extract key details
        // Returns: { "pkixPublicKey": { "ecdsaVerifyingKey": {...} } }
        // or similar based on key type
        todo!("Implement key details extraction from certificate")
    }
}
```

### Phase 2: Update SigningContext

#### 2.1 Modify SigningContext Structure
**File**: `src/bundle/sign.rs`

```rust
pub struct SigningContext {
    fulcio: FulcioClient,
    rekor_client: Box<dyn RekorClient>, // Changed from RekorConfiguration
    ctfe_keyring: Keyring,
}

impl SigningContext {
    pub fn new(
        fulcio: FulcioClient,
        rekor_client: Box<dyn RekorClient>,
        ctfe_keyring: Keyring,
    ) -> Self {
        Self {
            fulcio,
            rekor_client,
            ctfe_keyring,
        }
    }

    // Update from_trust_root_and_fulcio to detect Rekor version
    pub fn from_trust_root_and_fulcio(
        trust_root: SigstoreTrustRoot,
        fulcio_url: Option<String>,
        rekor_tlog_config: Option<&TlogService>, // From signing config
    ) -> SigstoreResult<Self> {
        // Extract CTFE keys
        let ctfe_keys = trust_root.ctfe_keys()?;
        let keys_with_ids: Vec<([u8; 32], &[u8])> = /* ... */;

        // Determine Rekor client based on tlog config
        let rekor_client: Box<dyn RekorClient> = if let Some(tlog) = rekor_tlog_config {
            if tlog.major_api_version == 2 {
                Box::new(RekorV2Client::new(tlog.url.clone()))
            } else {
                Box::new(RekorV1Client::new(tlog.url.clone()))
            }
        } else {
            // Default to production v1
            Box::new(RekorV1Client::new(
                "https://rekor.sigstore.dev".to_string()
            ))
        };

        // Create Fulcio client
        let fulcio_url_str = fulcio_url.as_deref().unwrap_or(FULCIO_ROOT);
        let fulcio_url_parsed = Url::parse(fulcio_url_str)?;

        Ok(Self::new(
            FulcioClient::new(fulcio_url_parsed, /* ... */),
            rekor_client,
            Keyring::new_with_ids(keys_with_ids.iter().map(|(id, bytes)| (id, *bytes)))?,
        ))
    }
}
```

#### 2.2 Update Signing Methods
**File**: `src/bundle/sign.rs`

```rust
impl<'ctx> SigningSession<'ctx> {
    pub async fn sign<R: Read>(&self, mut input: R) -> SigstoreResult<SigningArtifact> {
        // ... existing code for hashing and signing ...

        // Determine API version based on Rekor client
        let api_version = if self.context.rekor_client.api_version() == 2 {
            "0.0.2"
        } else {
            "0.0.1"
        };

        // Create the transparency log entry
        let proposed_entry = ProposedLogEntry::Hashedrekord {
            api_version: api_version.to_owned(),
            spec: hashedrekord::Spec { /* ... */ },
        };

        // Submit to Rekor using the client trait
        let log_entry = self.context.rekor_client
            .create_entry(proposed_entry)
            .await?;

        // ... rest of signing logic ...
    }
}
```

### Phase 3: Update Conformance CLI

#### 3.1 Parse Signing Config for Rekor TLog Info
**File**: `tests/conformance/conformance.rs`

```rust
fn sign_bundle(args: SignBundle) -> anyhow::Result<()> {
    // ... existing code ...

    // Parse signing config to get Fulcio URL AND Rekor tlog info
    let (fulcio_url, rekor_tlog_service) = if let Some(ref config_path) = signing_config {
        use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::SigningConfig;

        let config_data = std::fs::read(config_path)?;
        let config: SigningConfig = serde_json::from_slice(&config_data)?;

        let fulcio = if !config.ca_urls.is_empty() {
            Some(config.ca_urls[0].url.clone())
        } else {
            None
        };

        let rekor = if !config.rekor_tlog_urls.is_empty() {
            Some(&config.rekor_tlog_urls[0])
        } else {
            None
        };

        (fulcio, rekor)
    } else {
        (None, None)
    };

    // Create signing context with Rekor tlog info
    let context = if let Some(trusted_root_path) = trusted_root {
        let trust_root = SigstoreTrustRoot::from_file_unchecked(
            Path::new(&trusted_root_path)
        )?;
        SigningContext::from_trust_root_and_fulcio(
            trust_root,
            fulcio_url,
            rekor_tlog_service
        )?
    } else {
        SigningContext::production()?
    };

    // ... rest of signing logic ...
}
```

## Implementation Steps

### Step 1: Foundation (1-2 days)
- [ ] Create `src/rekor/client.rs` with `RekorClient` trait
- [ ] Add `async-trait` dependency to Cargo.toml
- [ ] Update `src/rekor/mod.rs` to expose new modules

### Step 2: V1 Client Refactor (1 day)
- [ ] Create `src/rekor/client_v1.rs`
- [ ] Implement `RekorV1Client` wrapping existing `entries_api`
- [ ] Add tests to verify v1 client works identically to current implementation

### Step 3: V2 Client Implementation (2-3 days)
- [ ] Create `src/rekor/client_v2.rs`
- [ ] Implement V2 API request format conversion
- [ ] Implement key details extraction from certificates
- [ ] Add integration tests against staging Rekor v2 instance

### Step 4: SigningContext Integration (1-2 days)
- [ ] Update `SigningContext` to use `Box<dyn RekorClient>`
- [ ] Modify `from_trust_root_and_fulcio()` to accept tlog config
- [ ] Update client selection logic based on `major_api_version`
- [ ] Update all signing methods to use trait-based client

### Step 5: Conformance CLI Updates (1 day)
- [ ] Parse `rekor_tlog_urls` from signing config
- [ ] Pass first tlog service to `SigningContext::from_trust_root_and_fulcio()`
- [ ] Test with staging configuration

### Step 6: Testing & Documentation (1-2 days)
- [ ] Add unit tests for v2 request format conversion
- [ ] Add integration tests for both v1 and v2 clients
- [ ] Update API documentation
- [ ] Test conformance suite passes 109/109 tests

## Key Differences from Python Implementation

### Similarities
1. **Trait-based abstraction** (like Python's ABC)
2. **Separate v1 and v2 clients** with different implementations
3. **Selection logic based on `major_api_version`** from trust root/signing config
4. **V2 uses different API endpoint** (`/api/v2/log/entries`)

### Differences
1. **Rust uses traits instead of ABC**: More compile-time safety
2. **Async/await**: Rust async is different from Python
3. **Type safety**: Stronger typing in Rust requires more explicit conversions
4. **Error handling**: Result types vs exceptions

## Testing Strategy

### Unit Tests
- Test v2 request format conversion for hashedrekord entries
- Test v2 request format conversion for dsse entries
- Test key details extraction

### Integration Tests
- Test v1 client against production Rekor
- Test v2 client against staging Rekor v2 instance
- Test client selection logic with different signing configs

### Conformance Tests
- Verify `test_sign_verify_rekor2` passes with v0.0.2 entries
- Verify all existing tests still pass with v1 client

## Potential Challenges

### 1. Request Format Conversion
The v2 API has a different request structure. Need to carefully map v1 `ProposedEntry` format to v2 request format.

**Mitigation**: Reference sigstore-python's implementation closely, use staging instance for testing.

### 2. Key Details Extraction
V2 API requires extracting key details from certificates (algorithm, curve info, etc.)

**Mitigation**: Use existing crypto libraries (x509-cert, p256, etc.) to parse certificate and extract details.

### 3. Backward Compatibility
Need to ensure existing code continues to work with v1 client.

**Mitigation**: Extensive testing, keep v1 as default, use feature flags if needed.

### 4. Trait Object Lifetimes
Using `Box<dyn RekorClient>` requires careful lifetime management.

**Mitigation**: Use `Send + Sync` bounds, ensure all implementations are thread-safe.

## Success Criteria

1. ✅ Conformance test `test_sign_verify_rekor2` passes
2. ✅ All existing conformance tests continue to pass
3. ✅ Can sign with both v1 and v2 Rekor instances
4. ✅ Client automatically selects correct version based on signing config
5. ✅ No breaking changes to existing public API

## Future Enhancements

1. **Multiple TLog Support**: Currently only uses first tlog from config, could support failover
2. **V2-specific Features**: Leverage v2-specific improvements (better performance, etc.)
3. **Client Pooling**: Reuse HTTP clients for better performance
4. **Metric Extraction**: V2 API may provide additional metadata worth capturing

## References

- [Sigstore Python Rekor v2 Implementation](https://github.com/sigstore/sigstore-python/blob/main/sigstore/_internal/rekor/client_v2.py)
- [Rekor v2 Client Documentation](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md)
- [Sigstore Protobuf Specs](https://github.com/sigstore/protobuf-specs)
