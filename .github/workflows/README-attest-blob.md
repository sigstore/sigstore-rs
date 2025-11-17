# Testing sigstore-cli attest-blob with GitHub OIDC

This workflow tests the `sigstore-cli attest-blob` command using GitHub Actions OIDC authentication.

## What it tests

1. **Building sigstore-cli** - Compiles the CLI with all required features
2. **OIDC Authentication** - Uses GitHub Actions' built-in OIDC token provider
3. **DSSE Attestation Creation** - Creates in-toto attestations wrapped in DSSE envelopes
4. **Sigstore Bundle v0.3** - Generates the latest bundle format
5. **Rekor Upload** - Uploads attestation to the Rekor transparency log
6. **Cosign Verification** - Verifies the attestation using cosign

## Running the workflow

The workflow runs automatically on:
- Pushes to the `experiments` branch
- Pull requests to `main`
- Manual trigger via `workflow_dispatch`

To run manually:
1. Go to Actions tab in GitHub
2. Select "Test attest-blob with OIDC"
3. Click "Run workflow"
4. Select the branch and click "Run workflow"

## What the workflow does

### Step 1: Build the CLI
```bash
cargo build --bin sigstore-cli --features sign,full,clap,sigstore-trust-root --release
```

### Step 2: Create test files
- Creates a test blob (`test-blob.txt`)
- Creates a JSON predicate with build metadata

### Step 3: Attest with OIDC
```bash
./target/release/sigstore-cli attest-blob \
  --statement predicate.json \
  --bundle test-blob.sigstore.json \
  -y \
  test-blob.txt
```

The CLI automatically:
- Detects GitHub Actions OIDC token from environment
- Authenticates with Fulcio to get a signing certificate
- Creates a DSSE envelope with the in-toto statement
- Signs the envelope
- Uploads to Rekor transparency log
- Creates a Sigstore Bundle v0.3

### Step 4: Verify with cosign
Uses cosign to verify the attestation matches expected identity

## Expected output

The workflow creates bundles that:
- Use `application/vnd.dev.sigstore.bundle.v0.3+json` format
- Contain DSSE envelopes with `application/vnd.in-toto+json` payload
- Include Fulcio certificates with GitHub OIDC claims
- Have Rekor transparency log entries

## Artifacts

The workflow uploads the generated bundles as artifacts for inspection:
- `test-blob.sigstore.json` - Attestation with full predicate
- `simple-blob.sigstore.json` - Minimal attestation with just type

## Verifying locally

After downloading the bundle artifact:

```bash
# Install cosign
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o cosign
chmod +x cosign

# Verify the attestation
./cosign verify-blob-attestation \
  --bundle test-blob.sigstore.json \
  --new-bundle-format \
  --type "https://example.com/predicate/v1" \
  --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/test-attest-blob.yml@refs/heads/experiments" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  test-blob.txt
```

## Debugging

If the workflow fails:
1. Check the build step for compilation errors
2. Check OIDC authentication - ensure `id-token: write` permission is set
3. Check bundle structure in the "Verify bundle structure" step
4. Download artifacts to inspect bundles locally
