This is a simple example that shows how perform cosign verification
using a bundle which contains everything required to verify a blob.

### Create the artifact to be signed.
```console
echo something > artifact.txt
```

### Sign the artifact.txt file using cosign
```
COSIGN_EXPERIMENTAL=1 cosign sign-blob --bundle=artifact.bundle artifact.txt
```

### Verify using sigstore-rs:
```console
cargo run --example verify-bundle -- \
    --rekor-pub-key ~/.sigstore/root/targets/rekor.pub \
    --bundle artifact.bundle \
    artifact.txt
```
