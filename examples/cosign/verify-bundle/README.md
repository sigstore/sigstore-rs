This example shows how to verify a blob, using a bundle that was created by the
`cosign sign-blob` command.

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
