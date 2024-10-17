This example shows how to verify a blob, using a bundle that was created by the
`cosign sign-blob` command.

### Sign README.md file using cosign
```
cd examples/cosign/verify-bundle
cosign sign-blob --bundle=artifact.bundle README.md
```

### Verify using sigstore-rs:
```console
cargo run --example verify-bundle -- \
    --rekor-pub-key ~/.sigstore/root/targets/rekor.pub \
    --bundle artifact.bundle \
    README.md
```
