This is an experimental crate to interact with [sigstore](https://sigstore.dev/).

This is under high development, many features and checks are still missing.

Right now I've been focusing on implementing the verification bits required
to verify something that has been previously signed with `cosign`.

## Examples

### Verification

Create a keypair using the official cosign client:

```console
cosign generate-key-pair
```

Sign a container image:

```console
cosign sign -key cosign.key registry-testing.svc.lan/busybox
```

Verify the image signature using the example program defined under
`examples/verify`:

```console
cargo run --example verify -- -k cosign.pub registry-testing.svc.lan/busybox
```
