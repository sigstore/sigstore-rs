Continuous integration | Docs | License
 ----------------------|------|---------
 [![Continuous integration](https://github.com/flavio/sigstore-rs/actions/workflows/tests.yml/badge.svg)](https://github.com/flavio/sigstore-rs/actions/workflows/tests.yml) | [![Docs](https://img.shields.io/badge/docs-%20-blue)](https://flavio.github.io/sigstore-rs/sigstore) |  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)


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
[`examples/verify`](https://github.com/flavio/sigstore-rs/tree/main/examples/verify):

```console
cargo run --example verify -- -k cosign.pub registry-testing.svc.lan/busybox
```
