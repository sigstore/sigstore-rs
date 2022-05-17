Continuous integration | Docs | License
 ----------------------|------|---------
 [![Continuous integration](https://github.com/sigstore/sigstore-rs/actions/workflows/tests.yml/badge.svg)](https://github.com/sigstore/sigstore-rs/actions/workflows/tests.yml) | [![Docs](https://img.shields.io/badge/docs-%20-blue)](https://sigstore.github.io/sigstore-rs/sigstore) |  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)


This is an experimental crate to interact with [sigstore](https://sigstore.dev/).

This is under high development, many features and checks are still missing.

## Features

### Verification

The crate implements the following verification mechanisms:

  * Verify using a given key
  * Verify bundle produced by transparency log (Rekor)
  * Verify signature produced in keyless mode, using Fulcio Web-PKI

Signature annotations and certificate email can be provided at verification time.

#### Known limitations

* Users must provide the public key of the transparency log (Rekor) and the
  certificate of the PKI (Fulcio). The removal of this limitation is tracked
  by [this issue](https://github.com/sigstore/sigstore-rs/issues/9).
* The crate does not handle verification of attestations yet.

## Examples

The `examples` directory contains demo programs using the library.

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/security/policy)
