# Example Key Interface

This is a simple example program that shows how to perform signing key pair
generation, signing with a private key, exporting the private/public key
and verifying with a public key.

The general idea is to randomly generate an `ECDSA_P256_ASN1` key pair
and sign the given data, and verify the signature using the public key.

# Run the example case

Run this example

```bash
cargo run --example key_interface
```

This is a simple example to use [`signing_key`](../../src/crypto/signing_key/mod.rs) module, including the following steps:

* Randomly generate an `ECDSA_P256_ASN1` key pair, which is represented as `signer` of type
`SigStoreSigner` and includes a private key and a public key. Here, the type of the key
pair is influenced by the given `SigningScheme`.
* Sign the given data `DATA_TO_BE_SIGNED` using the `signer`'s private key.
* Import the `signer`'s private key in pem format.
* Export the `signer`'s public key in pem format.
* Import the exported public key using [`verification_key`](../../src/crypto/verification_key.rs) module.
* Verify the signature generated before.
