This example shows how to sign and verify Sigstore signature bundles. The bundle
format used here is supported by most Sigstore clients but notably cosign requires
`--new-bundle-format` to do so.

This example uses `sigstore::bundle` for signing and verification. The sign subcommand uses
`sigstore::oauth` for interactive OIDC authorization. In addition to the bundle format, a
notable difference compared to the "cosign" examples is that `sigstore::bundle` also handles
the Sigstore trust root update before signing or verifying.

### Sign README.md

```console
cargo run --example bundle \
    sign README.md
```

A browser window will be opened to authorize signing with an OIDC identity.
After the authorization the signature bundle is created in `README.md.sigstore.json`.

### Verify README.md using the signature bundle

```console
cargo run --example bundle \
    verify --identity <EMAIL> --issuer <URI> README.md
```console

`EMAIL` is the email address of the OIDC account and <URI> is the OIDC issuer URI that were used
during signing. As an example `cargo run --example bundle verify --identity name@example.com --issuer https://github.com/login/oauth README.md`
verifies that the bundle `README.md.sigstore.json` was signed by "name@example.com" as authenticated by GitHub.
