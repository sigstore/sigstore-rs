This example shows how to verify a blob signature that was created by the
`cosign sign-blob` command.

### Create the artifact to be signed.
```console
cd examples/cosign/verify-blob
echo something > artifact.txt
```

### Sign the artifact.txt file using cosign
```
cosign sign-blob \
   --output-signature signature \
   --output-certificate certificate \
   artifact.txt

Using payload from: artifact.txt
Generating ephemeral keys...
Retrieving signed certificate...

        Note that there may be personally identifiable information associated with this signed artifact.
        This may include the email address associated with the account with which you authenticate.
        This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.
        By typing 'y', you attest that you grant (or have permission to grant) and agree to have this information stored permanently in transparency logs.

Are you sure you want to continue? (y/[N]): y
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&code_challenge=o2zGqxFdnIMy2n31excKZGDd25nj9bRocuCK_oSTKDk&code_challenge_method=S256&nonce=2MxS5IYq7wviqRPvAKMeSUcQiBS&redirect_uri=http%3A%2F%2Flocalhost%3A36653%2Fauth%2Fcallback&response_type=code&scope=openid+email&state=2MxS5NQBiv0oTvB0oU88qRbaKEk
Successfully verified SCT...
using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIICqTCCAi6gAwIBAgIUc4soYChsRq4lWUu990I7GrErO9IwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMwMzEzMTEzOTIwWhcNMjMwMzEzMTE0OTIwWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7zhgP7vhI8QzXm0nMC6wvj1c/82sRx4ozvIB
6od9xfiNofmjlDJtdG+IrObrxONhAXffZWDB2N8SmjAcHVz85qOCAU0wggFJMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU3U2j
b80jcAEZIXWnZgIjGEJ39EcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wJwYDVR0RAQH/BB0wG4EZZGFuaWVsLmJldmVuaXVzQGdtYWlsLmNvbTAsBgor
BgEEAYO/MAEBBB5odHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwgYoGCisG
AQQB1nkCBAIEfAR6AHgAdgDdPTBqxscRMmMZHhyZZzcCokpeuN48rf+HinKALynu
jgAAAYbaxJHJAAAEAwBHMEUCIFsrHqZF6pqZotjvHvvSPxk7jdtWkAPLn55APKmj
lD72AiEA3807EnFi2HLZcoP+85fmCH5awXDX1KLPUW7kibOwKpAwCgYIKoZIzj0E
AwMDaQAwZgIxAOf6C68qm6r7Rovurc7j+JQkki8hsoWd68vC+VvSazSFMpCxrvm7
HlrW7oMAzjlCzwIxANQWgC60eNi7QNeqlMlo/UraZz8xFho2d0Fr5fa0ZfALBE82
I9TvCXsVua7/ERp+eQ==
-----END CERTIFICATE-----

tlog entry created with index: 15311440
MEYCIQDSsR/enheXGrFNLtgEVNLvLFTYPa1cWOTBZBqNYv/kQQIhALFxLx27ECqtVyM3jGedhharRngiHJ4EMdfvA6Bl3+pm
```

The above command will have saved two files, one containing the signature
(which can also be seen as the last line of the output above), and one which
contains the certificate.

### Verify using sigstore-rs:
To verify the blob using this example use the following command:
```console
cd examples/cosign/verify-blob
cargo run --example verify-blob -- \
    --certificate certificate \
    --signature signature \
    artifact.txt
Verification succeeded
```

### Verify using cosign
To verify the blob using `cosign verify-blob` we need to specify a
`--certificate-oidc-issuer` which currently can be one of:
the following:
* https://github.com/login/oauth
* https://accounts.google.com
* https://login.microsoftonline.com


And we also have to specify the email address we used as the
`--certificate-identity`:
```console
cosign verify-blob \
   --cert certificate \
   --signature signature \
   --certificate-identity <email address> \
   --certificate-oidc-issuer https://github.com/login/oauth \
    artifact.txt
Verified OK
```
