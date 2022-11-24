# v0.6.0

## Fixes
* Fix typo in cosign/mod.rs doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/148
* Fix typo in KeyPair trait doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/149
* Update cached requirement from 0.39.0 to 0.40.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/154
* Fix typos in PublicKeyVerifier doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/155
* Fix: CI error for auto deref by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/160
* Fix typo and grammar in signature_layers.rs by @danbev in https://github.com/sigstore/sigstore-rs/pull/161
* Remove unused imports in examples/rekor by @danbev in https://github.com/sigstore/sigstore-rs/pull/162
* Update link to verification example by @danbev in https://github.com/sigstore/sigstore-rs/pull/156
* Fix typos in from_encrypted_pem doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/164
* Fix typos in doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/163
* Update path to fulcio-cert in verify example by @danbev in https://github.com/sigstore/sigstore-rs/pull/168

## Enhancements
* Add getter functions for LogEntry fields by @lkatalin in https://github.com/sigstore/sigstore-rs/pull/147
* Add TreeSize alias to Rekor by @avery-blanchard in https://github.com/sigstore/sigstore-rs/pull/151
* Updates for parsing hashedrekord LogEntry by @lkatalin in https://github.com/sigstore/sigstore-rs/pull/152
* Add certificate based verification by @flavio in https://github.com/sigstore/sigstore-rs/pull/159
* Add support for OCI Image signing (spec v1.0) by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/158
## Contributors
* Avery Blanchard (@avery-blanchardmade)
* Daniel Bevenius (@danbev)
* Flavio Castelli (@flavio)
* Lily Sturmann (@lkatalin)
* Xynnn (@Xynnn007)

# v0.5.3

## Fixes

* rustls should not require openssl by (https://github.com/sigstore/sigstore-rs/pull/146)

## Others
* Rework Rekor module structure and enable doc tests (https://github.com/sigstore/sigstore-rs/pull/145)

## Contributors
* Flavio Castelli (@flavio)
* Lily Sturmann (@lkatalin)

# v0.5.2

## Fixes

* Address compilation error (https://github.com/sigstore/sigstore-rs/pull/143)

## Contributors
* Flavio Castelli (@flavio)

# v0.5.1

## Fixes

* fix verification of signatures produced with PKI11 (https://github.com/sigstore/sigstore-rs/pull/142)

## Others

* Update rsa dependency to stable version 0.7.0 (https://github.com/sigstore/sigstore-rs/pull/141)
* Bump actions/checkout from 3.0.2 to 3.1.0 (https://github.com/sigstore/sigstore-rs/pull/140)

## Contributors
* Flavio Castelli (@flavio)
* Xynnn (@Xynnn007)

# v0.5.0

## Enhancements
* update user-agent value to be specific to sigstore-rs (https://github.com/sigstore/sigstore-rs/pull/122)
* remove /api/v1/version from client by (https://github.com/sigstore/sigstore-rs/pull/121)
* crate async fulcio client (https://github.com/sigstore/sigstore-rs/pull/132)
* Removed ring dependency (https://github.com/sigstore/sigstore-rs/pull/127)

## Others

* Update dependencies
* Refactoring and examples for key interface (https://github.com/sigstore/sigstore-rs/pull/123)
* Fix doc test failures (https://github.com/sigstore/sigstore-rs/pull/136)

## Contributors
* Bob Callaway (@bobcallaway)
* Bob McWhirter (@bobmcwhirter)
* Flavio Castelli (@flavio)
* Luke Hinds (@lukehinds)
* Xynnn (@Xynnn007)

# v0.4.0

## Enhancements

* feat: from and to interface for signing and verification keys (https://github.com/sigstore/sigstore-rs/pulls/115)
* Refactor examples to support subfolder execution (https://github.com/sigstore/sigstore-rs/pulls/111)
* Integrate Rekor with Sigstore-rs (https://github.com/sigstore/sigstore-rs/pulls/88)
* feat: add example case and docs for key interface (https://github.com/sigstore/sigstore-rs/pulls/99)
* feat: add signing key module (https://github.com/sigstore/sigstore-rs/pulls/87)

## Documention

* Update readme to include new features (https://github.com/sigstore/sigstore-rs/pulls/113)

## Others

* bump crate version (https://github.com/sigstore/sigstore-rs/pulls/118)
* Add RUSTSEC-2021-0139 to audit.toml (https://github.com/sigstore/sigstore-rs/pulls/112)
* Update xsalsa20poly1305 requirement from 0.7.1 to 0.9.0 (https://github.com/sigstore/sigstore-rs/pulls/101)
* ignore derive_partial_eq_without_eq (https://github.com/sigstore/sigstore-rs/pulls/102)
* fix clippy lints (https://github.com/sigstore/sigstore-rs/pulls/98)


## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Flavio Castelli (@flavio)
* Jyotsna (@jyotsna-penumaka)
* Lily Sturmann (@lkatalin)
* Luke Hinds (@lukehinds)
* Tony Arcieri (@tarcieri)
* Xynnn_ (@Xynnn007)
