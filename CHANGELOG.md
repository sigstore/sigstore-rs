# v0.8.0

## What's Changed

- chore(deps): Update rstest requirement from 0.17.0 to 0.18.1 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/282
- chore(deps): do not enable default features of chrono by @flavio in https://github.com/sigstore/sigstore-rs/pull/286
- chore(deps): Update pem requirement from 2.0 to 3.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/289
- conformance: add conformance CLI and action by @jleightcap in https://github.com/sigstore/sigstore-rs/pull/287
- chore: fix clippy warnings by @flavio in https://github.com/sigstore/sigstore-rs/pull/292
- chore(deps): Bump actions/checkout from 3.5.3 to 3.6.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/291
- chore(deps): Update tough requirement from 0.13 to 0.14 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/290
- chore(deps): update to latest version of picky by @flavio in https://github.com/sigstore/sigstore-rs/pull/293
- chore(deps): Bump actions/checkout from 3.6.0 to 4.0.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/294
- chore: add repository link to Cargo metadata by @flavio in https://github.com/sigstore/sigstore-rs/pull/297
- chore(deps): Update cached requirement from 0.44.0 to 0.45.1 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/298
- chore(deps): Bump actions/checkout from 4.0.0 to 4.1.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/302
- chore(deps): Update cached requirement from 0.45.1 to 0.46.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/301
- chore(deps): Update testcontainers requirement from 0.14 to 0.15 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/303
- chore(deps): Bump actions/checkout from 4.1.0 to 4.1.1 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/304
- cosign/tuf: use trustroot by @jleightcap in https://github.com/sigstore/sigstore-rs/pull/305
- Fix broken tests, update deps by @flavio in https://github.com/sigstore/sigstore-rs/pull/313

## New Contributors

- @jleightcap made their first contribution in https://github.com/sigstore/sigstore-rs/pull/287

**Full Changelog**: https://github.com/sigstore/sigstore-rs/compare/v0.7.2...v0.8.0

# v0.7.2

## What's Changed

- chore(deps): Update cached requirement from 0.42.0 to 0.44.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/277
- chore(deps): Bump actions/checkout from 3.5.2 to 3.5.3 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/278
- chore(deps): update picky dependency by @flavio in https://github.com/sigstore/sigstore-rs/pull/279

**Full Changelog**: https://github.com/sigstore/sigstore-rs/compare/v0.7.1...v0.7.2

# v0.7.1

## What's Changed

- fix: ensure cosign client can be sent between threads by @flavio in https://github.com/sigstore/sigstore-rs/pull/275

**Full Changelog**: https://github.com/sigstore/sigstore-rs/compare/v0.7.0...v0.7.1

# v0.7.0

## What's Changed

- Fix typo in SignatureLayer::new doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/170
- feat: replace example dependency docker_credential by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/172
- Clean up readme by @lukehinds in https://github.com/sigstore/sigstore-rs/pull/173
- chore(deps): Update rstest requirement from 0.15.0 to 0.16.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/174
- Fix typo in simple_signing.rs by @danbev in https://github.com/sigstore/sigstore-rs/pull/175
- Introduce SignedArtifactBundle by @danbev in https://github.com/sigstore/sigstore-rs/pull/171
- chore(deps): Update base64 requirement from 0.13.0 to 0.20.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/177
- chore(deps): Bump actions/checkout from 3.1.0 to 3.2.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/180
- chore(deps): Update serial_test requirement from 0.9.0 to 0.10.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/182
- chore(deps): Update cached requirement from 0.40.0 to 0.41.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/181
- Fix typo in SecretBoxCipher doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/179
- chore(deps): Update cached requirement from 0.41.0 to 0.42.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/185
- chore(deps): Bump actions/checkout from 3.2.0 to 3.3.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/183
- chore(deps): Update base64 requirement from 0.20.0 to 0.21.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/184
- Add cosign verify-bundle example by @danbev in https://github.com/sigstore/sigstore-rs/pull/186
- Fix incorrect base64_signature doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/188
- Fix typos in tuf/mod.rs by @danbev in https://github.com/sigstore/sigstore-rs/pull/195
- chore(deps): Update serial_test requirement from 0.10.0 to 1.0.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/200
- fix: show actual response status field by @ctron in https://github.com/sigstore/sigstore-rs/pull/197
- Update target -> target_name for consistency by @danbev in https://github.com/sigstore/sigstore-rs/pull/196
- fix: make the fields accessible by @ctron in https://github.com/sigstore/sigstore-rs/pull/202
- Add verify-bundle example to README.md by @danbev in https://github.com/sigstore/sigstore-rs/pull/203
- fix: make fields of hash accessible by @ctron in https://github.com/sigstore/sigstore-rs/pull/205
- Improve public key output and add file output by @Gronner in https://github.com/sigstore/sigstore-rs/pull/194
- Add TokenProvider::Static doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/208
- Changed the type of LogEntry.body from String to Body by @Neccolini in https://github.com/sigstore/sigstore-rs/pull/207
- Fix errors/warnings reported by clippy by @danbev in https://github.com/sigstore/sigstore-rs/pull/210
- Add fine-grained features to control the compilation by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/189
- fix: bring tuf feature out of rekor and add related docs by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/211
- chore: update crypto deps by @flavio in https://github.com/sigstore/sigstore-rs/pull/204
- Replace `x509-parser` with `x509-cert` by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/212
- Fix: Wrong parameter order inside documentation example. by @vembacher in https://github.com/sigstore/sigstore-rs/pull/215
- Remove lines about timestamp in lib.rs by @naveensrinivasan in https://github.com/sigstore/sigstore-rs/pull/213
- Fix ed25519 version conflict by @vembacher in https://github.com/sigstore/sigstore-rs/pull/223
- Support compiling to wasm32 architectures by @lulf in https://github.com/sigstore/sigstore-rs/pull/221
- Fix link to contributor doc in readme by @oliviacrain in https://github.com/sigstore/sigstore-rs/pull/225
- refactor: derive `Clone` trait by @flavio in https://gitub.com/sigstore/sigstore-rs/pull/227
- fix: correct typo in verify/main.rs by @danbev in https://github.com/sigstore/sigstore-rs/pull/228
- chore(deps): Update tough requirement from 0.12 to 0.13 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/237
- chore(deps): Bump actions/checkout from 3.3.0 to 3.4.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/240
- dep: update picky version to git rid of `ring` by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/226
- chore(deps): Bump actions/checkout from 3.4.0 to 3.5.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/245
- fix: make LogEntry Body an enum by @danbev in https://github.com/sigstore/sigstore-rs/pull/244
- Add verify-blob example by @danbev in https://github.com/sigstore/sigstore-rs/pull/239
- Introduce Newtype `OciReference` into API for OCI image references. by @vembacher in https://github.com/sigstore/sigstore-rs/pull/216
- Swap over to using CDN to fetch TUF metadata by @haydentherapper in https://github.com/sigstore/sigstore-rs/pull/251
- chore(deps): Bump actions/checkout from 3.5.0 to 3.5.2 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/252
- upgrade 'der' to 0.7.5 by @dmitris in https://github.com/sigstore/sigstore-rs/pull/257
- remove unused 'clock' feature for chrono by @dmitris in https://github.com/sigstore/sigstore-rs/pull/258
- update pkcs1 from 0.4.0 to 0.7.5 by @dmitris in https://github.com/sigstore/sigstore-rs/pull/260
- use 2021 Rust edition by @dmitris in https://github.com/sigstore/sigstore-rs/pull/261
- chore(deps): Update serial_test requirement from 1.0.0 to 2.0.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/264
- update scrypt to 0.11.0, adapt for API change (fix #231) by @dmitris in https://github.com/sigstore/sigstore-rs/pull/268
- upgrade ed25519-dalek to 2.0.0-rc.2 by @dmitris in https://github.com/sigstore/sigstore-rs/pull/263
- chore(deps): Update openidconnect requirement from 2.3 to 3.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/265
- chore(deps): Update rstest requirement from 0.16.0 to 0.17.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/271
- Update crypto deps by @flavio in https://github.com/sigstore/sigstore-rs/pull/269
- Update create_log_entry example to create key pair. by @jvanz in https://github.com/sigstore/sigstore-rs/pull/206

## New Contributors

- @ctron made their first contribution in https://github.com/sigstore/sigstore-rs/pull/197
- @Gronner made their first contribution in https://github.com/sigstore/sigstore-rs/pull/194
- @Neccolini made their first contribution in https://github.com/sigstore/sigstore-rs/pull/207
- @vembacher made their first contribution in https://github.com/sigstore/sigstore-rs/pull/215
- @naveensrinivasan made their first contribution in https://github.com/sigstore/sigstore-rs/pull/213
- @lulf made their first contribution in https://github.com/sigstore/sigstore-rs/pull/221
- @oliviacrain made their first contribution in https://github.com/sigstore/sigstore-rs/pull/225
- @haydentherapper made their first contribution in https://github.com/sigstore/sigstore-rs/pull/251
- @dmitris made their first contribution in https://github.com/sigstore/sigstore-rs/pull/257
- @jvanz made their first contribution in https://github.com/sigstore/sigstore-rs/pull/206

**Full Changelog**: https://github.com/sigstore/sigstore-rs/compare/v0.6.0...v0.7.0h

# v0.6.0

## Fixes

- Fix typo in cosign/mod.rs doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/148
- Fix typo in KeyPair trait doc comment by @danbev in https://github.com/sigstore/sigstore-rs/pull/149
- Update cached requirement from 0.39.0 to 0.40.0 by @dependabot in https://github.com/sigstore/sigstore-rs/pull/154
- Fix typos in PublicKeyVerifier doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/155
- Fix: CI error for auto deref by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/160
- Fix typo and grammar in signature_layers.rs by @danbev in https://github.com/sigstore/sigstore-rs/pull/161
- Remove unused imports in examples/rekor by @danbev in https://github.com/sigstore/sigstore-rs/pull/162
- Update link to verification example by @danbev in https://github.com/sigstore/sigstore-rs/pull/156
- Fix typos in from_encrypted_pem doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/164
- Fix typos in doc comments by @danbev in https://github.com/sigstore/sigstore-rs/pull/163
- Update path to fulcio-cert in verify example by @danbev in https://github.com/sigstore/sigstore-rs/pull/168

## Enhancements

- Add getter functions for LogEntry fields by @lkatalin in https://github.com/sigstore/sigstore-rs/pull/147
- Add TreeSize alias to Rekor by @avery-blanchard in https://github.com/sigstore/sigstore-rs/pull/151
- Updates for parsing hashedrekord LogEntry by @lkatalin in https://github.com/sigstore/sigstore-rs/pull/152
- Add certificate based verification by @flavio in https://github.com/sigstore/sigstore-rs/pull/159
- Add support for OCI Image signing (spec v1.0) by @Xynnn007 in https://github.com/sigstore/sigstore-rs/pull/158

## Contributors

- Avery Blanchard (@avery-blanchardmade)
- Daniel Bevenius (@danbev)
- Flavio Castelli (@flavio)
- Lily Sturmann (@lkatalin)
- Xynnn (@Xynnn007)

# v0.5.3

## Fixes

- rustls should not require openssl by (https://github.com/sigstore/sigstore-rs/pull/146)

## Others

- Rework Rekor module structure and enable doc tests (https://github.com/sigstore/sigstore-rs/pull/145)

## Contributors

- Flavio Castelli (@flavio)
- Lily Sturmann (@lkatalin)

# v0.5.2

## Fixes

- Address compilation error (https://github.com/sigstore/sigstore-rs/pull/143)

## Contributors

- Flavio Castelli (@flavio)

# v0.5.1

## Fixes

- fix verification of signatures produced with PKI11 (https://github.com/sigstore/sigstore-rs/pull/142)

## Others

- Update rsa dependency to stable version 0.7.0 (https://github.com/sigstore/sigstore-rs/pull/141)
- Bump actions/checkout from 3.0.2 to 3.1.0 (https://github.com/sigstore/sigstore-rs/pull/140)

## Contributors

- Flavio Castelli (@flavio)
- Xynnn (@Xynnn007)

# v0.5.0

## Enhancements

- update user-agent value to be specific to sigstore-rs (https://github.com/sigstore/sigstore-rs/pull/122)
- remove /api/v1/version from client by (https://github.com/sigstore/sigstore-rs/pull/121)
- crate async fulcio client (https://github.com/sigstore/sigstore-rs/pull/132)
- Removed ring dependency (https://github.com/sigstore/sigstore-rs/pull/127)

## Others

- Update dependencies
- Refactoring and examples for key interface (https://github.com/sigstore/sigstore-rs/pull/123)
- Fix doc test failures (https://github.com/sigstore/sigstore-rs/pull/136)

## Contributors

- Bob Callaway (@bobcallaway)
- Bob McWhirter (@bobmcwhirter)
- Flavio Castelli (@flavio)
- Luke Hinds (@lukehinds)
- Xynnn (@Xynnn007)

# v0.4.0

## Enhancements

- feat: from and to interface for signing and verification keys (https://github.com/sigstore/sigstore-rs/pulls/115)
- Refactor examples to support subfolder execution (https://github.com/sigstore/sigstore-rs/pulls/111)
- Integrate Rekor with Sigstore-rs (https://github.com/sigstore/sigstore-rs/pulls/88)
- feat: add example case and docs for key interface (https://github.com/sigstore/sigstore-rs/pulls/99)
- feat: add signing key module (https://github.com/sigstore/sigstore-rs/pulls/87)

## Documention

- Update readme to include new features (https://github.com/sigstore/sigstore-rs/pulls/113)

## Others

- bump crate version (https://github.com/sigstore/sigstore-rs/pulls/118)
- Add RUSTSEC-2021-0139 to audit.toml (https://github.com/sigstore/sigstore-rs/pulls/112)
- Update xsalsa20poly1305 requirement from 0.7.1 to 0.9.0 (https://github.com/sigstore/sigstore-rs/pulls/101)
- ignore derive_partial_eq_without_eq (https://github.com/sigstore/sigstore-rs/pulls/102)
- fix clippy lints (https://github.com/sigstore/sigstore-rs/pulls/98)

## Contributors

- Carlos Tadeu Panato Junior (@cpanato)
- Flavio Castelli (@flavio)
- Jyotsna (@jyotsna-penumaka)
- Lily Sturmann (@lkatalin)
- Luke Hinds (@lukehinds)
- Tony Arcieri (@tarcieri)
- Xynnn\_ (@Xynnn007)
