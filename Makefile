.PHONY: build
build:
	cargo build --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check
	taplo fmt --check

.PHONY: lint
lint:
	cargo clippy --all-targets -- -D warnings

.PHONY: doc
doc:
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps

.PHONY: check-features
check-features:
	cargo hack check --each-feature --skip cosign --skip full --skip mock-client --skip registry

.PHONY: check-features-native-tls
check-features-native-tls:
	cargo hack check --feature-powerset --features native-tls --skip wasm --skip test-registry --skip rustls-tls --skip rustls-tls-native-roots

.PHONY: check-features-rustls-tls
check-features-rustls-tls:
	cargo hack check --feature-powerset --features rustls-tls --skip wasm --skip test-registry --skip native-tls --skip rustls-tls-native-roots

.PHONY: test
test: fmt lint doc
	cargo test --workspace --no-default-features --features full,native-tls,test-registry
	cargo test --workspace --no-default-features --features full,rustls-tls,test-registry

.PHONY: clean
clean:
	cargo clean

.PHONY: coverage
coverage:
	cargo tarpaulin -o Html
