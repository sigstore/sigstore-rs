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
	cargo hack check --each-feature --skip cosign --skip full --skip mock-client --skip registry --skip test-remote-registry

.PHONY: check-features-native-tls
check-features-native-tls:
	cargo hack check --feature-powerset --features native-tls --skip test-registry --skip test-remote-registry --skip rustls-tls

.PHONY: check-features-rustls-tls
check-features-rustls-tls:
	cargo hack check --feature-powerset --features rustls-tls --skip test-registry --skip test-remote-registry --skip native-tls

.PHONY: check-all-features
check-all-features: check-features check-features-native-tls check-features-rustls-tls

.PHONY: test
test: fmt lint doc
	cargo test --workspace --no-default-features --features full,native-tls,test-registry,test-remote-registry
	cargo test --workspace --no-default-features --features full,rustls-tls,test-registry,test-remote-registry

.PHONY: clean
clean:
	cargo clean

.PHONY: coverage
coverage:
	cargo tarpaulin -o Html
