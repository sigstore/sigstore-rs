.PHONY: build
build:
	cargo build --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy --workspace -- -D warnings

.PHONY: doc
doc:
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps

.PHONY: test
test: fmt lint doc
	cargo test --workspace --features full-native-tls,test-registry

.PHONY: clean
clean:
	cargo clean

.PHONY: coverage
coverage:
	cargo tarpaulin -o Html
