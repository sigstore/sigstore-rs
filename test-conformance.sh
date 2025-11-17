#!/bin/bash

cd /Users/wolfv/Programs/sigstore-rs/tests/conformance && cargo b --release

cd /Users/wolfv/Programs/sigstore-rs/sigstore-conformance

# sync deps
uv sync

export RUST_LOG=debug
uv run pytest -v -n auto --entrypoint=/Users/wolfv/Programs/sigstore-rs/tests/conformance/target/release/sigstore $@