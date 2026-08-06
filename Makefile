.PHONY: check test run fmt clippy
check:
	cargo check --all-targets

test:
	cargo test

run:
	cargo run -- --config ./test-fixtures/etc/router-hub/router-hub.toml --test-mode serve

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

release:
	./scripts/build-release.sh aarch64-unknown-linux-musl
