.PHONY: check test test-linux test-nginx run fmt clippy release
check:
	cargo check --all-targets

test:
	cargo test

test-nginx:
	python3 -m unittest discover -s config/nginx/tests -p 'test_*.py' -v

test-linux:
	bash scripts/test-linux-integration.sh

run:
	cargo run -- --config ./test-fixtures/etc/router-hub/router-hub.toml --test-mode serve

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

release:
	./scripts/build-release.sh aarch64-unknown-linux-musl
