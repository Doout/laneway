.PHONY: build package test vet fmt-check benchmark benchmark-arch-smoke integration privileged-integration docker-exit-integration docker-plugin-integration docker-plugin-rootfs rust-test rust-node-interop proto-lint proto-check management-api-check

VERSION ?= dev
CARGO_WORKSPACE = --manifest-path rust/Cargo.toml --locked

build:
	cargo build $(CARGO_WORKSPACE)

# Package the verified native binaries as the release archive.
package:
	VERSION="$(VERSION)" PACKAGE_OS="$(PACKAGE_OS)" PACKAGE_ARCH="$(PACKAGE_ARCH)" ./scripts/package.sh

test:
	cargo test $(CARGO_WORKSPACE)

vet:
	cargo clippy $(CARGO_WORKSPACE) --all-targets -- -D warnings

rust-test: test vet

fmt-check:
	cargo fmt --manifest-path rust/Cargo.toml --all -- --check

benchmark: benchmark-arch-smoke

benchmark-arch-smoke:
	cargo run $(CARGO_WORKSPACE) --release -p laneway-bench -- --mode node --flows 1 --packet-size 1200 --duration-secs 1 --json

integration:
	./integration/nonprivileged.sh

privileged-integration:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh

rust-node-interop:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh

docker-exit-integration:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-exit-node.sh

docker-plugin-integration:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-plugin.sh

docker-plugin-rootfs:
	VERSION="$(VERSION)" ./deploy/docker-plugin/build-rootfs.sh

proto-lint:
	buf lint

# Cargo generates and compiles the Rust protocol bindings from the schemas.
proto-check: proto-lint
	cargo check $(CARGO_WORKSPACE) -p laneway-protocol

management-api-check:
	cd web && corepack pnpm api:check
