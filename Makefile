.PHONY: build package test race vet benchmark benchmark-matrix benchmark-relay-comparison benchmark-full-matrix benchmark-quic benchmark-unit benchmark-arch-smoke integration privileged-integration docker-exit-integration rust-test rust-interop rust-node-interop fmt-check proto proto-lint proto-check

VERSION ?= dev
PACKAGE_GOOS ?= $(shell cd go && go env GOOS)
PACKAGE_GOARCH ?= $(shell cd go && go env GOARCH)

BENCHMARK_SMOKE_GOOS ?= linux
BENCHMARK_SMOKE_GOARCH ?= $(shell cd go && go env GOARCH)
BENCHMARK_SMOKE_RUNNER ?=
BENCHMARK_SMOKE_DURATION ?= 1s
BENCHMARK_SMOKE_SIZE ?= 512
BENCHMARK_SMOKE_PPS ?= 1000
BENCHMARK_SMOKE_QUEUE ?= 256

build:
	cd go && go build ./...

# Create a self-contained Linux release archive in dist/. The archive includes
# the production Go binaries, examples, hardened systemd units, and installer.
package:
	VERSION="$(VERSION)" PACKAGE_GOOS="$(PACKAGE_GOOS)" PACKAGE_GOARCH="$(PACKAGE_GOARCH)" ./scripts/package.sh

test:
	cd go && go test ./...

race:
	cd go && go test -race ./...

benchmark: benchmark-unit benchmark-matrix

benchmark-unit:
	cd go && go test -run '^$$' -bench . -benchmem ./internal/protocol ./internal/routing ./internal/dataplane ./internal/relay ./internal/tcpfallback

benchmark-quic:
	cd go && go run ./cmd/laneway-bench quic-relay -duration 3s -size 1200

# Bounded smoke across native UDP, QUIC stream, and every packet-pump scenario. Use
# laneway-bench matrix directly for the full flow/size/profile cross-product.
benchmark-matrix:
	cd go && go run ./cmd/laneway-bench matrix -duration 250ms -pps 1000 -queue 256 -flows 1 -sizes small,mtu -profiles lan

# Bounded, apples-to-apples authenticated relay comparison. The Go driver owns
# the ephemeral PKI and node generators and supervises the release Rust relay.
benchmark-relay-comparison:
	cargo build --manifest-path rust/Cargo.toml --locked --release -p laneway-relay
	cd go && go run ./cmd/laneway-bench matrix -scenarios relay-quic,relay-tcp,rust-relay-quic,rust-relay-tcp -rust-relay-binary ../rust/target/release/laneway-relay -duration 250ms -pps 1000 -queue 256 -flows 1 -sizes small,mtu -profiles lan

# Release evidence: every scenario across 1/10/100 flows, small/MTU packets,
# LAN/WAN profiles, then the same cross-product under deterministic random and
# burst loss. The scheduled full-matrix workflow preserves both outputs.
benchmark-full-matrix:
	cargo build --manifest-path rust/Cargo.toml --locked --release -p laneway-relay
	cd go && go run ./cmd/laneway-bench matrix -duration 1s -pps 0 -queue 4096 -flows 1,10,100 -sizes small,mtu -profiles lan,wan -loss 0 -seed 1
	cd go && go run ./cmd/laneway-bench matrix -duration 1s -pps 10000 -queue 4096 -flows 1,10,100 -sizes small,mtu -profiles lan,wan -loss 1 -burst-loss 3 -seed 20260807
	cd go && go run ./cmd/laneway-bench matrix -scenarios relay-quic,relay-tcp,rust-relay-quic,rust-relay-tcp -rust-relay-binary ../rust/target/release/laneway-relay -duration 1s -pps 10000 -queue 4096 -flows 1,10,100 -sizes small,mtu -profiles lan,wan -loss 0 -seed 1
	cd go && go run ./cmd/laneway-bench matrix -scenarios relay-quic,relay-tcp,rust-relay-quic,rust-relay-tcp -rust-relay-binary ../rust/target/release/laneway-relay -duration 1s -pps 10000 -queue 4096 -flows 1,10,100 -sizes small,mtu -profiles lan,wan -loss 1 -burst-loss 3 -seed 20260807

# Functional architecture coverage only. In particular, results collected via
# BENCHMARK_SMOKE_RUNNER=qemu-aarch64 are not performance-comparable.
benchmark-arch-smoke:
	@set -eu; \
	bench_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$bench_tmp"' EXIT INT TERM; \
	cd go; \
	CGO_ENABLED=0 GOOS="$(BENCHMARK_SMOKE_GOOS)" GOARCH="$(BENCHMARK_SMOKE_GOARCH)" \
		go build -o "$$bench_tmp/laneway-bench" ./cmd/laneway-bench; \
	$(BENCHMARK_SMOKE_RUNNER) "$$bench_tmp/laneway-bench" matrix \
		-duration "$(BENCHMARK_SMOKE_DURATION)" -sizes "$(BENCHMARK_SMOKE_SIZE)" \
		-flows 1 -profiles lan -pps "$(BENCHMARK_SMOKE_PPS)" -queue "$(BENCHMARK_SMOKE_QUEUE)"

integration:
	./integration/nonprivileged.sh

privileged-integration:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/linux-netns.sh

docker-exit-integration:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-exit-node.sh

rust-test:
	cargo test --manifest-path rust/Cargo.toml --locked
	cargo clippy --manifest-path rust/Cargo.toml --all-targets --locked -- -D warnings

rust-interop:
	cd go && go test -count=1 -race -tags=rustinterop ./integration/rustrelay -v

rust-node-interop:
	LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh

vet:
	cd go && go vet ./...

fmt-check:
	@files="$$(find go -name '*.go' -type f -print)"; \
	if [ -n "$$files" ] && [ -n "$$(gofmt -l $$files)" ]; then \
		gofmt -l $$files; \
		exit 1; \
	fi

proto:
	buf generate

proto-lint:
	buf lint

proto-check: proto-lint proto
	git diff --exit-code -- go/api
