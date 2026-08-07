# Laneway

Laneway is a private IP overlay for connecting Linux hosts and private subnets
across NAT and restrictive firewalls. Applications use ordinary IP addresses
through the `lane0` interface—no application proxy is required.

Laneway is security-sensitive networking software. Start on an isolated test
network, keep CA keys off nodes and relays, and read the
[threat model](spec/threat-model.md) before production use. Relay transport is
encrypted and mutually authenticated, but relays terminate that transport and
can inspect forwarded IP packets.

## Features

- Dual-stack overlay networking through a Linux TUN interface
- Mutually authenticated QUIC relay and direct peer paths
- Automatic QUIC-to-TLS/TCP fallback when UDP is unavailable
- Controller-managed enrollment, renewal, revocation, routes, and ACLs
- Default-deny policy with approved subnet NAT/routed and exit-node routes
- Go controller, relay, node, and CLI; interoperable Rust relay and Linux node
- Transactional host networking, bounded queues, metrics, and recovery tooling

The controller is never in the packet path. Nodes prefer a healthy direct path
and retain a relay as the fallback.

## Install

Linux release packages are available for AMD64 and ARM64. The installer
downloads the matching package and verifies it against the release checksum
before installing anything:

```bash
curl -fsSLO https://raw.githubusercontent.com/Doout/laneway/main/install.sh
less install.sh
sudo sh install.sh
```

It installs one versioned `laneway` binary for enrollment, node operation, and
administration, plus dedicated relay/controller service binaries. A
`lanewayd` compatibility symlink dispatches to `laneway node run`. The package
also includes hardened systemd units, examples, and operational documentation.
It creates the locked `laneway` service account but never
overwrites configuration or starts a service.

To build the same package from source (Go 1.26+):

```bash
make package VERSION=dev
tar -xzf dist/laneway_linux_$(go env GOARCH).tar.gz
sudo ./laneway/install.sh
```

The native Rust implementations remain available as
[source builds](https://github.com/Doout/laneway/tree/main/rust).

## Quick start: join a managed network

Get the public Laneway domain and a durable Node invite from your administrator.
Save the one-time code in a protected file. One command authenticates discovery,
binds enrollment to the discovered network and durable-node class, discovers
the authorized relay, writes the strict configuration and credentials, and
enables the hardened systemd service. Direct P2P is enabled by default.

```bash
install -m 0600 enrollment-code.txt ./laneway.code
sudo laneway node install lane.example.com --token-file ./laneway.code

sudo laneway up
sudo laneway status
```

Use `--no-direct` only for a deliberate operator opt-out and `--no-start` when
activation is managed separately. Re-running the same command is idempotent and
does not consume another invite. Remove only command-owned Node credentials and
state with `sudo laneway node uninstall` (or preserve state with `--keep-state`).

`laneway up` is a readiness check; systemd starts and supervises the daemon.
The local management socket is intentionally restricted, so packaged service
commands normally require `sudo`.

Creating the first controller and relay requires PKI and explicit network
approval. Follow the [deployment guide](deploy/README.md) and
[operations guide](docs/operations.md); do not improvise production CA
handling from a quick-start example.

## Packages and releases

Create deterministic Linux archives locally with:

```bash
make package VERSION=1.0.0 PACKAGE_GOARCH=amd64
make package VERSION=1.0.0 PACKAGE_GOARCH=arm64
```

Pushing a stable `vMAJOR.MINOR.PATCH` tag runs the release workflow, builds both architectures,
generates `checksums.txt`, and publishes a GitHub release. Release binaries
support `laneway version`; `laneway node run -version` and the legacy
`lanewayd -version` alias report the identical embedded version.

## Documentation

- [Deployment and host requirements](deploy/README.md)
- [Operations and troubleshooting](docs/operations.md)
- [Architecture](spec/architecture.md)
- [Actor and deployment contract](spec/deployment-contract.md)
- [Threat model](spec/threat-model.md)
- [Protocol specifications](spec/)
- [Benchmarks](docs/benchmarks.md)
- [Rust implementations](https://github.com/Doout/laneway/tree/main/rust)
- [Security reporting](SECURITY.md)

## Development

```bash
make test
make race
make vet
make integration
make rust-test
```

`make privileged-integration` runs the disposable Linux network-namespace
suite. The full CI matrix also covers fuzzing, cross-builds, Go/Rust
interoperability, kernel routing/NAT, and release benchmarks.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
