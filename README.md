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

For a new controller and relay host, use the interactive installer.
The default path asks for the release tag and DNS name, generates the issuer
and recovery material automatically, supplies safe defaults for the remaining
settings, pins release artifacts and images by checksum/digest, starts the
hardened Compose stack, and leaves one protected recovery-kit directory to
copy off-host:

```bash
curl -fsSLO https://raw.githubusercontent.com/Doout/laneway/main/install.sh
less install.sh
sudo sh install.sh --control-plane
```

The installer never changes the host firewall, routes, interfaces, DNS, or
sysctls. Its default quick profile warns instead of stopping when a signature
service is unavailable and writes `/opt/laneway/PRODUCTION-CHECKLIST.md`. Run
`sudo laneway-control production-check` before production traffic; that check
is fail-closed. Use `--control-plane --production` to require signature
verification during installation itself. Configure public DNS and external
firewall rules before running it.

Upgrade an existing Compose control plane without rerunning the setup wizard:

```bash
sudo laneway-control update
```

The command detects the Docker Compose deployment and installs the latest stable
release. The upgrade preserves the
deployment identity, PKI, state, DNS name, ports, firewall, and host networking.
It verifies the signed release and image digests, takes an encrypted backup, and
uses health-checked container replacement with the existing rollback path.
For the higher-assurance path, `--prepare-control-plane` creates the kit on a
separate trusted Linux host; copy only its `control-plane-input` directory to
production. See the [control-plane guide](deploy/compose/README.md).

To build the same package from source (Go 1.26+):

```bash
make package VERSION=dev
tar -xzf dist/laneway_linux_$(go env GOARCH).tar.gz
sudo ./laneway/install.sh
```

The native Rust implementations remain available as
[source builds](https://github.com/Doout/laneway/tree/main/rust).

## Quick start: join a managed network

For a temporary foreground User session, ask an administrator for an
ephemeral invite and run one command. The enrollment code is prompted for on
the terminal with echo disabled, so it does not enter shell history or argv:

```bash
laneway connect lane.example.com
```

The session authenticates public bootstrap metadata, pins the private network
and service identities, uses only controller-authorized routes, and restores
its temporary networking when it exits. Administrators create the bounded,
single-use code on the controller with `laneway-control invite --name laptop --ephemeral`.

To provision a capability-bound Docker Connector, generate a single-use
`docker run` command on the control plane, copy it to the Docker host over your
trusted administrative channel, and run it as root:

```bash
sudo laneway-control invite --name egress-one --docker --connector
```

The command contains a short-lived one-time enrollment token, the public network
CA, a pinned `ghcr.io/doout/laneway-connector` image, and endpoint configuration.
It never contains the control-plane admin token. Connector identity is retained
in a named Docker volume across image upgrades without re-enrollment. Open UDP
4434 on the Connector host if direct paths should be reachable through its
external firewall.

For a long-running Exit Node, omit `--ephemeral`; ephemeral enrollment is best
for testing or intentionally short-lived egress capacity.

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
