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
`sudo laneway control production-check` before production traffic; that check
is fail-closed. Use `--control-plane --production` to require signature
verification during installation itself. Configure public DNS and external
firewall rules before running it.

Upgrade an existing Compose control plane without rerunning the setup wizard:

```bash
sudo laneway control update
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

Install the latest stable macOS user client with one command (Apple Silicon and
Intel are detected automatically):

```bash
curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install-client.sh | sh
```

The installer must run as the normal Mac user. It performs all read-only
pre-checks, detects the architecture, resolves a stable tagged release,
downloads and verifies the release checksum, and only then allows `configure`
to ask once for `sudo`. It installs and verifies the client and its root-owned,
credential-free helper. To pin a release, use
`curl -fsSL URL | LANEWAY_VERSION=vX.Y.Z sh` with the same URL above.
`laneway configure --check` is non-mutating. Future upgrades are simply
`laneway update`. It resolves the latest stable GitHub release, verifies the
release checksum as the normal user, rejects downgrades, and then reuses the
same configure transaction. Run `login`, `connect`, and `update` as your
normal macOS user.

## Quick start: connect a local user

Create a ten-minute, single-use login token on the control plane:

```bash
sudo laneway control user-token --name laptop
```

On the laptop, exchange that token once and then connect:

```bash
laneway login lane.example.com
laneway connect
```

Linux and macOS (Intel and Apple Silicon) are supported. On macOS the client
runs like an SSH tunnel: the foreground process remains owned by the local
user, prompts for `sudo` only to start a credential-free networking helper,
and removes its `utun` interface and owned routes when the process exits.

`login` prompts with echo disabled and replaces the bootstrap token with a
revocable device certificate and private keys in the local user's mode-0700
profile directory. The bearer token is never retained. Laneway automatically
rotates that credential over authenticated mTLS and reconnects before expiry.

`connect` is split tunnel by default. It derives the minimum private prefixes
from controller ACCEPT policy and sends each prefix only to its approved
Connector; all other traffic continues to use the laptop's native network.
Default routes are never selected automatically. Full-tunnel egress still
requires an explicit controller-authorized `--exit NAME` on Linux. The macOS
package is user-client-only: it has no Connector, route-advertisement,
control-plane, or Exit Node commands and supports private split routes only.

With exactly one saved login, `connect` remembers its domain. If more than one
login is saved, select one explicitly with `laneway connect DOMAIN`. For an
intentionally temporary session that stores no identity, use `laneway connect
lane.example.com --ephemeral`. Remove a saved local login with
`laneway logout lane.example.com`; revoke its printed NodeID at the controller
as well when retiring or losing a device.

To provision a role-bound Docker Connector, generate a single-use
`docker run` command on the control plane, copy it to the Docker host over your
trusted administrative channel, and run it as root:

```bash
sudo laneway-control invite --name egress-one --docker --connector
```

The control-plane command uses the locally installed, signed Laneway CLI and
does not pull or start an administrative container. Its output has one opaque
`SETUP_TOKEN`, a digest-pinned `ghcr.io/doout/laneway-connector` image, and no
expanded endpoint or identity variables. The capsule carries public network
metadata plus a short-lived, single-use enrollment code; it is not encryption
from the Docker administrator. After first start the controller invalidates the
code and the container retains its certificate and private keys in a named
Docker volume, so image upgrades do not re-enroll it. It never contains the
control-plane admin token.

This Connector terminates approved TCP and UDP flows in userspace and makes
ordinary outbound sockets to their private destinations. It starts as UID/GID
65532 with all Linux capabilities dropped, `no-new-privileges`, a read-only root
filesystem, no `/dev/net/tun`, no host sysctls, and no published port. No inbound
firewall rule is required. Use the separate full Exit Node deployment when raw
IP forwarding, ICMP, or a full-tunnel default route is required; that role still
needs a TUN device and `NET_ADMIN` inside its isolated container namespace.

The default invitation is durable. Add `--ephemeral` only for testing or
intentionally short-lived Connector capacity; durable identity is the normal
choice when the container will be upgraded in place.

Assign a private IP or subnet to an enrolled Connector from the control-plane
host with one idempotent command:

```bash
sudo laneway control route add --connector ibmcloud --to 10.240.64.6 --allow laptop
```

An address becomes a `/32` or `/128` host route automatically. The command
resolves both node names, preserves existing Connector capabilities, assigns
and approves the route, and creates the destination-scoped ACCEPT rule. Omit
`--allow` to authorize every enrolled user to that destination. Use a CIDR such
as `10.240.64.0/24` with `--to` to route a subnet.

Use `sudo laneway control status` for the control-plane health check and a
joined inventory of non-revoked, non-expired users, Nodes, Connectors, overlay
addresses, and approved subnets forwarded by each Connector. The controller
does not infer live dataplane reachability from enrollment state; runtime path
details remain in `laneway node status` and `laneway node peers` on the
individual host.

Get the public Laneway domain and a durable Node invite from your administrator.
Save the one-time code in a protected file. One command authenticates discovery,
binds enrollment to the discovered network and durable-node class, discovers
the authorized relay, writes the strict configuration and credentials, and
enables the hardened systemd service. Direct P2P is enabled by default.

```bash
install -m 0600 enrollment-code.txt ./laneway.code
sudo laneway node install lane.example.com --token-file ./laneway.code

sudo laneway node up
sudo laneway node status
```

Use `--no-direct` only for a deliberate operator opt-out and `--no-start` when
activation is managed separately. Re-running the same command is idempotent and
does not consume another invite. Remove only command-owned Node credentials and
state with `sudo laneway node uninstall` (or preserve state with `--keep-state`).

`laneway node up` is a readiness check; systemd starts and supervises the daemon.
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
