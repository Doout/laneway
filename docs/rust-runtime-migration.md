# Rust runtime migration

Public source baseline: `acac2047329dd4331e60d7f1f21de6fa67247df3`.
The September deployment also included private fleet features. Before a production
canary, capture the installed image digests, matching source, service configuration
and database schema, and rehearse restoring a backup on the isolated lab host.
Keep one controller writing to each database.

| Component | Starting point | Acceptance before switching the default |
| --- | --- | --- |
| Relay | Rust QUIC and TLS/TCP data relay, controller snapshots, TCP readiness probe | Mixed Go/Rust peers exchange packets, enforce revocation, and reconnect after restart. Exercise public HTTPS, ACME renewal, bootstrap discovery, console, and Dispatch OAuth on the shared port. |
| Node, connector, exit | Rust Linux TUN daemon, routing, DNS configuration, local socket and relay fallback | Enroll and renew each role. Test allowed and denied traffic, health and topology reports, loss of route authority, exit NAT and DNS recovery after restart and uninstall. |
| Controller | Go owns SQLite, PKI and management APIs | Start with read-only network inventory. Compare outputs on the same fixture DB, then cover auth, grants, policy snapshots, enrollment, OAuth, backups and migrations. Verify the web console and both generations of node. |
| Private fleet features | Fleet worktree includes private DNS, updates, recovery, policy history, diagnostics, alerts and topology | Compare against the identified deployed source and exercise each feature through its UI/API and node consumer. |
| Packaging and platforms | Go also provides the Docker plugin, platform-specific CLI/daemon entry points and readiness helpers | Verify signed install, update, rollback, desktop local API and active service processes per platform. The one-shot operator CLI and compatibility harness can stay in Go. |

## First Linux lab run

Use a separate CA and network on a disposable Linux host. Install the Rust
toolchain, Go 1.26, Docker, iproute2, nftables, iputils-ping, jq and procps.
The privileged gates require network namespaces and `/dev/net/tun`.

For a disposable rootless Docker VM with TUN support, run
`bash integration/rust-lab/run.sh`. It warms the build caches first, then runs
all three network-namespace gates with external networking disabled. The
checkout is mounted read-only and the test topology uses a temporary CA.

```sh
make rust-test
cargo build --locked --manifest-path rust/Cargo.toml -p laneway-relay
make rust-interop
docker build -f deploy/containers/Dockerfile.rust-relay -t laneway-rust-relay:lab .
```

Run the following from a root lab shell with Cargo and Go on its PATH:

```sh
LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh
LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh
LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-controller-node-netns.sh
```

The Rust relay image includes the existing Compose readiness invocation,
`/usr/local/bin/laneway-healthcheck -tcp 127.0.0.1:8443`. Match the port
to the lab's TCP fallback listener. A successful probe establishes that the
listener accepts TCP. The interop and namespace gates separately exercise
authentication, packet forwarding and route cleanup.

## Linux node image

Build the opt-in `node` target and check the packaged entry point after the
rootless lab run has populated the Go cache:

```sh
docker build --target node -f deploy/containers/Dockerfile.rust-relay \
  -t laneway-rust-node:migration-lab .
bash integration/rust-lab/node-image.sh
```

The image runs `lanewayd-rs` as UID 65532. It needs a readable Rust node
configuration and identity, `/dev/net/tun`, and `NET_ADMIN` in its own network
namespace. The default Docker healthcheck requests `/v1/status` on
`/run/laneway/lanewayd.sock`; it measures local daemon readiness, not peer
reachability. The fixture has no external network and uses a disposable test CA.
The userspace-only Go connector still needs a separate migration. Containerized
systemd-resolved integration and automatic enrollment/update are separate gates.

### Verified on the local ARM64 Linux VM

- Direct and relayed IPv4/IPv6 packets between the Go and Rust node binaries,
  including exit forwarding and blocked traffic.
- Kernel route, firewall and DNS ownership recovery, including SIGTERM cleanup.
- Go controller bootstrap of the Rust node, an approved route, traffic denial
  after ACL removal and certificate revocation, and authority expiry on outage.
- Packaged Rust node running non-root with TUN and a healthy status socket;
  Docker stop returned exit code zero.

Repeat on the dedicated host using its architecture and service manager before
any production canary. These results do not establish private fleet parity.

## Controller inventory

The Rust controller can read the public schema-18 database without running
migrations or starting a listener. An operator with filesystem access can run:

```sh
laneway-controller inventory networks /path/to/lab/controller.db
laneway-controller inventory nodes /path/to/lab/controller.db NETWORK_ID 100
```

Use a consistent lab backup or a lab database with its WAL files. An isolated
copy of the main file alone can omit recent commits. The commands return the
management JSON shape and reject unknown schema versions. They are full local
inventory, not a substitute for authenticated administrator endpoints.

`make rust-controller-interop` compares Rust output with actual Go HTTP
handler responses while Go still owns the database. The fixture covers IPv4
and dual-stack networks, limits, configuration epochs, empty networks,
durable and ephemeral enrollment, and a revoked node.

The separate `session-inventory` command exercises the native browser-session
store. Use it only on a disposable lab database; a successful read touches
the session, and expiry or credential invalidation records a revocation and
an audit event. Never point this mode at a running production controller.
Use the same arguments as `inventory` and supply the session token on stdin
from a protected source, never as a command-line argument. It does not issue
credentials or listen on a network socket.

The Go/Rust gate also checks scoped and all-network visibility, live changes
to grants, disabled principals, revoked credentials, logout, idle and absolute
expiry, and clock regression. An audit write failure must roll back expiry.

### Serve authenticated inventory over HTTPS (lab only)

Run this against a writable **disposable** schema-18 database, with a lab
certificate whose subject alternative names include the host used by the probe:

```sh
laneway-controller serve /lab/controller.db 127.0.0.1:9443 /lab/controller.crt /lab/controller.key
laneway-healthcheck -tcp 127.0.0.1:9443 -tls-ca /lab/ca.crt -tls-server-name 127.0.0.1
```

The listener requires loopback and TLS 1.3. It serves GET and HEAD for
`/v1/admin/networks` and `/v1/admin/networks/{id}/nodes`, using sessions
issued by Go. A successful browser request renews the session; the TLS probe
only checks the handshake and server identity. Go-issued automation tokens
can also read inventory: listing networks requires `network.list`; listing
nodes requires `node.read` and access to that network. Reads recheck the
token, principal, permissions and network scope in one SQLite snapshot.

Root access is off unless you append `--root-token-file /lab/root.token` to
the serve command. Use a private file (e.g. mode 0600); never pass its
contents on the command line. Restart after replacing the token file. To
verify the root credential, `GET /v1/admin/auth/root` returns 204; it does
not accept a session or automation token. Bearers are rejected in browser
contexts or when combined with a session cookie. Sign-in and management
writes remain on Go. Do not route production traffic here.

The optional non-root image can be built with
`docker build --target controller -f deploy/containers/Dockerfile.rust-relay -t laneway-rust-controller:migration-lab .`.
It does not replace a release image or change Compose. The interop gate
compares real Go and Rust HTTPS responses including error bodies, session
deadlines and request IDs; it also tests hostname verification in the probe.
After warming the lab toolchain and Go module cache, run
`bash integration/rust-lab/controller-image.sh` to repeat the gate using the
scratch image's binaries as UID 65532 with external networking disabled.
Next: browser session discovery and sign-in, then management writes with
CSRF, audit and rollback coverage.
