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

Use a separate CA and network on a disposable Linux host. Install Rust 1.91
or newer, Go 1.26, Docker, iproute2, nftables, iputils-ping, jq and procps.
The privileged gates require network namespaces and `/dev/net/tun`.

For a disposable rootless Docker VM with TUN support, run
`bash integration/rust-lab/run.sh`. It warms the build caches first, then runs
the unprivileged connector and network-namespace gates without external networking. The
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

### Public HTTPS on the Rust relay

With a controller-backed relay and `tcp_fallback.listen` enabled, retain
the Go relay's public hostname and cache directory:

```toml
[public_https]
server_name = "relay.example.test"
cache_dir = "/var/lib/laneway-public"
```

The Rust relay obtains and renews public certificates without restarting.
The configured DNS name must reach its TCP listener on public port 443
for [ACME TLS-ALPN-01](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01).
The bind port inside a container may differ. Rust writes owner-only files
into the `rust-v1` subdirectory. Run one ACME writer per cache. On first
startup with the default Let's Encrypt directory, Rust can read a still-valid
Go cached certificate while obtaining its own; it never overwrites the Go
certificates or account. If no usable certificate is cached, browser HTTPS
becomes available after the first successful order; node transport does not wait.

An explicit `acme_directory` can select a test CA. If required, point
`acme_ca` at that directory's TLS trust root; this does not change the
Laneway workload roots or what browsers trust. For an externally managed
certificate, omit `cache_dir` and set `certificate` and `private_key` to
absolute PEM paths. Restart to read replacements in this static mode. If
combined with `cache_dir`, a currently valid PEM pair can seed HTTPS until
ACME obtains a certificate.

The same TCP port accepts browser HTTPS and Laneway mTLS, selecting the
certificate and client-authentication policy from the TLS ClientHello.
The HTTPS handler forwards discovery, one-use bootstrap downloads, console
requests and OAuth to the configured controller. The relay verifies the
controller's hostname, CA and Laneway service identity before sending HTTP.
Node transport APIs and private administrator credentials stay off the public
proxy. An app can use its OAuth access token only on the scoped network
reads, node installer and route assignment endpoints. The controller accepts
delegated credentials only from a currently authorized mTLS relay and
verifies the active app installation, network grant, and operation in the
same database transaction. Root and non-application automation bearer
credentials remain private, including tokens with the same wire format.

Run `make rust-controller-interop` for shared-port discovery, one-use
downloads, browser sessions, the node mTLS handshake, and the application
flow from registration through scoped operations, refresh, and revoke.
Run `bash integration/rust-lab/acme.sh` to exercise TLS-ALPN validation,
live renewal, and offline restart using the cached certificate with a local
[Pebble](https://github.com/letsencrypt/pebble) CA. This rotates the relay's
public certificate, not its Laneway workload certificate.

To run the real Dispatch client in the same lab flow:

```sh
bash integration/rust-lab/dispatch.sh /path/to/dispatch REVISION
```

The script builds the client from a temporary source snapshot. The browser
approval is driven by the Laneway fixture; the Dispatch client performs the
backend calls. This does not run the Dispatch server or test its deployment.

### Internal controller TLS renewal

Add `--renew-controller-tls /var/lib/laneway-controller/tls-renewal` to
`laneway-controller serve` with `--node-issuer` and `--node-client-ca`.
Use a persistent state directory owned by the controller UID and accessible
only to that user. The positional certificate and key keep their existing
paths; they are never rewritten. The original CA-signed leaf pins the
controller's network, service ID and DNS/IP names, even after it expires.

The controller checks the expiry and starts renewal seven days early by
default (`--controller-renew-before` changes the window). It issues a new
key and certificate under the existing online issuer, verifies the chain
and identity, then saves them as one private file before switching new HTTPS
and QUIC handshakes. Established QUIC sessions keep running. On restart,
the controller reuses the last valid replacement; if the original expired
and the cache is unusable, it must issue a valid replacement before binding.
If issuance or persistence fails while running, the active credential stays
in place and renewal retries. An expiring issuer still needs operator action.

The lab checks this with `TestRustControllerServiceTLS`. The existing Compose
timer remains the renewal path for Go deployments.
Keep a still-valid conventional certificate and key for rollback to a Go
controller; it does not read the Rust renewal state.

### Internal relay TLS renewal

To opt in, add `renewal_dir = "/var/lib/laneway-relay/tls-renewal"` under
`[tls]` and use a registered relay with a Rust controller that serves private
mTLS HTTPS and has `--node-issuer` and `--node-client-ca` configured. Give each
relay its own persistent directory, writable and accessible only by the relay
user. Leave the option unset if an external job still manages its certificate.
The controller does not send a private key or accept new names from the relay.

After two-thirds of the current certificate lifetime, the relay creates a new
key and sends a signed request over the pinned controller connection. The
controller checks the live certificate and registration, keeps the relay's
identity and DNS/IP names, and logs the issuance. The relay validates the
replacement and saves it before switching new TCP and QUIC handshakes. Current
node sessions keep running; the relay reconnects to the controller to get a
lease under the new certificate. The public HTTPS certificate and CA files are
unchanged.

Restarting uses the last valid replacement from the private state directory.
Keep the seed files in place to pin the identity and names. If there is no
valid cached credential and the seed expires, install a new operator-issued
relay certificate; the relay cannot authenticate to ask for a renewal. The
`TestRustControllerRelayTLS` lab test uses both Rust binaries to verify live
rotation, authorization, and restart after seed expiry.

### Administrator console

The Rust controller image includes the same `pnpm build:live` console as the
Go image and enables it from `/usr/share/laneway-console`. For a standalone
controller, supply an absolute build output directory with `--console-dir` or
`LANEWAY_CONSOLE_DIR`. The controller takes a bounded read-only snapshot at
startup; install a complete build and restart together. Browser deep links
get the non-cacheable HTML shell, hashed assets are immutable, and API routes
never fall back to HTML. Broken asset links return 404.

To exercise a real web build through the Rust controller and relay instead
of the small HTTP fixture, build the console with `pnpm build:live` in `web`,
then run `LANEWAY_RUST_CONSOLE_ASSETS="$PWD/web/dist" make rust-controller-interop`
from the repository root. The controller image lab also tests the packaged
assets while running with its non-root UID and no network.

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
Containerized systemd-resolved integration and automatic enrollment/update
are separate gates.

### Linux userspace connector

The same Rust agent can terminate IPv4/IPv6 TCP and UDP flows and connect to
their destinations with ordinary host sockets. Enable `[connector] userspace =
true` and leave `tun.configure`, kernel forwarding, and exit mode off. The
agent opens no TUN device and does not change host addresses, routes, sysctls,
or firewall state. The socket status reports the interface as `userspace`.

For the static lab, use `deploy/examples/connector-rust.toml`. With controller
authority, omit static addresses, routes, peers, and owned prefixes. The
connector forwards only through approved local subnet routes permitted by the
current policy. It drops malformed traffic, fragmented packets, IPv6 extension
headers, datagrams over the overlay MTU, and protocols other than TCP/UDP.
It does not act as an exit gateway.

Build the separate `connector` image target for a pre-provisioned workload.
It needs a readable identity and configuration at `/etc/laneway`, but no
network capabilities or devices.

```sh
docker build --target connector -f deploy/containers/Dockerfile.rust-relay \
  -t laneway-rust-connector:migration-lab .
bash integration/rust-lab/connector-image.sh
```

For existing Docker Connectors, the opt-in `rust-connector` target in
`deploy/containers/Dockerfile.connector` holds the current image entrypoint
and named volume contract. The one-time Go installer keeps the setup-token
and encrypted bootstrap commands. For normal service it replaces itself
with the Rust agent. Rust reads `/var/lib/laneway/connector` in place and does
not rewrite the identity or Go configuration. It uses the controller's relay
list for QUIC and only dials TCP fallback addresses authorized for the
configured relay. The updater's read-only, offline preflight checks the saved
certificate chain, expiry, identity, private key, and settings before stopping
the old container. Configuration stays usable by the Go image for rollback.
The default release target still uses Go until promotion is approved.

```sh
docker build -f deploy/containers/Dockerfile.connector -t lane-edge:go-migration-lab .
docker build --target rust-connector -f deploy/containers/Dockerfile.connector \
  -t lane-edge:rust-migration-lab .
bash integration/rust-lab/connector-cutover.sh
bash integration/rust-lab/connector-cutover.sh lane-edge:go-migration-lab lane-edge:rust-migration-lab tcp-fallback
```

The cutover gate uses an isolated controller and disposable enrollment tokens
to verify a Go-to-Rust swap, offline validation, rollback, and first start with
the Rust-backed image. For existing identity it compares the original node ID
and the bytes of every rollback file across both image swaps. It checks
QUIC and forced TCP fallback separately and verifies that local status
reports the running image's build version.

### Durable Linux exit gateway

On an already enrolled Rust Linux node with a dedicated TUN and a known
uplink, opt in by adding this section to the controller-managed config:

```toml
[forwarding]
exit_gateway = true
exit_gateway_controller_sources = true
exit_output_interface = "eth0" # use the actual egress interface
```

Request an exit capability and a NAT default route through the controller.
The gateway starts as an ordinary node and forwards only after the route is
approved. It uses the controller's peer overlay host addresses, only in the
approved IP families; the network ACL still applies. Withdrawing the route
removes its forwarding rules without a daemon restart. Do not configure static
exit source ranges alongside controller-derived sources.

Run the dedicated packet gate on an isolated Linux lab with root, TUN and
nftables. Use `LANEWAY_NODE_TEST_CONTROLLER=rust` to repeat it with the Rust
controller and relay:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_DURABLE_EXIT=1 \
  ./integration/rust-controller-node-netns.sh
```

For an existing durable Docker Exit Node, the opt-in `rust-exit` target
accepts the same read-only Go TOML, certificates, state volume, health socket,
and `-config` command. It keeps the fixed direct port and the controller TLS
name even when the private Docker hostname differs. The process uses the same
non-root user and `NET_ADMIN`-only container contract. The Go CLI remains
available for one-shot administration; the daemon and readiness probe are Rust.

```sh
docker build -f deploy/containers/Dockerfile.exit-node --build-arg VERSION=go-exit-lab \
  -t laneway-go-exit:migration-lab .
docker build -f deploy/containers/Dockerfile.exit-node --target rust-exit \
  --build-arg VERSION=rust-exit-lab -t laneway-rust-exit:migration-lab .
bash integration/rust-lab/exit-cutover.sh
```

The gate keeps the controller approval and client selection in place during the
Go → Rust → Go image swaps. It checks the IPv4 MTU, real NAT with and without
UDP on the gateway's relay link, a controller health report, graceful cleanup,
and that the config, identity and state files remain unchanged.
For an operator-managed cutover, retain the previous image digest and stop the
old container before starting the replacement against the same mounts. Run
`lanewayd-rs --exit-config /etc/laneway/exit-node.toml --check-config` in the new
image with the original mounts to validate the configuration without networking.

The release default remains Go until promotion. The supported legacy profile
uses NAT and enables direct paths. WireGuard-enabled, routed-only and shared-host
ephemeral exits are separate migration work.

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

### Serve authenticated management APIs over HTTPS (lab only)

Run this against a writable **disposable** schema-18 database, with a lab
certificate whose subject alternative names include the host used by the probe:

```sh
laneway-controller serve /lab/controller.db 127.0.0.1:9443 /lab/controller.crt /lab/controller.key
laneway-healthcheck -tcp 127.0.0.1:9443 -tls-ca /lab/ca.crt -tls-server-name 127.0.0.1
```

The listener requires loopback and TLS 1.3. It serves GET and HEAD for
`/v1/admin/networks`, `/v1/admin/networks/{id}` and
`/v1/admin/networks/{id}/nodes`, using sessions
issued by Go or Rust. A successful browser inventory request renews the session; the TLS probe
only checks the handshake and server identity. Go-issued automation tokens
can also read inventory: listing networks requires `network.list`; reading
one network requires `network.read`; listing nodes requires `node.read`.
Both detail and nodes require access to that network. Reads recheck the
token, principal, permissions and network scope in one SQLite snapshot.

Root access is off unless you append `--root-token-file /lab/root.token` to
the serve command. Use a private file (e.g. mode 0600); never pass its
contents on the command line. Restart after replacing the token file. To
verify the root credential, `GET /v1/admin/auth/root` returns 204; it does
not accept a session or automation token. Bearers are rejected in browser
contexts or when combined with a session cookie.
Do not route production traffic here.

The console can check `GET /v1/admin/auth/state` for `bootstrap_required`
or `sign_in`. The lab listener limits that public lookup to 30 requests per
source and 300 total attempts per minute and does not trust relay-forwarded
client IPs. `GET /v1/admin/auth/session` requires both the session and CSRF
cookies. It returns the user's role, ordered permissions, network scope and
renewed deadline. A bad CSRF cookie does not extend the session.

The optional non-root image can be built with
`docker build --target controller -f deploy/containers/Dockerfile.rust-relay -t laneway-rust-controller:migration-lab .`.
It does not replace a release image or change Compose. The interop gate
compares real Go and Rust HTTPS responses including error bodies, session
deadlines and request IDs; it also tests hostname verification in the probe.
After warming the lab toolchain and Go module cache, run
`bash integration/rust-lab/controller-image.sh` to repeat the gate using the
scratch image's binaries as UID 65532 with external networking disabled.
`POST /v1/admin/auth/login` verifies existing Go Argon2id credentials. It
requires a same-origin HTTPS request, rate-limits attempts, bounds password
verification to two concurrent checks, and sets the session and CSRF cookies.
`POST /v1/admin/auth/session/rotate` replaces both cookies without extending
the absolute deadline. `POST /v1/admin/auth/logout` revokes the session and its
successors, even if the submitted cookies belong to a rotated predecessor.
Both mutations require the CSRF cookie and header as well as same-origin checks.

The HTTPS fixture signs in on one implementation and restores the session on
the other, and tests rotation and logout in both directions. It injects audit
failures to verify that failed mutations do not create or revoke sessions.

Rust also supports first-owner setup and owner recovery. The configured root
bearer issues a ten-minute grant using `POST /v1/admin/auth/bootstrap-grants`
or `POST /v1/admin/administrators/{id}/recovery-grants`. Redeem it once using
the same-origin `POST /v1/admin/auth/bootstrap` or `POST /v1/admin/auth/recover`,
then sign in normally. The database stores only a digest of the grant.
Recovery replaces the password, revokes the owner's sessions and outstanding
grants, and writes audit records in one transaction. The HTTPS fixture
checks Go/Rust grant and password compatibility and verifies rollback
when the recovery audit write fails.

The existing operator client can record root-token rotation with
`POST /v1/admin/auth/root-token-rotations/{id}/begin` and `/complete`.
The operator still replaces the protected token file and restarts the
controller. Both calls require the currently loaded root credential;
completion requires an existing begin marker. Retries do not duplicate audit
events. The lab gate verifies the replacement through a real restart and
checks that the old credential is rejected.

Administrator and session inventory is available to the root bearer and
owner browser sessions. Exact username lookup is limited to the root bearer.
The responses contain no credential hashes or plaintext. The root bearer and
owner browser sessions can also create administrators, update access, replace
passwords, and revoke sessions. Browser writes require same-origin and CSRF
checks. Access updates protect the last enabled owner, and a password or
access change revokes affected sessions in the same transaction. Revoking a
rotated session also revokes its successors.

Automation credentials no longer need Go for issuance or retirement. Owners
and the configured root bearer can create, list, and disable service
principals, and issue, list, or revoke their access tokens. Rust issues the
same `lnw_spat_v1` token format as Go. Only the issuance response contains
the plaintext; the database holds a digest. Network boundaries and the
100-active-token cap per principal apply in both implementations. Disabling
a service principal revokes its outstanding tokens atomically.

The Rust controller can accept application registrations, return a reviewed
manifest, record owner approval or denial, and exchange an approved code for
a client credential. It also serves the application inventory. Registration
does not install an application on a network. The lab gate crosses Go and
Rust at consent and exchange, validates PKCE and replay rejection, and
checks that an audit failure leaves the registration pending.
Callbacks require HTTPS by default. For a local lab only, the
`--allow-insecure-application-callbacks` flag permits HTTP on loopback
addresses.

Rust also serves OAuth authorization requests and the network installation
approval, cancellation, inventory, and revocation endpoints. Approval binds the
one-time code to the registered callback, the selected network, and the
approved scopes. Owners and scoped operators can approve; a root bearer
cannot approve on their behalf. Narrowing or revoking an installation retires
its prior credentials in the same transaction.

Rust also serves `POST /oauth/token` and `POST /oauth/revoke`. Exchange
checks the registered client credential, exact redirect URI, PKCE, and
installation scope in one transaction. Access tokens last one hour; refresh
families last 30 days without extending that deadline on rotation. A
duplicate refresh within five seconds does not revoke its successor. Later
reuse or explicit client revocation retires the whole family. The lab
exchanges and refreshes credentials across Go and Rust and checks both
implementations' access decisions after revocation.

Owners and the configured root bearer can rotate client secrets, disable
registered applications, and delete disabled applications. Secret rotation
replaces the client credential without invalidating existing access tokens.
Disable revokes the application's client credentials, installations, access
tokens, and refresh families together. Deletion removes the app and its
dependent records while retaining audit history and disabled service
identities. The HTTPS lab verifies both the Go and Rust views, including
rollback when an audit write fails.

The node-installer endpoint issues ten-minute, single-use enrollment tokens
bound to the selected network, node name, and node, connector, or exit
capability. It returns the existing systemd installer command; the lab
redeems a Rust-issued connector token at the Go controller.

The private bootstrap endpoints stage encrypted wrapper payloads in memory,
publish after the issuance audit commits, and let an enabled relay fetch each
bundle once over mTLS. The payload is never written to SQLite; expiry or a
controller restart discards it. The Rust relay exposes only the public
one-use URL and fetches the wrapper via its authenticated controller connection.

The controller serves `GET /v1/health` with the Go readiness response.
To enable `GET /.well-known/laneway/bootstrap.json` on the same listener,
pass `--bootstrap-profile PROFILE_JSON` and configure `--node-client-ca`.
The profile identifies the advertised enrollment origin, QUIC endpoint, and
controller DNS name; optionally list immutable artifacts by platform,
digest, and size:

```json
{
  "enrollment_endpoint": "https://relay.example.test",
  "quic_endpoint": "controller.example.test:8443",
  "server_name": "controller.example.test",
  "artifacts": []
}
```

Startup verifies the controller certificate against the advertised name and
CA. The network and service IDs come from that certificate. Each response
includes only enabled relays on the pinned network and expires in five
minutes. The endpoint returns 503 when there are no usable relays.

`POST /v1/admin/networks` accepts an owner session (same-origin and CSRF
required), the configured root bearer, or an automation token explicitly
granted `network.create`. The Rust transaction creates the IPv4 or dual-stack
network at epoch 1 and records the authenticated actor. Go and Rust can read
each other's networks without migrating the database. The gate also enrolls a
node through the Go store, checks both allocated addresses and the resulting
epoch through Rust, checks forbidden and
revoked subjects, and verifies rollback if the audit insert fails. When Go
and Rust race to create the same ID, exactly one succeeds and emits an audit event.

The Rust HTTPS listener also lists, assigns, approves, and withdraws routes.
Route inventory uses `route.read`; automation writes require `route.manage`.
Browser writes require a scoped owner or operator, same-origin request, and
CSRF proof. Node advertisements and owner withdrawals use the verified mTLS
certificate when `--node-client-ca` is configured. A node needs the relevant
subnet-router or exit capability to advertise; an advertisement does not
authorize forwarding until approved. Assignment is idempotent for the same
node, prefix, mode, and metric. Its capability change, route approval, audit
events, and configuration epochs commit together.

The HTTPS gate checks Go/Rust route inventory parity, scope, conflicting
routes, and assignment rollback. With `LANEWAY_NODE_TEST_CONTROLLER=rust`,
the namespace gate uses the existing Go CLI against the Rust route API and
verifies that approval carries packets, withdrawal stops them, and
reassignment restores the path.

Certificate inventory uses `certificate.read`; a certificate can be revoked
by network and serial with `certificate.revoke`. Node revocation and changes
to router or exit capabilities use `node.manage`. Revoking a node also
revokes its certificates, releases its overlay addresses and withdraws its
routes in the same transaction as the epoch and audit event. Removing a
capability withdraws only its route kind. A live node can query revocation
records within its own network over mutual TLS.

The device HTTPS gate verifies Go/Rust inventory and revocation record parity,
network isolation, rollback on audit failure, and denial for revoked leaves.
The namespace test uses the Rust API to remove a router capability and revoke
a gateway certificate, and checks that packets stop in both cases.

With a workload CA configured, existing clients may also poll
`POST /v1/configuration` over HTTPS. It uses the same snapshot as QUIC and
returns a bounded lease in the `X-Laneway-Configuration-Valid-Until` header
when a known epoch is unchanged. An epoch ahead of the controller is rejected
instead of renewing the lease. Ephemeral exit heartbeats still require an
authenticated QUIC connection with the exclusive exit claim.

Relay inventory uses `relay.read`; registration, update and disable use
`relay.manage`. Rust normalizes the advertised endpoint, enforces the shared
32-enabled-relay limit per network, and commits the change with the audit
event and configuration epoch. Disabled relays no longer appear in node
discovery and cannot renew their forwarding authority. The namespace gate
registers a live relay through the Rust API, disables it to stop forwarding,
then re-enables it and verifies traffic recovers without restarting it.

The Rust audit APIs serve both legacy lists and resumable pages. Scoped
reads require `audit.read` and the requested network; the global stream
requires an owner session, root bearer, or `audit.read_global`. Go and Rust
accept each other's cursor format. A cursor pins the scope and the last
event's timestamp and ID, so new events do not shift an in-progress page.
The HTTPS compatibility gate traverses both implementations and checks
that a cursor cannot be reused across scopes.

Controller-managed Rust nodes publish bounded health to `PUT /v1/status`
every 10 seconds. The client checks the exact controller identity in the
TLS handshake before sending a report. Reports include no peer IDs,
addresses, packets, or free-form diagnostics. Set
`disable_status_reporting = true` under `[controller]` to opt out.
Publication runs separately from forwarding and does not affect authority.

The controller keeps one 30-second observation per Rust node. The existing
`node.read` inventory exposes freshness: a current report can describe stale
configuration, while expired or inactive nodes expose only the last report
timestamps. The namespace gate waits for real Linux agent reports with active
relay QUIC and applied routes. The HTTPS gate verifies Go/Rust interchange,
expiry, revoked identity rejection and network scope.

Rust serves the existing node locations API and updates presence from
authenticated HTTPS polls, QUIC polls, and status reports. Enable automatic
city lookup with `--location-database /lab/City.mmdb`; the file stays local,
and a private or reserved peer address remains unlocated. Manual overrides
are audited without changing routing epochs. The namespace gate uses an
offline City fixture and a lab-only transport address to verify actual
automatic location inference.

`POST /v1/admin/enrollment-tokens` issues durable, remembered, and ephemeral
invitations. It accepts owner or operator sessions with network access, the
configured root bearer, or automation with `enrollment.issue` on that network.
Only a digest is stored; the token and its actor-attributed audit record commit
together. The mixed HTTPS test redeems Rust-issued tokens at the Go controller
and verifies their certificates, node names, network and user binding,
capabilities, ephemeral exit lease and replay rejection.

The Rust signer verifies a PKCS#10 request and takes only its public key. The
controller supplies the network and node IDs; the request cannot choose its
identity, add names or grant CA privileges. Expiry is bounded by the configured
lifetime, issuer chain and node lease. `make rust-controller-interop` uses
throwaway Go-generated CAs and five CSR signature variants to verify the
resulting Rust certificates with Go, including issuance through an intermediate.

To enable protobuf `POST /v1/enroll` on the isolated listener, append
`--node-issuer /lab/node-ca-chain.pem /lab/node-ca.key 86400` to the serve
command. The last argument is the maximum leaf lifetime in seconds. Use a
disposable **node CA**, not the HTTPS leaf key. Put the signing certificate
first, followed by any parent certificates. Without these arguments this
listener does not offer enrollment. Restart without them to disable it.

Redemption commits the token, node, addresses, certificate, route or exit
session if granted, audits, and network epoch in one SQLite transaction.
The interop gate checks all three classes, rollback on a late audit failure,
Go and Rust racing to redeem one invite, and address reuse after expiry. A
Go client also presents its Rust-issued certificate over mutual TLS and
renews that same node identity at the Go controller.

### Renew node certificates over HTTPS (lab only)

With enrollment configured, append `--node-client-ca /lab/node-trust-roots.pem`
to enable `POST /v1/renew`. This file contains the public CA certificates
trusted for workload client authentication. Keep it separate from the HTTPS
server certificate and the private signing key. Omit the flag to disable
renewal without disabling enrollment or administrator sessions.

The Go HTTPS client can present its existing certificate, renew at Rust using
a new CSR, and use the new private key and certificate at Go. Renewal leaves
the old certificate valid until expiry or explicit revocation. Omitting the
WireGuard key preserves its binding; changing it commits the new certificate,
key, audit events, and network epoch together. Ephemeral certificates cannot
outlive their leases. The interop gate revokes an admitted request's certificate
before sending its body and checks that no replacement is issued.

### Renew over the Rust controller's QUIC listener (lab only)

Add `--node-quic` alongside `--node-issuer` and `--node-client-ca`. By default
UDP binds the same loopback address and port as HTTPS. To put QUIC on a
dedicated lab interface, set `--quic-listen IP:PORT`; HTTPS stays loopback-only.
Use a service certificate
with the controller's network and service ID and the DNS name or IP the client
verifies. Omit `--node-quic` to return to HTTPS-only without changing stored state.

The Go node client can now renew at Rust using the existing
`laneway-control/1` protocol, with no working HTTPS fallback. The listener
requires mutual TLS and only accepts node and relay identities from its
own network, each limited to its own operations. Certificate
revocation takes effect on established connections; an ephemeral exit cannot
use a second connection to displace a healthy session. Renewal does not extend
the heartbeat lease.

The Rust listener also serves authenticated node configuration and conditional
leases. A snapshot includes dual-stack addresses, peers, approved routes,
default-deny traffic rules, relay endpoints, and certificate health and
revocations. The server bounds leases by upcoming authorization expiry and
advances the epoch when it durably expires a route or ephemeral identity.
An ephemeral exit configuration request must carry its live lease generation
on the owning connection to refresh its heartbeat. Configure the upper bound
with `--snapshot-validity SECONDS` (default 300).

Relays fetch peer ownership, policy, and revocations over QUIC or over
`POST /v1/relay/configuration` on the HTTPS listener. The controller checks
the relay certificate and enabled registration before every snapshot or lease,
including on existing connections. The relay keeps its last issued lease
until it expires; the controller does not renew it after disablement.

The Rust controller compiles existing user and team grants into node snapshots.
Named resources remain pinned to their approved route and service port ranges.
A deny rule for the user's devices precedes ordinary ACLs, so a global allow
cannot widen managed access. Disabling the user removes their grants and
retains that deny rule. Rust serves the full managed-access API: users,
teams, memberships, direct grants, named resources, services, and named
grants. TCP/UDP port ranges are merged and sealed on creation. Browser
writes require same-origin CSRF proof; scoped automation uses `acl.read`
or `acl.manage`. Each policy change, epoch advance, and audit entry commits
together. Other controller APIs are still pending; keep Go serving production.

Traffic rules can be listed, created, updated, and deleted through the same
Rust HTTPS listener. The controller validates canonical prefixes and port
ranges, and publishes rules in priority and ID order. The Rust network-namespace
gate uses the existing Go CLI against the Rust ACL API to prove that removing
the allow rule blocks a real routed packet and adding it back restores traffic.
The fixture still uses Go for route administration.

### Renew a Rust node at a Go or Rust controller (lab only)

Set `auto_renew_certificate = true` in the node's `[controller]` section.
Leave it off (the default) for read-only mounts or externally managed certificates.
Use a dedicated, writable directory owned by the node user and not writable by
group or others. The certificate must be a regular, singly linked, certificate-only
file owned by that user, with the same group as new files in that directory.
Keep the private key in its own file; the node never rewrites it.

At two-thirds of the certificate lifetime, a node with current authority can
request a replacement over authenticated QUIC. It keeps its key and WireGuard
binding. Before replacing the old file, it verifies the new identity, chain,
usages and expiry, then fetches a fresh configuration using the staged certificate.
A failed check leaves the old file in place; renewal cannot extend an ephemeral
lease. If the certificate expires first, recover through enrollment.

Successful replacement briefly interrupts traffic: the same process releases
its old connections and interface, then bootstraps again using the new leaf.
`integration/rust-controller-node-netns.sh` exercises this handoff, revokes
the superseded certificate, and sends real traffic through the renewed node.
Run it with `LANEWAY_NODE_TEST_CONTROLLER=rust` to test native Rust configuration,
renewal, route and ACL updates, certificate revocation, and lease expiry.
In that mode both the Rust relay and the Rust node use the Rust controller's
QUIC listener. The fixture still uses Go for admin mutations and the gateway.
