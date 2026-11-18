# Rust runtime migration

Public source baseline: `acac2047329dd4331e60d7f1f21de6fa67247df3`.
Target a fresh installation that runs Rust services from the start. Upgrading
or rolling back to the old Go runtime is not a release requirement. The Go
operator CLI and lab tools can still be used without running a Go server.

## Release handoff

Fresh control planes, managed Linux nodes, and foreground Linux/macOS sessions
select Rust. Before promoting to production, verify the following on the
signed candidate:

1. Run the native release matrix on the release commit, including the Linux
   systemd packet tests and the installed macOS helper on Intel and Apple
   Silicon. Verify the published archive checksums and image signatures, then
   install the signed candidate from empty state on the lab host.
2. On the fresh deployment, verify HTTPS, Dispatch authorization, client
   enrollment and connectivity, routes, certificate renewal and fleet
   operations. Back up the Rust deployment and restore it to a separate empty
   lab volume. Verify a Rust-to-Rust update from a previous signed release
   when one is available. Keep one controller writing to each database.
3. Test one isolated workload before promoting. Verify the recovery procedure
   with the same Rust images that will serve the deployment.

The tagged publish job now runs `integration/rust-release-install.sh` before
creating the GitHub release. It installs the exact signed AMD64 archive using
the release installer, verifies the running digest-pinned services and HTTPS
discovery, and restores its encrypted backup into a separate, empty controller
volume. It also redeems a one-time HTTPS invitation with the pinned Connector
image, checks for a live controller lease and QUIC relay path, and restarts the
Rust process with the same identity and no enrollment token. The gate also
enrolls a fresh Docker Exit Node and verifies its forwarding and IPv4 NAT
readiness after route approval. Download transport
and the relay's public certificate are local to the disposable runner; release
signature verification and image pulls are real.
The same gate passed an ARM64 rehearsal using fixture signatures and local
images; the actual tagged workflow is still required.

The isolated ARM64 installer rehearsal used fixture signatures and local
images. The packaged host-tools install left no daemon or systemd units; the
installer created an empty Rust deployment, verified authenticated inventory,
generated a Rust shared-host exit invitation, and wrote an encrypted backup.
Run `bash integration/rust-lab/installer-fresh.sh` on the marked lab to repeat.
The same test updates the real lab services to a fixture release, checks
that existing invitations survive, then starts a deliberately incompatible
candidate and verifies that the previous controller state is available again.
It also rotates the administrator root token on Rust, verifies rollback of a
failed credential check, and resumes after an interrupted completion. The
relay keeps serving discovery over lab HTTPS without being replaced.
It exercises real Compose and encrypted recovery, but does not exercise live
release signing and registry infrastructure.

| Component | Starting point | Acceptance before switching the default |
| --- | --- | --- |
| Relay | Rust QUIC and TLS/TCP data relay, controller snapshots, TCP readiness probe | Mixed Go/Rust peers exchange packets, enforce revocation, and reconnect after restart. Exercise public HTTPS, ACME renewal, bootstrap discovery, console, and Dispatch OAuth on the shared port. |
| Node, connector, exit | Rust Linux TUN daemon, routing, DNS configuration, local socket and relay fallback | Enroll and renew each role. Test allowed and denied traffic, health and topology reports, loss of route authority, exit NAT and DNS recovery after restart and uninstall. |
| Controller | Go owns SQLite, PKI and management APIs | Verify the web console and Rust nodes on fresh deployments, including auth, grants, policy snapshots, enrollment, OAuth and backups. Go peers and fixture databases remain test references. |
| Fleet features | Private DNS, updates, recovery, policy history, diagnostics, alerts and topology | Exercise each feature on a fresh Rust deployment through its UI/API and node consumer. |
| Packaging and platforms | Go also provides the Docker plugin, platform-specific CLI/daemon entry points and readiness helpers | Verify signed install, Rust recovery, desktop local API and active service processes per platform. The one-shot operator CLI and test harnesses can stay in Go. |

The tagged release workflow builds only the Rust runtime images:
`ghcr.io/doout/laneway-controller-rust`, `ghcr.io/doout/laneway-relay-rust`,
`ghcr.io/doout/laneway-node-rust`, `ghcr.io/doout/laneway-exit-node-rust`,
and `ghcr.io/doout/lane-edge-rust`. Each release job targets AMD64 and ARM64,
scans its build, signs its immutable digest, and adds it to the signed image
manifest. The Go administrator image remains a one-shot operator tool. New
releases do not publish the old Go images or archive their daemons and systemd
units. Mixed-language packet tests build Go peers from source. Existing
installations are not changed by this workflow. A local build is not a signed
release.
The local ARM64 lab built all four new image targets and verified that
their non-root Rust binaries reported the pinned build version. The tagged
AMD64 build, signing, and publication were not exercised locally.

## Linux managed nodes

The Linux release workflow builds the Rust runtimes on native
AMD64 and ARM64 runners and includes them in the signed archives as
`sbin/laneway-controller-rs`, `sbin/laneway-relay-rs`,
`sbin/lanewayd-rs`, `sbin/laneway-healthcheck-rs`, and
`sbin/laneway-update-rs`. The signed Linux installer installs the matching
Rust executables and systemd units. `lanewayd` points to the Rust daemon;
`laneway` remains the one-shot operator CLI. Installing the package does not
enable or start services or the updater. Go-only and mixed-version archives
are rejected. macOS uses its own native package and network helper.

On an isolated Linux host, pin the release tag with `LANEWAY_VERSION` when
using the signed download installer. With an already verified archive, run
`sudo sh install.sh` inside its extracted `laneway` directory. Then enroll
with `sudo laneway node install DOMAIN --token-file /path/to/invitation`.
Add `--no-start` to enroll without enabling the unit. To start that install
later, run the same command with the same node options but without the token
file or `--no-start`. Use `sudo laneway node status` to inspect the install
and `sudo laneway node uninstall` to remove it.

The CLI writes `/etc/laneway/node-rust.toml` and configures `lanewayd-rs.service`.
The daemon renews its certificate automatically in `/var/lib/laneway/identity`;
its private key and CA are protected from daemon writes under `/etc/laneway`.
The installer refuses to overwrite an unmanaged configuration or to start
alongside another node service. It does not migrate old installations.

For a foreground connection, use `sudo laneway login DOMAIN` to save a
login, then `sudo laneway connect DOMAIN`, or use
`sudo laneway connect DOMAIN --ephemeral` for a one-time session. This path
also runs the packaged Rust daemon. It uses a separate interface and leaves
no service enabled. Remembered logins use policy-derived private routes;
ephemeral logins default to overlay routes. `--route` accepts only prefixes
advertised by the controller. Full-tunnel routing still requires `--exit`
and an approved exit. An explicit `--dns` uses systemd-resolved on Linux;
omitting it leaves native DNS alone.

The ARM64 systemd lab verified this with unsigned binaries: an ephemeral
session, a remembered login, and a session through a controller-approved
Rust Exit all carried UDP traffic. The exit test checked NAT at the receiver,
native routing for relay traffic, and removal of the temporary interface,
policy rule, and route table on disconnect.

For a controller-managed standalone relay, base `/etc/laneway/relay-rust.toml`
on the packaged `relay-controller.toml` example. For native workload
renewal, add `renewal_dir = "/var/lib/laneway-relay/workload"` to its TLS
table when using a Rust controller. The relay keeps its read-only seed files
under `/etc/laneway` and writes the new credential into private runtime state.

To build and verify an unsigned preview on a Linux lab host, set `arch` to its
native architecture:

```sh
arch=arm64 # or amd64
version=0.0.0-rust-lab
artifacts="$(mktemp -d)"
docker buildx build --platform "linux/$arch" --build-arg VERSION="$version" \
  --file deploy/containers/Dockerfile.rust-release --target artifacts \
  --output "type=local,dest=$artifacts" .
PACKAGE_GOOS=linux PACKAGE_GOARCH="$arch" PACKAGE_RUST_RUNTIME_DIR="$artifacts" \
  make package VERSION="$version"
sh integration/rust-release-package.sh "dist/laneway_linux_$arch.tar.gz" "$arch" "$version"
```

The archive gate checks architecture and static linkage, executes each packaged
binary to verify its build version, and exercises both installer modes in an
isolated staging root. It checks the Rust daemon link and units, confirms
that control-plane tools install no host daemon, and rejects a partial package
before it creates files.
To test the archived binaries with real traffic, extract the `-rs` entries into
a disposable directory and point `LANEWAY_NODE_TEST_RUST_RUNTIME_DIR` at that
directory when running `integration/rust-controller-node-netns.sh` on the
isolated host. The package alone does not satisfy the systemd or cutover gates.

The unsigned native AMD64 archive `0.0.9102` passed the package check at
SHA-256 `b65960975cc6f38a7c694b88a5a89c4d7e33b5c1a085b98025046a153b1f531c`.
All five packaged Rust binaries ran and reported that version. Staged
installation later passed with
the same Rust binaries on AMD64 and with the ARM64 `0.0.0-fleet-rust-lab`
build, including refusal of an incomplete package.

The unsigned ARM64 `0.0.9104` archive passed the full systemd gate after
removing the Go daemons and units. It ran the packaged Rust relay and nodes,
redeemed a shared-host Exit invitation, and exercised the managed and
foreground Linux clients. The mixed-language phases used a source-built Go
relay fixture, not an archived Go service.

The release builds run `integration/rust-release-systemd.sh` on native AMD64
and ARM64 runners. It extracts the actual archive binaries and runs the
isolated systemd packet gate against both the Go and Rust controller/relay.
It also stages the package with its installer and runs the ordinary
`lanewayd-rs.service` against both controller implementations. The installed
node must renew its certificate, exchange traffic with a Go peer, pass a
local health probe, and remove the socket and tunnel on shutdown. With the Rust
controller, the test also runs `laneway-relay-rs.service`, checks its private
renewal cache, and verifies a fresh authenticated TLS connection receives the
replacement leaf while the seed files remain unchanged.
Both installed units passed on native Linux AMD64 and ARM64 with unsigned
lab builds and left no service account or credentials behind. AMD64 used
the `0.0.9102` archive for all Rust services; ARM64 paired the packaged node
and relay with a newer `0.0.9100` Rust controller.

The managed node gate exercises the default `node install` with a real
invitation and verifies startup without a second token, the actual Rust
process and health socket, and packet transfer through the Rust relay. It
also checks that uninstall removes the node's credentials, socket, and
tunnel without removing unrelated state. This passed on the ARM64 lab using
locally staged unsigned binaries; the signed release matrix is still pending.

The release gate also redeems a real one-use invitation through Rust HTTPS discovery and
enrollment, rejects a replay, and forwards traffic using the configuration
and protected credentials produced by the packaged Go enrollment CLI. It
checks that the archived bootstrap matches the one exercised by the test.
The unsigned AMD64 CI preview uses the same gate. After signing a tagged
release, the publish job checks the manifest using the bootstrap's exact
workflow, tag, and OIDC issuer policy and checks the hashes of the release
assets. Those are separate gates; neither claims the published bootstrap has
been installed with a real invitation on the dedicated host.

The isolated ARM64 systemd VM passed the archive gate for
`0.0.0-fleet-rust-lab`. The packaged Rust node exchanged encrypted traffic
with a Go peer over QUIC and TCP using both controller/relay pairs. The tests
also covered policy withdrawal, partition recovery, and NAT and revocation
after an invitation through Rust HTTPS. This archive was unsigned; it did not
exercise the fleet updater or a signed release.

The disposable native AMD64 systemd VM passed the same three phases using
the exact unsigned `0.0.9102` archive above. The packaged peers exercised
QUIC and full-MTU TCP, policy changes, partition drain and recovery, and
exit NAT through both controller/relay pairs. The Rust HTTPS invitation
phase verified one-use enrollment, NAT, revocation, and carrier cleanup.
The isolated QUIC listener explicitly opts into non-loopback binding;
the controller still refuses it without the opt-in and node trust inputs.

For the compatibility baseline, Cosign 3.1.3 verified the published
`v0.2.72` manifest under the pinned release workflow identity. The ARM64
archive matched its signed checksum, and asking for the `v0.2.71` identity
rejected that signature. The published archive contains Go runtimes only;
it is not a Rust updater test.

### Fresh Rust Compose bootstrap

The prepared Compose files can initialize an empty controller volume without
starting a Go server. Stage the generated issuer, service certificates and
bootstrap configuration with `prepare.sh`, then stage the verified Rust
metadata with `prepare-rust.py --release-metadata DIRECTORY`. Use the same
version for `LANEWAY_VERSION` and `LANEWAY_RUST_VERSION`, with the signed admin
tool image digest and the three signed Rust service image digests.

Run `sudo ./bootstrap.sh --rust` in the prepared Compose directory. The Rust
controller creates the database and first network, the admin tool registers
the relay through the API, and Compose starts the Rust relay. The command
refuses an existing deployment or database. For an interrupted startup after
the database was created, keep the volume and inspect service status and logs;
do not delete the database just to rerun bootstrap.

On the isolated ARM64 Docker VM, `integration/rust-lab/compose-fresh.sh`
started a fresh Rust controller and relay, served the console and discovery
through HTTPS, rejected a second bootstrap, and restored the encrypted backup
into a separate volume. This used local unsigned images and a lab certificate,
not a signed install or public ACME validation.

### Historical Compose cutover rehearsal

The packaged `deploy/compose/compose.rust.yaml` is an opt-in overlay for an
**existing** standard Compose stack. It preserves the service names, ports,
existing controller database and ACME volume. The Go operator CLI remains
available. The Rust controller requires `--listen-on-network` for non-loopback
TCP or UDP and requires the node issuer and client CA there. It cannot start
in that mode with insecure application callbacks enabled.

Rehearse on an isolated, restored copy first. Place `checksums.txt`,
`checksums.sigstore.json`, `image-digests.txt`, and `bootstrap-artifacts.toml`
from the same tagged release in a staging directory. From the trusted
package or checkout, run
`sh deploy/compose/verify-rust-release.sh vVERSION METADATA_DIRECTORY`.
The verifier checks the release identity and each immutable image signature
before printing all four `LANEWAY_RUST_*` settings. It does not read or change
the deployment. Copy those settings into the lab's `.env`; keep the Go
`LANEWAY_VERSION` and digests unchanged. Stage `compose.rust.yaml`,
`prepare-rust.py`, and `verify-rust-release.sh` as protected, root-owned
files from the same verified package in the lab's Compose directory. Then
run `sudo python3 prepare-rust.py --release-metadata /absolute/path/to/METADATA_DIRECTORY`
(Python 3.11+). It rechecks the signature, confirms the Rust image pins in
`.env` match, and stages only the four client archives for that Rust release in
discovery. It does not replace the Go configuration or its advertised
downloads. The separate `--lab` mode reuses the Go downloads for an unsigned,
isolated rehearsal only.
The relay uses a Compose alias matching the existing controller certificate
name. Custom controller settings are rejected rather than silently dropped.

Check the assembled services with `docker compose -f compose.yaml -f compose.rust.yaml config`.
Take a database backup while Go is still serving and verify a restore.
Disable the Go service-certificate renewal timer for the rehearsal; the
overlay uses native renewal and leaves the seed files available for rollback.
Stop the relay and controller with the base Compose file before starting
them with the overlay. Keep only one controller writer. To roll back,
stop the Rust services, then start with the base file. Do not remove volumes.
If a schema upgrade was applied, restore the prior backup before restarting
a Go controller that cannot read that schema. Confirm the Go seeds are
still valid and restore its renewal timer.
If the optional `exit-node` is running, stop it first with its profile
enabled. Start it after the replacement controller and relay are healthy,
using the same configuration and state volume. Use the same order on
rollback, and check a client packet round trip before reopening traffic.

The existing Go installer does not select this overlay. For an active Rust
stack, use the `laneway-control` and `recovery.sh` scripts from the same
verified package. Run `sudo laneway-control --rust readiness METADATA_DIRECTORY`
to check the signed digests against the rendered Compose config, the image
IDs actually running, health, authenticated inventory and public HTTPS
discovery. This check is read-only and creates no production approval marker.
It does not verify external firewall reachability, an off-host backup, or
rollback.

Use `laneway-control --rust status` for routine inventory and
`sudo laneway-control --rust backup NAME.age` for a backup. It takes an
online copy using the running controller, includes the Rust Compose inputs, and puts validated current
controller and relay certificates into the encrypted bundle as restore seeds
without changing the originals. The public ACME cache is not archived.
The updated wrapper refuses Go lifecycle commands while any Rust controller,
relay, or exit service is running in the project, even if the operator omits
`--rust`. The packaged Go upgrader checks before changing deployment files.
This guard does not block maintenance just because the overlay is staged; it
allows the Go commands again after a deliberate rollback.

On an empty, stopped deployment with the verified Rust images already
installed, use `sudo laneway-control --rust restore BUNDLE.age --identity
AGE_IDENTITY_FILE`. The restore requires a new database target and checks
that every archived file has a checksum. Version 2 is Rust-only; legacy
version 1 bundles still use the Go restore command. Reissue service
credentials before startup if the restored seeds have expired.

The isolated gate is `integration/rust-lab/compose-cutover.sh`; set
`LANEWAY_TEST_RUST_RECOVERY=1` with `age` and `age-keygen` available to include
authenticated status, online backup and fresh-volume restore. It uses local
lab images, not a published signed release.
The ARM64 run used the actual Compose files and the same SQLite volume. It
replaced Go with Rust, used the Go admin CLI to write another network,
checked the console and bootstrap discovery over HTTPS, and then confirmed
that Go could read both networks after rollback. The run did not change the
database schema.
The fixture uses an offline signature stub and checks that Rust advertises
all four candidate downloads over HTTPS, rejects mismatched image pins, and
leaves Go's bootstrap files unchanged. A real signed Go-only release is not
a Rust cutover candidate.
With recovery enabled on ARM64, the gate verified authenticated status,
rejected an image mismatch, and restored both networks and the refreshed TLS
seeds into a new project. The original volume was still usable for Go rollback.

For the optional exit packet gate, add `LANEWAY_TEST_COMPOSE_EXIT=1` and set
`LANEWAY_TEST_COMPOSE_NETPROBE` to an absolute path to a native static
`netprobe` binary (`CGO_ENABLED=0 go -C go build -o /tmp/netprobe ./integration/netprobe`).
Load `alpine:3.22` and build the `go-exit` target from
`deploy/containers/Dockerfile.exit-node` as
`laneway-go-exit:compose-cutover-lab` with version `0.0.9100`. The fixture
places the UDP target on a separate internal bridge so a Go client can reach
it only through the approved exit. It checks the NAT source address and
keeps the exit's identity, credentials, configuration, and volume constant
across Go, Rust, and rollback. It does not route to the Internet or test DNS.
On ARM64 the client received a UDP reply with the expected NAT source in all
three stages, without re-enrolling or changing its selected exit.
With both optional gates enabled, the Rust exit remained healthy during the
encrypted backup. A fresh Rust controller restored the exit registration,
certificate, key, and configuration before the original stack rolled back to
Go and forwarded traffic again.

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

On the marked Docker lab host, use `dispatch.sh --installed` with the same
arguments to run the contract on a fresh Compose install. The test signs the
first owner in through the relay on port 443 and checks the registration
and OAuth flow with the real Dispatch client. It provisions test networks
and router identities through Rust APIs, without inserting rows directly.
The disposable relay uses a lab certificate; it does not contact public ACME.
On ARM64 this passed with Dispatch revision `27be92b`, including the token
exchange through port 443, cross-network denials, connector installer and
route requests, token refresh, and revocation.

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

### Initialize a fresh Rust controller

With no database at the destination, run:

```sh
laneway-controller init /var/lib/laneway-controller/controller.db \
  /run/laneway-secrets/controller.crt production 100.96.0.0/16
```

Run the command as the same user that will run the controller. The database
parent must already exist and be writable by that user. The command creates
the fleet schema and first network, binds their identity to the controller
certificate, and publishes the owner-only database only after validation. It
does not replace an existing database or require a Go controller. Normally
start `serve` with the same certificate and complete administrator setup.

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

Fleet features in a private live console can be checked separately without
copying those assets into the public release. Install the Playwright browser
from the migration checkout (`cd web && pnpm install --frozen-lockfile &&
pnpm exec playwright install chromium`). Build the private console with
`pnpm build:live` in its own checkout, then run the following from the migration
checkout root:

```sh
cd go
LANEWAY_RUST_CONTROLLER=/absolute/path/to/laneway-controller \
LANEWAY_RUST_RELAY=/absolute/path/to/laneway-relay \
LANEWAY_RUST_FLEET_CONSOLE_ASSETS=/absolute/path/to/private/web/dist \
go test -count=1 -tags=rustinterop ./internal/controllerservice \
  -run '^TestRustControllerFleetConsole$' -v
```

The gate signs in through the Rust relay's public HTTPS listener and checks a
canary plan, alert acknowledgement, diagnostics, private DNS, policy preview and
history, and map location editing against a real Rust controller. It uses a
disposable database and blocks external browser requests. It does not install a
runtime release, measure live packet reachability, or certify which assets ship
in the public image.
The private console passed this check against native Rust controller and relay
builds on Apple Silicon, with all browser requests confined to the lab.

## macOS endpoint

`lanewayd-rs` runs the ordinary macOS tunnel and its privileged helper as
separate processes from the same installed Rust binary. The helper creates
the `utun`, passes a descriptor over an inherited Unix socket, and manages
only routes it owns on that tunnel. The unprivileged runtime verifies the
descriptor, handles IPv4/IPv6 packets, and keeps credentials out of the helper.
Closing either process ends the tunnel: the helper withdraws routes when the
client closes its socket, and the client stops if the privileged child exits.
The release workflow builds the native binary for
Apple Silicon and Intel and includes `bin/lanewayd-rs` in each macOS archive
covered by the release's signed checksums. The standalone Go CLI remains an
operator tool; installing an endpoint requires the full archive. No separate
Go helper is installed.

On an isolated Mac, run the release's `install.sh` as a normal user. The
installer verifies the tag's signed manifest and archive checksum before
running the bundled CLI. For an archive you verified yourself, run
`sudo sh install.sh` inside its extracted `laneway` directory. The Rust
binary installs at `/Library/Application Support/Laneway/lanewayd-rs`.
`laneway update` verifies and installs the complete signed package. Both
`laneway configure --check` and `laneway connect` reject an installed runtime
that does not match the CLI version. Missing Cosign is handled with a
checksum-pinned temporary verifier.

To build and check an unsigned local archive on native macOS without installing it:

```sh
version=0.0.0-lab
arch=$(go env GOARCH)
LANEWAY_PRODUCT_VERSION="$version" cargo build --locked --release \
  --manifest-path rust/Cargo.toml -p lanewayd-rs --bin lanewayd-rs
PACKAGE_RUST_MACOS="$PWD/rust/target/release/lanewayd-rs" make package VERSION="$version"
sh integration/rust-release-macos.sh "dist/laneway_darwin_$arch.tar.gz" "$arch" "$version"
```

Run `laneway connect DOMAIN` as your normal user. Add `--ephemeral`
for a one-time login, or repeat `--route PREFIX` for an exact controller
advertisement. Remembered logins use policy-derived private routes by
default; ephemeral logins default to overlay-only. Both preserve the packet
policy from the controller, and loss of a requested route withdraws the
session's route authority. The wrapper waits for tunnel cleanup before it
rotates a remembered credential and reconnects.

On an isolated Mac with the package installed, use a native node
configuration with `[tun]` set to `name = "utun"` and `configure = true`.
Set `socket_path` to a path in a private user-owned directory. Run the Rust
binary as a regular user. The macOS runtime is split-tunnel only; it does not
configure an exit or change host DNS. A changed overlay address requires
reconnecting, and losing controller authority withdraws the ordinary routes.

The native CI matrix runs the unprivileged stream-framing and credential
handoff tests on Apple Silicon and Intel. On disposable runners, the default
archive install must leave the old helper path absent. The probe exercises
the Rust helper with a real `utun`, isolated IPv4 routes, a conflicting
route, traffic, and cleanup. The archive gate fails if the exact privileged
test did not actually run.
On a disposable native Mac outside hosted CI, point the test at the local
archive and its companion Go executable. Mark **only that disposable host**
and run as an administrator account with noninteractive sudo:

```sh
sudo install -m 0600 -o root -g wheel /dev/null /var/run/.laneway-isolated-macos-lab
LANEWAY_MACOS_ARCHIVE_INSTALL=1 LANEWAY_MACOS_UTUN_TEST=1 \
  sh integration/rust-release-macos.sh "dist/laneway_darwin_$(go env GOARCH).tar.gz" \
  "$(go env GOARCH)" 0.0.0-lab
```

Use the version built into the archive. The gate refuses existing installation
paths, installs the default package for the test, then removes the fixture files.
For `0.0.9103`, eleven unprivileged Rust helper tests and three Go handoff
tests passed on Apple Silicon and for the x86-64 binaries under Rosetta.
Both archives contained and ran the expected thin Go and Rust executables.
The installed-helper test was not run. The test refuses Rosetta when asked
to install the helper, so translated checks cannot count as native Intel
network validation.
The release package gate checks both binaries, preserves the standalone Go
artifact, and verifies the installed runtime on disposable native runners. Release checksum
signing is separate from Apple Developer ID signing or notarization.
The `0.0.9104` unsigned archives passed package and updater-extraction
checks on Apple Silicon and for the Intel build under Rosetta. Both builds
also passed the CLI-to-Rust credential handoff check. The privileged `utun`
gate was not exercised in that local run.

## Managed Docker network plugin

The Rust driver implements Docker's local Unix HTTP protocol and reads the Go
plugin's v1 network journal and controller authorization format. It preserves
the derived bridge, route table, and veth names. It checks authorization before
creation, join, or startup reconciliation. Failed cleanup keeps the ownership
record, and an interrupted join stays pending until the backend confirms it.
Controller-authorized container networks also stop forwarding at lease expiry,
even if the plugin stops and the tunnel stays up. The running plugin watches the
local controller snapshot to fence removed grants and apply renewals without
recreating the network. Direct networks that don't require a grant are unchanged.
If startup cannot validate a recorded grant, it fences the owned firewall and
refuses readiness; restore the snapshot and restart the plugin.

The Linux backend uses the same bridge and veth aliases as Go. It installs
the nftables policy as one transaction and removes exact recorded routes and
rules rather than flushing tables or deleting rules by priority. The managed
plugin build and tagged workflow select Rust. CI exercises a fresh Rust install
against native AMD64 and ARM64 Docker Engine.

The isolated Linux ARM64 lab verified in-place adoption of a Go-created
network, preservation of unrelated routes and rules, and authorized packets
through the tunnel. Revoking or expiring the lease stopped container traffic
with the tunnel still up, and renewal restored traffic. After removing the
tunnel, the container's traffic was rejected even though the host could still
reach the destination. The Rust image also recovered persisted state across
restart through its Unix socket.

On a separate rootful Docker Engine 29.10 ARM64 VM, Docker installed and
enabled the Rust managed plugin, rejected an ungranted network, and connected
a running container through a test tunnel. The existing container lost the
path at grant expiry, regained it after renewal, and kept it through a plugin
disable/enable cycle. The Go package also passed the shared managed lifecycle
checks. Teardown removed the test bridge, policy rule, and firewall. The Rust
packet test adds and removes only the two host firewall rules needed for its
ICMP probe; Docker's default forwarding policy stays unchanged.

Repeat on a disposable rootful Linux Docker host with `iproute2`, `iptables`,
`iputils-ping`, and `nftables`:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_DOCKER_PLUGIN_RUNTIME=rust \
  ./integration/docker-plugin.sh
```

The same rootful ARM64 lab also exercised `docker plugin upgrade` from Go to
Rust and back to Go using a loopback registry. Docker preserved the plugin ID,
propagated mount, and both networks. The original container kept its process,
endpoint ID, and address. Go then loaded and removed a second endpoint written
by Rust after the upgrade. Both containers passed packet probes after rollback;
this verifies state and post-switch traffic, not uninterrupted packet delivery
during plugin disable/enable.

Run the upgrade gate on an isolated host with `curl` and `jq` in addition to
the forwarding test tools:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_DOCKER_PLUGIN_RUNTIME=go \
  LANEWAY_DOCKER_PLUGIN_UPGRADE=1 ./integration/docker-plugin.sh
```

This migration check is historical and not a release gate. Rolling back to
Go also rolls back Rust's kernel-enforced grant expiry.

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

The release builds the `rust-connector` target in
`deploy/containers/Dockerfile.connector`. The one-time installer handles the
setup token and encrypted bootstrap; only the Rust agent keeps running.
It uses the controller's relay list for QUIC and only dials TCP fallback
addresses authorized for the configured relay. Updates validate the named
volume read-only before stopping the old Rust container.

CI starts with a fresh Connector volume, verifies the negotiated transport and
the running Rust process, then restarts with only the saved identity:

```sh
docker build --target rust-connector -f deploy/containers/Dockerfile.connector \
  -t lane-edge:rust-migration-lab .
docker build --tag laneway-rust-lab:local integration/rust-lab
bash integration/rust-lab/connector-cutover.sh --prime-cache
bash integration/rust-lab/connector-cutover.sh --fresh lane-edge:rust-migration-lab
bash integration/rust-lab/connector-cutover.sh --fresh lane-edge:rust-migration-lab tcp-fallback
```

Historical Go-to-Rust cutover tests are available for reference only; they are
not release requirements.

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

The release builds the durable Docker Exit Node from the `rust-exit` target.
On a fresh Rust control plane, the optional Compose profile uses that pinned
image. Enroll it, render the packaged Exit Node template with the network and
service identities, then request and approve its exit route. The container
runs as a non-root user with only `NET_ADMIN`; the daemon and readiness probe
are Rust. The Go CLI is used only for one-shot administration.

Historical Go-to-Rust cutover experiments are not release requirements. The
following gate checks the legacy NAT profile and its existing state layout:

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

This Docker profile uses NAT and enables direct paths. The shared-host
ephemeral Exit uses the separate native WireGuard process described below.

### Ephemeral exit control

Run `bash integration/rust-lab/exit-lease.sh` to exercise the Rust node control
loop against both controller implementations. The fixture uses separate
disposable identities and revokes each while its authenticated QUIC session runs.
It checks that a same-epoch heartbeat extends only the lease, and that revocation
retires the authority without waiting for a timeout. The unit gate also checks
terminal expiry while a request is stalled.

The encrypted Linux runtime owns a kernel WireGuard link and installs a
default-deny nftables policy before bringing it up. Policy-only updates replace
the firewall in a single transaction without recreating the device. The
relay carries only encrypted UDP messages. Optional NAT opens only with live
controller approval, for authorized overlay sources and the configured uplink;
both directions still pass through the decrypted traffic ACL.

In a dedicated Linux network namespace with `ip`, `nft` and
`CAP_NET_ADMIN`, run the opt-in profile with a native node TOML and an existing
raw WireGuard private key (owned by the service user, mode 0600 or 0640):

```sh
lanewayd-rs --wireguard-config /etc/laneway/node-rust.toml \
  --wireguard-key /run/laneway/node.wireguard.key
# For an ephemeral Exit, also pass --exit-generation with its enrollment generation.
```

Use `--check-config` to validate the files without joining or creating a link.
Keep automatic certificate renewal, exit selection on this node and diagnostics
disabled in the native node TOML for this profile. Enabling gateway NAT requires
`forwarding.exit_gateway = true`, `forwarding.exit_gateway_controller_sources = true`
and an explicit `forwarding.exit_output_interface`. The kernel must provide
WireGuard. The daemon sends keys directly to the kernel over netlink; only the
lab fixture requires the `wg` command. Existing links and firewall tables are not adopted; discard or
clean up the isolated namespace after an unclean kill.

The packet gate requires the same tools and isolated network namespaces:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_WIREGUARD=1 \
  ./integration/rust-controller-node-netns.sh
# Repeat with LANEWAY_NODE_TEST_CONTROLLER=rust for the Rust controller and relay.
```

The test provisions a disposable ephemeral identity and starts the actual Rust
executable against a Go peer. It exercises QUIC and forced TLS/TCP, including
ciphertext larger than the legacy raw-IP ceiling. It checks a live ACL change,
source NAT through the approved exit, route withdrawal, live revocation and
device cleanup. Set `LANEWAY_NODE_WIREGUARD_NATIVE=0` to run just the
fixture-managed encrypted transport gate. Set `LANEWAY_NODE_WIREGUARD_DRAIN=1`
to partition the controller after opening an exit flow: the same flow continues,
new flows are blocked, and fresh mTLS restores forwarding without replacing the
device. The rootless lab exercises the shared-host credential parser using a
marked tmpfs. Use a disposable Linux VM for the actual transient systemd unit:

```sh
# Inside a disposable VM with systemd as PID 1 and kernel WireGuard support.
sudo install -m 0600 /dev/null /run/.laneway-isolated-systemd-lab
sudo env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_WIREGUARD=1 \
  LANEWAY_NODE_WIREGUARD_SYSTEMD=1 LANEWAY_NODE_WIREGUARD_DRAIN=1 \
  LANEWAY_NODE_TEST_CONTROLLER=rust ./integration/rust-controller-node-netns.sh
```

With a read-only checkout, supply `LANEWAY_NODE_TEST_RUST_RUNTIME_DIR` and
`LANEWAY_NODE_TEST_GO_FIXTURE_DIR` instead of building in the VM. The Go fixture
directory must contain `laneway` and `lanewayd` from `./cmd/laneway`,
`laneway-relay` from `./cmd/laneway-relay`, and `netprobe` and
`rustnodecontroller` from their respective `./integration/` packages in `go/`.
The systemd gate uses the installer unit definition with lab-only networking and
credentials. It checks the private namespace, dynamic UID, memory lock,
read-only credential mount and removal of source copies, then runs the same
packet, policy and teardown checks. It does not run the signed download path or
cover routed-only egress or IPv6 NAT on the encrypted profile.

To use a real invitation rather than pre-staged credentials, add
`LANEWAY_NODE_WIREGUARD_INVITATION=1` to the Rust-backed systemd command.
The discovery name and lab CA apply only within the enrollment process.
The generated config is passed to Rust unchanged; its time fields may be
integer nanoseconds from Go or strings from older hand-written configs.
This variant puts the actual installer veth, NAT and Docker forwarding rules
inside a dedicated host namespace and proves that the installed cleanup unit
removes them after revocation without changing unrelated rules or the VM's
global forwarding setting. It requires the iptables nftables backend.

### Verified on the local ARM64 Linux VM

- Direct and relayed IPv4/IPv6 packets between the Go and Rust node binaries,
  including exit forwarding and blocked traffic.
- Kernel route, firewall and DNS ownership recovery, including SIGTERM cleanup.
- Go controller bootstrap of the Rust node, an approved route, traffic denial
  after ACL removal and certificate revocation, and authority expiry on outage.
- Packaged Rust node running non-root with TUN and a healthy status socket;
  Docker stop returned exit code zero.
- Packaged Rust shared-host Exit under Ubuntu 24.04/systemd 255: QUIC and
  TLS/TCP fallback with both Go and Rust controllers/relays, live ACLs, scoped
  NAT and established-flow drain, route withdrawal, identity revocation, and
  kernel state cleanup.

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
together. Full parity with the deployed private fleet build is still unverified.
The isolated tests below cover individual features, not the exact deployed build
or its release and rollback procedures. Keep Go serving production.

The Rust controller preview serves the private directory through
`GET /v1/admin/networks/{network_id}/private-dns` and
`GET /v1/node/private-dns`. The administrator path requires network-scoped
`acl.read`; the node path derives the network from its verified client
certificate and rechecks certificate and identity state for every request.
It uses the managed grant compiler and never treats a manual traffic allow
rule as permission to enumerate names. It publishes permanent names, unique
friendly aliases, and granted services in the private fleet JSON format. The
catalog is not cacheable by HTTP, and its lifetime is at most 30 seconds and
no longer than the visible node leases or the requesting certificate.

The Rust node can opt into a loopback-only UDP resolver with the same setting
as Go. Leave it omitted or empty to disable it:

```toml
[controller]
private_dns_listen = "127.0.0.1:5354"
```

The resolver uses the node's pinned mTLS HTTPS client even when the node
uses QUIC for control. It accepts A and AAAA questions in its own network
zone, does not recurse or modify OS DNS settings, and returns SERVFAIL when
its bounded cache expires and the catalog cannot be renewed. Answers last
no more than five seconds and never beyond the catalog or leaf certificate.
Existing installed node-role configurations keep their explicit setting.
The isolated Linux gate (`LANEWAY_NODE_TEST_PRIVATE_DNS=1` with the Rust
controller) queries the running daemon over UDP after certificate renewal,
blocks its HTTPS path while QUIC remains available, then checks SERVFAIL and
recovery without restarting the node. It does not configure OS split DNS.

### Fleet schema and policy history (lab only)

Rust accepts public schema 18 and the exact additive schema 19 defined by
the local Go fleet source. It checks the version history and each named fleet
table and index before serving; unknown layouts and newer versions are rejected.
Serving never migrates a database automatically. To exercise the migration,
stop the writer, take a backup, and run this command against a disposable copy:

```sh
laneway-controller migrate-fleet /path/to/disposable-controller.db
```

The migration is transactional and a second run on the same layout is a no-op.
The lab read backups and restored copies from the Go fleet controller and
verified that Go fleet code can reopen a Rust-migrated database. Rollback on
schema 19 requires a Go **fleet** build; public schema-18 Go is not a fallback.

On schema 19, Rust records the manual ACL policy before and after every ACL
mutation. The history API requires network-scoped `acl.read`. Restoring a saved
revision requires `acl.manage` and the current configuration epoch. It compiles
the restored policy and commits the ACLs, epoch, history, and audit together.
The HTTPS fixture verifies permissions, stale epochs, and rollback on a failed
audit write. These checks do not cover all fleet workflows, the private
console, or the deployed production database; do not promote the controller
on schema support alone.

`POST /v1/admin/networks/{network_id}/policy-preview` works on both schemas.
It uses the Rust packet-policy evaluator for current rules and an optional
proposed replacement of the manual rules, with the same managed-access grants
and configuration epoch for both. The trace stops at the first match; no
packets are sent and no policy, epoch, or audit entries are written by the
preview. The route requires network-scoped `acl.read` and same-origin CSRF
proof for browser sessions. The HTTPS fixture checks overlay and subnet
resolution, managed-access isolation, and unchanged policy state.
Managed-rule priorities stay compatible with the matching Go schema: the
public runtime offsets priorities, whereas fleet snapshots re-rank manual
rules without collapsing their order at the numeric upper bound.

`POST /v1/admin/networks/{network_id}/diagnostics` uses the same evaluator and
the source node's permission-filtered private DNS catalog. It reports certificate
and lease state, endpoint report freshness, route candidates, and configured DNS
answers without making any network requests. End-to-end reachability stays
`unknown` even if policy permits traffic and every available check passes.
An expired overlay identity whose address has not been reclaimed does not fall
through to a default route. Like preview, diagnostics requires network-scoped
`acl.read` and browser CSRF proof.

### Live topology (lab only)

Fleet schema 19 accepts node topology over mTLS at `PUT /v1/topology`.
The map's `GET /v1/admin/networks/{network_id}/topology` requires scoped
`node.read` and returns only recent contacts between active nodes in that
network. Each node replaces its previous report, and the controller purges
expired reports even when no new traffic arrives.

Rust nodes using the raw or userspace dataplane opt in with
`topology_reporting = true` under `[controller]`. They report the latest
carrier that delivered authenticated inbound traffic from each peer. A
configured peer or route does not create an edge. Reports omit packet content,
IP addresses, and unmeasured latency. Reports run every 30 seconds and expire
after two minutes, so turning reporting off lets existing edges age out. The
encrypted-only WireGuard carrier does not claim a peer contact based on relay
ciphertext alone.

The isolated Linux packet gate uses `LANEWAY_NODE_TEST_TOPOLOGY=1` with
`LANEWAY_NODE_TEST_CONTROLLER=rust` to verify that the map stays empty until
an authenticated reply actually crosses the relay.

### Native controller backup and restore (lab only)

On Unix, take an online backup using SQLite's online copy API. Restore only
into a new path, with the destination controller stopped. Use a trusted,
already-created directory owned by the controller operator:

```sh
laneway-controller backup /path/to/controller.db /path/to/backups/snapshot.db
laneway-controller restore /path/to/backups/snapshot.db /path/to/restored/controller.db
```

Both commands validate the canonical schema (18 or 19), SQLite integrity
and foreign keys, and controller identity and authorization invariants
before publishing a standalone, private database. Neither command overwrites
an existing database, symlink, or SQLite sidecar. Restore and migration use
the same lifecycle lock as the Go service on Linux. For older database
versions, upgrade a disposable copy using Go before using these commands.

Restore retains durable configuration and app registrations. It discards
browser sessions and unused administrator recovery grants, revokes automation
service access tokens, and records a system audit event. On schema 19 it also
clears topology and updater presence, removes unused node recovery grants,
and pauses active rollouts. Running update claims remain reserved for operator
reconciliation. The database does not include CA keys, TLS files, or the
separately managed root token: back those up and protect them separately.

Traffic rules can be listed, created, updated, and deleted through the same
Rust HTTPS listener. The controller validates canonical prefixes and port
ranges, and publishes rules in priority and ID order. The Rust network-namespace
gate uses the existing Go CLI against the Rust ACL API to prove that removing
the allow rule blocks a real routed packet and adding it back restores traffic.
The fixture still uses Go for route administration.

### Operational alerts (lab only)

Fleet schema 19 reconciles node status, certificate expiry, exit availability,
and terminal update outcomes every minute. A node that has never reported is
not offline. An expired report opens an offline incident after a two-minute
grace period; stale or unknown exit status cannot clear an exit incident.
Certificates expiring within seven days and failed or rolled-back updates are
tracked separately. Acknowledgment does not change forwarding or suppress a
later recurrence.

The existing console endpoints are `GET /v1/admin/networks/{network_id}/alerts`
(`node.read`) and
`POST /v1/admin/networks/{network_id}/alerts/{alert_id}/acknowledge`
(`node.manage` plus CSRF for browser sessions). Each open, acknowledgment,
or resolution records one durable event in the same transaction.

Webhook delivery is off by default. To enable it, pass
`--alert-webhook-url-file PATH --alert-webhook-secret-file PATH` to the Rust
controller. Both Unix files should be private regular files, mode 0600 or
0400, readable by the service. The first contains one HTTPS URL on port 443
without credentials or a fragment. The second contains a signing secret of
at least 32 bytes, with the file bounded to 4096 bytes. Keeping the URL in a
file also keeps notification tokens out of process arguments.

The client rejects proxies, redirects, and private or special-use destinations.
Every DNS answer must pass the public-address check, and the actual connection
uses only those addresses with TLS still verifying the original hostname.
The address filter is conservative about the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry)
special-purpose ranges.

The webhook signs `timestamp + "." + eventID + "." + rawRequestBody` using
HMAC-SHA256, with the Go-compatible `X-Laneway-Event-ID`,
`X-Laneway-Timestamp`, and `X-Laneway-Signature: v1=<hex>` headers. Retries
use the original event ID and payload. A send has an eight-second deadline
and at most five attempts. Receivers should deduplicate by event ID: a crash
after acceptance can lead to a repeat. Events processed while delivery is
disabled are not replayed if it is later enabled.

`bash integration/rust-lab/alert-webhook.sh` exercises the actual signed TLS
request and rejects a redirect inside a Docker namespace with no egress.

### Managed fleet updates (lab only)

Schema 19 supports the existing Fleet Updates console API. Listing requires
`node.read`; creating, promoting, and cancelling require `node.manage` for
the network. Plans pin a stable release tag and put the first selected targets
in the canary stage. Promotion requires healthy reports from all original
canaries. A failure or verified rollback pauses the plan. These changes are
audited without bumping the network configuration epoch.

The node poll and result endpoints require a current, authenticated node
certificate. The runtime node and network identifiers in the request must
match that certificate. A running claim survives cancellation, and retrying a
terminal report does not repeat the state change or audit. The controller
returns a release tag, not a binary, executable command, or download URL.

Linux amd64 and arm64 archives include the native opt-in updater for the
standard `lanewayd-rs.service` installation. It uses the root-owned
`/etc/laneway/node-rust.toml` for the controller identity, node certificate,
and local status socket. Its CA file and parent directories must be
root-owned and not writable by the daemon. The updater uses the existing pinned Cosign verifier
at `/usr/local/libexec/laneway/cosign-v3.1.3`, requires the exact tagged
`Doout/laneway` release workflow identity, and extracts only
`laneway/sbin/lanewayd-rs` after checking the archive's signed digest.
It does not update Go nodes or standalone exit profiles, and does not change
installed config, CA, or private keys.

To manage an already-cut-over Docker Connector instead, use the optional
`[connector]` settings in the example. Supply the container name, controller
origin and TLS name, network and controller IDs, and a separately protected
CA. Only the standard non-root, read-only Rust Connector with
`<container>-state:/var/lib/laneway` is accepted. The worker does not re-enroll
or copy setup-token settings. It uses the current node certificate from the
selected container, not shared administrator or registry credentials.

The release workflow publishes `ghcr.io/doout/lane-edge-rust`.
A Connector update verifies both the signed
release manifest and the native image's digest signature. It runs an offline,
read-only state preflight before stopping the old container. After a swap,
success requires a fresh daemon instance, the same network and node IDs,
the requested version, and a current authenticated controller lease.
Rollback restarts the same previous container and volume. An ambiguous Docker
operation retains the controller claim and the preserved container for
inspection; it never deletes a volume or a container by guessed name.

Install the updater binary and its service and timer from a verified package.
Copy `examples/managed-updates-rust.toml` to
`/etc/laneway/managed-updates-rust.toml` (root-owned, mode 0600). Do not
run the legacy updater on this service. After verifying the installation and
rollback in the lab, tests may opt in with `enabled = true` and
`systemctl enable --now laneway-rust-updater.timer`. Installing the files or
upgrading the controller does not enable the timer.

If a request or activation is interrupted, the updater does not claim again or
reinstall. Stop the timer, inspect the durable `rust-journal.json` under
`/var/lib/laneway-updater` (`rust-<container>-journal.json` for Connectors),
and verify the runtime's authenticated controller
lease. A terminal ACK can be retried by rerunning the worker. For unresolved
claims, inspect the installed executable and any
`/usr/local/sbin/.lanewayd-rs-update-{previous,next}` before moving those
markers out of the installation directory. With the known daemon healthy,
run `laneway-update-rs --reconcile UPDATE_ID vTARGET vPREVIOUS`; the
controller rechecks the exact claimed node and versions. Do not enable this
on production without the signed release and real systemd rollback gate.

The optional `TestRustControllerFleetUpdates/managed-worker` lab case uses
the actual controller and Rust daemon over mTLS and the local Unix socket.
Set `LANEWAY_RUST_UPDATER`, `LANEWAY_RUST_CONTROLLER`, and
`LANEWAY_RUST_NODE` to the three Linux binaries in a disposable, root-run
Docker container without existing Laneway installation paths. Run
`go test -tags=rustinterop ./internal/controllerservice -run '^TestRustControllerFleetUpdates$'`
from the `go` directory. The test claims a release already running locally:
it verifies opt-in, credential binding, and terminal acknowledgment without
needing release network access. Local activation tests exercise atomic
replacement and rollback separately.

To also exercise a real systemd restart and rollback, use the marked
disposable VM from the Linux packet gate. Stage two native Rust nodes built
from this branch with different numeric `LANEWAY_PRODUCT_VERSION` values,
and the test executable printed by
`cargo test --locked --manifest-path rust/Cargo.toml -p lanewayd-rs --lib --no-run`.
In the VM, compile the Go fixture with
`go test -tags=rustinterop -c -o /tmp/fleet-updater-check ./internal/controllerservice`
from the `go` directory, then run it:

```sh
sudo env LANEWAY_RUST_CONTROLLER=/absolute/path/to/laneway-controller \
  LANEWAY_RUST_UPDATER=/absolute/path/to/laneway-update-rs \
  LANEWAY_RUST_NODE=/absolute/path/to/old-node \
  LANEWAY_LAB_NODE_CANDIDATE=/absolute/path/to/new-node \
  LANEWAY_RUST_SYSTEMD_ACTIVATION_TEST=/absolute/path/to/rust-test-executable \
  /tmp/fleet-updater-check -test.run '^TestRustControllerFleetUpdates$/^managed-worker$' -test.v
```

The test refuses existing Laneway installation paths and services. It uses
the production activation code against a temporary `lanewayd-rs.service`,
requires a fresh daemon with a live controller lease, then restores the
previous executable after a candidate fails. The candidates are supplied
directly to the test; it does not verify downloading and rolling out a
new signed release.
On the isolated ARM64 VM, the gate upgraded `v0.0.9100` to `v0.0.9101`,
then restored that exact executable after the next candidate never became
healthy. Both restarts preserved the node's identity and certificate.
The release matrix now runs `integration/rust-release-fleet-update.sh`
on native AMD64 and ARM64. It takes the controller, updater, and upgrade
candidate from the actual release archive. The previous runtime and the
activation harness are built for the lab and excluded from the archive.
The ARM64 rehearsal activated the packaged `v0.0.9104` node from the
synthetic `v0.0.0` fixture, then restored it after the next candidate failed.
It verified the same node certificate and a fresh authenticated controller
lease after both restarts.

New durable Rust Connector invitations use the encrypted one-time bootstrap.
It activates the identity in a named volume before starting the serving
container. The serving container carries no invitation and uses the image's
exec-form health check; the scratch image does not contain a shell.

On the Connector host, `laneway-update-connector NAME [--version TAG]` uses
the same Rust transaction as fleet updates. It authenticates the release
manifest and immutable Rust image, verifies the candidate against the
identity volume read-only, and checks the restarted daemon's version,
identity, and controller lease. It refuses downgrades, legacy Go images,
and updates with a pending fleet claim.

The Connector transaction has a separate Docker gate. Give it a local native
Connector image built with a numeric release version and the local daemon
socket path as seen by the test VM. Use a disposable Docker lab:

```sh
bash integration/rust-lab/connector-managed-updater.sh \
  lane-edge:rust-migration-lab /var/run/docker.sock
```

It performs an actual replacement and forces a failed version check, then
verifies that the identical previous container is serving again and that
certificate, key, and configuration bytes in the state volume did not
change. The gate uses local images without downloading from a registry;
it does not verify publication of a signed Rust Connector release.
The ARM64 Docker lab also ran the packaged updater's manual mode against the
serving fixture. It recognized the running version, rejected a downgrade,
then verified a real container replacement and rollback without changing the
identity files. The lab did not download a signed candidate.

### Recover an expired Rust node credential (lab only)

On schema 19, a scoped `node.manage` administrator can request a 10-minute
approval at `POST /v1/admin/nodes/{node_id}/credential-recovery-grants` with
the expired certificate's hex serial and a reason. The token is shown once
and must be delivered separately in a private file. Stop the node first.
For a native Rust node configuration, run this as the owner of the writable
certificate directory, with access to the existing private key:

```sh
lanewayd-rs recover --config /path/to/node.toml --recovery-token-file /path/to/private/approval
```

The command connects to the configured, identity-pinned controller HTTPS
origin without offering the expired leaf. The controller issues a certificate
only after verifying the approval and a signed CSR for the same key. The node
checks the returned CA chain and identity, then replaces only the certificate.
The flow rejects revoked credentials, leased ephemeral nodes, and disabled
managed users. It does not change the read-only imported Connector or Exit
profiles. A failed install after issuance requires another approval. Restart
the node and verify its normal connection.

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
