# Laneway operations runbook

This runbook covers production-oriented deployment, observation, incident
response, and safe cleanup. The examples use the files under `deploy/`; adjust
paths, interfaces, ports, and address pools for the site.

## Service and network boundaries

Run the controller and relay as separate unprivileged services. Only a node
that creates `lane0`, installs routes, serves a subnet, or provides an exit
needs `CAP_NET_ADMIN` and `/dev/net/tun`. Do not grant that capability to the
relay or controller. The userspace Docker Connector is also unprivileged: it
proxies controller-authorized TCP/UDP flows with outbound sockets and does not
create `lane0`, mutate routes, or provide raw-IP Exit service.

The default port plan is:

| Component | Transport | Default example | Exposure |
| --- | --- | --- | --- |
| Relay | UDP/QUIC | `4433` | Public when nodes connect over the Internet |
| Relay fallback | TLS/TCP | `443` | Public when fallback is enabled |
| Controller | HTTPS/TCP + control QUIC/UDP | `8443` | Prefer private management/node networks |
| Diagnostics | HTTP | disabled | Loopback only; never proxy publicly |
| Node local API | HTTP over Unix socket | `/run/laneway/lanewayd.sock` | Local owner only (`0600`) |

Keep relay, controller, and node private keys readable only by their service.
The offline root CA key is the highest-value credential: do not install it on
the controller, relay, or nodes. Use `laneway pki intermediate` to create a
path-length-zero online issuer, install only its key on the controller, and
back up both keys encrypted under separate operational controls. Configure
`tls.ca` as the root-only trust bundle and `controller.issuer_certificate` as
the issuer-first intermediate bundle. The controller returns that intermediate
on enrollment and renewal, allowing root-only node trust without online root
key access.
Enrollment and administrator tokens must not be placed in shell history,
process arguments, source control, or logs.

### Public bootstrap and short invite codes

A fresh user client must authenticate discovery before it accepts the private
network CA. The standard Compose deployment enables `[bootstrap]` on the
controller and `[public_https]` on the relay. TLS ALPN shares relay TCP 443:
normal HTTPS receives an automatically issued public Web-PKI certificate,
while `laneway-fallback/1` retains the private Laneway mutual-TLS identity.
The public handler serves only `/.well-known/laneway/bootstrap.json`; controller
HTTPS/QUIC on 8443 and relay QUIC on 4433 keep their private certificates.
ACME certificate state is stored in the private `laneway-relay-public-certs`
volume and renews automatically. Never copy a public private key into `.env`.

Public HTTP requests have a global ceiling and bounded token buckets by IPv4
/24 or IPv6 /64. A source IP receives a temporary higher allowance only after
it completes a valid Laneway mutual-TLS fallback connection. Promotion cannot
be requested with an HTTP header or public token, expires after one hour, and
the in-memory source tables are size-bounded. Rate-limited requests receive
HTTP 429 with `Retry-After`; unauthenticated clients retain enough baseline
capacity to perform first login.

Bootstrap configuration pins one network, the internal controller HTTPS and
QUIC endpoints, its DNS name, the configured Linux and macOS release artifacts,
their exact byte sizes, and lowercase SHA-256 digests. Enabled relay targets and
ServiceIDs are read from controller state for each short-lived response. The
controller refuses to start if static bootstrap data is malformed or if the
configured NetworkID differs from its controller certificate. A response
fails closed when there is no enabled relay.

On the control-plane host, issue a ten-minute local-user login token without
spelling controller, CA, relay, network, or service IDs:

```sh
sudo laneway control user-token --name laptop
```

This is a remembered-user enrollment code, not a permanent API bearer token.
Codes are random, stored by the controller only as a hash, network/class-bound,
single-use, limited to one hour of validity, and protected by a bounded
per-source token bucket. The advanced `laneway controller enrollment-token
issue` interface remains available for automation.

On a clean Linux or macOS AMD64/ARM64 client:

```sh
laneway login lane.example.com
laneway connect lane.example.com
```

On a clean Mac, install the user-only client first with:

```sh
curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install-client.sh | sh
```

The installer runs as the normal user, resolves a stable release tag, verifies
the downloaded architecture-specific binary against that release's checksum,
and invokes the built-in configuration transaction. Privilege is requested
only after the checks pass and only to install the client and credential-free
network helper. To pin a release, put `LANEWAY_VERSION=vX.Y.Z` immediately
before `sh` in the pipeline.

The client obtains metadata using TLS 1.3 and the host system's public roots,
rejects redirects and non-DNS authorities, then prompts on `/dev/tty` with terminal echo
disabled. `login` stores only the resulting certificate and private keys in a
mode-0700 directory owned by the local user; it does not save the enrollment
code. The product token binds the requested device name, so the client does
not repeat it and a substitution attempt leaves the code unused. For
non-interactive login, pass a mode-0600 `--token-file`;
the bootstrap flow rejects codes in argv. It also refuses endpoint/pin
overrides and sends the authenticated expected NetworkID so a wrong-network
code is rejected before consumption. Saved credentials rotate automatically
over mTLS before expiry. `connect` derives private split routes from ACCEPT
policy, preserves the native default route, runs the User session in the
foreground, and transactionally restores its temporary interface, routes, and
DNS state when it exits. `--route PREFIX` remains an exact manual restriction;
`--exit NAME` is the only way to select a default route. The older many-flag
`join` form remains the advanced
explicit enrollment path for migration, debugging, and automation.

On macOS, `connect` behaves like an SSH tunnel. The user process retains all
credentials while a short-lived, credential-free helper creates `utun`, adds
only the validated private routes, and restores them on disconnect. The helper
refuses to replace an existing route. The macOS package and command surface are
user-client-only: they do not include Connector, route-advertisement,
control-plane, or Exit Node operations. Unknown exit flags fail during local
argument parsing before enrollment or any networking change.

The standalone release binary installs itself with `laneway configure`. It
performs read-only preflight first, asks once before invoking `sudo`, stages
both copies, and verifies that `/usr/local/bin/laneway` and the root-owned
credential-free helper are byte-identical. `laneway configure --check` changes
nothing, and `connect` fails before networking if either copy is missing,
insecure, or mismatched. `laneway update DOMAIN` accepts only the current
Darwin artifact pinned by that domain's public-Web-PKI bootstrap metadata,
verifies its authenticated size and SHA-256 before extraction, and invokes the
same configure transaction only after every unprivileged check succeeds.

Linux login additionally requires its authenticated platform artifact record.
macOS installation verifies the release checksum before installing a
root-owned helper; an already installed macOS client can therefore connect to
an older control plane whose bootstrap document lists only Linux artifacts.
That older control plane cannot authorize `laneway update` until its bootstrap
artifact list is extended with Darwin AMD64 and ARM64 release archives.

Artifact downloaders must stream into an unprivileged temporary file, enforce
the authenticated `size_bytes`, and call the same SHA-256 verification logic
before extraction or privilege. Never pipe a download into a shell.

```sh
laneway bootstrap inspect lane.example.com
laneway bootstrap download lane.example.com --out ./laneway_linux.tar.gz
```

`bootstrap download` follows at most five HTTPS-only redirects, writes a
mode-0600 temporary file in the destination directory, verifies exact length
and SHA-256, and publishes with a no-replace hard link. It neither overwrites,
extracts, executes, nor elevates the artifact.

## Deployment checklist

1. Build with the pinned Go toolchain and run `make test`, `make vet`, and
   `make fmt-check`. Run `make integration`; use `make privileged-integration`
   only on a disposable Linux runner.
2. Create the CA and service identities, or import the site's authority. Check
   every certificate's role and SAN before installation. Generate the
   immutable network ID first, embed it in the controller certificate, and
   pass the same value to `laneway controller network create --network-id`;
   the controller therefore does not need a temporary bootstrap identity.
3. Copy the relevant example TOML to `/etc/laneway` and replace all sample IDs
   and addresses. Validate Go node, relay, and controller files with `laneway
   config validate -config PATH`. Validate strict Rust files with
   `lanewayd-rs --config PATH --check-config` or `laneway-relay --config PATH
   --check-config` before starting the service.
4. Create the fixed locked service identity used by the supplied relay and
   controller units, then install credentials with restrictive group access:

   ```sh
   sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin laneway
   sudo chown root:laneway /etc/laneway/*.key /etc/laneway/*.crt /etc/laneway/*.toml /etc/laneway/admin.token
   sudo chmod 0640 /etc/laneway/*.key /etc/laneway/*.crt /etc/laneway/*.toml /etc/laneway/admin.token
   ```

   The relay unit carries only `CAP_NET_BIND_SERVICE` for the documented TCP
   fallback listener on port 443. The controller needs no ambient capability.
5. Review the systemd unit and nftables example. Open only the required ports;
   preserve SSH or console access before applying a default-drop firewall.
6. Start the controller first, then controller-backed relays, then nodes. A
   controller-backed relay must first be registered with `laneway controller
   relay register` using the exact service ID in its relay-role certificate.
   It fetches a complete authorization/policy snapshot before opening its
   listeners. Unknown, legacy-unbound, and disabled relay identities are
   rejected even when their certificate chain is otherwise valid.
   Configure `controller.network_id` and `controller.service_id` on every
   controller client, plus `node.relay_network_id` and
   `node.relay_service_id` on nodes. These immutable pins prevent a different
   controller- or relay-role certificate under the same CA from impersonating
   the configured service.
7. Confirm node status, routes, carrier metrics, and end-to-end reachability.
   Test TCP fallback from a network that deliberately blocks UDP.

Configuration changes are snapshot-based. Approve advertised subnet and exit
routes deliberately, verify the resulting configuration epoch, and wait for
relay/node polling before assuming the policy is active. Treat an unexpected
epoch change as an administrative event to audit.

Subnet and exit roles are separate controller grants. Set the complete desired
role mask before accepting an advertisement; omitted flags remove that role:

```sh
laneway controller node capabilities --controller https://controller:8443 \
  --admin-token-file /etc/laneway/admin.token --ca /etc/laneway/ca.crt \
  --node-id GATEWAY_NODE_ID --subnet-router --exit-node
```

Disable a retired or compromised relay identity immediately; this advances
the network epoch and records a `relay.disable` audit event:

```sh
laneway controller relay disable --controller https://controller:8443 \
  --admin-token-file /etc/laneway/admin.token --ca /etc/laneway/ca.crt \
  --relay-id RELAY_RECORD_ID
```

Administrative inventory is bounded and does not require direct database
access. Use `--limit` (1 through 1000) on each list command; the common
controller identity, CA, and admin-token flags are omitted below for clarity:

```sh
laneway controller network list
laneway controller node list --network-id NETWORK_ID
laneway controller relay list --network-id NETWORK_ID
laneway controller acl list --network-id NETWORK_ID
laneway controller certificate list --network-id NETWORK_ID
```

Relay name/endpoint rotation and re-enablement preserve the immutable relay
record and certificate service identity while advancing the network epoch:

```sh
laneway controller relay update --relay-id RELAY_RECORD_ID \
  --name primary --endpoint relay-new.example:4433 --enabled=true
```

### Managed persistent Nodes

After the release package creates the locked service account and installs the
hardened unit, a durable Node invite is the only secret input required:

```sh
install -m 0600 enrollment-code.txt ./laneway.code
sudo laneway node install lane.example.com --token-file ./laneway.code
sudo laneway status
```

The command verifies the root-owned package files and service account before it
reads the invite. Public-Web-PKI bootstrap supplies the private CA, controller
identity, and endpoints; the first mTLS controller snapshot supplies the relay
identity and endpoint. The generated controller-authoritative configuration has
no static overlays or peers and enables the shared-socket direct path on an
ephemeral UDP port. `--no-direct` is the explicit opt-out.

The installation writes `0640 root:laneway` credentials/configuration and a
`0600 root:root` ownership manifest. An exact re-run validates those files and
starts the existing identity without reusing the consumed invite. A fresh
start must remain active across bounded systemd probes; otherwise the service
is stopped and disabled and the newly installed credentials are removed. The
invite was consumed by that point, so retry with a newly issued invite.

Package upgrades replace the binary and unit but preserve `/etc/laneway` and
`/var/lib/laneway`. Confirm `systemctl is-enabled lanewayd`, restart the unit,
and check `laneway status` after an upgrade. Reboot behavior follows the same
enabled unit. Rotate a managed credential with `sudo laneway node renew`; it
stages a locally generated key, stops the service for pair promotion, verifies
the restarted service remains active, and restores the previous pair if the
new credential cannot start. To uninstall command-owned Node state after a
graceful stop:

```sh
sudo laneway node uninstall
# Or retain /var/lib/laneway while removing credentials and configuration:
sudo laneway node uninstall --keep-state
```

Uninstall refuses to operate without the root-owned managed manifest and never
removes the shared binary, unit, service account, controller, or relay files.
For an existing manual Node, stop the unit, back up and move the four files
`ca.crt`, `node.crt`, `node.key`, and `laneway.toml` out of `/etc/laneway`, then
run the managed install with a fresh durable invite. The installer deliberately
refuses to overwrite unmanaged files.

For one compromised node credential, prefer certificate-specific revocation
so another credential for the same node remains usable:

```sh
laneway controller certificate revoke --controller https://controller:8443 \
  --controller-network-id NETWORK_ID --controller-service-id CONTROLLER_ID \
  --admin-token-file /etc/laneway/admin.token --ca /etc/laneway/ca.crt \
  --network-id NETWORK_ID --serial CERTIFICATE_SERIAL_HEX \
  --reason "compromised key"
```

The serial is the canonical positive unsigned certificate serial encoded as
lowercase, even-length hexadecimal. Revocation is audited and advances the
network epoch atomically. Fresh controller snapshots carry all revoked,
unexpired serials; relays reject new QUIC/TCP sessions and close matching
active sessions, while direct endpoints reject new peers and close matching
active direct paths.

Renew credentials into a staged pair; the CLI never overwrites the active key
and certificate and never sends either private key to the controller:

```sh
sudo -u laneway laneway renew --controller https://controller:8443 \
  --controller-quic controller:8443 \
  --controller-network-id NETWORK_ID --controller-service-id CONTROLLER_ID \
  --ca /etc/laneway/ca.crt --cert /etc/laneway/node.crt \
  --key /etc/laneway/node.key --out-cert /var/lib/laneway/node.next.crt \
  --out-key /var/lib/laneway/node.next.key
```

Verify the staged certificate's network/node URI and public-key match, then
stop the node before replacing both active files. Install the staged pair with
the same ownership and mode, start the node, and confirm a new authenticated
relay session before revoking the old serial. Stopping the daemon makes the
two-file promotion failure-atomic from the network's perspective: a crash or
mismatched pair prevents restart rather than continuing with an unintended
identity. Go and Rust nodes consume the same PEM credential format; the Rust
direct listener also requires a graceful restart to use the renewed server
certificate.

Controller snapshots are short authorization leases (five minutes by
default). Successful unchanged QUIC requests renew the lease without changing the
epoch. If controller access is lost through the deadline, nodes remove
controller routes and forwarding authorization and relays reject/re-authorize
sessions fail-closed; service resumes from the retained complete snapshot only
after the controller renews it.

Issue a fully temporary identity code with its authorization lifetime fixed by
the controller (the client cannot extend it):

```sh
laneway controller enrollment-token issue \
  --network-id NETWORK_ID --label laptop-session \
  --class ephemeral --session-lifetime 8h --expires-in 10m \
  --controller https://controller:8443 \
  --controller-network-id NETWORK_ID --controller-service-id CONTROLLER_ID \
  --admin-token-file /etc/laneway/admin.token --ca /etc/laneway/ca.crt
```

Use `--class remembered` for an explicitly remembered user or the default
`--class durable` for a persistent Node. The JSON response is the only command
output containing the single-use bearer secret; protect or prompt for it rather
than placing it in shell history. Ephemeral certificates and all distributed
authorization expire at `lease_expires_at_unix_seconds`. The controller keeps
expired session records for seven days, prunes them in bounded batches, and
retains their audit events.

Statically configured daemon transport endpoints are DNS-pinned at process startup. A node resolves
the bootstrap relay QUIC address, TCP fallback address, and controller HTTPS and QUIC endpoints once,
installs native bypass host routes for exactly those IP addresses, and uses
the corresponding numeric targets for every reconnect. Controller-backed
relays likewise pin their controller QUIC dial target. The configured hostname is
still used for HTTP `Host`, TLS SNI, optional `server_name` verification, and
the required Laneway certificate identity check. DNS changes therefore take
effect only after a deliberate daemon restart; confirm the new address is
reachable through the native network before restarting. IPv4 and IPv6
transport endpoints are both pinned to native host routes before tunnel routes
are installed.

Controller-issued node relay discovery is snapshot-scoped instead: every
bounded `relays[].endpoint` may be a numeric IP or canonical DNS `host:port`.
Before an epoch is published, Go and Rust nodes resolve the listed endpoints
under finite answer and time bounds, deduplicate all usable IPv4/IPv6 targets,
and transactionally include every retained IP in native route and exit-policy
bypasses. One unresolvable relay is skipped when another authorized target is
usable; zero usable targets rejects the snapshot and fails closed. Each
connection still verifies the exact relay SPIFFE ServiceID. The configured
relay `server_name` remains the shared WebPKI/SNI name for v1 discovery.

## Routine observation

For a node, use the protected local Unix-socket API through the CLI:

```sh
laneway status --config /etc/laneway/laneway.toml
laneway peers --config /etc/laneway/laneway.toml
laneway routes --config /etc/laneway/laneway.toml
```

All local-management commands also accept `--socket PATH`. The explicit socket
skips configuration parsing, which is useful for managing `lanewayd-rs` from
the shared Go CLI (its strict TOML schema intentionally differs) and for
recovery checks when the daemon configuration is temporarily unavailable.
The Rust daemon implements the same protected endpoints at its configured
`socket_path`, including controller-authorized transactional `exit use` and
`exit disable`; its explicit choice survives restarts through the bounded,
mode-0600 `exit_intent_path` journal.

`status` reports connection/reconnect and sent/received/dropped packet counts,
plus QUIC failure, TCP connection/failure, the active carrier, and selected-exit
state. `peers` reports the carrier independently for every authorized peer.
Hybrid WireGuard nodes use the stable names `direct-wireguard`,
`wireguard-relay-quic`, and
`wireguard-relay-tcp`; `negotiating`, `degraded`, `disconnected`, and `mixed`
describe transitional, unavailable, or non-uniform peer state. A rising
QUIC-failure count with working TCP connections usually indicates a UDP path
problem rather than an identity problem.
For controller-managed nodes it also reports whether candidate exchange is
currently enabled, the accepted certificate expiry time, and whether the
controller says renewal is due. These fields come from the same validated
leased snapshot used by the dataplane. When authority is withdrawn, candidate
exchange is disabled and renewal is marked needed while the last accepted
expiry remains visible for diagnosis.

The Go daemons have an opt-in loopback-only diagnostics listener:

```sh
laneway-relay -config /etc/laneway/relay.toml -diagnostics 127.0.0.1:6060
laneway-controller -config /etc/laneway/controller.toml -diagnostics 127.0.0.1:6061
laneway node run -config /etc/laneway/laneway.toml -diagnostics 127.0.0.1:6062
curl --fail --silent http://127.0.0.1:6060/metrics
curl --fail --output /tmp/laneway-relay.heap \
  http://127.0.0.1:6060/debug/pprof/heap
```

The controller binds HTTPS/TCP at `controller.listen` and authenticated
control QUIC/UDP at `controller.quic_listen`; they normally share one numeric
port. Every controller-backed node and relay must set
`controller.quic_endpoint = "host:port"`. Snapshots, unchanged-lease refreshes,
and node certificate renewal then use direct mTLS QUIC. HTTPS is retained for
administrative requests and one-time enrollment, because a joining node does
not yet possess a client certificate. See
[controller control transport v1](../spec/controller-control-v1.md).

The process rejects wildcard and non-loopback diagnostic addresses. The
endpoint has no application authentication because it cannot bind remotely;
it exposes sensitive runtime profiles, so do not publish it through a reverse
proxy. Remove profiles after analysis. Relay metrics include sessions, bindings,
queued packets, forwarded packets/bytes, and aggregate drops. Node metrics
include carrier and unified-dataplane packet, malformed-input, path-failure,
and fallback counters. When direct connectivity is enabled,
`laneway_path_direct_failures_total` and `laneway_path_switches_total` expose
automatic fallback/recovery decisions; observations, aggregate failures, and
bounded active-peer count are exported alongside them without per-peer labels.
Hybrid WireGuard nodes additionally export label-free
`laneway_wireguard_carrier_*` packet, failure, retry, observation, switch, and
peer counters. These counters observe only opaque encrypted WireGuard messages
and carrier state; they do not expose peer identities, endpoint addresses,
failure strings, key material, or packet contents.
The controller exports its up indicator and bounded request, success,
malformed-input, authorization-failure, and internal-failure counters without
identity-derived labels.
Diagnostics are disabled when the flag is omitted; node counters also remain
available through `laneway status`.

`laneway status` is the concise readiness view for either node
implementation. It reports the actor, overlay addresses, selected route
prefixes, active carrier, controller certificate and ephemeral identity-lease
deadlines, and Exit selection. A serving Exit Node also reports forwarding/NAT
readiness, forwarded packets, and cleanup failures. The JSON form uses the same
fields and is preferred for automation:

```sh
laneway status -json
```

Foreground `laneway connect` sessions identify `actor=user`, their owned
routes, local-LAN bypasses, DNS owner, lease deadline, and active helper cleanup
journal. The final `temporary networking restored` message confirms successful
cleanup. None of these diagnostics include an invite, enrollment token, private
key, rendezvous token, or packet content.

The Go Exit Node diagnostics names are
`laneway_exit_forwarded_packets_total`, `laneway_exit_forwarding_ready`,
`laneway_exit_nat_ready`, and
`laneway_exit_namespace_cleanup_failures_total`. Forwarded packets count
encrypted-carrier/TUN transfers, not confirmed Internet replies.
The native Rust node exposes the same classes with the
`laneway_rust_node_exit_` prefix and additionally counts forwarded bytes.

Recommended alerts are: certificate or identity lease approaching its renewal
safety window; sustained `laneway_relay_limiter_saturated` or increasing
throttled bytes; a sustained rise in direct failures/switches with loss of
active direct paths; any cleanup-failure increment; and a configured Exit Node
whose forwarding or NAT readiness is zero. Tune time and rate windows to the
deployment's normal reconnect behavior to avoid alerting on brief, successful
fallback.

The native Rust node enables its metrics endpoint in strict TOML instead of a
command-line flag:

```toml
[diagnostics]
listen = "127.0.0.1:6062"
```

```sh
curl --fail --silent http://127.0.0.1:6062/metrics
```

It serves only `GET /metrics`, with bounded concurrent connections, request
bytes, and read/write deadlines. It has no application authentication, must
remain loopback-only, and has no remote pprof endpoint. Its label-free metrics
cover traffic, classified drops, reconnects, QUIC/TCP/direct attempts and
state, direct switches, selected-exit health, current bounded queue depths,
and allocation/concurrency saturation.

The native Rust relay uses a separate strict relay setting:

```toml
[relay]
metrics_listen = "127.0.0.1:6063"
```

### Relay packet-data ceiling

Both relay implementations accept the same optional aggregate limiter. It is
one process-wide token bucket shared by QUIC and TCP fallback sessions; it
applies only to authenticated packet frames, so health, controller snapshots,
authentication, and direct-path rendezvous remain responsive when saturated.
Exhaustion drops the newest packet without sleeping or creating another queue.

```toml
[relay]
packet_rate_bits_per_second = 2000000
packet_burst_bytes = 65536
```

Set both values or neither. The rate is payload framing bits per second, not
wire usage. The burst must hold a complete 1285-byte framed packet and is
bounded at 64 MiB. Metrics export forwarded, throttled, and total dropped
packet/byte counters plus `laneway_relay_limiter_saturated`.

For defense in depth, Linux operators may also apply a host `tc` ceiling to
cover UDP/TCP/IP and encryption overhead. For a dedicated relay interface,
for example, `tc qdisc replace dev eth0 root tbf rate 2200kbit burst 64kb
latency 100ms` provides headroom over a 2 Mbit application limit. This command
limits all egress on that interface; use a dedicated interface or an
operator-reviewed classifier when the host carries unrelated traffic. Persist
the rule in host network configuration and verify it after reboot.

```sh
curl --fail --silent http://127.0.0.1:6063/metrics
```

It likewise serves only `GET /metrics`, with no remote profiler or application
authentication. Wildcard and non-loopback addresses fail configuration
validation. The label-free output covers relay sessions and bindings,
forwarded packets/bytes, classified drops, QUIC/TCP connection attempts and
failures, current/peak outbound queue depth, and TLS/TCP packet-pool misses.
It also exports successful process allocation calls and requested bytes; these
are monotonic instrumentation counters used by the native relay benchmark, not
a replacement for an allocator heap profiler.
The existing `relay.metrics_interval` continues to control structured snapshot
logs independently; setting the HTTP listener does not disable those logs.

Profile the Rust node locally with the host's normal process tooling. A
debug-symbol-bearing release binary is recommended; capture for a short,
explicit interval and treat the output as sensitive:

```sh
sudo perf record --call-graph dwarf --pid "$(pidof lanewayd-rs)" -- sleep 30
sudo perf report
cargo install flamegraph
sudo cargo flamegraph --manifest-path rust/Cargo.toml --bin lanewayd-rs -- \
  --config deploy/examples/node-rust.toml
```

Do not expose a profiler over TCP. Remove `perf.data`, flamegraphs, and other
profiles after analysis according to the site's retention policy.

With systemd, enable diagnostics using an override so package updates do not
replace local policy:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/sbin/laneway-relay -config /etc/laneway/relay.toml -diagnostics 127.0.0.1:6060
```

Always inspect service logs and bounded recent history instead of streaming
secrets indefinitely:

```sh
systemctl status laneway-relay laneway-controller lanewayd
journalctl -u laneway-relay --since '30 minutes ago' --no-pager
```

## Troubleshooting

### A node cannot connect

- Verify clock synchronization, certificate validity, CA chain, certificate
  role, network ID, and configured TLS server name.
- Resolve the relay/controller hostname from the node and confirm the resolved
  transport address is not routed through `lane0`.
- Remember that static bootstrap, TCP fallback, and controller addresses remain
  pinned until restart. Controller-discovered relay DNS is refreshed only by a
  complete newer configuration epoch, not by reconnect backoff or a same-epoch
  lease renewal.
- Test UDP/QUIC separately from TCP. If TCP fallback works, inspect outbound
  UDP filtering, NAT idle timeouts, and MTU/fragmentation. Do not lower the
  TUN MTU below the validated minimum as a first response.
- On the relay, compare authenticated sessions with bindings. A session with
  no binding points to registration or authorization, not raw connectivity.

### Overlay packets connect but do not pass

- Compare `laneway routes` with the approved controller snapshot and confirm
  the destination prefix has exactly one expected next hop.
- Check packet/drop counters on both endpoint and relay. Source/destination
  validation intentionally drops spoofed packets and unapproved prefixes.
- Confirm host firewalls permit traffic on `lane0`; Laneway policy acceptance
  does not override a later operator firewall drop.

### Subnet routing fails

- Confirm `routing.output_interface` names the physical/LAN interface and the
  advertised prefix is approved.
- Inspect `nft list table inet laneway`, `sysctl net.ipv4.ip_forward`, and
  `sysctl net.ipv6.conf.all.forwarding`.
- In routed mode, the private LAN needs a return route to the overlay pool. NAT
  mode avoids that requirement but changes the observed source address.
- Never solve a conflict by flushing nftables. Preserve unrelated host rules.

### Exit selection fails or leaks are suspected

- Exit use is explicit: confirm `laneway status` shows the intended authorized
  exit node and expected failure mode.
- `laneway exit use` and `laneway exit disable` durably record the local choice
  in `/var/lib/laneway/exit-intent-v1.json` (or the configured `state_dir`) with
  mode `0600`. A persisted CLI choice takes precedence over `[exit].enabled`,
  `selected_node_id`, and `failure_mode` in TOML; static configuration is only
  the bootstrap default before the first CLI choice. Disable writes a neutral
  record rather than deleting it, so a statically enabled exit cannot return on
  restart. DNS servers and LAN bypasses remain static administrator settings.
- Treat an intent-file permission, schema, version, or read error as a security
  incident. `lanewayd` aborts startup with the path and validation error rather
  than guessing a selection or failure mode. Correct the file deliberately;
  do not delete it merely to make the daemon start, because deletion restores
  static bootstrap precedence.
- Confirm policy rule priority `11000` selects Laneway's dedicated table
  `51820` for each enabled address family. That table contains the split
  defaults (`0.0.0.0/1` and `128.0.0.0/1`, or `::/1` and `8000::/1`) through
  `lane0`, while relay/controller/direct endpoints and configured LAN prefixes
  retain native bypass routes. Laneway does not replace the host's main-table
  default route.
- Check per-link resolver state with `resolvectl dns lane0`,
  `resolvectl domain lane0`, and `resolvectl default-route lane0`.
- For the native Rust node, `forwarding.exit_client.dns_servers` owns those
  three per-link fields transactionally. The mode-`0600` journal at
  `forwarding.dns_state_file` preserves the exact predecessor across a crash.
  Do not edit or delete a journal to bypass an ownership error: inspect current
  resolver state and reconcile external changes deliberately.
- Disable exit routing through `laneway exit disable`; verify native routes and
  DNS are restored before stopping investigation.

### Controller-backed configuration stops updating

- Check controller QUIC/UDP reachability and mTLS identity independently from
  the HTTPS enrollment/management endpoint and relay data port.
- Inspect the controller audit log and current configuration epoch. Repeated
  unchanged leases are normal; rollback or a decreasing epoch is not.
- A relay retains its last immutable snapshot during a transient poll failure.
  Correct controller access rather than switching it to mixed static peers;
  those authorization modes are intentionally exclusive.

## Shutdown, crash recovery, and upgrades

Use `systemctl stop` and allow the configured stop timeout. Graceful node
shutdown removes owned routes, restores DNS/sysctl state, deletes only its
nftables table, closes TUN, and removes the Unix socket. Capture these before
and after an upgrade:

```sh
ip -4 route show
ip -6 route show
nft list table inet laneway
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
resolvectl status lane0
```

After `SIGKILL`, power loss, or kernel failure, user-space defers cannot run.
A non-persistent TUN disappears when its last file descriptor closes, but
routes or nftables/sysctl state may remain. On restart, the subnet-router and
exit-gateway managers automatically reclaim only a table whose deterministic
configuration marker, session record, chains, hooks, policies, comments, and
every rule exactly match the current desired Laneway ruleset. They carry the
recorded pre-crash forwarding value into the new session, so a later graceful
stop still restores the original sysctl baseline. An unknown marker, changed
configuration, missing rule, or additional rule is treated as foreign state
and fails closed without deleting or changing it.

The exit client reloads its versioned, mode-`0600` intent before any host-state
reconciliation. It adopts priority `11000` only when it still selects table
`51820` and the table contains no unexpected entries. Every surviving route
must be part of the desired plan and tagged with Laneway protocol `251`. A
crashed non-persistent TUN causes Linux to delete its `/1` routes, so restart
may reconstruct those broad routes only when at least one desired native bypass
route survives as the protocol-marked ownership proof. An occupied rule with an
empty table, an altered route, or any extra entry remains untouched and causes
an ownership error. Adopted rule/routes are removed on graceful stop.

If exact recovery is refused, stop all Laneway processes, inspect the objects,
and follow `deploy/nftables/README.md`; delete only residue whose provenance is
confirmed. Restore DNS with `resolvectl revert lane0` if the interface still
exists, and compare routes and forwarding with the site's documented baseline.

For Compose upgrades and disaster recovery, configure an off-host age X25519
recipient and use `sudo laneway control backup`. It takes a validated SQLite online
snapshot and encrypts it together with the exact pinned release environment,
configuration, online intermediate, service identities, and admin token. The
root-owned final bundle is isolated from the controller-writable staging
directory and must be copied to separately controlled storage. `laneway control restore
BUNDLE.age --identity FILE` is fresh-state only: it rejects unexpected archive
types/paths, checksum failures, existing files, a running controller, and an
existing database. The private age identity and offline root key remain
off-host except for the short, operator-controlled restore window. The exact
procedure is documented in `deploy/compose/README.md`. Deploy relay/controller
first, then roll nodes. Never roll back the database independently of migrations
without a tested matching bundle.

For a new Compose control plane, the default installer generates the root in
`/dev/shm`, encrypts it immediately to a newly generated age recovery identity,
deploys only the online intermediate, creates an initial encrypted recovery
bundle, and leaves one protected recovery-kit directory for immediate off-host
copy. After verifying that copy, remove the server copy because it contains the
private age identity. The running deployment retains neither that identity nor
the root private key.

For the higher-assurance boundary, run `install.sh --prepare-control-plane` on
a separate trusted Linux host and transfer only its `control-plane-input`
directory. The normal installer recognizes its issuer files and recovery
recipient. The root key and recovery identity never reach production. Manual
issuer exports remain supported. `sudo laneway control init --issuer DIR` rejects a root
key, verifies the authority, and generates service identities, the admin secret,
and strict configuration without overwriting existing or partial state. Its
preflight checks Docker version/Compose, public DNS, and foreign TCP/UDP
listeners read-only. If an existing Laneway Compose stack owns containers, port
collision checks are skipped so repeated init remains idempotent. The optional
Exit profile additionally requires `/dev/net/tun`.

Tagged releases publish Linux and macOS AMD64/ARM64 archives, standalone macOS
client binaries, and controller, relay, administrative, and isolated Exit Node
images. Every release includes signed
checksums, GitHub build provenance, immutable image digest records, and SPDX
JSON SBOMs. Images are keylessly signed by the tagged release workflow and
carry registry SBOM/provenance attestations. Production Compose requires both
the semantic version and each verified manifest digest; it never consumes a
mutable `latest` tag. Follow the exact verification commands in
`deploy/compose/README.md` before an initial deployment, upgrade, or rollback.

Laneway currently has one release channel: immutable semantic-version tags.
There is no `latest`, edge, or floating production channel. Patch releases keep
the same control/packet protocol contract; minor releases within one major must
retain documented rolling compatibility long enough to upgrade controller and
relay first, then nodes. A release that cannot do so must increment the major
version and document an explicit migration. GitHub release assets and GHCR
manifests for earlier versions are retained so operators can roll application
images back to the immediately previous compatible version. Database state is
never rolled back independently: restore a tested matching backup when a
schema migration is not backward compatible.

## Containers and rootless operation

The supplied scratch image is intended for the relay or controller. It runs as
UID/GID `65532`, contains no shell or package manager, and should be launched
with a read-only root filesystem, read-only credential mounts, a writable
state volume only where required, and all Linux capabilities dropped. Bind
unprivileged container ports and publish them to the desired host ports when
using a rootless runtime. Ensure every mounted configuration and credential is
readable by container UID/GID `65532` (or by the runtime's mapped equivalent);
the host-systemd `root:laneway 0640` ownership convention does not
automatically grant access to this separate container identity.

The general scratch image is not a node image. Use the dedicated isolated Exit
Node image and Compose profile when containerizing that role; it reduces the
long-running `laneway node run` process to UID 65532 plus `NET_ADMIN`, exposes
only `/dev/net/tun`, and keeps routes and nftables state in the container
network namespace. Rootless containers cannot provide that kernel contract.
Ordinary host nodes use the hardened systemd unit.

The same release also provides a public userspace Connector entrypoint. With no
explicit config argument it consumes a single `SETUP_TOKEN` on first start,
stores its durable identity in the mounted volume, drops every capability, and
needs neither `/dev/net/tun` nor an inbound port. It supports approved TCP/UDP
resource access, not ICMP or raw-IP/full-tunnel Exit behavior.

## Unified node command and compatibility

The supported Go node entrypoint is:

```sh
laneway node run -config /etc/laneway/laneway.toml
```

Release packages install `/usr/local/sbin/lanewayd` as a compatibility symlink
to the same versioned `/usr/local/bin/laneway` artifact. Invoking that symlink
with legacy `-config`, `-diagnostics`, or `-version` arguments remains
supported. New service definitions and automation should use `laneway node
run`; no separate daemon binary needs to be upgraded or version-matched.
