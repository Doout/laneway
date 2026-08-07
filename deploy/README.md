# Deployment assets

`systemd/` contains hardened service units for nodes, relays, and the
controller. `containers/Dockerfile` builds a selected command with
`--build-arg BINARY=<command>`. Static and controller-backed examples live in
`examples/`. `compose/` contains the hardened container-first
controller/relay/admin stack; see [compose/README.md](compose/README.md). The
controller's `admin_token_file` must contain an independently
generated bearer secret of at least 32 characters and should be readable only
by the service account.

The node service requires `/dev/net/tun` and `CAP_NET_ADMIN`. Relay and
controller services deliberately run without network-administration
capabilities. Production certificate and key files are never included here.
Node units leave the non-process `/proc` APIs visible (`ProcSubset=all`) because
subnet and exit roles must transactionally read, update, and restore their
owned forwarding sysctls; `ProtectProc=invisible` still restricts visibility
of other users' process details.
Both node implementations default their protected management socket to
`/run/laneway/lanewayd.sock`. The Rust node stores its crash-safe explicit exit
choice at `/var/lib/laneway/exit-intent-v1.json`; the systemd runtime/state
directories make both paths writable under `ProtectSystem=strict`, and both
objects are created mode `0600`.
The relay and controller units use a locked, fixed `laneway` account so
root-owned `0640 root:laneway` credentials remain readable without becoming
world-readable; create that account before enabling either unit. The relay's
only ambient capability is `CAP_NET_BIND_SERVICE`, required when the optional
TCP fallback listener uses port 443.
The supplied scratch container is for the unprivileged relay/controller path,
not `lanewayd`. It runs as UID/GID `65532`, so read-only configuration and
credential mounts must be readable by that container identity or its rootless
runtime mapping. See [`../docs/operations.md`](../docs/operations.md) for the
rootless and node-container boundaries.

For the Rust relay, use `examples/relay-rust.toml` (static authorization) or
the shared `examples/relay-controller.toml` (leased controller authorization)
and build `containers/Dockerfile.rust-relay`. The controller-backed example is
also accepted by the Go relay. The Rust relay serves QUIC and an optional bounded
`laneway-fallback/1` TLS/TCP listener using the same credentials and policy.
Controller mode requires the exact controller SPIFFE `service_id` in addition
to normal CA and hostname validation.
The matching hardened host unit is
`systemd/laneway-relay-rs.service`.

The relay example listens on UDP/4433 for the preferred QUIC carrier and
TCP/443 for fallback; both ports must reach the same relay process. Nodes need
only outbound access. TCP fallback uses the same certificate identities,
authorization, route handles, and packet policy after QUIC fails. While TCP is
healthy, the Rust node keeps one packet pump active and performs bounded QUIC
recovery handshakes at `relay.quic_recovery_interval`; promotion occurs only
after exact relay identity validation and registration.

Managed Go node configurations enable authenticated direct paths unless
`direct.enabled = false` is set explicitly; the Rust node always enables its
direct manager. Host Node/User examples bind an ephemeral UDP port, while the
isolated Docker Exit Node publishes a fixed port. `laneway peers` reports each
peer as `direct`, `relay-quic`, `tcp-fallback`, or `disconnected`.
Both relay implementations
derive each candidate from the source address of the node's QUIC session,
coordinate a short-lived UDP probe exchange, and remain available as fallback.
Nodes reuse one UDP socket for the relay, probes, and peer QUIC, so host firewalls must
allow replies and peer traffic on that socket. Do not set `allow_loopback` or
`allow_link_local` outside a deliberately isolated test deployment. Candidate
addresses are relay-observed and each rendezvous uses a fresh bounded token and
coordinated start time; failure leaves the authenticated relay carrier active.
Rust nodes refresh candidates on `direct.candidate_refresh_interval`; configure
that above the Rust relay's `relay.candidate_republish_floor` so long-lived
sessions retry failed direct paths without triggering the publication limit.

`relay-controller.toml` uses the relay's mTLS service credential to fetch an
initial complete peer-authorization and ACL snapshot before opening listeners.
The controller port must be exposed on both TCP (HTTPS enrollment/management)
and UDP (`laneway-control/1` mTLS QUIC). Authenticated node and relay control
requires `controller.quic_endpoint`; it does not silently fall back to HTTPS.
Before starting it, register the exact service ID encoded in that credential
with `laneway controller relay register`; an unknown, disabled, or legacy
unbound relay identity is rejected. The relay then polls by configuration
epoch. Do not add `[[peers]]` entries to that file: static peers and
controller-managed authorization are intentionally mutually exclusive.
Replace `controller.network_id` and `controller.service_id` with the exact
identity encoded in the controller certificate.

`node-controller.toml` is the matching controller-authoritative node example,
started with `laneway node run -config /etc/laneway/laneway.toml`.
It deliberately contains neither `node.overlay_addresses` nor `[[peers]]`:
The node runtime fetches a complete leased snapshot before opening `lane0`, validates
the assigned address against its certificate identity and self-owned host
route, and fails startup closed when that bootstrap is unavailable.
Replace its controller identity pins and `node.relay_network_id` and
`node.relay_service_id` with the exact identities encoded in the controller
and relay certificates. CA, role, and optional DNS-name verification remain
enabled in addition to these immutable pins.

`nftables/` contains an operator-reviewed host firewall example and guidance
for the runtime-owned subnet table. The full deployment, diagnostics,
troubleshooting, crash-recovery, and upgrade procedure is in the operations
runbook. Go node, relay, and controller diagnostics are opt-in via
`-diagnostics 127.0.0.1:PORT`. The native Rust node instead uses
`[diagnostics] listen = "127.0.0.1:PORT"` in its strict TOML and serves only
Prometheus `GET /metrics`; the native Rust relay uses
`[relay] metrics_listen = "127.0.0.1:PORT"` for the same restricted HTTP
surface. Every implementation rejects non-loopback binds.
