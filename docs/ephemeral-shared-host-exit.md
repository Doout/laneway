# Ephemeral shared-host Exit

Laneway can borrow a systemd Linux host as an Exit without installing a
persistent service or retaining an identity on disk. The Docker Exit remains
the default for durable deployments; this mode is for short, supervised use on
a shared machine.

On the controller host, issue a one-use invitation:

```sh
sudo laneway control invite --name borrowed-egress --shared-host-exit
```

The command prints an immutable release bootstrap command to stderr and the
one-use invitation to stdout. Run the command on the Linux host, then paste the
invitation at its hidden `/dev/tty` prompt. Never put the invitation in argv,
an environment variable, shell history, or a pipe shared with another user.

## Runtime and failure semantics

The bootstrap verifies the signed release manifest, creates a bounded executable
tmpfs beneath `/run` (without changing `/run`'s own mount policy), extracts only
the Laneway binary there, and enrolls with a fresh Ed25519 key and WireGuard key.
It starts a collected transient systemd unit with `DynamicUser`,
`PrivateNetwork`, a strict capability and device allowlist, no application
stdout/stderr, no core dumps, locked memory, and an absolute runtime limit.
Credentials are copied through systemd's credential directory and the source
files and executable are unlinked after startup.

The private namespace receives an anonymous veth carrier. The bootstrap creates
only a randomly named, ownership-marked host veth and nftables table; cleanup
removes exactly those objects. It refuses conflicting state and does not change
global forwarding settings. IPv4 forwarding and `/dev/net/tun` must already be
available. The host must expose at least one non-loopback IPv4 resolver (the
systemd-resolved upstream resolver file is preferred); a private read-only copy
is mounted into the runtime namespace.

The controller accepts one active control session for the identity. A
configuration request is also its 10-second heartbeat. After 20 seconds without
a heartbeat the local configuration enters drain: it refuses new outbound flows
and permits only established or related traffic. At 60 seconds the controller
atomically terminates the lease, revokes its certificate,
withdraws its route, releases its overlay address, increments the network epoch,
and records a system audit event. Reconnection before revocation requires a new
TLS proof-of-possession handshake with the same identity and generation. A late
heartbeat cannot reactivate a terminal lease.

The operator can stop the transient unit early with:

```sh
sudo systemctl stop laneway-ephemeral-exit-….service
```

## Threat boundary

This removes durable Laneway files, units, state, and application logs. It does
not make a hostile host trustworthy while the process is running: host root can
inspect memory, network traffic, kernel telemetry, and system journal metadata.
The bootstrap therefore refuses non-tmpfs runtime storage, disables dumps,
locks current/future memory, closes the enrollment secret immediately, and
bounds both controller authorization and local runtime. Use a dedicated Exit
Node when the host administrator is outside the trust boundary.
