# Deployment files

Release packages install these files under `/usr/local/share/laneway/deploy`:

| Directory | Contents |
| --- | --- |
| `compose/` | Control plane, Connector, and isolated Exit Node |
| `systemd/` | Controller, relay, and Node units |
| `examples/` | Go and Rust configuration examples |
| `nftables/` | Host firewall example and recovery notes |
| `containers/` | Container definitions and Connector updater |

Use the [Compose guide](compose/README.md) for a new control plane. Install a
managed Linux Node with `sudo laneway node install DOMAIN` instead of assembling
its controller configuration by hand.

Controllers and relays need no network-administration capability. Connectors
need no capability, TUN device, or published port; their ephemeral UDP socket
and outbound relay mapping support synchronized NAT traversal. Host Nodes and
full Exit Nodes require `/dev/net/tun` and `NET_ADMIN` in the namespace they
manage. Host firewalls must allow reply and peer traffic on ephemeral
direct-path sockets.

For a deliberately temporary Exit on a shared systemd Linux host, issue
`laneway control invite --name NAME --shared-host-exit` on the control plane.
The generated signed-release bootstrap runs from `/run` in a private network
namespace and leaves the durable Docker Exit deployment unchanged. See the
[ephemeral shared-host Exit guide](../docs/ephemeral-shared-host-exit.md) for
lease, cleanup, and host-administrator trust boundaries.

For the supplied systemd units, install credentials as `root:laneway` mode
`0640`. Container mounts must be readable by UID/GID `65532` without making
credentials world-readable. See the [operations runbook](../docs/operations.md)
for ports, diagnostics, and recovery.
