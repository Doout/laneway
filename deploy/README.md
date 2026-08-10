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

For the supplied systemd units, install credentials as `root:laneway` mode
`0640`. Container mounts must be readable by UID/GID `65532` without making
credentials world-readable. See the [operations runbook](../docs/operations.md)
for ports, diagnostics, and recovery.
