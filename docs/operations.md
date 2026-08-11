# Operations

Use the [root README](../README.md) for first-time setup and the
[Compose guide](../deploy/compose/README.md) for deployment and recovery.

## Boundaries

| Component | Listener | Host access |
| --- | --- | --- |
| Relay | UDP `4433`; TCP `443` fallback | Public; no network-admin capability |
| Controller | TCP+UDP `8443` | No network-admin capability |
| Docker Connector | None | Outbound only; no capabilities or TUN |
| Host Node | `/run/laneway/lanewayd.sock` | `/dev/net/tun` and `NET_ADMIN` |
| Diagnostics | Disabled | Loopback only |

Keep service keys private and keep the offline root CA key and recovery identity
off the control-plane host. Laneway does not manage the host firewall.

## Routine control-plane work

```sh
sudo laneway control status
sudo laneway control update
sudo laneway control backup
```

`status` exits nonzero when a required service is unhealthy. `update` verifies
the release, creates a backup, and retains the prior release for rollback.

Connector identities persist in named Docker volumes. Do not remove the volume
during an upgrade. Update a Connector with:

```sh
sudo laneway-update-connector laneway-connector-office
```

## Client lifecycle

With one saved login, `laneway connect` remembers its domain. With several,
specify it:

```sh
laneway connect lane.example.com
```

Use an ephemeral session when no identity should be saved:

```sh
laneway connect lane.example.com --ephemeral
```

Remove a saved login with `laneway logout lane.example.com`. This does not
revoke the device; revoke its NodeID at the controller when it is retired, lost,
or compromised.

Full-tunnel routing is never automatic. It requires an authorized Exit Node and
an explicit `--exit NAME`. The macOS client supports private split routes only.

## Managed Linux Nodes

Create a durable invitation on the control-plane host:

```sh
sudo laneway control invite --name server-one
```

Install Laneway on the Node, save the invitation code in a mode-`0600` file,
then enroll it:

```sh
sudo laneway node install lane.example.com --token-file ./laneway.code
sudo laneway node status
```

The command writes managed configuration and credentials, enables direct paths,
and starts the systemd unit. Use `--no-direct` for relay-only operation or
`--no-start` when another tool owns activation.

```sh
sudo laneway node peers
sudo laneway node routes
sudo laneway node renew
sudo laneway node uninstall
```

`node uninstall --keep-state` preserves `/var/lib/laneway`. Managed commands
refuse to remove files they do not own.

After a package update:

```sh
sudo systemctl restart lanewayd
sudo laneway node status
```

## Monitoring

```sh
sudo laneway control status
sudo laneway node status -json
sudo laneway node peers
systemctl status laneway-relay laneway-controller lanewayd
journalctl -u laneway-relay --since '30 minutes ago' --no-pager
```

Node status reports addresses, routes, carrier, certificate and configuration
lease health, and Exit selection. Peer status reports `direct`, `relay-quic`,
`tcp-fallback`, or `disconnected`.

Alert on credentials approaching expiry, sustained relay throttling, loss of
all paths, cleanup failures, or an Exit Node whose forwarding/NAT readiness is
zero. Diagnostic listeners must remain on loopback; see the
[observability profile](../spec/observability-v1.md).

## Troubleshooting

### Cannot connect

1. Check system time and certificate validity.
2. Resolve the controller and relay names from the affected host.
3. Test controller TCP+UDP and relay UDP separately from relay TCP fallback.
4. If TCP works but QUIC does not, inspect UDP filtering, NAT timeouts, and MTU.
5. Restart after an intentional DNS endpoint change; addresses are pinned for
   the process lifetime.

### Connected but traffic fails

1. Compare `laneway node routes` with the approved control-plane route.
2. Confirm source and destination authorization.
3. Check Node and relay drop counters.
4. Check the host firewall on `lane0`.

Docker Connectors carry TCP and UDP, not ICMP. Test them with an application
connection rather than `ping`.

### Subnet routing fails

Confirm the advertised prefix and output interface, then inspect:

```sh
sudo nft list table inet laneway
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
```

Routed mode needs a LAN return route to the overlay pool. NAT mode changes the
observed source but does not need that route. Never flush nftables; follow the
[nftables guide](../deploy/nftables/README.md) when recovery fails.

### Exit routing is wrong

Check the selected Exit and failure mode, native bypass routes, policy rule
`11000`, table `51820`, and `resolvectl` state for `lane0`. Disable the Exit and
confirm routes and DNS are restored:

```sh
sudo laneway node exit disable
```

Do not delete exit-intent or DNS ownership journals to force startup.

### Controller updates stop

Check controller QUIC/UDP reachability, mTLS identity, audit events, and the
configuration epoch. Services retain the last complete snapshot only until its
lease expires, then fail closed.

## Shutdown and crash recovery

Stop Nodes normally so they can restore routes, DNS, nftables, sysctls, and TUN
state:

```sh
sudo systemctl stop lanewayd
```

After a crash, Laneway reclaims only exact state carrying its ownership markers.
If startup refuses recovery, stop every Laneway process, inspect the conflicting
objects, remove only confirmed Laneway residue, and restore the site's recorded
baseline.

Controller, relay, and `lane-edge` Connector containers run non-root with
read-only scratch roots. The full Exit Node alone needs `NET_ADMIN` and
`/dev/net/tun`, inside its own container namespace. Do not give it host
networking, the Docker socket, or privileged mode.
