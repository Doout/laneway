# Laneway Docker network plugin v1

## Contract

The plugin is a Linux Docker Engine managed network plugin with local scope. It implements the libnetwork remote-driver activation, capability, network, endpoint, join, leave, and operational-info calls. Swarm/global allocation, rootless Docker, Docker Desktop, Windows, and IPv6 are rejected explicitly.

Network membership is the policy boundary. The plugin creates one deterministically named bridge and routing table per Docker network and one veth pair per joined endpoint. Containers receive no network capability and do not see the Laneway tunnel device. Docker invokes the plugin over its managed-plugin socket; the Docker socket is not mounted.

## Policy

The generic Docker network options are:

| Option | Values | Default |
| --- | --- | --- |
| `laneway.policy` | `direct`, `selective`, `full-tunnel`, `isolated` | `direct` |
| `laneway.egress-cidrs` | comma-separated canonical IPv4 CIDRs | empty |
| `laneway.ingress` | `deny`, `established`, `allow` | `deny` |
| `laneway.ingress-sources` | comma-separated canonical IPv4 CIDRs | empty |
| `laneway.exit` | controller-authorized exit identifier | empty |
| `laneway.dns` | comma-separated IPv4 resolvers | Docker-provided |
| `laneway.fail-mode` | `closed` | `closed` |
| `laneway.mtu` | 576–9000 | 1380 |
| `laneway.nat` | boolean explicit direct-path masquerade | `false` |

`selective` requires at least one egress prefix. `full-tunnel` requires an exit. `allow` ingress requires at least one source prefix. Prefixes within the same list may not overlap. Any IPv6 request fails closed. Separate managed container subnets may not overlap.

Except for a direct/deny network, requested container subnets, egress prefixes, ingress sources, and exits must be contained by a current controller authorization lease. The plugin reads a complete authenticated snapshot from `controller-authorization-v1.json`; a missing, malformed, partial, or expired snapshot denies creation and startup reconciliation. Docker options are never treated as authority.

## Linux ownership and packet behavior

Names are derived from the full Docker object identifier using SHA-256. Before reusing an existing object, the plugin checks its type, MTU, and nftables ownership marker. Cleanup deletes only recorded objects with the expected marker. State is written with mode `0600` by atomic rename before and after Linux mutations.

Each network has a dedicated `inet laneway_*` nftables table. New ingress is rejected unless the policy is `allow` and the source is authorized; established and related packets are accepted first. Selective destinations and all full-tunnel destinations are rejected when their output interface is not the Laneway tunnel. Isolated networks reject every other destination. An explicit NAT option applies only to traffic leaving outside the tunnel.

Tunnel ingress receives a per-network conntrack mark. Reply packets restore that mark to the packet mark, and a dedicated policy rule selects the network's tunnel table. Consequently direct ingress replies through the main table while tunneled ingress replies through Laneway. Routes use protocol 99 in a dedicated table. Full-tunnel controller, relay, peer-transport, and management bypass prefixes come only from the controller snapshot and are persisted as part of the owned policy.

If the tunnel disappears, retained policy rules and nftables output-interface checks make assigned traffic fail closed. Direct networks and unrelated host traffic do not match those rules. A plugin restart reconciles recorded network state; incomplete create transactions are cleaned rather than promoted.

## Privileges and operations

Installation grants host network administration authority and is supported only on trusted Linux Docker Engine hosts. The managed plugin requests `CAP_NET_ADMIN`, `CAP_NET_RAW`, host networking, `/dev/net/tun`, and a Docker-managed propagated state mount at `/data`. Docker preserves that mount across plugin upgrades. It does not request all devices, an arbitrary host bind mount, or the Docker socket.

`POST /status` on the plugin socket reports version, readiness, managed network and endpoint counts, and effective policy counts. Docker endpoint operational info includes the assigned address, join state, and egress policy. Authorization, route, tunnel, and ownership errors have distinct error prefixes in Docker's response.

Removal requires deleting attached containers and networks, disabling the plugin, and removing it. The network delete path removes endpoint veths, exact rules, protocol-99 routes, the owned nftables table, and the bridge. Forced plugin removal can prevent this cleanup; reinstalling the same plugin with its preserved state causes reconciliation to fail closed and permits exact cleanup.
