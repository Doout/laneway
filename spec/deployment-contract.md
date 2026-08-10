# Laneway Actor and Deployment Contract

Status: Design-stable normative deployment contract.

Normative terms have the meaning defined in BCP 14.

## 1. Actors

- A **User** is a foreground client whose identity and host-network changes have
  bounded lifetimes.
- A **Node** is a persistent host agent. It MAY advertise
  controller-approved private subnets.
- An **Exit Node** forwards explicitly selected default-route traffic. The
  default deployment is an isolated container.
- The **controller** owns identities, leases, addresses, routes, ACLs, and relay
  authorization. It never carries user packets.
- A **relay** provides rendezvous and an unprivileged fallback packet path. It
  does not grant authorization.

Roles are controller-granted capabilities. An endpoint MUST NOT acquire a role
by selecting a local option. The wire model is defined in
[architecture.md](architecture.md).

## 2. Supported paths

| Source | Destination | Preferred | Fallback | Destination authorization |
| --- | --- | --- | --- | --- |
| Node | Node | direct authenticated QUIC | relay QUIC, then relay TLS/TCP | ordinary endpoint |
| User | Node | direct authenticated QUIC | relay QUIC, then relay TLS/TCP | ordinary endpoint |
| User | Exit Node | direct authenticated QUIC | relay QUIC, then relay TLS/TCP | approved exit |
| Node | Exit Node | direct authenticated QUIC | relay QUIC, then relay TLS/TCP | approved exit |

Generated managed configurations MUST enable direct authenticated QUIC unless
controller policy or an explicit operator choice disables it. A healthy relay
path remains available until the direct path is authenticated and usable.
Direct-path failure MUST NOT broaden routing or policy.

All packet paths follow the same shape:

```text
application -> actor-owned route -> lane0 -> source endpoint
  |-> direct authenticated carrier ---------------------------.
  `-> relay QUIC/TCP -> unprivileged relay (fallback) ---------'
                                  -> destination endpoint -> lane0
                                  -> application, subnet, or exit forwarding
```

`lane0` belongs to the actor's network namespace: temporary host state for a
User, persistent host state for a Node, and container state for an Exit Node.
Controller traffic, relay carriers, direct peer endpoints, required gateways,
and selected local-LAN prefixes MUST bypass an active exit route to prevent
recursion.

## 3. State ownership

| State | Owner and namespace | Lifetime and cleanup |
| --- | --- | --- |
| User TUN, addresses, routes, rules, and DNS | User helper in the host network namespace | session journal; exact restoration on exit; validated crash reconciliation |
| Node TUN, addresses, routes, and rules | Node service in the host network namespace | persistent intent; rollback after failed start or removal |
| Exit TUN, routes, nftables, and forwarding sysctls | Exit container network namespace | recreated from configuration; namespace deletion is the crash boundary |
| Docker bridge and host NAT | Docker Engine | Docker-owned; Laneway MUST NOT edit or remove it |
| Controller database and online issuer | controller volumes and read-only secret mounts | consistent backup and restore; offline root MUST NOT be present |
| Endpoint and service private keys | authenticating process | durable for services/Nodes and lease-bounded for Users; never sent to a relay |
| Relay sessions, handles, and rendezvous tokens | relay memory | bounded; invalid after disconnect or expiry |
| Exit selection | invoking User or persistent Node state | MUST NOT be persisted for a temporary User |

An actor MUST change only state it owns. Cleanup MUST verify an object's exact
shape and ownership marker. A conflicting foreign object causes a fail-closed
error; Laneway MUST NOT delete or overwrite it.

## 4. Privilege boundary

| Process | Required boundary | Forbidden by default |
| --- | --- | --- |
| Controller container | dedicated non-root UID; no capabilities; read-only root; database as its only writable durable volume | offline root key, endpoint keys, broad writable mounts |
| Relay container | dedicated non-root UID; no capabilities; read-only root; bounded runtime tmpfs | durable packet state or control-plane authority |
| User process | invoking user; no elevated privilege | direct network administration |
| User helper | root setup narrowed to `CAP_NET_ADMIN`; `no_new_privs`; requester-bound private channel; allowlisted network operations | listening control socket, commands, enrollment tokens, endpoint keys |
| Node service | locked service identity; `CAP_NET_ADMIN`; `/dev/net/tun` | unrelated host capabilities or state |
| Exit Node container | dedicated non-root UID where supported; `NET_ADMIN`; `/dev/net/tun` | `privileged`, host networking, Docker socket, host network-state mounts |

Controller and relay containers MUST drop all capabilities and set
`no-new-privileges`. Secret mounts MUST be read-only and MUST NOT be baked into
images or generated configuration.

The User helper accepts versioned structured requests, rejects unknown or
unsafe operations, and binds one ownership transaction to one requester. It
MUST NOT execute caller-supplied commands or receive credentials. A non-root
launcher MUST elevate only a resolved, root-owned executable whose path cannot
be modified by an unprivileged user. Requester death triggers bounded cleanup
or leaves an exact, recoverable journal.

## 5. Exit Node network boundary

The default Exit Node uses a dedicated Docker bridge and a fixed published UDP
port for direct paths. Relay access remains an ordinary outbound connection.
IPv4 traffic normally crosses Laneway-owned source NAT in the container and
Docker-owned masquerade on the host. Source-preserving routing requires a
separately reviewed topology.

The configured MTU MUST cover Laneway and carrier overhead across the bridge.
Deployment MUST fail clearly when required IPv6 forwarding or NAT is
unavailable; IPv6 MUST NOT leak through an IPv4-only exit policy.

## 6. Shutdown and recovery

On SIGINT or SIGTERM, packet-path actors MUST stop new work, stop the TUN pump,
drain only bounded in-flight work, remove owned network state, flush durable
state where applicable, and exit within a documented timeout.

| Actor | Recovery rule |
| --- | --- |
| User | restore previous routes, rules, and DNS; validate and reconcile its journal after a crash |
| Node | roll back only Node-owned state after failed start or removal; validate state before reboot recovery |
| Exit Node | remove in-namespace objects on graceful stop; reapply declared intent after recreation |
| Relay | invalidate handles and rendezvous tokens on disconnect |
| Controller | complete or roll back transactions; back up from a consistent snapshot |

No recovery path may infer ownership from a name alone.

## 7. Deployment invariants

- Direct and relay carriers enforce the same identity, lease, route, ACL, and
  source-validation decisions defined by the protocol specifications.
- Relay packet traffic MUST have a bounded aggregate rate independent of
  control and rendezvous progress.
- Diagnostics follow [observability-v1.md](observability-v1.md) and remain local
  by default.
- Runtime images and binaries MUST be pinned to a version or immutable digest;
  a mutable `latest` tag is not a deployment input.
