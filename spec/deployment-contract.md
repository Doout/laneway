# Laneway Actor and Deployment Contract

Status: Design-stable normative deployment contract.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD
NOT**, and **MAY** are to be interpreted as described by BCP 14 when, and only
when, they appear in all capitals.

## 1. Scope and terminology

This document defines the supported product actors, their privilege boundaries,
and ownership of host and container state. It complements the language-neutral
wire architecture in [architecture.md](architecture.md).

- A **User** is a foreground, temporary Laneway client on a host. Its overlay
  identity and network changes have bounded lifetimes and are not a durable Node.
- A **Node** is a persistent host agent. It exposes that host and MAY advertise
  controller-approved private subnets.
- An **Exit Node** is a controller-authorized agent that can forward selected
  IPv4 or IPv6 default-route traffic. The default deployment is an isolated
  Docker container, not a privileged host agent.
- The **controller** is the durable authority for identities, leases, routes,
  ACLs, and relay authorization. It never carries user packets.
- A **relay** is an unprivileged packet-path fallback and direct-path rendezvous
  service. It is not a controller and does not grant authorization.

User, Node, and Exit Node are product actors. On the wire they are authenticated
Laneway endpoint identities with controller-granted capabilities. An identity
MUST NOT acquire a role merely by selecting a local configuration option.

## 2. Supported path matrix

| Source | Destination | Preferred path | Fallback | Required destination role |
| --- | --- | --- | --- | --- |
| Node | Node | authenticated direct QUIC | relay QUIC, then relay TLS/TCP | ordinary endpoint |
| User | Node | authenticated direct QUIC | relay QUIC, then relay TLS/TCP | ordinary endpoint |
| User | Exit Node | authenticated direct QUIC | relay QUIC, then relay TLS/TCP | approved exit |
| Node | Exit Node | authenticated direct QUIC | relay QUIC, then relay TLS/TCP | approved exit |

Direct authenticated QUIC MUST be enabled in generated managed configurations
unless controller policy or an explicit operator choice disables it. Negotiation
MUST retain a healthy relay path until the direct path is authenticated and
usable. Failure of a direct path MUST NOT silently broaden routing or policy.

## 3. Packet flows

The arrows below show packet flow, not control traffic. Every carrier is mutually
authenticated. `lane0` exists in the source and destination actor's network
namespace.

### 3.1 Node to Node

```text
application -> host route -> host lane0 -> Node agent
  -> direct QUIC ---------------------------------> Node agent -> host lane0 -> application
  `-> relay QUIC/TCP -> unprivileged relay ------'  (fallback)
```

### 3.2 User to Node

```text
application -> temporary owned host route -> temporary lane0 -> User process
  -> direct QUIC ---------------------------------> Node agent -> host lane0 -> application
  `-> relay QUIC/TCP -> unprivileged relay ------'  (fallback)
```

### 3.3 User to Exit Node

```text
application -> temporary selected exit routes -> temporary lane0 -> User process
  -> direct QUIC ----------------------------------------------.
  `-> relay QUIC/TCP -> unprivileged relay -> Exit Node agent -'
       -> container lane0 -> container forwarding/NAT
       -> Docker bridge/veth -> host forwarding/NAT -> Internet
```

### 3.4 Node to Exit Node

```text
application -> explicitly selected host exit routes -> host lane0 -> Node agent
  -> direct QUIC ----------------------------------------------.
  `-> relay QUIC/TCP -> unprivileged relay -> Exit Node agent -'
       -> container lane0 -> container forwarding/NAT
       -> Docker bridge/veth -> host forwarding/NAT -> Internet
```

Controller HTTPS/QUIC traffic, relay carriers, direct peer endpoints, required
local gateways, and operator-selected local-LAN prefixes MUST remain outside an
active exit route to prevent recursion through `lane0`.

## 4. Namespace and state ownership

| State | Owner and namespace | Persistence and cleanup |
| --- | --- | --- |
| User TUN, addresses, routes, rules, DNS | narrowly scoped helper in the User's host network namespace | session journal; exact restoration on clean exit; validated reconciliation after a crash |
| Node TUN, addresses, routes, rules | Node service in the host network namespace | persistent service intent; transactional rollback on failed start or removal |
| Exit TUN, routes, nftables, forwarding sysctls | Exit Node container network namespace | recreated from declared configuration; cleaned on graceful stop; container namespace deletion is the crash boundary |
| Host Docker bridge and host NAT | Docker Engine | Docker-owned; Laneway MUST NOT edit or remove it |
| Controller database | controller state volume | durable; included in consistent backup and restore |
| Controller online issuer key | controller read-only secret mount | durable secret; offline root key MUST NOT be present on the VPS |
| Endpoint and service private keys | the process that authenticates with them | durable for Nodes/services, lease-bounded for Users; never sent to the relay |
| Relay sessions, handles, rendezvous tokens | relay memory | bounded and ephemeral; invalid after disconnect/expiry |
| Exit intent | invoking User for a temporary User; Node state for a persistent Node | never persisted for a temporary User |

An actor MUST change only state it owns. Cleanup MUST first verify the exact
shape and ownership marker of an object. A conflicting foreign route, rule,
nftables object, DNS state, file, or container MUST cause a fail-closed error;
Laneway MUST NOT delete or overwrite it.

## 5. Process privilege and mount contract

| Process | UID | Capabilities/devices | Writable storage | Read-only inputs |
| --- | --- | --- | --- | --- |
| controller container | dedicated non-root | none; `no-new-privileges` | controller database volume only | configuration, trust bundle, TLS identity, online intermediate identity/key, admin secret |
| relay container | dedicated non-root | none; `no-new-privileges` | bounded runtime tmpfs only | configuration, trust bundle, TLS identity |
| administrative CLI | invoking operator | none by default | explicit backup/output path | configuration and trust material as required |
| foreground User process | invoking user | none | user-owned bounded session state | downloaded trust/bootstrap metadata |
| User network helper | root or `CAP_NET_ADMIN`, separately invoked | allowlisted TUN/route/rule and optional DNS operations only; `no_new_privs` after setup | root-owned bounded ownership journal | structured authenticated request; no enrollment token or private key |
| Node host service | locked service identity | `CAP_NET_ADMIN` and `/dev/net/tun` | Node state/runtime directories | configuration, trust bundle, Node TLS identity |
| Exit Node container | dedicated non-root where supported | `NET_ADMIN` and `/dev/net/tun`; never `privileged` by default | bounded state/runtime volumes | configuration, trust bundle, Exit TLS identity |

Container roots MUST be read-only. Controller and relay containers MUST drop all
capabilities and set `no-new-privileges`. Secret mounts MUST be read-only and
MUST NOT be baked into images or committed to generated configuration.

The Exit Node MAY need a small init to reap processes and forward signals. It
MUST NOT mount the Docker socket, the host network namespace, host `/proc`, host
`/sys`, or host nftables state in the default deployment. Host networking is an
advanced, explicitly selected mode with a separately documented threat model.

## 6. Exit Node bridge behavior

The default Exit Node attaches to a dedicated Docker bridge. Its direct-path UDP
listener uses a fixed container port published on the host; Users and Nodes may
use ephemeral local UDP ports. The relay remains reachable through an ordinary
outbound container connection.

IPv4 Internet traffic normally crosses two translation boundaries: Laneway-owned
source NAT inside the Exit Node namespace and Docker-owned masquerade on the
host. This double NAT is deliberate isolation, but it obscures original overlay
sources beyond the container and adds conntrack/state overhead. Operators needing
routed source preservation must use a separately reviewed advanced topology.

MTU MUST account for the application's IP packet, Laneway framing and encrypted
carrier overhead, and the Docker bridge path. Generated configuration MUST use a
conservative MTU or a measured path value and MUST fail clearly when required
IPv6 forwarding/NAT semantics are unavailable. IPv6 MUST NOT silently leak
outside an IPv4-only exit policy.

## 7. Shutdown and crash recovery

On SIGINT or SIGTERM, packet-path actors MUST stop accepting new work, stop the
TUN packet pump, drain only bounded in-flight work, remove owned network state,
flush durable state where applicable, and exit within a documented timeout.

- A User clean exit restores its exact previous routes, rules, and DNS state.
  SIGKILL leaves an ownership journal which the next invocation validates and
  reconciles before creating new state.
- A Node failed start or uninstall transaction restores only Node-owned host
  state. Reboot recovery validates prior state before replacement.
- Exit Node graceful shutdown removes its in-namespace objects. Abrupt container
  deletion destroys that namespace; durable intent is reapplied on recreation.
- Relay disconnect invalidates session handles and rendezvous tokens.
- Controller shutdown completes or rolls back a database transaction before
  stopping. Backups MUST use a database-consistent snapshot.

No recovery path may infer ownership from a name alone.

## 8. Security invariants

- The offline root private key MUST remain offline. Only a constrained online
  intermediate issuer and its chain may be mounted on the controller.
- Enrollment codes MUST be single-use, short-lived, rate-limited, network- and
  class-bound, and absent from argv, URLs, logs, and shell history.
- Direct paths and both relay transports enforce the same certificate identity,
  lease expiry, route authorization, ACL, and source-validation decisions.
- Relay packet data MUST have an aggregate bounded rate independent of control
  and rendezvous progress. Host `tc` MAY add a wire-overhead ceiling.
- Diagnostics bind locally by default and MUST NOT expose secrets or packet
  contents.
- Published images and binaries MUST be pinned to a version or immutable digest;
  `latest` is not an acceptable deployment input.
