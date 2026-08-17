# Laneway Threat Model

Status: Stable-v1 threat model.

Normative terms have the meaning defined in BCP 14.

## 1. Security goals and limits

Laneway aims to provide:

- mutual authentication and network-scoped identity;
- confidentiality and integrity in transit;
- authorization of overlay addresses, routes, and exit use;
- source and destination validation before forwarding or local injection;
- isolation between networks sharing infrastructure;
- rejection of stale, replayed, or downgraded state; and
- bounded work and memory under malformed or excessive traffic.

Laneway does not make a compromised endpoint trustworthy, hide traffic metadata
from a relay, or protect cleartext after an authorized subnet router or Exit
Node forwards it outside the overlay.

## 2. Trust boundaries

| Component | Trusted for | Boundary |
| --- | --- | --- |
| Offline root and online issuer | issuing correct identities | the root key MUST remain offline; only the constrained online issuer belongs on the controller |
| Controller | identities, leases, addresses, routes, and policy | it MUST NOT receive endpoint private keys or carry user packets |
| Relay | session isolation and authorized forwarding | legacy carriers expose packet plaintext; a hybrid WireGuard relay sees only encrypted datagrams |
| Endpoint | its OS, daemon, configuration, certificate, and private key | compromise defeats the protections granted to that identity |
| Container runtime and kernel | namespace, device, mount, and capability isolation | compromise is outside Laneway's container boundary |

The public network, NAT, DNS, unauthenticated peers, node names, hostnames,
claimed addresses, and identity fields inside protocol messages are untrusted.
The deployment boundary is defined in
[deployment-contract.md](deployment-contract.md).

Compromise of an issuing CA, controller authorization store, endpoint OS, or
endpoint key is outside the containment promise for identities governed by that
component. Recovery requires revocation and re-issuance.

## 3. Adversaries

The design considers:

- passive observers and active on-path attackers;
- unauthenticated clients contacting public listeners;
- authenticated nodes attempting impersonation, address spoofing,
  cross-network access, unauthorized routing, or resource exhaustion;
- stale or revoked nodes attempting to reconnect;
- compromised relays attempting to inspect, alter, replay, or disrupt traffic;
- malformed input intended to exploit parsers or exhaust resources; and
- local users or compromised containers attempting to escape their assigned
  privilege and state-ownership boundaries.

## 4. Required controls

The documents below contain the normative controls. Their requirements are
cumulative and cannot be negotiated away.

| Threat | Normative controls |
| --- | --- |
| Identity spoofing, key theft, and enrollment abuse | [Identity](identity-v1.md) defines certificate identity, message binding, local key generation, rotation, and revocation. [Bootstrap](bootstrap-v1.md) defines authenticated discovery, bounded metadata, invitations, and enrollment. |
| Cross-network forwarding, address spoofing, and unauthorized routes | [Routing](routing-v1.md) defines network-scoped ownership, approval, ACLs, snapshots, handles, and source validation. [Packet format](packet-format-v1.md) defines frame, size, handle, source, and destination validation. |
| Replay, stale state, and downgrade | [Control protocol](control-protocol-v1.md) defines session state, ephemeral identity and configuration leases, handle lifetime, capability negotiation, 0-RTT prohibition, and resource limits. [Compatibility](compatibility.md) defines version behavior. |
| Shared-host ephemeral Exit | [Ephemeral Exit lease v1](ephemeral-exit-v1.md) binds one active mTLS session to a durable generation, drains at the suspect deadline, revokes atomically at the terminal deadline, and confines runtime networking to a transient private namespace. Host root, kernel, hypervisor, audit, and provider telemetry remain trusted/observable. |
| Direct-path impersonation | [Direct path](direct-path-v1.md) defines authenticated candidate exchange, probes, peer identity, and relay fallback. |
| Relay compromise and carrier fallback | [TCP fallback](tcp-fallback-v1.md) preserves the authenticated relay boundary and its plaintext limitation. [WireGuard hybrid](wireguard-hybrid-v1.md) defines the opaque end-to-end carrier and key binding. Endpoints retain packet validation for every carrier. |
| Route recursion and traffic leaks | [Routing](routing-v1.md) defines explicit exit authorization. [Deployment](deployment-contract.md) defines endpoint bypasses, namespace isolation, fail-closed ownership, and exit behavior. |
| Local privilege abuse and unsafe cleanup | [Deployment](deployment-contract.md) defines the User helper, container capabilities, mounts, journals, and ownership checks. |
| Resource exhaustion and log disclosure | Protocol limits are defined by the control and packet specifications. [Observability](observability-v1.md) requires bounded, label-safe signals outside the packet path. |

## 5. Privacy and relay visibility

Relays learn authenticated identity, timing, observed public endpoints, packet
sizes, and forwarding destinations. Legacy relay carriers can inspect packet
content; the hybrid WireGuard carrier cannot. Controllers learn membership,
addresses, approved routes, and policy. Logs SHOULD minimize public-endpoint
retention and MUST NOT contain packet bodies, credentials, or private keys.
Stable NodeIDs are linkable within one network by design.

## 6. Security validation

Release validation MUST cover certificate and identity failures, cross-network
and stale handles, malformed or oversized frames, spoofed routes and sources,
version and capability downgrade, bounded resource exhaustion, carrier
fallback, lease expiry, host-state recovery, helper and container isolation,
bootstrap tampering, enrollment replay, and shared Go/Rust golden vectors.

## 7. Residual risks

A compromised relay can observe metadata and can drop, delay, duplicate, or
misroute live traffic subject to endpoint validation. It can also inspect packet
content on legacy carriers. Rendezvous tokens reveal short-lived reachability
information to the relay, though direct QUIC still authenticates both peers.
Traffic analysis, compromised endpoints, and compromised issuing authorities
remain outside the containment promise.
