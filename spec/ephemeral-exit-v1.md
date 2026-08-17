# Ephemeral Exit lease v1

An ephemeral Exit is an existing `ephemeral` enrollment carrying exactly the
controller-granted `exit-node-v1` capability. It is not a new role and cannot
be upgraded locally or combined with another forwarding capability.

Enrollment consumes the invitation and creates the node, certificate, overlay
allocation, approved Exit route, random nonzero 63-bit lease generation, and
`ephemeral_exit.session.start` audit in one database transaction. The
generation is non-secret. Every later configuration request carries it inside
the TLS 1.3 mTLS session; the certificate private key supplies proof of
possession and the new handshake supplies a fresh server challenge. 0-RTT is
disabled.

The controller admits one active QUIC control connection per identity. A
concurrent connection before `suspect_at` is rejected. At or after
`suspect_at`, a new handshake for the same active certificate may replace the
stale transport; release of the superseded connection cannot remove the new
session. The generation must match durable live state.

Each accepted heartbeat sets:

```text
suspect_at = controller_now + 20 seconds
revoke_at  = controller_now + 60 seconds
```

The returned configuration validity never exceeds `suspect_at`. At that local
deadline the Exit replaces outbound admission with established/related-only
conntrack rules. A valid response before `revoke_at` restores the complete
controller-authorized plan. At `revoke_at`, or at the absolute ephemeral
identity lifetime when earlier, the controller transaction terminates the
session, revokes the node and certificates, withdraws routes, releases overlay
addresses, increments each affected network epoch once, and writes a system
revocation audit. Predicates on generation, terminal state, and deadline make
a racing heartbeat lose closed at the exact boundary. Terminal rows are never
reactivated; restart requires a new invitation, identity key, and generation.

The runner polls every 10 seconds and independently exits at the earlier of its
last controller `revoke_at`, absolute identity expiry, or systemd runtime cap.
