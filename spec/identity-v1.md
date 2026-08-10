# Laneway Identity v1

## Identifiers

`NetworkID`, `NodeID`, and service IDs are independently generated, immutable,
nonzero 128-bit values. Their wire form is exactly 16 opaque bytes. The text
form is exactly 32 lowercase hexadecimal characters with no separators; byte 0
is the first pair. Certificate URI parsers MUST reject every other form,
including uppercase, hyphens, braces, prefixes, and percent-encoding.

Identifiers MUST come from a cryptographically secure random source and MUST
NOT be derived from names, hostnames, MAC addresses, overlay addresses, or
keys. They have no UUID version semantics. User-facing tools MAY accept a
documented alternate input form, but protocol serializers MUST emit the
canonical form.

`boot_id` and `session_id` are nonzero random 16-byte values. A daemon creates
a new `boot_id` at every process start; a server creates a new `session_id` for
each successful control session. Neither authenticates a peer.

## Certificate identities

Node certificates use exactly:

```text
spiffe://laneway/network/<network-id>/node/<node-id>
```

Service certificates use:

```text
spiffe://laneway/network/<network-id>/relay/<service-id>
spiffe://laneway/network/<network-id>/controller/<service-id>
```

The scheme and host MUST be exactly `spiffe` and `laneway`; IDs use canonical
text. The URI MUST NOT contain user information, a port, query, fragment,
percent-encoding, empty path segments, or a trailing slash.

Parsers MUST parse structurally. A certificate MUST contain exactly one usable
Laneway URI identity and be authorized for its expected role and NetworkID.
Zero or multiple matching URIs are invalid, even when values agree. DNS/IP
SANs, common names, subjects, hostnames, node names, and overlay addresses do
not establish Laneway identity. Multi-network services MUST use distinct
authenticated identity and authorization contexts.

## Certificate profile

Leaf certificates MUST:

- be X.509 v3 and chain to a configured trust anchor;
- set `basicConstraints` to `CA=FALSE`;
- allow digital signatures;
- allow TLS client and server authentication for node and relay
  interoperability, unless separate role certificates are used;
- be within their validity interval; and
- contain the identity URI defined above.

Issuing CAs MUST set `CA=TRUE` and certificate-signing key usage. Validation
MUST enforce path and name constraints, signatures, validity, and critical
extensions; unknown critical extensions are invalid. Implementations SHOULD
support Ed25519 and ECDSA P-256 leaves and MUST NOT require another signature
scheme without declaring that deployment constraint. TLS 1.3 is REQUIRED;
earlier TLS versions MUST NOT be negotiated.

## Authentication binding

Authorization MUST use only the role, NetworkID, and node/service ID extracted
after certificate validation. A node's first `Hello.network_id` and
`Hello.node_id` MUST match that identity byte-for-byte. A mismatch is fatal,
uses `ERROR_CODE_UNAUTHENTICATED` when a reply is safe, closes the connection,
and MUST NOT allocate a session or route handle.

A relay identity MUST match the configured NetworkID and expected relay
authorization. Possession of any certificate from the CA is insufficient.

## Keys, renewal, and revocation

Nodes MUST generate private keys locally. Private keys MUST NOT appear in CSRs,
enrollment requests, controller state, logs, diagnostics, or production test
fixtures. A CSR MUST request the intended Laneway URI. The controller MUST
construct or independently validate the issued identity from authoritative
enrollment state rather than trusting that request.

Enrollment tokens are one-time credentials, not identities. The controller
stores only a hash and consumes each token once. Renewal MUST authenticate the
existing non-revoked identity, preserve NetworkID and NodeID, and MAY use a new
locally generated key pair.

Rotation MUST NOT change node identity. Overlapping valid certificates MAY be
used during rotation; new connections SHOULD use the newest, while existing
sessions MAY continue until policy or revocation ends them. Revocation MUST deny
new relay and direct sessions, and matching active sessions SHOULD be terminated
promptly. Revocation data MUST identify the issuer and serial, or the immutable
identity plus a monotonic revocation epoch. Certificate expiry always prevents
new authentication. Manual deployments MUST define how to remove authorization
and terminate active sessions.

Implementations MUST distinguish invalid chain, validity period, identity URI,
network, role, message binding, and revocation failures using stable error
categories rather than free-form string matching. Peer-facing details MUST be
limited to information appropriate for the caller's authentication state.
