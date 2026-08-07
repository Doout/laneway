# Laneway Identity v1

Status: Stable-v1 normative identity profile.

Normative terms have the meaning defined in BCP 14.

## 1. Identifiers

`NetworkID` and `NodeID` are immutable, independently generated 128-bit values. Their wire representation is exactly 16 opaque bytes; byte 0 is rendered as the first two hexadecimal characters in text. The all-zero value is invalid. Identifiers MUST be generated with a cryptographically secure random source; implementations MUST NOT derive them from names, hostnames, MAC addresses, overlay addresses, or public keys.

The canonical text form is exactly 32 lowercase hexadecimal characters with no separators, for example `2f1c06d86d884e41b3dce25ea572cc90`. URI identity parsers MUST reject uppercase, hyphens, braces, prefixes, percent-encoding, and every other representation. Outside certificate identity parsing, user-facing tools MAY accept a documented alternate input form, but protocol serializers MUST always emit the canonical form. The 16 bytes are opaque and do not imply UUID version semantics.

`boot_id` and `session_id` are ephemeral 16-byte nonzero random values. A daemon MUST generate a new `boot_id` on every process start. A server MUST generate a new `session_id` for every successful control session. Neither value authenticates a peer.

## 2. Node identity URI

A node certificate identity is a URI subjectAltName with this exact form:

```text
spiffe://laneway/network/<network-id>/node/<node-id>
```

Both identifiers MUST use their canonical lowercase text form. The URI scheme and host MUST be exactly `spiffe` and `laneway`. The URI MUST contain no user information, port, query, fragment, percent-encoding, empty path segment, or trailing slash.

An implementation MUST parse the URI structurally, not with substring matching. A certificate used as a node identity MUST contain exactly one URI SAN matching this profile. It MUST be rejected if it contains zero or multiple matching Laneway identity URIs, even when the values agree.

DNS SANs, IP SANs, common names, certificate subjects, node names, hostnames, and overlay addresses do not determine Laneway identity.

## 3. Service identities

Service certificates use:

```text
spiffe://laneway/network/<network-id>/relay/<service-id>
spiffe://laneway/network/<network-id>/controller/<service-id>
```

`service-id` obeys the same 16-byte and canonical text rules as `NodeID`. A service certificate MUST contain exactly one usable Laneway URI identity and MUST be authorized for the expected role. A relay or controller MAY serve more than one network only through distinct authenticated identity and authorization contexts; it MUST NOT infer cross-network authority from a service certificate for one network.

Stable v1 defines node, relay, and controller service identities.

## 4. Certificate hierarchy and profile

The recommended hierarchy is an offline Laneway root CA, an online or operationally protected intermediate CA, and leaf certificates. A small manual deployment MAY issue leaves directly from a protected root, but validation behavior is unchanged and the root then cannot remain offline.

Leaf certificates:

- MUST be X.509 v3 certificates;
- MUST chain to a configured trust anchor;
- MUST contain `basicConstraints` with `CA=FALSE`;
- MUST permit digital signatures in key usage;
- MUST permit both TLS client and TLS server authentication in extended key usage for node and relay interoperability, unless separate role-specific certificates are deployed;
- MUST be within their validity interval; and
- MUST contain one identity URI as defined above.

Issuing CA certificates MUST have `CA=TRUE` and appropriate certificate-signing key usage. Implementations MUST perform normal path constraints, name constraints when present, signature, validity, and critical-extension validation. Unknown critical extensions MUST cause rejection.

Implementations SHOULD support Ed25519 and ECDSA P-256 leaf keys. Implementations MUST NOT require a particular signature scheme without advertising that deployment constraint. TLS 1.3 is REQUIRED; TLS 1.2 and earlier MUST NOT be negotiated.

## 5. Authentication and message binding

After TLS certificate verification, an endpoint extracts an `AuthenticatedIdentity` containing role, `NetworkID`, and node/service ID. This object is the sole identity input to authorization.

The first `Hello` from a node contains `network_id` and `node_id` for protocol consistency. The receiver MUST compare both byte-for-byte with the authenticated certificate identity. A mismatch is a fatal identity error, represented as `ERROR_CODE_UNAUTHENTICATED` if a control error can safely be returned; the connection MUST be closed and no session or route handle may be allocated.

An authenticated relay identity MUST match the locally configured network and expected relay authorization. Merely possessing any certificate issued by the CA is insufficient to act as a relay.

## 6. Keys and enrollment

Nodes MUST generate private keys locally. Private keys MUST NOT appear in CSRs, enrollment requests, controller state, logs, diagnostics, or test fixtures intended for production use. A CSR MUST contain or request the intended Laneway URI, but the controller MUST construct or independently validate the issued identity from authoritative enrollment state rather than trusting the CSR request.

Enrollment tokens are one-time bootstrap credentials, not node identities. The controller stores only a hash and consumes each token once. Renewal MUST authenticate with the existing, non-revoked node identity and MUST preserve the immutable `NetworkID` and `NodeID`, while allowing a new locally generated key pair.

## 7. Rotation and revocation

Certificate rotation MUST NOT change a node's identity. A node MAY hold overlapping valid certificates during a safe rotation window. New connections SHOULD use the newest valid certificate; existing sessions MAY continue until policy or revocation requires termination.

The controller is the revocation authority. Revocation data MUST identify at least the issuer and certificate serial or the immutable identity plus a monotonic revocation epoch. A revoked credential MUST be denied new relay and direct-path sessions, and matching active relay and direct-path sessions SHOULD be terminated promptly after the revocation update.

Manual static deployments MUST provide an explicit operator procedure to remove authorization and terminate active sessions. Certificate expiry MUST always prevent new authentication.

## 8. Validation errors

Identity failures MUST be represented by stable protocol or implementation error categories rather than matching free-form strings. At minimum implementations distinguish invalid chain, expired/not-yet-valid, invalid identity URI, wrong network, wrong role, identity-message mismatch, and revoked identity. Detailed local diagnostics MAY be logged, but peers MUST receive only information appropriate to an unauthenticated or partially authenticated client.
