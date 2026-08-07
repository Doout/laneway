# Laneway authenticated bootstrap v1

## 1. Trust transition

The discovery authority is a canonical DNS HTTPS origin. A client MUST fetch
`/.well-known/laneway/bootstrap.json` using TLS 1.3, hostname validation, and
the host's public Web PKI roots before trusting any field in the document. It
MUST reject IP authorities, redirects, credentials, alternate paths, unknown
JSON fields, trailing JSON, non-JSON content, and documents larger than 256
KiB. The public listener MUST serve no enrollment, administration, or node
control operation.

The authenticated document pins the private controller HTTPS origin, QUIC
host:port, DNS name, NetworkID, controller ServiceID, CA bundle, enabled relay
host:ports and ServiceIDs, stable protocol versions/capabilities, and release
artifacts. A private controller connection MUST validate its chain through the
discovered CA, its optional DNS name, controller role, NetworkID, and ServiceID.
Transport DNS resolution never replaces these identity checks.

## 2. Freshness and bounds

`schema_version` is exactly 1. `generated_at_unix_seconds` and
`valid_until_unix_seconds` define a UTC validity interval no longer than ten
minutes; a client allows at most two minutes of positive clock skew and rejects
an expired document. There are 1..32 unique enabled relays and 1..16 unique
artifact platforms. All IDs are canonical nonzero 128-bit lowercase hex.

Release artifacts identify `os`, `arch`, an HTTPS URL, exact positive byte
size no greater than 512 MiB, and canonical lowercase SHA-256. Stable v1
requires Linux AMD64 and ARM64 records. A downloader MUST reject excess or
short bytes and a digest mismatch before extraction or any privileged action.
Authenticated bytes MUST never be piped into a shell.

## 3. Invitations and enrollment

An invitation is the existing cryptographically random enrollment secret. Its
stored record is immutable with respect to NetworkID, enrollment class, token
expiry, optional operator-selected device name, and (for ephemeral users)
session lifetime. The controller stores only
SHA-256 of the random secret and consumes it atomically with node identity,
address, and certificate creation. Token lifetime is bounded; product invites
default to ten minutes and MUST NOT exceed one hour.

Interactive clients read the code from a controlling terminal with echo
disabled. They MUST NOT accept it in argv, a URL, bootstrap metadata, logs, or
diagnostics. A protected regular token file is permitted for automation. The
client sends `expected_network_id` from authenticated bootstrap metadata; the
controller compares it with the token's network before consumption. A
mismatch returns a clear permission error and leaves the code unconsumed.
Product invites also bind `requested_name`; the client MAY omit the name, in
which case the controller uses the bound value. Any supplied different name is
rejected before consumption. Advanced tokens MAY remain name-unbound.

The unauthenticated enrollment endpoint applies a bounded per-source rate
limit based on the transport peer address, never an untrusted forwarding
header. Invalid, expired, replayed, wrong-network, and throttled requests fail
without issuing credentials. The enrollment token alone cannot select or
upgrade its durable, ephemeral, or remembered class.
