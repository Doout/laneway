# Management API v1

This document is the operator and client-developer guide to the current
administrator HTTP surface. The normative machine-readable contract is
[`api/openapi/management-v1.yaml`](../api/openapi/management-v1.yaml), with
shared definitions in [`api/openapi/components.yaml`](../api/openapi/components.yaml).
Both files use OpenAPI 3.1.

The API is mounted at `/v1/admin`. JSON request and response objects are strict:
unknown properties are rejected. Identifiers, integer bounds, UTF-8 byte limits,
conditional fields, and other DTO rules are defined in the OpenAPI schemas and
enforced again at the browser boundary.

## Authentication and browser-origin rules

The credential and request classes are intentionally distinct:

| Request class | Required authentication | Origin and CSRF rules |
| --- | --- | --- |
| Authentication state | None | `GET /auth/state` ignores supplied credentials and is direct-peer rate limited. |
| Public account lifecycle | None | Login, bootstrap, and recovery require an HTTPS same-origin `Origin` and reject active administrator or root credentials. Login may replace a stale or expired session cookie. No CSRF header is required before a session exists. |
| Current session read | Administrator session cookie and CSRF cookie | `GET /auth/session` requires both cookies but does not require `Origin` or `X-Laneway-CSRF`. |
| Safe protected resource read | Administrator session cookie **or** root bearer | No CSRF header is required. Ordinary authorization and network scoping still apply. |
| Session lifecycle mutation | Administrator session cookie, CSRF cookie, and `X-Laneway-CSRF` | Rotate and logout are same-origin, session-only operations. |
| Protected resource mutation | Administrator session cookie, CSRF cookie, and `X-Laneway-CSRF`, **or** root bearer | Cookie-authenticated mutations must be same-origin. Root automation does not use CSRF. |
| Root-only automation | Root bearer | Any `Origin` or `Sec-Fetch-*` header causes authentication failure. |

The session and CSRF cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, and
use the `__Host-` prefix. Browser JavaScript receives the CSRF token in the
authenticated session view and sends it as `X-Laneway-CSRF`; it never reads a
cookie. The root bearer is a local file-based automation credential, not a
console credential.

The root-only operations are the root credential probe, bootstrap-grant issue,
both root-token rotation journal operations, and administrator recovery-grant
issue. The exact `username` filter on `GET /administrators` is also root-only
and cannot be combined with `limit`.

## Current route inventory

The contract contains exactly 54 operations:

| Method | Path | Access class |
| --- | --- | --- |
| `GET` | `/v1/admin/auth/state` | Authentication state |
| `POST` | `/v1/admin/auth/login` | Public account lifecycle |
| `GET` | `/v1/admin/auth/session` | Current session read |
| `POST` | `/v1/admin/auth/session/rotate` | Session lifecycle mutation |
| `POST` | `/v1/admin/auth/logout` | Session lifecycle mutation |
| `GET` | `/v1/admin/auth/root` | Root-only automation |
| `POST` | `/v1/admin/auth/bootstrap` | Public account lifecycle |
| `POST` | `/v1/admin/auth/recover` | Public account lifecycle |
| `POST` | `/v1/admin/auth/bootstrap-grants` | Root-only automation |
| `POST` | `/v1/admin/auth/root-token-rotations/{rotation_id}/begin` | Root-only automation |
| `POST` | `/v1/admin/auth/root-token-rotations/{rotation_id}/complete` | Root-only automation |
| `GET` | `/v1/admin/administrators` | Safe protected read; `username` is root-only |
| `POST` | `/v1/admin/administrators` | Protected mutation |
| `GET` | `/v1/admin/administrators/{principal_id}` | Safe protected read |
| `PATCH` | `/v1/admin/administrators/{principal_id}` | Protected mutation |
| `POST` | `/v1/admin/administrators/{principal_id}/password` | Protected mutation |
| `POST` | `/v1/admin/administrators/{principal_id}/recovery-grants` | Root-only automation |
| `GET` | `/v1/admin/administrators/{principal_id}/sessions` | Safe protected read |
| `POST` | `/v1/admin/sessions/{session_id}/revoke` | Protected mutation |
| `GET` | `/v1/admin/audit` | Safe protected read |
| `GET` | `/v1/admin/audit/page` | Safe protected read |
| `POST` | `/v1/admin/enrollment-tokens` | Protected mutation |
| `POST` | `/v1/admin/bootstrap-bundles` | Protected mutation |
| `GET` | `/v1/admin/networks` | Safe protected read |
| `POST` | `/v1/admin/networks` | Protected mutation |
| `GET` | `/v1/admin/networks/{network_id}` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/nodes` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/endpoint-statuses` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/relays` | Safe protected read |
| `POST` | `/v1/admin/networks/{network_id}/relays` | Protected mutation |
| `GET` | `/v1/admin/networks/{network_id}/acl-rules` | Safe protected read |
| `POST` | `/v1/admin/networks/{network_id}/acl-rules` | Protected mutation |
| `GET` | `/v1/admin/networks/{network_id}/access-subjects` | Safe protected read |
| `POST` | `/v1/admin/networks/{network_id}/users` | Protected mutation |
| `PATCH` | `/v1/admin/users/{user_id}` | Protected mutation |
| `POST` | `/v1/admin/networks/{network_id}/teams` | Protected mutation |
| `PUT` | `/v1/admin/teams/{team_id}/members/{user_id}` | Protected mutation |
| `DELETE` | `/v1/admin/teams/{team_id}/members/{user_id}` | Protected mutation |
| `POST` | `/v1/admin/networks/{network_id}/access-grants` | Protected mutation |
| `DELETE` | `/v1/admin/access-grants/{grant_id}` | Protected mutation |
| `GET` | `/v1/admin/networks/{network_id}/certificates` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/routes` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/audit` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/audit/page` | Safe protected read |
| `GET` | `/v1/admin/networks/{network_id}/access-subjects` | Safe protected read |
| `POST` | `/v1/admin/networks/{network_id}/users` | Protected mutation |
| `PATCH` | `/v1/admin/users/{user_id}` | Protected mutation |
| `POST` | `/v1/admin/networks/{network_id}/teams` | Protected mutation |
| `PUT` | `/v1/admin/teams/{team_id}/members/{user_id}` | Protected mutation |
| `DELETE` | `/v1/admin/teams/{team_id}/members/{user_id}` | Protected mutation |
| `POST` | `/v1/admin/networks/{network_id}/access-grants` | Protected mutation |
| `DELETE` | `/v1/admin/access-grants/{grant_id}` | Protected mutation |
| `POST` | `/v1/admin/networks/{network_id}/certificates/{serial}/revoke` | Protected mutation |
| `POST` | `/v1/admin/routes/assign` | Protected mutation |
| `POST` | `/v1/admin/routes/{route_id}/approve` | Protected mutation |
| `POST` | `/v1/admin/routes/{route_id}/withdraw` | Protected mutation |
| `PUT` | `/v1/admin/acl-rules/{rule_id}` | Protected mutation |
| `DELETE` | `/v1/admin/acl-rules/{rule_id}` | Protected mutation |
| `POST` | `/v1/admin/nodes/{node_id}/revoke` | Protected mutation |
| `PUT` | `/v1/admin/nodes/{node_id}/capabilities` | Protected mutation |
| `POST` | `/v1/admin/relays/{relay_id}/disable` | Protected mutation |
| `PUT` | `/v1/admin/relays/{relay_id}` | Protected mutation |

## Collection pages and mutation semantics

List operations return a bounded snapshot with one collection property and no
pagination metadata:

| Resource | Response shape |
| --- | --- |
| Administrators | `{ "administrators": [...] }` |
| Administrator sessions | `{ "sessions": [...] }` |
| Networks | `{ "networks": [...] }` |
| Nodes | `{ "nodes": [...] }` |
| Endpoint status | `{ "endpoint_statuses": [...] }` |
| Relays | `{ "relays": [...] }` |
| ACL rules | `{ "acl_rules": [...] }` |
| Certificates | `{ "certificates": [...] }` |
| Routes | `{ "routes": [...] }` |
| Audit events | `{ "events": [...] }` |
| Audit cursor pages | `{ "events": [...], "next_cursor": "..." }` |

When supported, `limit` is between 1 and 1000; omission or an empty value uses
100. Most collection operations, including the existing global and network
`/audit` routes, remain bounded snapshots with no cursor, total count, or
snapshot revision. Their exact `{ "events": [...] }` response stays unchanged
for strict v1 clients. Clients must not infer that a short response is a
durable end-of-list marker for those resources.

The explicit global and network `/audit/page` operations are cursor-paginated
in authoritative `created_at DESC, event_id DESC` order. A response includes
`next_cursor` only when the controller proved that older rows remain. Clients
continue by sending that opaque value as `cursor` with the same global or
network scope and the same `limit` semantics. Audit cursors are versioned
implementation details: clients must not decode, alter, or transfer them
between scopes. Invalid, empty, repeated, or out-of-scope cursors fail as
malformed requests rather than silently restarting pagination.

The v1 surface does not claim entity tags, `If-Match` preconditions, or a general
idempotency-key header. Two operations have narrower documented replay behavior:
repeating the same root-token rotation journal step is idempotent, and route
assignment may return the existing exact active route. These behaviors do not
create a general retry guarantee for other mutations.

Enrollment-token expiry must be strictly in the future and no more than 30
days after the controller's current time. Bootstrap-bundle expiry must be
strictly in the future and no more than 10 minutes after the controller's
current time.

## Responses, correlation, and session renewal

The v1 response contract includes a server-generated
`X-Laneway-Request-ID` on every response. It is an opaque value of exactly 32
lowercase hexadecimal characters; client-supplied request identifiers are
ignored.

The stable JSON error envelope is:

```json
{
  "request_id": "0123456789abcdef0123456789abcdef",
  "code": "ERROR_CODE_MALFORMED",
  "detail": "request body is invalid",
  "retryable": false
}
```

`request_id` is the required body-level correlation field and matches the
server-generated `X-Laneway-Request-ID` response header. `Retry-After`, when
present on a rate-limited error, is a whole number
of seconds. Consumers should branch on `code` and `retryable`, not on the human
readable `detail`.

Successful login, session read, and session rotation responses require:

- `X-Laneway-Session-ID`
- `X-Laneway-Session-Idle-Expires-At`
- `X-Laneway-Session-Absolute-Expires-At`

Protected successes authenticated by a browser session carry the same renewal
headers when a live session remains. Root-authenticated responses omit them, and
a self-revoking operation may omit them after invalidating the caller's session.
Expiry values are Unix seconds encoded as JSON-safe integers.

## Generated browser SDK boundary

The browser artifact under `web/src/generated/management-v1` is deliberately
narrower than the full automation contract. It uses relative `/v1/admin/...`
paths, same-origin credentials, and `redirect: error`. It provides no configurable
API origin or base URL, root-bearer or `Authorization` input, cookie input, raw
header override, or root-only operation. The root-only administrator username
lookup is likewise unavailable through its public types. Runtime guards reject
root-only paths and browser-context credential/header escape attempts even if a
caller circumvents TypeScript.

Integration code may supply a CSRF-token callback and a custom `fetch`
implementation when constructing the operation-bound API; neither can be
replaced per call. The public factory returns generated operations only, not a
generic HTTP client, so callers cannot provide raw URLs, headers, bodies,
serializers, or validator hooks.
The transport adds `X-Laneway-CSRF` to protected mutations and does not expose
the session cookie. Generated Zod v4 request and response validators are strict, including safe-integer,
UTF-8-byte, omission/default, and cross-field constraints. The browser SDK is
therefore suitable for the same-origin management console; non-browser root
automation must use a separate client.

Traffic-selector requests use a canonical safe subset of protobuf JSON:
snake_case field names, named protocol enums, padded standard base64, and
uint32 JSON integers or quoted ASCII decimal digits. Quoted integers are
normalized before transmission, and every canonical selector returned by the
controller round-trips losslessly. The controller's raw HTTP parser is more
permissive—for example, it can accept lowerCamel aliases and other protobuf
JSON spellings—but those forms deliberately have no browser SDK path. Relay
input similarly uses the canonical ASCII-DNS/numeric-IP browser subset. It
accepts non-mapped IPv6 with an embedded dotted IPv4 tail, rejects IPv4-mapped
IPv6 and zones, and lets the controller normalize additional non-ASCII DNS
spellings outside that subset. Canonical responses still round-trip.

Generation is pinned to `@hey-api/openapi-ts` 0.99.0 and `@redocly/cli` 2.46.1.
From `web/`, the contract gates are:

```sh
corepack pnpm api:lint
corepack pnpm api:routes
corepack pnpm api:generate
corepack pnpm api:check
```

`api:lint` applies strict OpenAPI linting. `api:routes` rejects duplicate YAML
mapping keys and verifies parity with all 52 registered management operations.
Generation is deterministic: CI regenerates the SDK and fails on a diff. The
repository-level equivalent is `make management-api-check`; CI installs the
pinned lockfile and runs the same gate.
