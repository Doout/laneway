# Local daemon desktop contract v1

Status: foundation contract. It does not declare the desktop client stable or
expand the privileged networking boundary.

## Boundary

The desktop client is an endpoint application, not an administrator console.
It does not load the management API, controller administrator credentials,
node private keys, or the privileged network-helper protocol.

On Unix platforms, v1 talks to the existing HTTP/1.1 local API over a Unix
socket. The socket is the authentication and authorization boundary for this
slice. Before connecting, the native desktop adapter requires all of the
following:

- an absolute, bounded path with no `.` or `..` components;
- a canonical physical parent directory owned by the desktop user with no
  group or other permissions;
- a socket rather than a file or symlink;
- ownership by the desktop process's effective user ID; and
- no group or other permission bits (the daemon creates mode `0600`).

After connecting, the adapter verifies the server's effective user ID from
Unix peer credentials (`SO_PEERCRED` on Linux and `getpeereid` on macOS). The
physical path and post-connect identity checks close path-alias and replacement
races without weakening the socket mode.

The adapter connects only to that socket and only sends these fixed requests:

- `GET /v1/status`
- `GET /v1/peers`
- `GET /v1/routes`
- an internal, unregistered `POST /v1/exit` adapter on Linux

Exit intent is limited to either a disabled selection with no node ID or an
enabled selection with one canonical 32-character lowercase hexadecimal node
ID. The all-zero ID is invalid. Invalid intent is rejected before the daemon is
contacted. The desktop webview cannot invoke this operation: the current daemon
contract exposes neither authoritative exit capability nor authorized exit
candidates.

Headers are limited to 8 KiB, bodies to 1 MiB, request bodies to 4 KiB, and a
complete request to five seconds. JSON responses require one content length; an
empty `204 No Content` may omit it, matching Go's HTTP server behavior. Chunked
responses, duplicate content lengths, trailing bytes, malformed JSON,
unexpected status codes, and incomplete bodies fail closed. The webview cannot
supply a socket path, URL, shell command, file path, or raw request.

Root can bypass ordinary Unix file permissions by design. This contract does
not claim protection from a compromised root account.

## Same-user limitation

The installed Linux host-node service runs as the locked `laneway` account and
owns `/run/laneway/lanewayd.sock` with mode `0600`. An ordinary desktop user
must not be granted access by making that socket broadly readable. Consequently,
the v1 desktop foundation supports only an already-running daemon owned by the
same user.

A future managed desktop session needs a dedicated per-user endpoint daemon or
an authenticated broker with peer-credential verification. That daemon must
own profile credentials and session lifetime while continuing to use the
existing inherited, typed privileged helper. Until that boundary exists, the
desktop client reports system-daemon access and connection control as
unsupported.

## Desktop snapshot

The Rust adapter reads status, peers, routes, and status again before producing
a UI-safe envelope:

```text
contract_version: 1
platform: linux | macos
ownership: same-user-daemon
capabilities: explicit booleans
status: local daemon status
peers: current peers
routes: current private routes
```

Revision 1 status includes a nonzero canonical `daemon_instance_id` that stays
fixed for one local-API server lifetime and an additive `api_revision`. The
adapter requires those fields to remain valid and identical across both status
reads. A mismatch retries the entire snapshot once and then fails closed.
Legacy daemons that omit both fields are accepted with
`snapshot_coherence: false`; the UI identifies restart detection as unavailable.
Mixed or malformed identity fields fail closed. A failed refresh discards the
previous snapshot so stale routes can never remain visibly authoritative.

The shared fixture at
`testvectors/local-api/desktop-snapshot-v1.json` is consumed by the Go local API,
the Rust daemon, and the Tauri adapter. Required-field drift therefore fails CI.
Additive daemon response fields remain compatible because the adapter ignores
fields it does not present to the webview.

## Capability truth

The foundation advertises only capabilities it implements:

| Capability | Linux same-user daemon | macOS same-user daemon |
| --- | --- | --- |
| Status | yes | yes |
| Private-route visibility | yes | yes |
| Restart-coherent snapshot | yes with API revision 1; visibly reduced for legacy | yes with API revision 1; visibly reduced for legacy |
| Exit selection | no | no |
| Profile management | no | no |
| Connect/disconnect ownership | no | no |
| Explicit ephemeral sessions | no | no |
| Updates and rollback | no | no |
| Diagnostic bundles | no | no |

Windows returns unsupported before opening any transport. No Windows support is
claimed by this contract.

The webview capability grants no Tauri core or plugin permissions and registers
only the read-only snapshot command. The dormant Linux exit adapter remains a
native test target until the daemon publishes capability and candidate data.

## Privileged operations

`go/internal/nethelper` remains the only foreground privileged mutation
boundary. It uses a private inherited socket, peer-process authentication,
strict typed plans, bounded messages, and authoritative cleanup. The desktop
adapter neither imports that protocol nor gains a command capable of reaching
it.

Profile lifecycle, session ownership, sleep/wake recovery, network-change
recovery, signed updates, rollback, diagnostics, tray state, and launch at login
require a later versioned daemon contract. They must not be implemented as shell
command escape hatches in the desktop process.
