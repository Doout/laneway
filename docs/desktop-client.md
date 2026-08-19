# Desktop client foundation

The desktop source lives in `desktop/`. It is a standalone Tauri endpoint
application; it does not reuse or embed the administrator console.

The first slice provides:

- typed local status, peer, and private-route views;
- a strict same-user Unix-socket adapter in the native process;
- restart detection for revisioned daemons, with visibly reduced legacy mode;
- explicit capability reporting for everything not yet supported; and
- the shared Laneway color, type, and radius token vocabulary.

It intentionally does not provide profile/login lifecycle, connect/disconnect
ownership, exit selection, update installation, signing, rollback, packaging,
launch at login, or tray behavior. Exit selection additionally requires an
authoritative daemon capability and authorized candidate set. Those features
require the per-user managed daemon described in
[the desktop endpoint contract](../spec/desktop-client-v1.md) and the
[normative local daemon API](local-daemon-api-v1.md).

## Develop

Install the normal Tauri 2 platform prerequisites, Rust 1.88 or newer, Node 24,
and the pinned pnpm version. Then run:

```sh
cd desktop
corepack pnpm install --frozen-lockfile
corepack pnpm check
corepack pnpm tauri dev
```

The application uses `/run/laneway/lanewayd.sock` by default. Development and
tests may point at another same-user socket without exposing the path to the
webview:

```sh
LANEWAY_DESKTOP_SOCKET=/absolute/private/lanewayd.sock corepack pnpm tauri dev
```

The socket must be a real mode-`0600` Unix socket owned by the current user,
inside a mode-`0700` physical parent owned by that user. Its post-connect peer
credentials must identify the same user.
The installed root or `laneway`-owned Linux service is expected to fail this
check. Do not change it to mode `0666` or add the desktop user to a broad
privileged group.

## Gates

```sh
cd desktop
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
corepack pnpm tauri build --no-bundle
```

The native gate proves that the Tauri binary compiles on macOS. A Linux CI gate
compiles and runs the native trust and dormant exit-adapter tests. Neither gate
produces, signs, notarizes, publishes, or updates an installer. Linux lifecycle
and Windows native build/lifecycle matrices remain required before those
platforms can be declared supported.
