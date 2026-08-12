# Laneway admin console

This directory contains the administrator-facing web console. It is a React and TypeScript single-page application built with Vite and emitted as static assets.

The console is intentionally separate from the future endpoint desktop client:

- The web console administers controller-owned networks, enrollments, nodes, routes, ACL rules, relays, certificates, and audit events.
- The future desktop client should be a Tauri 2 application for local profile, connection, exit-node, tray, update, and diagnostic workflows.
- Both surfaces may share design tokens, primitives, schemas, and generated API clients, but they should not share navigation or page composition.
- Neither surface moves packet forwarding into the controller or UI process.

## Development

```sh
corepack pnpm install
corepack pnpm dev
```

The development server always starts in the deliberate demo mode.

Builds must select their data boundary explicitly:

```sh
# Controller-hosted production artifact. Never falls back to demo records.
corepack pnpm build:live

# Deliberate review artifact with a visible demo-data notice.
corepack pnpm build:demo
```

Both commands write to `dist/`. The unscoped `corepack pnpm build` command fails so a production artifact cannot silently inherit demo behavior.
