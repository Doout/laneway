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

The production build is created with `corepack pnpm build` and written to `dist/`.
