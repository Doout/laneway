# Laneway admin console

This React console manages the controller. The [desktop client](../docs/desktop-client.md)
manages the local node. The node forwards packets; neither UI does.

## Development

```sh
corepack pnpm install
corepack pnpm dev
```

The development server uses demo data. Choose a build mode:

```sh
# For a controller. No demo data.
corepack pnpm build:live

# For local review with sample data.
corepack pnpm build:demo
```

Both write to `dist/`. A build without a mode fails.
