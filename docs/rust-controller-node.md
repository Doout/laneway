# Controller-managed Linux node

For a managed install, use `sudo laneway node install DOMAIN` with a node
invitation. See [Operations](operations.md) for install and recovery commands.

For manual setup, start with
[`node-rust-controller.toml`](../deploy/examples/node-rust-controller.toml).
Validate the installed configuration before opening a TUN device:

```sh
lanewayd-rs --config /etc/laneway/node-rust-controller.toml --check-config
```

Inspect the running daemon through its [protected local socket](https://github.com/Doout/laneway/blob/main/docs/local-daemon-api-v1.md):

```sh
laneway node status --socket /run/laneway/lanewayd.sock
laneway node peers --socket /run/laneway/lanewayd.sock
laneway node routes --socket /run/laneway/lanewayd.sock
```

In controller mode, addresses, routes, and peers come from validated controller
snapshots. Lease expiry removes controller-owned address and route authority.
Keep the node key readable only by the service account, and match the
controller and relay certificates to the configured Laneway SPIFFE identities.

See the [integration test guide](../integration/README.md) for the managed-node
network namespace tests.
