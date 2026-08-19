# Rust Node with the Go controller

Start with
[`node-rust-controller.toml`](../deploy/examples/node-rust-controller.toml),
then validate the installed configuration before opening a TUN device:

```sh
lanewayd-rs --config /etc/laneway/node-rust-controller.toml --check-config
```

The Rust daemon uses the same protected local socket API as the Go Node:

```sh
laneway node status --socket /run/laneway/lanewayd.sock
laneway node peers --socket /run/laneway/lanewayd.sock
laneway node routes --socket /run/laneway/lanewayd.sock
laneway node exit use NODE_ID --socket /run/laneway/lanewayd.sock
laneway node exit disable --socket /run/laneway/lanewayd.sock
```

Both implementations follow the [local daemon API v1](local-daemon-api-v1.md)
compatibility and error contract.

Controller mode cannot be combined with static addresses, routes, or peers. A
complete controller snapshot is validated before `lane0` is created; lease
expiry removes controller-owned address and route authority. Keep the Node key
readable only by its daemon account, and match controller and relay certificates
to their configured Laneway SPIFFE identities.

The Linux prerequisites and Go-controller/Rust-Node gate are in the
[integration test guide](../integration/README.md).
