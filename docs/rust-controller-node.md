# Rust node controller authority

The native Rust node can use the Go controller as its sole dynamic authority.
Configure it with [`deploy/examples/node-rust-controller.toml`](../deploy/examples/node-rust-controller.toml).

Validate the complete file, local certificate identity, private-key mode, and
trust material without opening a socket, TUN interface, or kernel forwarding
state:

```sh
lanewayd-rs --config /etc/laneway/node-rust-controller.toml --check-config
```

The native daemon serves the same bounded local-management JSON API as the Go
daemon on `socket_path` (the deployment default is
`/run/laneway/lanewayd.sock`). The shared CLI can therefore manage it without
parsing the Rust TOML schema:

```sh
laneway status --socket /run/laneway/lanewayd.sock
laneway peers --socket /run/laneway/lanewayd.sock
laneway routes --socket /run/laneway/lanewayd.sock
laneway exit use NODE_ID --socket /run/laneway/lanewayd.sock
laneway exit disable --socket /run/laneway/lanewayd.sock
```

The socket is created mode `0600`; a live socket is never replaced and cleanup
removes only the inode created by the running process. Exit changes require an
unexpired controller lease, local `forwarding.exit_client.authorized = true`,
an explicit failure mode, and an advertised exit route for the selected node.
The daemon serializes the change with controller refresh, atomically reconciles
policy routing and DNS, and records the explicit choice in `exit_intent_path`.
Invalid/corrupt intent fails startup closed.

The Rust relay supports the same side-effect-free check with
`laneway-relay --config /etc/laneway/relay-rust.toml --check-config`.

Controller mode has deliberately narrow ownership rules:

- the local certificate fixes the network and node IDs;
- the HTTPS enrollment origin, QUIC endpoint, and controller network/service
  SPIFFE identity are pinned;
- static TUN addresses, routes, and direct peers cannot be mixed with controller
  state;
- the first complete, unexpired `NodeConfiguration` is compiled before `lane0`
  is created;
- epochs only advance, while a QUIC `ConfigurationLease` must echo the current
  epoch and may never shorten its deadline;
- each accepted snapshot replaces addresses, routes, peers, capabilities,
  revoked serials, resolved relay targets, and the default-deny ACL policy
  transactionally; relay DNS resolution is bounded and an epoch is rejected
  only when the entire authorized relay set yields no usable target; and
- an expired lease removes controller-owned native address/route authority and
  closes live paths. Polling continues so a later valid snapshot can recover the
  node without weakening fail-close behavior.

Keep the node key readable only by the daemon account (normally mode `0600`).
The controller and relay service certificates must chain to the configured CA
and contain their exact Laneway SPIFFE identities. A DNS name or IP SAN alone
is not sufficient.

## Live release gate

The privileged gate starts the real Go controller service with a bounded
two-second test lease, a controller-backed Go relay, a Go subnet gateway, and
the real Rust node in disposable Linux network namespaces. It proves:

1. the controller deliberately holds the initial configuration response and
   `lane0` does not exist during that hold;
2. an approved subnet route is installed and carries a real NATed UDP exchange;
3. deleting the only accept ACL fails traffic closed without removing the
   still-authorized route, and a new accept rule restores traffic;
4. revoking the gateway certificate closes its established relay session; and
5. stopping the controller lets the last lease expire, after which the Rust
   process stays alive but its controller-owned address and route are absent.

Run it on Linux with root, `/dev/net/tun`, `iproute2`, nftables, Go, and Rust:

```sh
sudo env PATH="$PATH" HOME="$HOME" \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
  RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-controller-node-netns.sh
```

The script skips safely unless `LANEWAY_RUN_PRIVILEGED=1` is set. Set
`LANEWAY_KEEP_INTEGRATION_WORK=1` to retain logs after a failure.
