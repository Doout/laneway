# Integration tests

Run all commands from the repository root.

## Unprivileged

The default suite does not change host networking:

```sh
./integration/nonprivileged.sh
```

The Go-to-Rust relay gate also requires a Rust toolchain:

```sh
make rust-interop
```

`integration/login-connect.py` exercises public discovery, one-time enrollment,
and saved-profile compatibility against a real controller and relay. Supply
the Rust CLI with `--launcher`, the full Go reference CLI with `--go-cli`,
and the service binaries with `--controller` and `--relay`. The fixture
uses temporary state and a private test CA. On an isolated Linux host, add
`--native-connect` for a privileged foreground session or `--helper-connect`
as an ordinary user with the installed network helper. Both exercise
renewal, ephemeral login, and route cleanup.

The controller QUIC interoperability test starts the Go production controller
and Rust candidate from the same Go backup. It exercises configuration,
policy changes, renewal and revoked credentials with production clients.
See the [Rust controller test commands](../rust/laneway-controller/README.md).

## Privileged Linux

These gates require root, `/dev/net/tun`, Go, Cargo, `iproute2`, `iputils`,
nftables, and `sysctl`. Preserve the toolchain paths when using `sudo`.

```sh
sudo env PATH="$PATH" HOME="$HOME" LANEWAY_RUN_PRIVILEGED=1 ./integration/linux-netns.sh
sudo env PATH="$PATH" HOME="$HOME" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh
sudo env PATH="$PATH" HOME="$HOME" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh
sudo env PATH="$PATH" HOME="$HOME" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-controller-node-netns.sh
```

The scripts skip unless `LANEWAY_RUN_PRIVILEGED=1` is set and remove their
temporary namespaces on exit. Add `LANEWAY_KEEP_INTEGRATION_WORK=1` to the
controller/Rust Node gate to retain failure logs.

The Rust node executable gates use `lanewayd run --system --config PATH`.
Mixed-language fixtures start the Go node with `laneway node run`.

On disposable Linux hosts, the Go network-helper client tests accept
`LANEWAY_TEST_HELPER` pointing to the standalone Rust `laneway` binary.
With `LANEWAY_PRIVILEGED_TEST=1` they exercise real TUN descriptor transfer,
route restoration and process death. The macOS release workflow runs the
Go client against the staged Rust helper and checks utun packet delivery
and route cleanup before uploading the release artifact.

In a disposable loopback-only Linux network namespace, run
`python3 integration/linux-network-helper.py /path/to/laneway --exit` to
exercise split routes, crash recovery and live exit policy refresh. Use
`--resolved` where a private systemd-resolved and D-Bus instance run in the
same namespace to check per-link DNS restoration and external changes.

Collect kernel benchmark JSONL from the main Linux gate with an absolute path:

```sh
sudo env PATH="$PATH" HOME="$HOME" LANEWAY_RUN_PRIVILEGED=1 \
  LANEWAY_KERNEL_BENCHMARK_OUTPUT=/absolute/path/results.jsonl \
  ./integration/linux-netns.sh
```

## Docker Connector

```sh
docker build --file deploy/containers/Dockerfile.connector \
  --build-arg VERSION=ci --tag lane-edge:ci .
./integration/connector-bootstrap.sh lane-edge:ci
./integration/connector-upgrade.sh lane-edge:ci
```

These gates cover the scratch image, encrypted bootstrap, and replacement flow.

## Docker Exit Node

This gate also requires Docker, `jq`, and OpenSSL. It creates and removes
containers, networks, volumes, routes, and firewall state, so run it only on a
disposable Docker host:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-exit-node.sh
```

Cleanup is limited to resources carrying the gate's ownership label. Do not run
it on a shared Docker host.
