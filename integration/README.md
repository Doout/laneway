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

## Privileged Linux

These gates require root, `/dev/net/tun`, Go, `iproute2`, `iputils`, nftables,
and `sysctl`. The Rust gates also require Cargo.

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/linux-netns.sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-controller-node-netns.sh
```

The scripts skip unless `LANEWAY_RUN_PRIVILEGED=1` is set and remove their
temporary namespaces on exit. Add `LANEWAY_KEEP_INTEGRATION_WORK=1` to the
controller/Rust Node gate to retain failure logs.

Collect kernel benchmark JSONL from the main Linux gate with an absolute path:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 \
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
