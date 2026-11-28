# Integration tests

Run these commands from the repository root.

## Unprivileged

Run the Rust workspace and frontend contract checks:

```sh
make test
make proto-check
make management-api-check
```

The [rootless client guide](../docs/rootless.md#run-the-linux-integration-test)
explains how to test the packaged binary as an ordinary Linux user.

## Privileged Linux

Run on an isolated Linux host with Cargo, `/dev/net/tun`, iproute2, nftables,
iputils, and jq. The tests create disposable network namespaces:

```sh
sudo env PATH="$PATH" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh
sudo env PATH="$PATH" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh
sudo env PATH="$PATH" LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-controller-node-netns.sh
```

Add `LANEWAY_NODE_TEST_PRIVATE_DNS=1` to the controller and node test to
exercise private DNS. Use `LANEWAY_KEEP_INTEGRATION_WORK=1` to keep its
working directory and logs after a failure.

Docker Exit Node and network plugin tests also require Docker and modify
networking inside the test lab. Run them on a disposable Docker host:

```sh
sudo env PATH="$PATH" LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-exit-node.sh
sudo env PATH="$PATH" LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-plugin.sh
```

## Docker Connector

Build the same Edge target that the release workflow publishes:

```sh
docker build --file deploy/containers/Dockerfile.exit-node --target edge \
  --build-arg VERSION=0.0.0 --tag laneway-edge:dev .
./integration/connector-bootstrap.sh laneway-edge:dev

docker build --tag laneway-rust-lab:local integration/rust-lab
bash integration/rust-lab/connector-cutover.sh --prime-cache
bash integration/rust-lab/connector-cutover.sh --fresh laneway-edge:dev
bash integration/rust-lab/connector-cutover.sh --fresh laneway-edge:dev tcp-fallback
```

These checks cover encrypted one-time bootstrap and restart with the enrolled
identity over QUIC and TCP fallback. The release workflow separately tests
the signed installation, Exit Node forwarding, and encrypted recovery.
