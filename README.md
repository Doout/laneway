# Laneway

Laneway connects clients to Linux hosts and private networks through an
encrypted IP overlay. The rootless client exposes an authenticated SOCKS5 proxy
on loopback. System clients can route traffic directly through a tunnel.

## Quick start

This setup connects a laptop to a private subnet through an unprivileged Docker
Connector.

You need a Linux control-plane host with Docker Engine 26+, Docker Compose v2,
`age`, and `age-keygen`; a public DNS name for that host; and inbound TCP+UDP
`8443`, UDP `4433`, and TCP `443`.

### 1. Deploy the control plane

Replace the domain and use a signed release tag. This example pins v0.3.12.
Run it on the control-plane host:

```sh
version=v0.3.12
curl -fsSL "https://github.com/Doout/laneway/releases/download/$version/install.sh" |
  sudo env LANEWAY_VERSION="$version" LANEWAY_DOMAIN=lane.example.com sh
```

Copy the printed recovery-kit directory off the server, then verify the
deployment:

```sh
sudo laneway control readiness
```

The installer does not change DNS, firewall rules, routes, interfaces, or
sysctls.

### 2. Add a private network

Create a one-time Connector invitation:

```sh
sudo laneway control invite --name office --docker --connector --bootstrap
```

Run the generated `curl | sudo bash` command within ten minutes on a Linux
Docker host that can reach the private network. Its encrypted payload is
single-use. Enrollment starts the signed `ghcr.io/doout/laneway/edge` image
with no setup token or key. The Connector needs no inbound port, TUN device,
or Linux capability.

### 3. Enroll a client

For an ordinary user account, follow the [rootless client guide](docs/rootless.md).
A fresh client install defaults to this mode.

To follow the system tunnel example below, install the system client on Linux or macOS:

```sh
version=v0.3.12
curl -fsSL "https://github.com/Doout/laneway/releases/download/$version/install.sh" |
  env LANEWAY_VERSION="$version" sh -s -- --system
```

Create a login token on the control-plane host:

```sh
sudo laneway control user-token --name laptop
```

Then enter that token from the client. On Linux, use `sudo` for both `login`
and `connect` to keep the saved login and temporary network setup under the
same account. On macOS, run the same commands without `sudo`.

```sh
sudo laneway login lane.example.com
```

### 4. Allow traffic and connect

After the Connector and client have enrolled, run this on the control-plane
host:

```sh
sudo laneway control route add \
  --connector office \
  --to 10.0.0.0/24 \
  --allow laptop
```

Connect from the client:

```sh
sudo laneway connect
```

Only approved private prefixes use Laneway. Docker Connectors support TCP and
UDP, not ICMP; test with a reachable service such as
`curl http://10.0.0.10:8080`, not `ping`.

## Documentation

- [Control-plane deployment and recovery](https://github.com/Doout/laneway/blob/main/deploy/compose/README.md)
- [Rootless SOCKS5 client](docs/rootless.md)
- [Operations and troubleshooting](docs/operations.md)
- [Protocol specifications](https://github.com/Doout/laneway/tree/main/spec)
- [Build and test from source](https://github.com/Doout/laneway/blob/main/rust/README.md)
- [Security reporting](SECURITY.md)

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
