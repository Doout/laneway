# Laneway

Laneway connects clients to hosts and private networks through an encrypted IP
overlay. A full node routes applications transparently and supports direct QUIC
and relay fallback. The [`lanewayd` node](docs/rootless.md) runs by default as an
ordinary user, serves approved TCP and UDP destinations, and offers a local
authenticated SOCKS5 proxy over the relay.

## Configure and start

With the client installed and a native setup invitation from your administrator, run:

```sh
laneway configure
laneway start
```

Paste the invitation at the prompt. The first setup prints a password for the local SOCKS5 proxy on `127.0.0.1:1080`. Repeat configuration keeps your identity and credentials. On Linux, use `sudo laneway configure --system` and `sudo laneway start --system` for host networking. [Installation and node setup](docs/rootless.md)

Run `laneway update` to update the local installation. On a managed Docker host use `sudo laneway update server` for the control plane or `sudo laneway update connector office` for a named connector. [Updates and operations](docs/operations.md)

## Quick start

This setup connects a laptop to a private subnet through an unprivileged Docker
Connector.

You need a Linux control-plane host with Docker Engine 26+, Docker Compose v2,
`age`, and `age-keygen`; a public DNS name for that host; and inbound TCP+UDP
`8443`, UDP `4433`, and TCP `443`.

### 1. Deploy the control plane

Replace the domain and run this on the control-plane host:

```sh
export LANEWAY_DOMAIN=lane.example.com; curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install.sh | sudo env LANEWAY_DOMAIN="$LANEWAY_DOMAIN" bash
```

Copy the printed recovery-kit directory off the server, then verify the
deployment:

```sh
sudo laneway control production-check
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
single-use; enrollment starts a clean scratch `lane-edge` container with no
setup token or key. The Connector needs no inbound port, TUN device, or Linux
capability.

### 3. Enroll a client

Install the same Laneway package on Linux or macOS:

```sh
curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install.sh | bash
```

Create a login token on the control-plane host:

```sh
sudo laneway control user-token --name laptop
```

Then enter that token from the client:

```sh
laneway login lane.example.com
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
laneway connect
```

Only approved private prefixes use Laneway. Docker Connectors support TCP and
UDP, not ICMP; test with a reachable service such as
`curl http://10.0.0.10:8080`, not `ping`.

## Documentation

- [Control-plane deployment and recovery](deploy/compose/README.md)
- [Operations and troubleshooting](docs/operations.md)
- [Protocol specifications](spec/)
- [Security reporting](SECURITY.md)

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
