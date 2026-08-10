# Laneway

Laneway connects clients to Linux hosts and private networks through an
encrypted IP overlay. Applications use normal IP addresses without a proxy.
Direct QUIC is preferred; an authenticated relay provides fallback.

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

Create a Connector invitation:

```sh
sudo laneway control invite --name office --docker --connector
```

Run the generated `docker run` command as root on a Linux Docker host that can
reach the private network. The Connector needs no inbound port, TUN device, or
Linux capability.

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
