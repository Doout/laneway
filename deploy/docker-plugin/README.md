# Laneway managed Docker network plugin

Build a local managed-plugin package with:

```sh
make docker-plugin-rootfs VERSION=0.1.0
docker plugin create laneway:dev dist/docker-plugin
docker plugin enable laneway:dev
```

Published releases use independent `docker-plugin/vX.Y.Z` source tags and are installed with:

```sh
docker plugin install --alias laneway --grant-all-permissions ghcr.io/doout/laneway-docker-plugin:X.Y.Z
```

The grant permits host network administration, host networking, and access to `/dev/net/tun`. Install it only on a trusted Linux Docker Engine host. It does not mount the Docker socket or all host devices.

A direct network can be created immediately:

```sh
docker network create --driver laneway \
  --subnet 172.30.50.0/24 --gateway 172.30.50.1 \
  --opt laneway.policy=direct private-services
```

Selective, full-tunnel, isolated-with-destinations, and routed ingress policies additionally require a current controller lease in the plugin-owned `/data/controller-authorization-v1.json`. The embedded driver treats this as a complete control-plane snapshot and will not derive authority from Docker options. The snapshot is written by the Laneway controller participation layer and is intentionally not an operator-editable configuration interface.

Compose uses the same network-level options:

```yaml
services:
  app:
    image: example/service
    networks: [private]
networks:
  private:
    driver: laneway
    ipam:
      config:
        - subnet: 172.30.50.0/24
          gateway: 172.30.50.1
    driver_opts:
      laneway.policy: selective
      laneway.egress-cidrs: 10.1.0.0/16
      laneway.ingress: established
```

Before upgrade or removal, delete attached containers and Docker networks. Then run `docker plugin disable laneway` followed by `docker plugin upgrade laneway ghcr.io/doout/laneway-docker-plugin:NEW_VERSION`, or `docker plugin rm laneway`. Docker preserves the propagated `/data` state across upgrades. Do not force-remove a plugin with live networks; reinstall the same plugin and delete those networks so recorded state can be cleaned exactly.
