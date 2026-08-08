#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "docker compose v2 is required" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
compose_file=$repo_dir/deploy/compose/compose.yaml

LANEWAY_VERSION=1.2.3 \
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111 \
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222 \
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333 \
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444 \
LANEWAY_BIND_ADDRESS=127.0.0.1 \
LANEWAY_CONTROLLER_PORT=18443 \
LANEWAY_RELAY_QUIC_PORT=14433 \
LANEWAY_RELAY_TCP_PORT=10443 \
LANEWAY_EXIT_DIRECT_PORT=14434 \
LANEWAY_CONTROLLER_SERVER_NAME=controller.example.test \
docker compose --project-directory "$repo_dir/deploy/compose" \
  --env-file /dev/null --profile tools --profile exit-node -f "$compose_file" config --format json |
jq -e '
  (.services | keys | sort) == ["admin", "controller", "exit-node", "relay"] and
  ([.services[] | .user == "65532:65532"] | all) and
  ([.services[] | .read_only == true] | all) and
  ([.services[] | .cap_drop == ["ALL"]] | all) and
  ([.services[] | .security_opt == ["no-new-privileges:true"]] | all) and
  ([.services[] | (.privileged // false) == false] | all) and
  ([.services[] | (.network_mode // "") != "host"] | all) and
  (.services.controller.image == "ghcr.io/doout/laneway-controller:1.2.3@sha256:1111111111111111111111111111111111111111111111111111111111111111") and
  (.services.relay.image == "ghcr.io/doout/laneway-relay:1.2.3@sha256:2222222222222222222222222222222222222222222222222222222222222222") and
  (.services.admin.image == "ghcr.io/doout/laneway-admin:1.2.3@sha256:3333333333333333333333333333333333333333333333333333333333333333") and
  (.services["exit-node"].image == "ghcr.io/doout/laneway-exit-node:1.2.3@sha256:4444444444444444444444444444444444444444444444444444444444444444") and
  (.services.controller.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "18443" and .protocol == "tcp")) and
  (.services.controller.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "18443" and .protocol == "udp")) and
  (.services.relay.ports | any(.host_ip == "127.0.0.1" and .target == 4433 and .published == "14433" and .protocol == "udp")) and
  (.services.relay.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "10443" and .protocol == "tcp")) and
  (.services["exit-node"].ports | any(.host_ip == "127.0.0.1" and .target == 4434 and .published == "14434" and .protocol == "udp")) and
  (.services["exit-node"].cap_add == ["NET_ADMIN"]) and
  (.services["exit-node"].devices | any(.source == "/dev/net/tun" and .target == "/dev/net/tun" and .permissions == "rwm")) and
  (.services["exit-node"].sysctls["net.ipv4.ip_forward"] == "1") and
  (.services["exit-node"].sysctls["net.ipv6.conf.all.forwarding"] == "1") and
  (.services["exit-node"].volumes | any(.type == "volume" and .target == "/var/lib/laneway")) and
  ([.services["exit-node"].volumes[] | select(.type == "bind") | .read_only == true] | all) and
  (.services["exit-node"].healthcheck.test == ["CMD", "/usr/local/bin/laneway-healthcheck", "-unix", "/run/laneway/lanewayd.sock"]) and
  (.services.controller.volumes | any(.type == "volume" and .target == "/var/lib/laneway-controller")) and
  (.services.controller.volumes | any(.type == "bind" and .target == "/backups" and ((.read_only // false) == false))) and
  ([.services.controller.volumes[] | select(.type == "bind" and .target != "/backups") | .read_only == true] | all) and
  ([.services.relay.volumes[] | select(.type == "bind") | .read_only == true] | all) and
  (.services.controller.healthcheck.test[-1] == "controller.example.test") and
  (.services.relay.healthcheck.test[0] == "CMD")
' >/dev/null

echo "Compose security and port contract is valid"
