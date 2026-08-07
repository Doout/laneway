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
LANEWAY_BIND_ADDRESS=127.0.0.1 \
LANEWAY_CONTROLLER_PORT=18443 \
LANEWAY_RELAY_QUIC_PORT=14433 \
LANEWAY_RELAY_TCP_PORT=10443 \
LANEWAY_CONTROLLER_SERVER_NAME=controller.example.test \
docker compose --project-directory "$repo_dir/deploy/compose" \
  --env-file /dev/null --profile tools -f "$compose_file" config --format json |
jq -e '
  (.services | keys | sort) == ["admin", "controller", "relay"] and
  ([.services[] | .user == "65532:65532"] | all) and
  ([.services[] | .read_only == true] | all) and
  ([.services[] | .cap_drop == ["ALL"]] | all) and
  ([.services[] | .security_opt == ["no-new-privileges:true"]] | all) and
  ([.services[] | (.privileged // false) == false] | all) and
  ([.services[] | (.network_mode // "") != "host"] | all) and
  ([.services[] | .image | endswith(":1.2.3")] | all) and
  (.services.controller.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "18443" and .protocol == "tcp")) and
  (.services.controller.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "18443" and .protocol == "udp")) and
  (.services.relay.ports | any(.host_ip == "127.0.0.1" and .target == 4433 and .published == "14433" and .protocol == "udp")) and
  (.services.relay.ports | any(.host_ip == "127.0.0.1" and .target == 8443 and .published == "10443" and .protocol == "tcp")) and
  (.services.controller.volumes | any(.type == "volume" and .target == "/var/lib/laneway-controller")) and
  ([.services.controller.volumes[] | select(.type == "bind") | .read_only == true] | all) and
  ([.services.relay.volumes[] | select(.type == "bind") | .read_only == true] | all) and
  (.services.controller.healthcheck.test[-1] == "controller.example.test") and
  (.services.relay.healthcheck.test[0] == "CMD")
' >/dev/null

echo "Compose security and port contract is valid"
