#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v go >/dev/null 2>&1; then
  cd "$repo_root/go"
  go test ./internal/dockerplugin
  go build ./cmd/laneway-docker-plugin
elif [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != 1 ]]; then
  echo "missing go" >&2
  exit 1
fi

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != 1 ]]; then
  printf '%s\n' 'docker-plugin: set LANEWAY_RUN_PRIVILEGED=1 for managed-plugin lifecycle tests'
  exit 0
fi

for command in docker ip nft; do command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }; done
work=$(mktemp -d)
plugin_ref="laneway/docker-plugin-test:$(date +%s)-$$"
cleanup() {
  docker network rm laneway-plugin-test >/dev/null 2>&1 || true
  docker network rm laneway-plugin-unauthorized >/dev/null 2>&1 || true
  docker network rm laneway-plugin-selective >/dev/null 2>&1 || true
  if ip -d link show dev lane0 2>/dev/null | grep -F 'alias laneway-docker-integration' >/dev/null; then
    ip link del dev lane0 >/dev/null 2>&1 || true
  fi
  docker plugin disable -f "$plugin_ref" >/dev/null 2>&1 || true
  docker plugin rm -f "$plugin_ref" >/dev/null 2>&1 || true
  find "$work" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

VERSION=integration "$repo_root/deploy/docker-plugin/build-rootfs.sh" "$work/plugin"
docker plugin create "$plugin_ref" "$work/plugin"
docker plugin enable "$plugin_ref"
docker network create --driver "$plugin_ref" --subnet 172.30.251.0/24 --gateway 172.30.251.1 --opt laneway.policy=direct laneway-plugin-test
docker run --rm --network laneway-plugin-test alpine:3.22 ip -4 address show dev eth0 | grep -F '172.30.251.'

# Docker-managed propagated state survives a plugin process restart. Existing
# owned bridge/firewall state is validated before the socket becomes ready.
docker plugin disable -f "$plugin_ref"
docker plugin enable "$plugin_ref"
docker run --rm --network laneway-plugin-test alpine:3.22 ip -4 address show dev eth0 | grep -F '172.30.251.'

# A Docker option is a policy request, never authority. Missing controller
# authorization must fail before creating any Linux object.
if docker network create --driver "$plugin_ref" --subnet 172.30.252.0/24 --gateway 172.30.252.1 \
  --opt laneway.policy=selective --opt laneway.egress-cidrs=10.1.0.0/16 laneway-plugin-unauthorized; then
  echo 'unauthorized selective network was accepted' >&2
  exit 1
fi
if docker network inspect laneway-plugin-unauthorized >/dev/null 2>&1; then
  echo 'failed authorization left a Docker network behind' >&2
  exit 1
fi

# Exercise real policy routing, conntrack-mark, nftables, and exact cleanup
# with a short-lived controller-style lease and a disposable tunnel device.
plugin_id=$(docker plugin inspect --format '{{.ID}}' "$plugin_ref")
plugin_state="/var/lib/docker/plugins/$plugin_id/propagated-mount"
test -d "$plugin_state"
valid_until=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')
install -m 0600 /dev/null "$plugin_state/controller-authorization-v1.json"
sed "s/VALID_UNTIL/$valid_until/" > "$plugin_state/controller-authorization-v1.json" <<'EOF'
{"epoch":1,"valid_until":"VALID_UNTIL","container_subnets":["172.30.252.0/24"],"egress_cidrs":["10.1.0.0/16"],"ingress_sources":[],"exits":[],"bypass_cidrs":[]}
EOF
if ! ip link show dev lane0 >/dev/null 2>&1; then
  ip link add name lane0 type dummy
  ip link set dev lane0 alias laneway-docker-integration
  ip link set dev lane0 up
fi
docker network create --driver "$plugin_ref" --subnet 172.30.252.0/24 --gateway 172.30.252.1 \
  --opt laneway.policy=selective --opt laneway.egress-cidrs=10.1.0.0/16 laneway-plugin-selective
ip rule show | grep -F 'from 172.30.252.0/24 to 10.1.0.0/16'
docker run --rm --network laneway-plugin-selective alpine:3.22 ip -4 address show dev eth0 | grep -F '172.30.252.'
docker network rm laneway-plugin-selective
if ip -d link show dev lane0 2>/dev/null | grep -F 'alias laneway-docker-integration' >/dev/null; then
  ip link del dev lane0
fi
docker network rm laneway-plugin-test

test -z "$(ip -o link show | grep -F 'lwbr' || true)"
test -z "$(nft list tables | grep -F 'laneway_' || true)"
