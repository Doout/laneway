#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != 1 ]]; then
  cargo test --locked --manifest-path "$repo_root/rust/Cargo.toml" -p laneway-docker-plugin
  printf '%s\n' 'docker-plugin: set LANEWAY_RUN_PRIVILEGED=1 for managed-plugin lifecycle tests'
  exit 0
fi

for command in docker ip nft iptables ping; do command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }; done
if ip link show dev lane0 >/dev/null 2>&1; then
  echo 'managed-plugin test requires its own lane0 on an isolated host' >&2
  exit 1
fi
work=$(mktemp -d)
run_id="$(date +%s)-$$"
plugin_ref="laneway/docker-plugin-test:$run_id"
test_client="laneway-plugin-client-$$"
remote_ns="laneway-plugin-remote-$$"
link_alias="laneway-docker-integration-$$"
test_bridge=
test_host_firewall() {
  # Accept only this probe and its replies through the host's Docker firewall.
  # Laneway's separate nftables forward chain still enforces the lease.
  local op=$1 result=0
  iptables -w 5 "$op" DOCKER-USER -i "$test_bridge" -o lane0 \
    -s 172.30.252.0/24 -d 198.51.100.2/32 -p icmp --icmp-type echo-request \
    -m comment --comment "$link_alias" -j ACCEPT || result=$?
  iptables -w 5 "$op" DOCKER-USER -i lane0 -o "$test_bridge" \
    -s 198.51.100.2/32 -d 172.30.252.0/24 -p icmp --icmp-type echo-reply \
    -m comment --comment "$link_alias" -j ACCEPT || result=$?
  return "$result"
}
cleanup() {
  if [[ -n "$test_bridge" ]]; then
    test_host_firewall -D >/dev/null 2>&1 || true
  fi
  if [[ "$(docker plugin inspect --format '{{.Enabled}}' "$plugin_ref" 2>/dev/null)" == false ]]; then
    docker plugin enable "$plugin_ref" >/dev/null 2>&1 || true
  fi
  docker rm -f "$test_client" >/dev/null 2>&1 || true
  docker network rm laneway-plugin-test >/dev/null 2>&1 || true
  docker network rm laneway-plugin-unauthorized >/dev/null 2>&1 || true
  docker network rm laneway-plugin-selective >/dev/null 2>&1 || true
  if ip -d link show dev lane0 2>/dev/null | grep -Fq "alias $link_alias"; then
    ip link del dev lane0 >/dev/null 2>&1 || true
  fi
  ip netns delete "$remote_ns" >/dev/null 2>&1 || true
  docker plugin disable -f "$plugin_ref" >/dev/null 2>&1 || true
  docker plugin rm -f "$plugin_ref" >/dev/null 2>&1 || true
  find "$work" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

VERSION=integration "$repo_root/deploy/docker-plugin/build-rootfs.sh" "$work/plugin"
docker plugin create "$plugin_ref" "$work/plugin"
docker plugin enable "$plugin_ref"
docker network create --driver "$plugin_ref" --subnet 172.30.251.0/24 --gateway 172.30.251.1 --opt laneway.policy=direct laneway-plugin-test >/dev/null
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
docker_root=$(docker info --format '{{.DockerRootDir}}')
plugin_state="$docker_root/plugins/$plugin_id/propagated-mount"
test -d "$plugin_state"
write_grant() {
  local valid_until staged
  valid_until=$(date -u -d "$1" '+%Y-%m-%dT%H:%M:%SZ')
  staged=$(mktemp "$plugin_state/.integration-grant.XXXXXX")
  sed "s/VALID_UNTIL/$valid_until/" > "$staged" <<'EOF'
{"epoch":1,"valid_until":"VALID_UNTIL","container_subnets":["172.30.252.0/24"],"egress_cidrs":["198.51.100.0/24"],"ingress_sources":[],"exits":[],"bypass_cidrs":[]}
EOF
  mv "$staged" "$plugin_state/controller-authorization-v1.json"
}
write_grant '+1 hour'
ip netns add "$remote_ns"
ip link add lane0 type veth peer name lanepeer
ip link set dev lane0 alias "$link_alias"
ip link set dev lanepeer netns "$remote_ns"
ip -n "$remote_ns" addr add 198.51.100.2/24 dev lanepeer
ip -n "$remote_ns" link set dev lanepeer up
ip -n "$remote_ns" route add 172.30.252.0/24 via 198.51.100.1
ip addr add 198.51.100.1/24 dev lane0
ip link set dev lane0 up
selective_id=$(docker network create --driver "$plugin_ref" --subnet 172.30.252.0/24 --gateway 172.30.252.1 \
  --opt laneway.policy=selective --opt laneway.egress-cidrs=198.51.100.0/24 laneway-plugin-selective)
ip rule show | grep -F 'from 172.30.252.0/24 to 198.51.100.0/24'
docker run --detach --name "$test_client" --network laneway-plugin-selective alpine:3.22 sleep 180
docker exec "$test_client" ip -4 address show dev eth0 | grep -F '172.30.252.'
if iptables -w 5 -S FORWARD | grep -Fx -- '-P FORWARD DROP' >/dev/null; then
  bridge_hash=$(printf '%s' "$selective_id" | sha256sum)
  test_bridge="lwbr${bridge_hash:0:10}"
  test_host_firewall -I
fi
probe() { docker exec "${1:-$test_client}" ping -c 1 -W 1 198.51.100.2; }
probe
write_grant '+6 seconds'
sleep 7
# Verify the peer is still reachable on the host and that the existing
# container's original network namespace loses only its forwarding grant.
ping -c 1 -W 1 198.51.100.2
docker exec "$test_client" true
if probe; then
  echo 'container kept forwarding after its authorization expired' >&2
  exit 1
fi
write_grant '+1 hour'
restored=false
for _ in {1..6}; do
  if probe; then
    restored=true
    break
  fi
  sleep 1
done
if [[ "$restored" != true ]]; then
  echo 'renewing the grant did not restore the running container connection' >&2
  exit 1
fi
docker plugin disable -f "$plugin_ref"
docker plugin enable "$plugin_ref"
probe
if [[ -n "$test_bridge" ]]; then
  test_host_firewall -D
  test_bridge=
fi
docker rm -f "$test_client"
docker network rm laneway-plugin-selective
if ip -d link show dev lane0 2>/dev/null | grep -Fq "alias $link_alias"; then
  ip link del dev lane0
fi
docker network rm laneway-plugin-test

test -z "$(ip -o link show | grep -F 'lwbr' || true)"
test -z "$(nft list tables | grep -F 'laneway_' || true)"
test -z "$(ip -4 rule show | grep -F '172.30.252.0/24' || true)"
