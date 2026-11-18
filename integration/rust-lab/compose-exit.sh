#!/usr/bin/env bash
# Sourced by compose-cutover.sh after its disposable-VM guard.
# shellcheck disable=SC2034,SC2154

prepare_compose_exit() {
  netprobe_path=${LANEWAY_TEST_COMPOSE_NETPROBE:?point to the native, static Go netprobe test binary}
  [[ $netprobe_path == /* && -f $netprobe_path && -x $netprobe_path ]]
  docker image inspect laneway-go-exit:compose-cutover-lab alpine:3.22 >/dev/null
  target=192.168.77.25
  client_container="$project-exit-client"
  target_container="$project-exit-target"
  exit_overlay=(-f exit-lab.yaml)
  cat >exit-lab.yaml <<'EOF'
services:
  exit-node:
    image: laneway-go-exit:compose-cutover-lab
    restart: "no"
    networks:
      control:
        interface_name: eth1
      exit-lan:
        interface_name: eth0
networks:
  exit-lan:
    internal: true
    ipam:
      config:
        - subnet: 192.168.77.0/24
EOF
}

clean_compose_exit() {
  local container
  if (( $1 != 0 )); then
    rust_compose logs --no-color --tail=30 exit-node >&2 || true
    for container in "$client_container" "$target_container"; do
      if docker container inspect "$container" >/dev/null 2>&1; then docker logs --tail 30 "$container" >&2; fi
    done
  fi
  docker rm -f "$client_container" "$target_container" >/dev/null 2>&1 || true
}

compose_exit_join() {
  local node_name=$1 prefix=$2
  admin enrollment-token issue --network-id "$network" --label "$node_name" --expires-in 10m |
    jq -er '.enrollment_token' >"$work/join.token"
  chmod 0600 "$work/join.token"
  docker run --rm --pull never --network "${project}_control" --user 0:0 \
    -v "$work:$work" -w "$PWD" laneway-go-admin:compose-cutover-lab join \
    --token-file "$work/join.token" --controller https://controller:8443 \
    --ca "$base/generated/pki/ca.crt" --server-name "$name" \
    --controller-network-id "$network" --controller-service-id "$controller" --name "$node_name" \
    --out-cert "$prefix.crt" --out-key "$prefix.key" --out-wireguard-key "$prefix.wg"
}

enroll_compose_exit() {
  local config=generated/config/exit-node.toml client_dir="$work/exit-client" joined route
  sed -e "s/REPLACE_NETWORK_ID/$network/g" \
    -e "s/REPLACE_RELAY_SERVICE_ID/$relay/g" -e "s/REPLACE_CONTROLLER_SERVICE_ID/$controller/g" \
    -e "s/relay.example.com/$name/g" -e "s/controller.example.com/$name/g" \
    -e 's/"30s"/"1s"/g' "$root/deploy/compose/generated/config/exit-node.toml.example" >"$config"
  joined=$(compose_exit_join exit-node "$base/generated/pki/exit-node")
  gateway=$(sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p' <<<"$joined")
  [[ $gateway =~ ^[0-9a-f]{32}$ ]]
  chown 65532:65532 generated/pki/exit-node.{crt,key}
  chmod 0400 generated/pki/exit-node.key
  admin node capabilities --node-id "$gateway" --exit-node >/dev/null
  route=$(base_compose run --rm --no-deps --pull never -T --entrypoint /usr/local/bin/laneway \
    exit-node exit enable --family ipv4 --config /etc/laneway/exit-node.toml |
    jq -er '.advertisements[0].route_id')
  admin route approve --route-id "$route" >/dev/null
  admin acl add --network-id "$network" --priority 100 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description compose-exit-fixture >/dev/null
  mkdir -m 0700 "$client_dir"
  compose_exit_join exit-client "$client_dir/node" >/dev/null
  cp generated/pki/ca.crt "$client_dir/ca.crt"
  sed -e 's@/run/laneway-secrets/exit-node@/fixture/node@g' \
    -e 's@/run/laneway-secrets/ca.crt@/fixture/ca.crt@' \
    -e 's@/var/lib/laneway@/tmp/state@' -e 's@/run/laneway/lanewayd.sock@/tmp/client.sock@' \
    -e 's/name = "exit-node"/name = "exit-client"/' -e 's/serve = true/serve = false/' \
    "$config" >"$client_dir/node.toml"
  printf 'dns_servers = ["%s"]\n' "$target" >>"$client_dir/node.toml"
  # Go requires a systemd-resolved interface even for these IP-only probes.
  # Keep its fixture state within the disposable client; never change host DNS.
  cat >"$client_dir/resolvectl" <<'EOF'
#!/bin/sh
set -eu
command=$1 interface=$2
test "$interface" = lane0
case "$command" in
  revert) rm -f /tmp/resolver-dns /tmp/resolver-domain /tmp/resolver-default-route ;;
  dns|domain|default-route)
    shift 2
    file="/tmp/resolver-$command"
    if [ "$#" -gt 0 ]; then
      printf '%s\n' "$*" >"$file"
    else
      value=""
      if [ -f "$file" ]; then value=$(cat "$file"); fi
      printf 'Link 1 (%s): %s\n' "$interface" "$value"
    fi ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$client_dir/resolvectl"
  docker run -d --pull never --name "$client_container" --network "${project}_control" \
    --user 0:0 --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$client_dir:/fixture:ro" -v "$client_dir/resolvectl:/usr/bin/resolvectl:ro" \
    -v "$netprobe_path:/netprobe:ro" --entrypoint /usr/local/bin/laneway \
    laneway-go-exit:compose-cutover-lab node run --config /fixture/node.toml >/dev/null
  # The client has no route to the target on the other internal bridge.
  if docker exec "$client_container" ip route get "$target" >"$work/direct-route.out" 2>&1; then
    echo "fixture can bypass the exit" >&2
    return 1
  fi
  sha256sum "$config" generated/pki/exit-node.{crt,key} >"$work/exit-inputs.sha256"
}

test_compose_exit() {
  local compose=$1 stage=$2 port=$3 id address status endpoint ready=0
  echo "==> verify Compose exit NAT: $stage"
  "$compose" up --no-deps --pull never -d exit-node --wait --wait-timeout 35
  id=$("$compose" ps -q exit-node)
  [[ $(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/laneway"}}{{.Name}}{{end}}{{end}}' "$id") == "$project-exit" ]]
  [[ $(docker inspect -f '{{.Config.Image}}' "$id") == "$(
    if [[ $stage == rust-cutover ]]; then echo laneway-rust-exit:0.0.9100-lab; else echo laneway-go-exit:compose-cutover-lab; fi
  )" ]]
  if [[ $stage == go-baseline ]]; then
    "$compose" exec -T exit-node sh -c 'printf "%s\n" preserved >/var/lib/laneway/rollback-marker'
    for _ in {1..40}; do
      if docker exec "$client_container" /usr/local/bin/laneway exit use "$gateway" --socket /tmp/client.sock \
        >"$work/select-exit.out" 2>&1; then ready=1; break; fi
      sleep 0.25
    done
    if (( ! ready )); then cat "$work/select-exit.out" >&2; return 1; fi
  fi
  "$compose" exec -T exit-node grep -qx preserved /var/lib/laneway/rollback-marker
  sha256sum --check --status "$work/exit-inputs.sha256"
  for _ in {1..40}; do
    if status=$("$compose" exec -T exit-node /usr/local/bin/laneway status --socket /run/laneway/lanewayd.sock -json) &&
      jq -e --arg id "$gateway" '.node_id == $id and .exit.serving and .exit.nat_ready' <<<"$status" >/dev/null; then
      ready=1
      break
    fi
    ready=0
    sleep 0.25
  done
  (( ready ))
  address=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${project}_exit-lan\").IPAddress}}" "$id")
  docker run -d --pull never --name "$target_container" --network "${project}_exit-lan" --ip "$target" \
    -v "$netprobe_path:/netprobe:ro" alpine:3.22 /netprobe udp-server -listen "$target:$port" >/dev/null
  for _ in {1..30}; do
    if docker logs "$target_container" 2>&1 | grep -qF ready=udp-server; then break; fi
    sleep 0.2
  done
  if ! docker exec "$client_container" /netprobe udp-client -target "$target:$port" -message "$stage" -timeout 15s; then
    "$compose" exec -T exit-node ip route get "$target" >&2 || true
    for endpoint in "$id:/run/laneway/lanewayd.sock" "$client_container:/tmp/client.sock"; do
      docker exec "${endpoint%%:*}" /usr/local/bin/laneway status --socket "${endpoint#*:}" -json |
        jq '{selected_path, metrics, controller, exit}' >&2 || true
    done
    return 1
  fi
  [[ $(timeout 10 docker wait "$target_container") == 0 ]]
  docker logs "$target_container" | grep -F "remote=$address:"
  docker rm "$target_container" >/dev/null
}
