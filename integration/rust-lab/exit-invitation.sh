#!/usr/bin/env bash
# Sourced by the isolated packet gate; no changes to host trust or DNS.

redeem_lab_invitation() {
  local exit_name="$1"
  # Only this process sees the fixture hostname and lab CA. TLS hostname and
  # certificate verification remain enabled, and no proxy is inherited.
  ip netns exec "${rust_ns}" unshare --mount --propagation private bash -eu -c '
    mount --bind "$1" /etc/hosts
    exec env -i PATH="$PATH" SSL_CERT_FILE="$2" SSL_CERT_DIR=/nonexistent "${@:3}"
  ' bash "${work_dir}/exit-lab.hosts" "${work_dir}/pki/ca.crt" \
    "${work_dir}/native-cli/laneway" node ephemeral-exit-prepare \
    --authority "${discovery_name}:9443" --runtime-dir "${systemd_runtime}" \
    --runtime-name "${systemd_unit%.service}" --name "${exit_name}" --token-fd 3 \
    3<"${systemd_sources}/invitation"
}

check_invited_systemd_exit() {
  local exit_name="borrowed-lab-exit" rust_id rust_key rust_overlay nat_pid route_id credential
  stage_systemd_exit
  if [[ ! -x "$work_dir/native-cli/laneway" ]]; then
    mkdir "$work_dir/native-cli"
    ln "$work_dir/rust-node" "$work_dir/native-cli/laneway"
  fi
  printf '%s %s\n' "${location_controller_ip}" "${discovery_name}" >"${work_dir}/exit-lab.hosts"
  (umask 077
    ip netns exec "${controller_ns}" "${work_dir}/laneway" controller enrollment-token issue \
      --network-id "${network_id}" --label borrowed-exit --expires-in 5m \
      --class ephemeral --session-lifetime 10m --exit-node --requested-name "${exit_name}" \
      "${management_connection[@]}" |
      jq -jer '.enrollment_token | select(type=="string" and length>0)' >"${systemd_sources}/invitation"
  )
  echo "==> redeem a real one-use exit invitation through authenticated Rust discovery"
  redeem_lab_invitation "${exit_name}" >"${work_dir}/exit-prepared.json"
  rust_id="$(jq -er --arg network "${network_id}" --arg name "${systemd_unit%.service}" '
    select(.network_id==$network and .runtime_name==$name) | .node_id | select(test("^[0-9a-f]{32}$"))
  ' "${work_dir}/exit-prepared.json")"
  for credential in ca.crt node.crt node.key wireguard.key laneway.toml; do
    [[ $(stat -c '%u:%a' "${systemd_runtime}/${credential}") == 0:400 ]]
    mv -- "${systemd_runtime}/${credential}" "${systemd_sources}/${credential}"
  done
  if redeem_lab_invitation "${exit_name}" >"${work_dir}/redeem-replay.log" 2>&1; then
    echo 'ERROR: controller accepted a used invitation' >&2
    return 1
  fi
  if ! grep -Fq 'enrollment code has already been used' "${work_dir}/redeem-replay.log"; then
    echo 'ERROR: replay did not get the expected used-invitation response' >&2
    sed -n '1,12p' "${work_dir}/redeem-replay.log" >&2
    return 1
  fi
  rm -- "${systemd_sources}/invitation"
  rust_key="$(base64 -w0 <"${systemd_sources}/wireguard.key" | wg pubkey)"
  prepare_lab_carrier
  start_staged_systemd_exit quic
  wait_relay_sessions 2
  verify_systemd_transport quic
  rust_overlay="$(ip -n "${rust_ns}" -j addr show dev lane0 |
    jq -er '.[0].addr_info[] | select(.family=="inet") | "\(.local)/\(.prefixlen)"')"
  route_id="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route list \
    --network-id "${network_id}" "${management_connection[@]}" |
    jq -er --arg id "${rust_id}" '.routes[] | select(.node_id==$id and .kind=="exit" and .state=="approved" and .prefix=="0.0.0.0/0") | .route_id')"
  [[ "${route_id}" =~ ^[0-9a-f]{32}$ ]]

  echo '==> forward an encrypted packet through the invited exit'
  start_process "${lan_ns}" "${work_dir}/invited-nat.log" \
    "${work_dir}/netprobe-stream" udp-server -listen 203.0.113.2:9793 -max-packets 16 -timeout 75s
  nat_pid="${last_pid}"
  wait_log "${nat_pid}" "${work_dir}/invited-nat.log" ready=udp-server
  ip netns exec "${gateway_ns}" wg set lane0 peer "${rust_key}" \
    allowed-ips "${rust_overlay},203.0.113.2/32"
  ip -n "${gateway_ns}" route add 203.0.113.2/32 dev lane0
  for _ in $(seq 1 10); do
    if ip netns exec "${gateway_ns}" "${work_dir}/netprobe-stream" udp-client \
      -target 203.0.113.2:9793 -message invited-exit-nat -timeout 1s; then break; fi
  done
  grep -Eq 'remote=203\.0\.113\.1:[0-9]+ payload=invited-exit-nat' "${work_dir}/invited-nat.log"
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node revoke \
    --node-id "${rust_id}" --reason invitation-packet-lab "${management_connection[@]}" >/dev/null
  wait_systemd_revocation
  if ip netns exec "${gateway_ns}" "${work_dir}/netprobe-stream" udp-client \
    -target 203.0.113.2:9793 -message revoked-exit -timeout 2s; then
    echo 'ERROR: the invited exit still forwarded after revocation' >&2
    return 1
  fi
  stop_process "${nat_pid}"
  stop_systemd_exit
  verify_lab_carrier_cleanup
  echo 'PASS: real invitation, installer carrier, protected Rust service, NAT and revocation'
}
