#!/usr/bin/env bash
# Sourced only by the marked systemd VM packet fixture.
# shellcheck disable=SC2154
packaged_node_owned=false
packaged_node_user=false
packaged_node_group=false
packaged_node_started=false
packaged_relay_started=false
packaged_node_unit=/run/systemd/system/lanewayd-rs.service
packaged_node_dropin=/run/systemd/system/lanewayd-rs.service.d
packaged_relay_unit=/run/systemd/system/laneway-relay-rs.service
packaged_relay_dropin=/run/systemd/system/laneway-relay-rs.service.d
packaged_relay_log=/run/laneway-relay-fixture.log
if [[ $managed_invitation == 1 ]]; then
  packaged_node_unit=/usr/local/lib/systemd/system/lanewayd-rs.service
fi

cleanup_packaged_node() {
  [[ $packaged_node_owned == true ]] || return 0
  if [[ $packaged_node_started == true ]]; then
    systemctl stop lanewayd-rs.service || {
      echo 'Cannot stop the fixture unit; retain its files for lab inspection' >&2
      return 1
    }
    packaged_node_started=false
  fi
  systemctl reset-failed lanewayd-rs.service 2>/dev/null || true
  if [[ $packaged_relay_started == true ]]; then
    systemctl stop laneway-relay-rs.service || {
      echo 'Cannot stop the fixture relay; retain its files for lab inspection' >&2
      return 1
    }
    packaged_relay_started=false
  fi
  if [[ $packaged_relay == 1 ]]; then
    systemctl reset-failed laneway-relay-rs.service 2>/dev/null || true
    for path in "$packaged_relay_unit" "$packaged_relay_dropin" "$packaged_relay_log" \
      /usr/local/sbin/laneway-relay-rs /var/lib/laneway-relay /run/laneway-relay; do
      if [[ -e "$path" ]]; then find "$path" -depth -delete; fi
    done
  fi
  if [[ $managed_invitation == 1 ]]; then
    for path in /usr/local/bin/laneway /usr/local/sbin/laneway-healthcheck-rs; do
      if [[ -e "$path" ]]; then find "$path" -maxdepth 0 -delete; fi
    done
  fi
  for path in "$packaged_node_unit" "$packaged_node_dropin" /usr/local/sbin/lanewayd-rs \
    /etc/laneway /run/laneway /var/lib/laneway; do
    if [[ -e "$path" ]]; then find "$path" -depth -delete; fi
  done
  systemctl daemon-reload
  if [[ $packaged_node_user == true ]]; then userdel laneway; fi
  if [[ $packaged_node_group == true ]] && getent group laneway >/dev/null; then groupdel laneway; fi
  packaged_node_owned=false
}

start_packaged_relay() {
  local installed="$packaged_node/usr/local" seed="$work_dir/relay-seed" pid hashes old_leaf relay_leaf
  local log="$packaged_relay_log" renewed=/var/lib/laneway-relay/workload/relay-service.pem
  "$work_dir/laneway" pki relay --ca-cert "$work_dir/pki/ca.crt" --ca-key "$work_dir/pki/ca.key" \
    --network-id "$network_id" --service-id "$relay_service" --ip 10.254.0.2 --validity 39s \
    --out-cert "$seed.crt" --out-key "$seed.key" >/dev/null
  install -m 0440 -o root -g laneway "$seed.crt" /etc/laneway/relay.crt
  install -m 0440 -o root -g laneway "$seed.key" /etc/laneway/relay.key
  install -m 0440 -o root -g laneway "$work_dir/pki/ca.crt" /etc/laneway/relay-ca.crt
  hashes=$(sha256sum /etc/laneway/relay.{crt,key})
  old_leaf=$(openssl x509 -noout -serial -in /etc/laneway/relay.crt)
  install -m 0755 "$installed/sbin/laneway-relay-rs" /usr/local/sbin/laneway-relay-rs
  install -m 0644 "$installed/lib/systemd/system/laneway-relay-rs.service" "$packaged_relay_unit"
  mkdir "$packaged_relay_dropin"
  sed -e "s@$work_dir/relay-state@/var/lib/laneway-relay@" -e "s@$work_dir/relay.sock@/run/laneway-relay/relay.sock@" \
    -e "s@$work_dir/pki/relay.crt@/etc/laneway/relay.crt@" -e "s@$work_dir/pki/relay.key@/etc/laneway/relay.key@" \
    -e "s@$work_dir/pki/ca.crt@/etc/laneway/relay-ca.crt@" \
    -e '/^\[tls\]/a renewal_dir = "/var/lib/laneway-relay/workload"' \
    "$work_dir/relay.toml" >"$work_dir/installed-relay.toml"
  printf '\n[tcp_fallback]\nlisten = "10.254.0.2:8444"\n' >>"$work_dir/installed-relay.toml"
  install -m 0440 -o root -g laneway "$work_dir/installed-relay.toml" /etc/laneway/relay-rust.toml
  cat >"$packaged_relay_dropin/fixture.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/$relay_ns
Environment=RUST_LOG=info
StandardOutput=append:$log
StandardError=inherit
EOF
  systemctl daemon-reload
  packaged_relay_started=true
  systemctl start laneway-relay-rs.service
  pid=$(systemctl show --property=MainPID --value laneway-relay-rs.service)
  [[ $pid =~ ^[1-9][0-9]*$ ]]
  wait_log "$pid" "$log" 'renewed internal relay TLS certificate'
  [[ $(readlink "/proc/$pid/exe") == /usr/local/sbin/laneway-relay-rs &&
    $(awk '/^Uid:/ {print $3}' "/proc/$pid/status") == "$(id -u laneway)" ]]
  [[ $(sha256sum /etc/laneway/relay.{crt,key}) == "$hashes" &&
    $(stat -c '%u:%g:%a' "$renewed") == "$(id -u laneway):$(id -g laneway):600" ]]
  relay_leaf=$(openssl x509 -noout -serial -in "$renewed")
  [[ $relay_leaf != "$old_leaf" ]]
  # A client with a signed node certificate must receive that same replacement
  # leaf on a fresh connection; do not accept an on-disk-only renewal.
  ip netns exec "$gateway_ns" timeout 5 openssl s_client \
    -connect 10.254.0.2:8444 -alpn laneway-fallback/1 -verify_ip 10.254.0.2 -verify_return_error \
    -CAfile "$work_dir/pki/ca.crt" -cert "$work_dir/pki/gateway.crt" -key "$work_dir/pki/gateway.key" \
    </dev/null >"$work_dir/relay-handshake.log" 2>&1 ||
    { tail -30 "$work_dir/relay-handshake.log" >&2; return 1; }
  [[ $(openssl x509 -noout -serial -in "$work_dir/relay-handshake.log") == "$relay_leaf" ]]
  echo 'PASS: packaged systemd relay renewed its private workload bundle and served the replacement TLS leaf.'
}

run_managed_node_installer() {
  # Expand the positional arguments inside the isolated mount namespace.
  # shellcheck disable=SC2016
  ip netns exec "$rust_ns" unshare --mount --propagation private bash -eu -c '
    mount --bind "$1" /etc/hosts
    exec env -i PATH="$PATH" SSL_CERT_FILE="$2" SSL_CERT_DIR=/nonexistent "${@:3}"
  ' bash "$work_dir/managed-node.hosts" "$work_dir/pki/ca.crt" /usr/local/bin/laneway "$@"
}

check_invited_packaged_node() {
  local installed="$packaged_node/usr/local" token="$work_dir/managed-invitation" pid peer_pid node
  local cert=/var/lib/laneway/identity/node.crt
  install -m 0755 "$installed/bin/laneway" /usr/local/bin/laneway
  install -m 0755 "$installed/sbin/laneway-healthcheck-rs" /usr/local/sbin/laneway-healthcheck-rs
  mkdir -p -- "$(dirname "$packaged_node_unit")"
  install -m 0644 "$installed/lib/systemd/system/lanewayd-rs.service" "$packaged_node_unit"
  mkdir "$packaged_node_dropin"
  cat >"$packaged_node_dropin/fixture.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/$rust_ns
Environment=RUST_LOG=info
StandardOutput=append:/var/lib/laneway/fixture.log
StandardError=inherit
EOF
  systemctl daemon-reload
  start_packaged_relay
  start_process "$gateway_ns" "$work_dir/gateway.log" "$work_dir/lanewayd" -config "$work_dir/gateway.toml"
  wait_log "$last_pid" "$work_dir/gateway.log" interface=lane0
  printf '%s %s\n' "$location_controller_ip" "$discovery_name" >"$work_dir/managed-node.hosts"
  (umask 077
    ip netns exec "$controller_ns" "$work_dir/laneway" controller enrollment-token issue \
      --network-id "$network_id" --label managed-node --expires-in 5m \
      --requested-name managed-rust-fixture "${management_connection[@]}" |
      jq -jer '.enrollment_token | select(type=="string" and length>0)' >"$token"
  )
  run_managed_node_installer node install "$discovery_name:9443" --token-file "$token" --no-direct --no-start
  ! systemctl is-active --quiet lanewayd-rs.service
  [[ $(stat -c '%u:%g:%a' "$cert") == "$(id -u laneway):$(id -g laneway):400" ]]
  [[ $(stat -c '%u:%g:%a' /etc/laneway/node.key) == "0:$(id -g laneway):640" ]]
  [[ ! -e /etc/laneway/wireguard.key && ! -e /etc/laneway/laneway.toml ]]
  node=$(jq -er '.node_id | select(test("^[0-9a-f]{32}$"))' /etc/laneway/node-install.json)
  jq -e --arg network "$network_id" '.runtime == "rust" and .network_id == $network and .direct_enabled == false' \
    /etc/laneway/node-install.json >/dev/null
  rm -- "$token"
  packaged_node_started=true
  # Starting the same install must reuse its identity without another invite.
  run_managed_node_installer node install "$discovery_name:9443" --no-direct
  [[ $(jq -r .node_id /etc/laneway/node-install.json) == "$node" ]]
  pid=$(systemctl show --property=MainPID --value lanewayd-rs.service)
  [[ $(readlink "/proc/$pid/exe") == /usr/local/sbin/lanewayd-rs ]]
  [[ $(awk '/^Uid:/ {print $3}' "/proc/$pid/status") == "$(id -u laneway)" ]]
  /usr/local/sbin/laneway-healthcheck-rs -unix /run/laneway/lanewayd.sock

  start_process "$gateway_ns" "$work_dir/managed-node-udp.log" "$work_dir/netprobe" udp-server -listen "$gateway_address:9777"
  peer_pid=$last_pid
  wait_log "$peer_pid" "$work_dir/managed-node-udp.log" ready=udp-server
  ip netns exec "$rust_ns" "$work_dir/netprobe" udp-client -target "$gateway_address:9777" -message managed-node -timeout 15s
  wait "$peer_pid"
  unset "active_processes[$peer_pid]"
  # Uninstall may remove its own state, not unrelated files in the state directory.
  printf 'unmanaged\n' >/var/lib/laneway/fixture-marker
  /usr/local/bin/laneway node uninstall
  packaged_node_started=false
  [[ ! -e "$cert" && ! -e /etc/laneway/node.key && ! -e /etc/laneway/node-install.json &&
     ! -e /run/laneway/lanewayd.sock && -f /var/lib/laneway/fixture-marker ]]
  ! ip -n "$rust_ns" link show lane0 >/dev/null 2>&1
  cleanup_packaged_node
  echo 'PASS: default managed CLI redeemed a real invitation, started Rust as laneway, exchanged packets, and uninstalled safely.'
}

check_packaged_node() {
  local installed="$packaged_node/usr/local" path before after key_hash pid
  local cert=/var/lib/laneway/identity/node.crt key=/etc/laneway/node.key
  local log=/var/lib/laneway/fixture.log socket=/run/laneway/lanewayd.sock
  local probe_pid
  if [[ $managed_invitation == 1 ]]; then
    for path in /usr/local/bin/laneway /usr/local/sbin/laneway-healthcheck-rs; do
      [[ ! -e "$path" && ! -L "$path" ]] || { echo "refusing to replace $path" >&2; return 1; }
    done
    [[ -x "$installed/bin/laneway" ]] || return 1
  fi
  for path in "$packaged_node_unit" "$packaged_node_dropin" /usr/local/sbin/lanewayd-rs \
    /etc/laneway /run/laneway /var/lib/laneway; do
    [[ ! -e "$path" && ! -L "$path" ]] || { echo "refusing to replace $path" >&2; return 1; }
  done
  [[ $(systemctl show --property=LoadState --value lanewayd-rs.service) == not-found &&
    $(systemctl show --property=LoadState --value lanewayd.service) == not-found ]] ||
    { echo 'existing Laneway unit in systemd VM' >&2; return 1; }
  if getent passwd laneway >/dev/null || getent group laneway >/dev/null; then
    echo 'existing Laneway account in systemd VM' >&2
    return 1
  fi
  [[ -x "$installed/sbin/lanewayd-rs" && -x "$installed/sbin/laneway-healthcheck-rs" &&
    -f "$installed/lib/systemd/system/lanewayd-rs.service" ]] || return 1
  if [[ $packaged_relay == 1 ]]; then
    [[ $(systemctl show --property=LoadState --value laneway-relay-rs.service) == not-found &&
      $(systemctl show --property=LoadState --value laneway-relay.service) == not-found ]] || return 1
    for path in "$packaged_relay_unit" "$packaged_relay_dropin" "$packaged_relay_log" \
      /usr/local/sbin/laneway-relay-rs /var/lib/laneway-relay /run/laneway-relay; do
      [[ ! -e "$path" && ! -L "$path" ]] || { echo "refusing to replace $path" >&2; return 1; }
    done
    [[ -x "$installed/sbin/laneway-relay-rs" && -f "$installed/lib/systemd/system/laneway-relay-rs.service" ]] || return 1
  fi

  packaged_node_owned=true
  groupadd --system laneway
  packaged_node_group=true
  useradd --system --gid laneway --home-dir /var/lib/laneway --shell /usr/sbin/nologin laneway
  packaged_node_user=true
  install -m 0755 "$installed/sbin/lanewayd-rs" /usr/local/sbin/lanewayd-rs
  install -d -m 0750 -o root -g laneway /etc/laneway
  if [[ $managed_invitation == 1 ]]; then
    check_invited_packaged_node
    return
  fi
  install -d -m 0700 -o laneway -g laneway /var/lib/laneway/identity
  install -m 0400 -o laneway -g laneway "$work_dir/pki/rust.crt" "$cert"
  install -m 0440 -o root -g laneway "$work_dir/pki/rust.key" "$key"
  install -m 0440 -o root -g laneway "$work_dir/pki/ca.crt" /etc/laneway/ca.crt
  sed -e "s@$work_dir/rust.sock@$socket@" -e "s@$work_dir/rust-exit-intent.json@/var/lib/laneway/exit-intent.json@" \
    -e "s@$work_dir/pki/rust.crt@$cert@" -e "s@$work_dir/pki/rust.key@$key@" \
    -e "s@$work_dir/pki/ca.crt@/etc/laneway/ca.crt@" "$work_dir/rust.toml" >"$work_dir/installed-node.toml"
  install -m 0440 -o root -g laneway "$work_dir/installed-node.toml" /etc/laneway/node-rust.toml
  install -m 0644 "$installed/lib/systemd/system/lanewayd-rs.service" "$packaged_node_unit"
  mkdir "$packaged_node_dropin"
  # The only lab settings are the isolated namespace and a captured log.
  cat >"$packaged_node_dropin/fixture.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/$rust_ns
Environment=RUST_LOG=info
StandardOutput=append:$log
StandardError=inherit
EOF
  systemctl daemon-reload

  if [[ $packaged_relay == 1 ]]; then
    start_packaged_relay
  else
    start_process "$relay_ns" "$work_dir/relay.log" "$work_dir/laneway-relay" -config "$work_dir/relay.toml"
    wait_log "$last_pid" "$work_dir/relay.log" listening
  fi
  start_process "$gateway_ns" "$work_dir/gateway.log" "$work_dir/lanewayd" -config "$work_dir/gateway.toml"
  wait_log "$last_pid" "$work_dir/gateway.log" interface=lane0
  before=$("$work_dir/netprobe" certificate-info -cert "$cert")
  key_hash=$(sha256sum "$key")
  packaged_node_started=true
  systemctl start lanewayd-rs.service
  pid=$(systemctl show --property=MainPID --value lanewayd-rs.service)
  [[ $pid =~ ^[1-9][0-9]*$ ]]
  wait_log "$pid" "$log" 'renewed node certificate; restarting authenticated connections'
  [[ $(readlink "/proc/$pid/exe") == /usr/local/sbin/lanewayd-rs ]]
  [[ $(awk '/^Uid:/ {print $3}' "/proc/$pid/status") == "$(id -u laneway)" &&
    $(awk '/^Gid:/ {print $3}' "/proc/$pid/status") == "$(id -g laneway)" ]]
  after=$("$work_dir/netprobe" certificate-info -cert "$cert")
  [[ ${before% serial=*} == "${after% serial=*}" && ${before##* serial=} != "${after##* serial=}" ]]
  [[ $(sha256sum "$key") == "$key_hash" && $(stat -c '%u:%g:%a' "$cert") == "$(id -u laneway):$(id -g laneway):400" ]]

  start_process "$gateway_ns" "$work_dir/installed-node-udp.log" "$work_dir/netprobe" udp-server -listen "$gateway_address:9777"
  probe_pid=$last_pid
  wait_log "$probe_pid" "$work_dir/installed-node-udp.log" ready=udp-server
  ip netns exec "$rust_ns" "$work_dir/netprobe" udp-client -target "$gateway_address:9777" -message packaged-node -timeout 15s
  wait "$probe_pid"
  unset "active_processes[$probe_pid]"
  "$installed/sbin/laneway-healthcheck-rs" -unix "$socket"
  systemctl stop lanewayd-rs.service
  packaged_node_started=false
  [[ ! -e "$socket" ]] && ! ip -n "$rust_ns" link show lane0 >/dev/null 2>&1
  cleanup_packaged_node
  echo 'PASS: packaged systemd node renewed as laneway, exchanged traffic with a Go peer, and removed its socket and tunnel.'
}
