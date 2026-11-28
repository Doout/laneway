#!/usr/bin/env bash
# Prove the packaged updater and runtime on an isolated systemd runner.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo 'usage: bash integration/rust-release-fleet-update.sh ARCHIVE ACTIVATION_FIXTURE_DIRECTORY' >&2
  exit 2
fi
marker=/run/.laneway-isolated-systemd-lab
if [[ $(id -u) != 0 || $(cat /proc/1/comm) != systemd ||
      ! -f $marker || -L $marker || $(stat -c '%u:%a' "$marker") != 0:600 ]]; then
  echo 'The fleet update gate requires root on a marked disposable systemd runner.' >&2
  exit 2
fi
archive=$1
fixture=$(realpath -e -- "$2")
for executable in prior-node activation-test; do
  [[ -f $fixture/$executable && ! -L $fixture/$executable && -x $fixture/$executable ]]
done
work=$(mktemp -d -t laneway-release-fleet.XXXXXX)
installed=/usr/local/sbin/lanewayd-rs
settings=/etc/laneway/managed-updates-rust.toml
config=/etc/laneway/node-rust.toml
trust=/etc/laneway/ca.crt
updater_state=/var/lib/laneway-updater
unit=lanewayd-rs.service
controller_pid=
systemd_started=false
installed_owned=false
config_owned=false
cleanup() {
  local result=$?
  if ((result != 0)); then
    [[ ! -f $work/controller.log ]] || cat "$work/controller.log" >&2
    [[ $systemd_started != true ]] || journalctl --unit "$unit" --no-pager -n 30 >&2 || true
  fi
  if [[ $systemd_started == true ]]; then
    systemctl stop "$unit" || true
    systemctl reset-failed "$unit" 2>/dev/null || true
  fi
  if [[ -n $controller_pid ]]; then
    kill "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
  fi
  if [[ $installed_owned == true ]]; then
    find "$installed" -maxdepth 0 -delete
  fi
  if [[ $config_owned == true ]]; then
    find /etc/laneway -depth -delete
    [[ ! -e $updater_state ]] || find "$updater_state" -depth -delete
  fi
  find "$work" -depth -delete
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Extract only the exact release binaries. The prior version and instrumented
# activation test are CI fixtures, never members of the release archive.
umask 077
listing=$(tar -tzf "$archive")
member=laneway/bin/laneway
[[ $(grep -Fxc "$member" <<<"$listing") == 1 ]]
tar -xzOf "$archive" "$member" > "$work/laneway"
chmod 0755 "$work/laneway"
for name in laneway-controller-rs laneway-update-rs lanewayd-rs; do
  member=laneway/sbin/$name
  [[ $(grep -Fxc "$member" <<<"$listing") == 1 ]]
  tar -xzOf "$archive" "$member" > "$work/$name"
  chmod 0755 "$work/$name"
done
[[ $("$work/lanewayd-rs" --version) != "$("$fixture/prior-node" --version)" ]]
for path in "$installed" /etc/laneway "$updater_state"; do
  [[ ! -e $path && ! -L $path ]] || { echo "refusing to replace $path" >&2; exit 1; }
done
[[ $(systemctl show -p LoadState --value "$unit") == not-found ]] ||
  { echo "refusing to replace $unit" >&2; exit 1; }

cli=$work/laneway
controller=$work/laneway-controller-rs
updater=$work/laneway-update-rs
network=71000000000000000000000000000001
service=71000000000000000000000000000002
relay=71000000000000000000000000000003
listen=127.0.0.1:18443
endpoint=https://$listen
token=laneway-disposable-fleet-administrator-token
printf '%s\n' "$token" > "$work/admin.token"
"$cli" pki init -out-dir "$work/pki" >/dev/null
"$cli" pki intermediate --ca-cert "$work/pki/ca.crt" --ca-key "$work/pki/ca.key" \
  --out-cert "$work/pki/issuer.crt" --out-key "$work/pki/issuer.key" >/dev/null
"$cli" pki controller -ca-cert "$work/pki/issuer.crt" -ca-key "$work/pki/issuer.key" \
  -network-id "$network" -service-id "$service" -ip 127.0.0.1 \
  -out-cert "$work/pki/controller.crt" -out-key "$work/pki/controller.key" >/dev/null
"$controller" init "$work/controller.db" "$work/pki/controller.crt" fleet-lab 100.115.2.0/24 >/dev/null
"$controller" serve "$work/controller.db" "$listen" "$work/pki/controller.crt" "$work/pki/controller.key" \
  --root-token-file "$work/admin.token" --node-client-ca "$work/pki/ca.crt" \
  --node-issuer "$work/pki/issuer.crt" "$work/pki/issuer.key" 3600 --node-quic \
  > "$work/controller.log" 2>&1 &
controller_pid=$!
for _ in {1..100}; do
  grep -q 'listening quic://' "$work/controller.log" && break
  kill -0 "$controller_pid"
  sleep 0.1
done
grep -q 'listening quic://' "$work/controller.log"

remote=(--controller "$endpoint" --ca "$work/pki/ca.crt" --server-name 127.0.0.1
  --controller-network-id "$network" --controller-service-id "$service")
admin=(--admin-token-file "$work/admin.token")
"$cli" controller relay register --network-id "$network" --service-id "$relay" \
  --name fixture-relay --endpoint 127.0.0.1:4433 "${remote[@]}" "${admin[@]}" >/dev/null
"$cli" controller enrollment-token issue --network-id "$network" --label fleet-lab \
  --requested-name fleet-canary --class durable "${remote[@]}" "${admin[@]}" |
  jq -er '.enrollment_token' > "$work/join.token"
joined=$("$cli" join --token-file "$work/join.token" --name fleet-canary "${remote[@]}" \
  --out-cert "$work/node.crt" --out-key "$work/node.key" --out-wireguard-key "$work/node.wg")
node=$(sed -n 's/.* node=\([a-f0-9]\{32\}\).*/\1/p' <<<"$joined")
[[ $node =~ ^[0-9a-f]{32}$ ]]

mkdir -m 0755 /etc/laneway
config_owned=true
install -m 0600 "$work/pki/ca.crt" "$trust"
install -m 0755 "$fixture/prior-node" "$installed"
installed_owned=true
printf 'enabled=false\nchannel="stable"\n' > "$settings"
socket="$work/worker.sock"
cat > "$config" <<EOF
mode = "node"
socket_path = "$socket"
exit_intent_path = "$work/worker-exit.json"
[identity]
node_id = "$node"
network_id = "$network"
[tls]
certificate = "$work/node.crt"
private_key = "$work/node.key"
ca = "$trust"
[controller]
endpoint = "$endpoint"
quic_endpoint = "$listen"
service_id = "$service"
server_name = "127.0.0.1"
poll_interval = "1s"
[tun]
name = "lane-test"
[relay]
server_name = "unused.test"
service_id = "$relay"
[connector]
userspace = true
EOF
systemd_started=true
systemd-run --quiet --unit="$unit" --description='Laneway isolated updater activation fixture' \
  --property=Type=exec --property=Restart=no "$installed" --config "$config"
lease_ready() {
  curl --fail --silent --max-time 1 --unix-socket "$socket" http://localhost/v1/status |
    jq -e --arg node "$node" --argjson now "$(date +%s)"       '.node_id == $node and .controller.configuration_lease_valid_until_unix_seconds > $now' >/dev/null
}
for _ in {1..100}; do
  lease_ready && break
  systemctl is-active --quiet "$unit"
  sleep 0.1
done
lease_ready

fleet_api() {
  curl --fail-with-body --silent --show-error --max-time 5 --noproxy '*' \
    --cacert "$work/pki/ca.crt" --header "Authorization: Bearer $token" \
    "$@" "$endpoint/v1/admin/networks/$network/fleet-updates"
}
version=$("$installed" --version)
update=$(jq -n --arg version "v${version#v}" --arg node "$node" \
  '{version: $version, component: "node", channel: "stable", node_ids: [$node], canary_count: 1}' |
  fleet_api --header 'Content-Type: application/json' --data-binary @- | jq -er '.id')
assert_state() {
  fleet_api | jq -e --arg id "$update" --arg state "$1" \
    '.fleet_updates | any(.id == $id and .state == $state)' >/dev/null
}
"$updater"
assert_state canary
printf 'enabled=true\nchannel="stable"\n' > "$settings"
chmod 0666 "$trust"
if "$updater"; then
  echo 'updater accepted an unprotected CA' >&2
  exit 1
fi
assert_state canary
chmod 0600 "$trust"
"$updater"
assert_state complete
"$updater"
[[ ! -e $updater_state/rust-journal.json ]]
python3 - "$work/controller.db" "$update" <<'AUDIT'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as database:
    claims, = database.execute(
        "SELECT count(*) FROM audit_events WHERE action='fleet_update.claim' AND lower(hex(target_id))=?",
        (sys.argv[2],),
    ).fetchone()
    if claims != 1:
        raise SystemExit(f"expected one fleet update claim, recorded {claims}")
AUDIT

LANEWAY_LAB_NODE_SOCKET="$socket" LANEWAY_LAB_NODE_CANDIDATE="$work/lanewayd-rs" \
  "$fixture/activation-test" --ignored --exact --nocapture \
  'fleet_update::tests::activation_on_live_systemd_node' | tee "$work/result"
grep -Fq 'systemd activated' "$work/result"
grep -Fq 'the same credential, and a fresh controller lease' "$work/result"
