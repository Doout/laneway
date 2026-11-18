#!/usr/bin/env bash
# Exercise the exact, signed release input before publishing a GitHub release.
set -euo pipefail

marker=/run/.laneway-isolated-signed-release-lab
if [[ $(id -u) != 0 || ! -f $marker || -L $marker || $(stat -c '%u:%a' "$marker") != 0:600 ||
      -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} ]]; then
  echo 'Run as root on a marked disposable Linux runner with local Docker.' >&2
  exit 2
fi
if [[ $# != 2 || ! $2 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo 'usage: bash integration/rust-release-install.sh SIGNED_RELEASE_DIRECTORY vVERSION' >&2
  exit 2
fi
assets=$(realpath -e -- "$1")
tag=$2
name='laneway-release.localhost'
if [[ $(getent ahostsv4 "$name" | awk '{print $1}' | sort -u) != 127.0.0.1 ||
      $(docker context inspect --format '{{.Endpoints.docker.Host}}') != unix:///var/run/docker.sock ||
      ! -c /dev/net/tun ]]; then
  echo "The signed release lab requires $name on loopback, the standard local Docker socket, and /dev/net/tun." >&2
  exit 2
fi
for path in /usr/local/bin/laneway /usr/local/bin/lane /usr/local/sbin/laneway-control /usr/local/share/laneway; do
  if [[ -e $path || -L $path ]]; then
    echo "Refusing to overwrite an existing installation: $path" >&2
    exit 2
  fi
done
for volume in laneway-controller-state laneway-relay-public-certs laneway-exit-node-state; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "Refusing to reuse an existing volume: $volume" >&2
    exit 2
  fi
done
for member in install.sh checksums.txt checksums.sigstore.json; do
  [[ -f $assets/$member && ! -L $assets/$member ]]
done
cosign verify-blob --bundle "$assets/checksums.sigstore.json" \
  --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$assets/checksums.txt" >/dev/null
[[ $(grep -c '  install.sh$' "$assets/checksums.txt") == 1 ]]
(cd "$assets" && sha256sum --strict -c checksums.txt >/dev/null)

work=$(mktemp -d /var/tmp/laneway-signed-release.XXXXXXXX)
project="laneway-release-${work##*.}"
project=${project,,}
destination=$work/deploy
restore=$work/restore
restore_volume=$project-restored-controller
server=
install_started=false
connector=
connector_volume=
export COMPOSE_PROJECT_NAME="$project" NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,$name"
compose() {
  local directory=$1
  shift
  docker compose --project-directory "$directory" --env-file "$directory/.env" \
    -f "$directory/compose.yaml" -f "$directory/compose.rust.yaml" "$@"
}
restore_compose() {
  COMPOSE_PROJECT_NAME="$project-restore" LANEWAY_RUST_CONTROLLER_STATE_VOLUME="$restore_volume" compose "$restore" "$@"
}
cleanup() {
  local result=$?
  if [[ -n $server ]]; then
    kill "$server" 2>/dev/null || true
    wait "$server" 2>/dev/null || true
  fi
  if [[ -n $connector ]]; then
    if (( result != 0 )); then docker logs --tail 20 "$connector" >&2 2>/dev/null || true; fi
    docker rm -f "$connector" >/dev/null 2>&1 || true
    docker volume rm "$connector_volume" >/dev/null 2>&1 || true
  fi
  if [[ -f $restore/.env ]]; then restore_compose down --volumes >/dev/null 2>&1 || true; fi
  if [[ -f $destination/.env ]]; then
    if (( result != 0 )); then
      compose "$destination" --profile exit-node logs --no-color --tail=20 controller relay exit-node >&2 || true
    fi
    compose "$destination" --profile exit-node down --volumes >/dev/null 2>&1 || true
  fi
  if [[ $install_started == true ]]; then
    if [[ $(readlink /usr/local/sbin/laneway-control 2>/dev/null || true) == "$destination/laneway-control" ]]; then
      unlink /usr/local/sbin/laneway-control
    fi
    if [[ $(readlink /usr/local/bin/lane 2>/dev/null || true) == laneway ]]; then unlink /usr/local/bin/lane; fi
    if [[ -f /usr/local/bin/laneway && ! -L /usr/local/bin/laneway ]]; then unlink /usr/local/bin/laneway; fi
    if [[ -d /usr/local/share/laneway && ! -L /usr/local/share/laneway ]]; then
      find /usr/local/share/laneway -depth -delete
    fi
  fi
  find "$work" -depth -delete
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Override only the download origin. Use real HTTPS, Cosign, Docker pulls
# and the released installer. Never feed a local CA into Cosign or Docker.
openssl req -quiet -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=$name" -addext "subjectAltName=DNS:$name,IP:127.0.0.1" \
  -keyout "$work/lab.key" -out "$work/lab.crt"
python3 - "$assets" "$work" <<'PY' &
import functools
import http.server
from pathlib import Path
import ssl
import sys

assets, work = map(Path, sys.argv[1:])
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=assets)
with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(work / "lab.crt", work / "lab.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    (work / "asset-port").write_text(str(server.server_port), encoding="ascii")
    server.serve_forever()
PY
server=$!
for _ in {1..50}; do
  [[ ! -s $work/asset-port ]] || break
  kill -0 "$server"
  sleep 0.1
done
asset_port=$(cat "$work/asset-port")
[[ $asset_port =~ ^[0-9]{1,5}$ ]]
export CURL_CA_BUNDLE="$work/lab.crt"
install_started=true
env LANEWAY_VERSION="$tag" LANEWAY_RELEASE_BASE_URL="https://127.0.0.1:$asset_port" \
  LANEWAY_NONINTERACTIVE=true LANEWAY_CONFIRM=deploy LANEWAY_DOMAIN="$name" LANEWAY_BIND_ADDRESS=127.0.0.1 \
  LANEWAY_DEPLOY_DIR="$destination" LANEWAY_INSTALLER_ANSWERS_FILE="$work/answers/installer" \
  LANEWAY_RECOVERY_KIT_DIR="$work/recovery" sh "$assets/install.sh" --control-plane --production

grep -Fxq LANEWAY_CONTROL_RUNTIME=rust "$destination/.env"
grep -Fxq "LANEWAY_RUST_VERSION=${tag#v}" "$destination/.env"
grep -Fxq -- '- Outer installer archive signature verification: **true**' "$destination/PRODUCTION-CHECKLIST.md"
[[ -z $(find /usr/local/lib/systemd/system /usr/local/sbin -maxdepth 1 -name 'lanewayd*' -print 2>/dev/null || true) ]]
[[ $(compose "$destination" exec -T controller /usr/local/bin/laneway-controller --version) == "${tag#v}" ]]
[[ $(compose "$destination" exec -T relay /usr/local/bin/laneway-relay --version) == "${tag#v}" ]]

# Replace ACME with a disposable local HTTPS certificate only after the
# unmodified release has successfully installed. Readiness then checks the
# signed discovery data against the image digests and authenticated inventory.
install -m 0444 "$work/lab.crt" "$destination/generated/pki/lab-public.crt"
install -m 0400 "$work/lab.key" "$destination/generated/pki/lab-public.key"
chown 65532:65532 "$destination/generated/pki/lab-public.key"
sed -i '/^cache_dir = "\/var\/lib\/laneway-public"$/d' "$destination/generated/config/relay.rust.toml"
printf '\ncertificate = "/run/laneway-secrets/lab-public.crt"\nprivate_key = "/run/laneway-secrets/lab-public.key"\n' \
  >> "$destination/generated/config/relay.rust.toml"
sed -i '/^  relay:$/,/^  exit-node:$/ { /    volumes:$/a\      - ./generated/pki/lab-public.crt:/run/laneway-secrets/lab-public.crt:ro\n      - ./generated/pki/lab-public.key:/run/laneway-secrets/lab-public.key:ro
}' "$destination/compose.rust.yaml"
compose "$destination" up -d --no-deps --force-recreate --pull never --wait --wait-timeout 90 relay
"$destination/laneway-control" readiness

# Exercise the real one-time invitation from the packaged control tool. Both
# invocations of the pinned image need lab-only access to loopback listeners.
connector_name="$project-connector"
candidate="laneway-connector-$connector_name"
candidate_volume="$candidate-state"
if docker container inspect "$candidate" >/dev/null 2>&1 ||
  docker volume inspect "$candidate_volume" >/dev/null 2>&1; then
  echo 'Refusing to reuse an existing Connector or state volume.' >&2
  exit 2
fi
connector=$candidate
connector_volume=$candidate_volume
"$destination/laneway-control" invite --docker --connector --name "$connector_name" > "$work/invitation"
read -r url key < <(awk -F"'" 'NF == 7 {print $4, $6}' "$work/invitation")
bundle=${url##*/}
[[ $url == "https://$name/.well-known/laneway/bootstrap/$bundle" &&
  $bundle =~ ^[A-Za-z0-9_-]{43}$ && $key =~ ^[A-Za-z0-9_-]{43}$ ]]
curl --fail --silent --show-error --proto '=https' --tlsv1.3 --max-time 15 "$url" -o "$work/bootstrap.sh"
[[ $(curl --silent --show-error --proto '=https' --tlsv1.3 --max-time 15 -o /dev/null -w '%{http_code}' "$url") == 404 ]]
(
  # shellcheck disable=SC2329 # The downloaded bootstrap calls the exported function.
  docker() {
    if [[ ${1:-} == run ]]; then
      shift
      command docker run --network host --add-host "$LANEWAY_RELEASE_LAB_HOST:127.0.0.1" "$@"
    else
      command docker "$@"
    fi
  }
  export LANEWAY_RELEASE_LAB_HOST="$name"
  export -f docker
  bash "$work/bootstrap.sh" "$key" >/dev/null
)
unset key
connector_digest=$(sed -n 's/^LANEWAY_RUST_CONNECTOR_IMAGE_DIGEST=//p' "$destination/.env")
[[ $connector_digest =~ ^sha256:[a-f0-9]{64}$ ]]
docker inspect "$connector" | jq -e --arg image "ghcr.io/doout/lane-edge-rust:${tag#v}@$connector_digest" '
  .[0].Config | .Image == $image and
  all(.Env[]; (startswith("SETUP_TOKEN") or startswith("ENROLLMENT_TOKEN")) | not)
' >/dev/null

connector_node_id() {
  local status
  # A new node waits for the relay's authorization poll, then reconnects.
  for _ in {1..90}; do
    if status=$(docker exec "$connector" /usr/local/bin/laneway status --socket /run/laneway/lanewayd.sock --json 2>/dev/null) &&
      jq -e --arg version "${tag#v}" --argjson now "$(date +%s)" '
        .running and .product_version == $version and .interface == "userspace" and .selected_path == "relay-quic" and
        .controller.configuration_lease_expired == false and
        .controller.configuration_lease_valid_until_unix_seconds > $now
      ' <<<"$status" >/dev/null; then
      docker top "$connector" -eo pid,comm | awk 'NR > 1 { if ($2 != "lanewayd-rs") exit 1; seen++ } END { if (seen != 1) exit 1 }' ||
        return 1
      jq -er '.node_id | select(test("^[a-f0-9]{32}$"))' <<<"$status"
      return
    fi
    sleep 1
  done
  echo 'The Rust Connector did not acquire a live controller lease and QUIC path.' >&2
  return 1
}
node_id=$(connector_node_id)
docker restart --time 10 "$connector" >/dev/null
[[ $(connector_node_id) == "$node_id" ]]
echo "PASS: Connector enrolled through the one-time HTTPS bootstrap and restarted with the same identity."

# Start the digest-pinned, optional durable Exit Node with fresh credentials.
# The packaged client is used for enrollment and route approval only.
setting() { sed -n "s/^$1=//p" "$destination/.env"; }
network_id=$(setting LANEWAY_NETWORK_ID)
controller_id=$(setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(setting LANEWAY_RELAY_SERVICE_ID)
exit_digest=$(setting LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST)
[[ $network_id =~ ^[a-f0-9]{32}$ && $controller_id =~ ^[a-f0-9]{32}$ &&
  $relay_id =~ ^[a-f0-9]{32}$ && $exit_digest =~ ^sha256:[a-f0-9]{64}$ ]]
exit_image="ghcr.io/doout/laneway-exit-node-rust:${tag#v}@$exit_digest"
laneway=/usr/local/bin/laneway
pki="$destination/generated/pki"
remote=(--controller "https://127.0.0.1:$(setting LANEWAY_CONTROLLER_PORT)"
  --ca "$pki/ca.crt" --server-name "$name"
  --controller-network-id "$network_id" --controller-service-id "$controller_id")
admin=(--admin-token-file "$destination/generated/secrets/admin.token")
(
  umask 077
  "$laneway" controller enrollment-token issue --network-id "$network_id" \
    --label release-exit --requested-name exit-node --class durable --expires-in 10m \
    "${remote[@]}" "${admin[@]}" | jq -er '.enrollment_token' >"$work/exit.token"
)
joined=$("$laneway" join --token-file "$work/exit.token" --name exit-node "${remote[@]}" \
  --out-cert "$pki/exit-node.crt" --out-key "$pki/exit-node.key" --out-wireguard-key "$work/exit.wg")
exit_node=$(sed -n 's/.* node=\([a-f0-9]\{32\}\) .*/\1/p' <<<"$joined")
[[ $exit_node =~ ^[a-f0-9]{32}$ ]]
unlink "$work/exit.token"
unlink "$work/exit.wg"
install -m 0444 /dev/null "$destination/generated/config/exit-node.toml"
sed -e "s/REPLACE_NETWORK_ID/$network_id/g" \
  -e "s/REPLACE_CONTROLLER_SERVICE_ID/$controller_id/g" -e "s/REPLACE_RELAY_SERVICE_ID/$relay_id/g" \
  -e "s/relay\.example\.com/$name/g" -e "s/controller\.example\.com/$name/g" \
  /usr/local/share/laneway/deploy/compose/generated/config/exit-node.toml.example \
  > "$destination/generated/config/exit-node.toml"
chmod 0444 "$pki/exit-node.crt"
chown 65532:65532 "$pki/exit-node.key"
chmod 0400 "$pki/exit-node.key"
# An Exit-scoped invitation auto-approves IPv4; use an ordinary invitation
# so this rehearsal exercises a separate administrative approval.
"$laneway" controller node capabilities --node-id "$exit_node" --exit-node "${remote[@]}" "${admin[@]}" >/dev/null
docker pull --quiet "$exit_image" >/dev/null
route=$(compose "$destination" run --rm --no-deps --pull never -T --entrypoint /usr/local/bin/laneway \
  exit-node exit enable --family ipv4 --config /etc/laneway/exit-node.toml |
  jq -er 'select(.approval_needed == true) | .advertisements[0].route_id | select(test("^[a-f0-9]{32}$"))')
"$laneway" controller route approve --route-id "$route" "${remote[@]}" "${admin[@]}" >/dev/null
compose "$destination" up -d --pull never --wait --wait-timeout 90 exit-node
exit_container=$(compose "$destination" ps -q exit-node)
[[ -n $exit_container && $(docker inspect --format '{{.Config.Image}}' "$exit_container") == "$exit_image" ]]
ready=false
for _ in {1..90}; do
  if status=$(compose "$destination" exec -T exit-node /usr/local/bin/laneway status --socket /run/laneway/lanewayd.sock --json) &&
    jq -e --arg version "${tag#v}" --arg id "$exit_node" '
      .running and .product_version == $version and .node_id == $id and
      .exit.serving and .exit.forwarding_ready and .exit.nat_ready
    ' <<<"$status" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
"$ready"
echo "PASS: approved Rust Exit Node is running with forwarding and IPv4 NAT ready."

# Verify the installer's original encrypted bundle in a separate, empty
# controller volume, leaving the first database untouched.
shopt -s nullglob
bundles=("$destination/generated/recovery"/initial-recovery-*.age)
[[ ${#bundles[@]} == 1 ]]
mkdir "$restore"
if docker volume inspect "$restore_volume" >/dev/null 2>&1; then
  echo "Refusing to reuse an existing restore volume: $restore_volume" >&2
  exit 2
fi
cp "$destination"/{compose.yaml,compose.rust.yaml,recovery.sh,validate.sh} "$restore/"
sed -i "s/^    name: laneway-/    name: $project-restore-/" "$restore/compose.yaml"
COMPOSE_PROJECT_NAME="$project-restore" LANEWAY_RUST_CONTROLLER_STATE_VOLUME="$restore_volume" \
  "$restore/recovery.sh" --rust restore "${bundles[0]}" "$work/recovery/laneway-recovery.identity"
restore_compose run --rm --no-deps --pull never controller inventory networks /var/lib/laneway-controller/controller.db |
  jq -e --arg id "$network_id" '.networks | length == 1 and .[0].network_id == $id' >/dev/null
echo "PASS: signed $tag installed from empty state, passed HTTPS, Connector, and Exit Node readiness, and restored its encrypted backup into a separate volume."
