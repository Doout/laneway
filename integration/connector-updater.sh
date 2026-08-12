#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture" "$work_dir/locks"

digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
printf 'ghcr.io/doout/lane-edge@%s\n' "$digest" > "$work_dir/fixture/image-digests.txt"
(
  cd "$work_dir/fixture"
  sha256sum image-digests.txt > checksums.txt
)
: > "$work_dir/fixture/checksums.sigstore.json"

cat > "$work_dir/bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exit 1
EOF
cat > "$work_dir/bin/cosign" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$work_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --header|--write-out) shift 2 ;;
    --fail|--silent|--show-error|--location) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */releases/latest\?laneway_cache_bust=*)
    [ "$output" = /dev/null ]
    printf '%s' 'https://github.com/Doout/laneway/releases/tag/v9.8.7'
    ;;
  */image-digests.txt) cp "$LANEWAY_UPDATER_FIXTURE/image-digests.txt" "$output" ;;
  */checksums.txt) cp "$LANEWAY_UPDATER_FIXTURE/checksums.txt" "$output" ;;
  */checksums.sigstore.json) cp "$LANEWAY_UPDATER_FIXTURE/checksums.sigstore.json" "$output" ;;
  *) echo "unexpected updater URL: $url" >&2; exit 1 ;;
esac
EOF
cat > "$work_dir/bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$LANEWAY_UPDATER_DOCKER_LOG"
command=$1
shift
case "$command" in
  version|pull|run|stop|rename|start|rm|logs) exit 0 ;;
  volume) exit 0 ;;
  inspect)
    if [ "${1:-}" != --format ]; then exit 0; fi
    format=$2
    case "$format" in
      # Exercise replacement of the pre-split shared Connector/Exit image.
      *Config.Image*) echo 'ghcr.io/doout/laneway-connector:0.2.29' ;;
      *Mounts*) echo 'volume laneway-connector-test-state' ;;
      *Config.Hostname*) echo 'laneway-connector-test' ;;
      *State.Health*) echo "${LANEWAY_UPDATER_HEALTH:-healthy}" ;;
      *State.Running*) echo "${LANEWAY_UPDATER_RUNNING:-true}" ;;
      *) echo "unexpected docker inspect format: $format" >&2; exit 1 ;;
    esac
    ;;
  *) echo "unexpected docker command: $command" >&2; exit 1 ;;
esac
EOF
chmod 0755 "$work_dir/bin/"*

run_updater() {
  env \
    PATH="$work_dir/bin:$PATH" \
    LANEWAY_COSIGN_BIN="$work_dir/bin/cosign" \
    LANEWAY_LOCK_DIR="$work_dir/locks" \
    LANEWAY_UPDATER_FIXTURE="$work_dir/fixture" \
    LANEWAY_UPDATER_DOCKER_LOG="$work_dir/docker.log" \
    LANEWAY_UPDATER_HEALTH="${LANEWAY_UPDATER_HEALTH:-}" \
    LANEWAY_UPDATER_RUNNING="${LANEWAY_UPDATER_RUNNING:-}" \
    "$@"
}

output=$(run_updater sh "$repo_dir/deploy/containers/update-connector.sh" laneway-connector-test)
printf '%s\n' "$output" | grep -F 'updated successfully to v9.8.7' >/dev/null
grep -F 'stop laneway-connector-test' "$work_dir/docker.log" >/dev/null
grep -F 'rename laneway-connector-test laneway-connector-test-previous-' "$work_dir/docker.log" >/dev/null
grep -F -- '--volume laneway-connector-test-state:/var/lib/laneway' "$work_dir/docker.log" >/dev/null
grep -F 'ghcr.io/doout/lane-edge:9.8.7@sha256:1111111111111111111111111111111111111111111111111111111111111111' \
  "$work_dir/docker.log" >/dev/null
grep -F 'connector validate --state-dir /var/lib/laneway/connector' "$work_dir/docker.log" >/dev/null
if grep -F -- '--entrypoint /bin/sh' "$work_dir/docker.log" >/dev/null; then
  echo "Connector updater still requires a shell in the target image" >&2
  exit 1
fi
if grep -F -- '--health-cmd' "$work_dir/docker.log" >/dev/null; then
  echo "Connector updater overrides the scratch image health check with a shell command" >&2
  exit 1
fi
if grep -F 'config-backup' "$work_dir/docker.log" >/dev/null; then
  echo "Connector updater created a redundant configuration backup volume" >&2
  exit 1
fi
if grep -F 'SETUP_TOKEN' "$work_dir/docker.log" >/dev/null; then
  echo "Connector updater reused an enrollment token" >&2
  exit 1
fi

: > "$work_dir/docker.log"
set +e
output=$(LANEWAY_UPDATER_HEALTH=unhealthy LANEWAY_UPDATER_RUNNING=false \
  run_updater sh "$repo_dir/deploy/containers/update-connector.sh" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "unhealthy replacement unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$output" | grep -F 'previous Connector restored' >/dev/null
grep -F 'start laneway-connector-test' "$work_dir/docker.log" >/dev/null

echo "Connector updater verifies, replaces, preserves state, and rolls back unhealthy releases"
