#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
work_dir=$(CDPATH='' cd -- "$work_dir" && pwd -P)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture" "$work_dir/locks" "$work_dir/insecure-locks" \
  "$work_dir/docker-state"
updater_under_test=$work_dir/update-connector.sh
sed \
  -e "s|^PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\$|PATH=$work_dir/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" \
  -e "s|/usr/local/libexec/laneway/cosign-v3.1.3|$work_dir/bin/cosign|g" \
  "$repo_dir/deploy/containers/update-connector.sh" > "$updater_under_test"
chmod 0755 "$updater_under_test"

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
[ "${DOCKER_CONFIG:-}" = /root/.docker ] && [ "${HOME:-}" = /root ] || {
  echo "Cosign environment was not pinned to the trusted root path" >&2
  exit 1
}
if [ "${1:-}" = version ] && [ "${2:-}" = --json ]; then
  printf '{"gitVersion":"%s"}\n' "${LANEWAY_UPDATER_COSIGN_VERSION:-v3.1.3}"
fi
exit 0
EOF
cat > "$work_dir/bin/stat" <<'EOF'
#!/bin/sh
set -eu
format=${2:-}
path=${3:-}
case "$format:$path" in
  %u:%g:*/insecure-locks) printf '%s\n' 501:20 ;;
  %u:%g:%h:*/cosign)
    case "${LANEWAY_UPDATER_COSIGN_METADATA:-protected}" in
      hardlink) printf '%s\n' 0:0:2 ;;
      *) printf '%s\n' 0:0:1 ;;
    esac
    ;;
  %a:%u:%g:*/laneway-connector-update-*) printf '%s\n' 700:0:0 ;;
  %a:%u:%g:/var/tmp) printf '%s\n' 1777:0:0 ;;
  %a:%u:%g:*) printf '%s\n' 755:0:0 ;;
  %u:%g:*) printf '%s\n' 0:0 ;;
  %a:/var/tmp) printf '%s\n' 1777 ;;
  %a:/root|%a:/root/.docker|%a:*/locks|%a:*/tmp.*) printf '%s\n' 700 ;;
  %a:*) printf '%s\n' 755 ;;
  *) /usr/bin/stat "$@" ;;
esac
EOF
cat > "$work_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = --disable ] || { echo "curl configuration was not disabled first" >&2; exit 1; }
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --disable) shift ;;
    --output) output=$2; shift 2 ;;
    --header|--write-out) shift 2 ;;
    --proto|--proto-redir)
      [ "$2" = '=https' ] || { echo "curl allowed a non-HTTPS protocol" >&2; exit 1; }
      shift 2
      ;;
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
[ "${1:-}" = --context ] && [ "${2:-}" = default ] || {
  echo "Docker command was not pinned to the default context" >&2
  exit 1
}
[ "${DOCKER_DEFAULT_PLATFORM+x}" != x ] || {
  echo "Docker inherited DOCKER_DEFAULT_PLATFORM" >&2
  exit 1
}
[ "${DOCKER_CONFIG:-}" = /root/.docker ] && [ "${HOME:-}" = /root ] || {
  echo "Docker client configuration was not pinned to the trusted root path" >&2
  exit 1
}
shift 2
command=$1
shift
stateful=${LANEWAY_UPDATER_STATEFUL:-0}
state_dir=${LANEWAY_UPDATER_DOCKER_STATE:-}
state_id_path() {
  case "$1" in
    laneway-connector-test) printf '%s\n' "$state_dir/current.id" ;;
    laneway-connector-test-previous-*) printf '%s\n' "$state_dir/previous.id" ;;
    *) return 1 ;;
  esac
}
state_label_path() {
  case "$1" in
    laneway-connector-test) printf '%s\n' "$state_dir/current.label" ;;
    laneway-connector-test-previous-*) printf '%s\n' "$state_dir/previous.label" ;;
    *) return 1 ;;
  esac
}
case "$command" in
  version|pull|logs) exit 0 ;;
  stop)
    if [ "$stateful" = 1 ]; then
      stop_id_file=$(state_id_path "${1:-}") || exit 1
      [ -f "$stop_id_file" ] || exit 1
    fi
    if [ "${LANEWAY_UPDATER_SIGNAL_AFTER:-}" = stop ]; then
      kill -TERM "$PPID"
      sleep 1
    fi
    exit 0
    ;;
  rename)
    if [ "${LANEWAY_UPDATER_RENAME_COLLISION:-0}" = 1 ] && \
      [ "${1:-}" = laneway-connector-test ]; then
      exit 1
    fi
    if [ "$stateful" = 1 ]; then
      old_name=${1:-}
      new_name=${2:-}
      old_id_file=$(state_id_path "$old_name") || exit 1
      new_id_file=$(state_id_path "$new_name") || exit 1
      old_label_file=$(state_label_path "$old_name") || exit 1
      new_label_file=$(state_label_path "$new_name") || exit 1
      [ -f "$old_id_file" ] && [ ! -e "$new_id_file" ] || exit 1
      mv "$old_id_file" "$new_id_file"
      [ ! -f "$old_label_file" ] || mv "$old_label_file" "$new_label_file"
      if [ "${LANEWAY_UPDATER_SIGNAL_AFTER:-}" = forward-rename ] && \
        [ "$old_name" = laneway-connector-test ]; then
        kill -TERM "$PPID"
        sleep 1
      fi
    fi
    exit 0
    ;;
  run)
    detached=false
    run_name=
    run_label=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -d) detached=true; shift ;;
        --name) run_name=$2; shift 2 ;;
        --label) run_label=${2#*=}; shift 2 ;;
        *) shift ;;
      esac
    done
    if [ "$stateful" = 1 ] && [ "$detached" = true ]; then
      [ "$run_name" = laneway-connector-test ] || exit 1
      printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
        > "$state_dir/current.id"
      printf '%s\n' "$run_label" > "$state_dir/current.label"
    fi
    exit 0
    ;;
  start)
    if [ "$stateful" = 1 ]; then
      start_id_file=$(state_id_path "${1:-}") || exit 1
      [ -f "$start_id_file" ] || exit 1
    fi
    exit 0
    ;;
  rm)
    [ "${1:-}" != -f ] || shift
    remove_name=${1:-}
    if [ "$stateful" = 1 ]; then
      remove_id_file=$(state_id_path "$remove_name") || exit 1
      remove_label_file=$(state_label_path "$remove_name") || exit 1
      [ -f "$remove_id_file" ] || exit 1
      find "$remove_id_file" "$remove_label_file" -maxdepth 0 -delete 2>/dev/null || true
      if [ "${LANEWAY_UPDATER_SIGNAL_AFTER:-}" = previous-rm ]; then
        case "$remove_name" in
          laneway-connector-test-previous-*)
            kill -TERM "$PPID"
            sleep 1
            ;;
        esac
      fi
    fi
    exit 0
    ;;
  volume) exit 0 ;;
  inspect)
    if [ "${1:-}" != --format ]; then
      if [ "$stateful" = 1 ]; then
        inspect_id_file=$(state_id_path "${1:-}") || exit 1
        [ -f "$inspect_id_file" ]
        exit
      fi
      case "${1:-}" in
        laneway-connector-test-previous-*)
          [ "${LANEWAY_UPDATER_PREVIOUS_COLLISION:-0}" = 1 ] && exit 0
          exit 1
          ;;
        *) exit 0 ;;
      esac
    fi
    format=$2
    inspect_name=$3
    case "$format" in
      *'.Id'*)
        if [ "$stateful" = 1 ]; then
          inspect_id_file=$(state_id_path "$inspect_name") || exit 1
          cat "$inspect_id_file"
        else
          case "$inspect_name" in
            laneway-connector-test)
              echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
              ;;
            laneway-connector-test-previous-*)
              [ "${LANEWAY_UPDATER_PREVIOUS_COLLISION:-0}" = 1 ] || exit 1
              echo cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
              ;;
            *) exit 1 ;;
          esac
        fi
        ;;
      *'io.laneway.update-transaction'*)
        if [ "$stateful" = 1 ]; then
          inspect_label_file=$(state_label_path "$inspect_name") || exit 1
          [ ! -f "$inspect_label_file" ] || cat "$inspect_label_file"
        fi
        ;;
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

reset_docker_state() {
  find "$work_dir/docker-state" -mindepth 1 -maxdepth 1 -delete
  printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    > "$work_dir/docker-state/current.id"
}

run_updater() {
  env \
    -u TMPDIR \
    PATH="$work_dir/bin:$PATH" \
    LANEWAY_LOCK_DIR="$work_dir/locks" \
    LANEWAY_UPDATER_FIXTURE="$work_dir/fixture" \
    LANEWAY_UPDATER_DOCKER_LOG="$work_dir/docker.log" \
    LANEWAY_UPDATER_HEALTH="${LANEWAY_UPDATER_HEALTH:-}" \
    LANEWAY_UPDATER_RUNNING="${LANEWAY_UPDATER_RUNNING:-}" \
    LANEWAY_UPDATER_PREVIOUS_COLLISION="${LANEWAY_UPDATER_PREVIOUS_COLLISION:-0}" \
    LANEWAY_UPDATER_RENAME_COLLISION="${LANEWAY_UPDATER_RENAME_COLLISION:-0}" \
    LANEWAY_UPDATER_SIGNAL_AFTER="${LANEWAY_UPDATER_SIGNAL_AFTER:-}" \
    LANEWAY_UPDATER_STATEFUL="${LANEWAY_UPDATER_STATEFUL:-0}" \
    LANEWAY_UPDATER_DOCKER_STATE="$work_dir/docker-state" \
    "$@"
}

for docker_key in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_CONFIG; do
  : > "$work_dir/docker.log"
  set +e
  output=$(run_updater env "$docker_key=shadow" \
    sh "$updater_under_test" laneway-connector-test 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || { echo "Connector updater accepted $docker_key" >&2; exit 1; }
  [ ! -s "$work_dir/docker.log" ] || {
    echo "Connector updater reached Docker with $docker_key" >&2
    exit 1
  }
done

for trust_key in COSIGN_REPOSITORY SIGSTORE_ROOT_FILE TUF_ROOT_JSON \
  CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR LANEWAY_REPOSITORY LANEWAY_RELEASE_BASE_URL \
  LANEWAY_AUTHENTICATED_RELEASE_BASE_URL LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE \
  LANEWAY_AUTHENTICATED_COSIGN_BIN LANEWAY_COSIGN_BIN LANEWAY_COMMAND LANEWAY_CONTROL_COMMAND
do
  : > "$work_dir/docker.log"
  set +e
  output=$(run_updater env "$trust_key=shadow" \
    sh "$updater_under_test" laneway-connector-test 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || { echo "Connector updater accepted $trust_key" >&2; exit 1; }
  [ ! -s "$work_dir/docker.log" ] || {
    echo "Connector updater reached Docker with $trust_key" >&2
    exit 1
  }
done

for verifier_fixture in wrong-version hardlink; do
  : > "$work_dir/docker.log"
  set +e
  case "$verifier_fixture" in
    wrong-version)
      output=$(LANEWAY_UPDATER_COSIGN_VERSION=v3.1.2 \
        run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
      ;;
    hardlink)
      output=$(LANEWAY_UPDATER_COSIGN_METADATA=hardlink \
        run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
      ;;
  esac
  status=$?
  set -e
  [ "$status" -ne 0 ] || {
    echo "Connector updater accepted $verifier_fixture Cosign verifier" >&2
    exit 1
  }
  if grep -E '^--context default (pull|stop|rename|run|rm) ' "$work_dir/docker.log" >/dev/null; then
    echo "Connector updater reached mutable Docker work with $verifier_fixture Cosign verifier" >&2
    exit 1
  fi
done

: > "$work_dir/docker.log"
set +e
output=$(run_updater env LANEWAY_LOCK_DIR="$work_dir/insecure-locks" \
  sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "Connector updater accepted an attacker-owned lock parent" >&2; exit 1; }
[ ! -s "$work_dir/docker.log" ] || {
  echo "Connector updater reached Docker before rejecting an attacker-owned lock parent" >&2
  exit 1
}

: > "$work_dir/docker.log"
attacker_tmp=$work_dir/attacker-tmp
mkdir "$attacker_tmp"
output=$(run_updater env TMPDIR="$attacker_tmp" HOME="$attacker_tmp" DOCKER_DEFAULT_PLATFORM=linux/arm64 \
  sh "$updater_under_test" laneway-connector-test)
printf '%s\n' "$output" | grep -F 'updated successfully to v9.8.7' >/dev/null
test -z "$(find "$attacker_tmp" -mindepth 1 -maxdepth 1 -print -quit)"

output=$(run_updater sh "$updater_under_test" laneway-connector-test)
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
  run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "unhealthy replacement unexpectedly succeeded" >&2; exit 1; }
printf '%s\n' "$output" | grep -F 'previous Connector restored' >/dev/null
grep -F 'start laneway-connector-test' "$work_dir/docker.log" >/dev/null

: > "$work_dir/docker.log"
set +e
output=$(LANEWAY_UPDATER_RENAME_COLLISION=1 \
  run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "rollback-name collision unexpectedly succeeded" >&2; exit 1; }
grep -F 'start laneway-connector-test' "$work_dir/docker.log" >/dev/null
if grep -F 'rm -f laneway-connector-test' "$work_dir/docker.log" >/dev/null; then
  echo "rename collision caused cleanup to remove the legitimate Connector" >&2
  exit 1
fi

: > "$work_dir/docker.log"
set +e
output=$(LANEWAY_UPDATER_PREVIOUS_COLLISION=1 \
  run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "stale rollback-name collision unexpectedly succeeded" >&2; exit 1; }
if grep -F 'stop laneway-connector-test' "$work_dir/docker.log" >/dev/null; then
  echo "stale rollback-name collision stopped the serving Connector" >&2
  exit 1
fi

reset_docker_state
: > "$work_dir/docker.log"
set +e
output=$(LANEWAY_UPDATER_STATEFUL=1 LANEWAY_UPDATER_SIGNAL_AFTER=forward-rename \
  run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "rename-interrupted replacement unexpectedly succeeded" >&2; exit 1; }
grep -F 'rename laneway-connector-test laneway-connector-test-previous-' "$work_dir/docker.log" >/dev/null
grep -F 'rename laneway-connector-test-previous-' "$work_dir/docker.log" >/dev/null
grep -F 'start laneway-connector-test' "$work_dir/docker.log" >/dev/null
grep -Fx aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "$work_dir/docker-state/current.id" >/dev/null
test ! -e "$work_dir/docker-state/previous.id"
test -z "$(find "$work_dir/locks" -mindepth 1 -maxdepth 1 -print -quit)"

reset_docker_state
: > "$work_dir/docker.log"
set +e
output=$(LANEWAY_UPDATER_STATEFUL=1 LANEWAY_UPDATER_SIGNAL_AFTER=previous-rm \
  run_updater sh "$updater_under_test" laneway-connector-test 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "removal-interrupted replacement unexpectedly succeeded" >&2; exit 1; }
grep -Fx bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  "$work_dir/docker-state/current.id" >/dev/null
test ! -e "$work_dir/docker-state/previous.id"
if grep -F 'rm -f laneway-connector-test' "$work_dir/docker.log" >/dev/null; then
  echo "old-container cleanup interruption removed the healthy replacement" >&2
  exit 1
fi
test -z "$(find "$work_dir/locks" -mindepth 1 -maxdepth 1 -print -quit)"

echo "Connector updater verifies, replaces, preserves state, and rolls back unhealthy releases"
