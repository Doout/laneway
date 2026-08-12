#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(id -u)" -ne 0 ] || { echo "administrator lifecycle integration must start as a non-root user" >&2; exit 1; }
sudo -n true >/dev/null 2>&1 || { echo "passwordless sudo is required" >&2; exit 1; }

test_dir=$(mktemp -d)
cleanup() {
  cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ] && [ -f "${stderr_log:-}" ]; then
    echo "administrator lifecycle integration failed; last protected diagnostic follows" >&2
    sed 's/^/  /' "$stderr_log" >&2 || true
    if [ -f "${log:-}" ]; then
      echo "administrator lifecycle integration call trace follows" >&2
      sed 's/^/  /' "$log" >&2 || true
    fi
  fi
  sudo find "$test_dir" -depth -delete 2>/dev/null || true
  return "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM
compose_dir=$test_dir/compose
fake_bin=$test_dir/bin
log=$test_dir/calls.log
active_token=$test_dir/controller-active.token
stdout_log=$test_dir/stdout.log
stderr_log=$test_dir/stderr.log
old_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
new_token=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
partial_token=partial-publication-secret-canary

mkdir -p "$compose_dir/generated/pki" "$fake_bin"
cp "$repo_dir/deploy/compose/laneway-control" "$compose_dir/laneway-control"
chmod 0755 "$compose_dir/laneway-control"
: > "$compose_dir/compose.yaml"
: > "$log"
cat > "$compose_dir/.env" <<'EOF'
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=8443
LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test
LANEWAY_NETWORK_ID=11111111111111111111111111111111
LANEWAY_CONTROLLER_SERVICE_ID=22222222222222222222222222222222
EOF
printf '%s\n' fixture-ca > "$compose_dir/generated/pki/ca.crt"

cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
printf 'laneway' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"

if [ "${1:-}" = id ] && [ "$#" -eq 1 ]; then
  printf '%s\n' "${LANE_TEST_ROTATION_ID:-1234567890abcdef1234567890abcdef}"
  exit 0
fi
[ "${1:-} ${2:-}" = "controller administrator" ] || exit 1
if [ "${3:-}" = bootstrap ] || [ "${3:-}" = recover ]; then
  action=$3
  shift 3
  username=
  token_file=
  token_file_count=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --username) username=$2; shift 2 ;;
      --admin-token-file)
        [ "$#" -ge 2 ] && [ "$token_file_count" -eq 0 ] || exit 1
        token_file=$2
        token_file_count=$((token_file_count + 1))
        shift 2
        ;;
      --controller|--ca|--server-name|--controller-network-id|--controller-service-id) shift 2 ;;
      --password|--password-file|--grant|--grant-file) exit 1 ;;
      *) exit 1 ;;
    esac
  done
  [ "$username" = owner ] && [ "$token_file_count" -eq 1 ] && \
    [ "$token_file" = "$LANEWAY_DEPLOY_DIR/generated/secrets/admin.token" ]
  exit 0
fi
[ "${1:-} ${2:-} ${3:-}" = "controller administrator root-token" ] || exit 1
action=${4:-}
shift 4
token_file=
token_file_count=0
expect=
out_file=
rotation_id=
rotation_id_count=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --admin-token-file)
      [ "$#" -ge 2 ] && [ "$token_file_count" -eq 0 ] || exit 1
      token_file=$2
      token_file_count=$((token_file_count + 1))
      shift 2
      ;;
    --expect) expect=$2; shift 2 ;;
    --out-file) out_file=$2; shift 2 ;;
    --rotation-id)
      [ "$#" -ge 2 ] && [ "$rotation_id_count" -eq 0 ] || exit 1
      rotation_id=$2
      rotation_id_count=$((rotation_id_count + 1))
      shift 2
      ;;
    --controller|--ca|--server-name|--controller-network-id|--controller-service-id) shift 2 ;;
    *) exit 1 ;;
  esac
done

rotation_credential_kind() {
  [ -f "$token_file" ] && [ ! -L "$token_file" ] && [ "$(stat -c %h "$token_file")" -eq 1 ] || return 1
  case "$token_file" in
    "$LANEWAY_DEPLOY_DIR/generated/lifecycle/administrator-root-token-rotation/old.token") printf old ;;
    "$LANEWAY_DEPLOY_DIR/generated/lifecycle/administrator-root-token-rotation/new.token") printf new ;;
    *) return 1 ;;
  esac
}

require_rotation_id() {
  [ "$rotation_id_count" -eq 1 ] && [ "${#rotation_id}" -eq 32 ] && \
    [ "$rotation_id" != 00000000000000000000000000000000 ] || return 1
  case "$rotation_id" in *[!0-9a-f]*) return 1 ;; esac
}

case "$action" in
  generate)
    [ -n "$out_file" ] && [ ! -e "$out_file" ] && [ "$token_file_count" -eq 0 ] && \
      [ "$rotation_id_count" -eq 0 ]
    umask 077
    printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > "$out_file"
    chmod 0600 "$out_file"
    chown 0:0 "$out_file"
    [ "$(stat -c %h "$out_file")" -eq 1 ]
    ;;
  rotation-begin)
    [ "$token_file_count" -eq 1 ] && [ -z "$expect" ] && [ -z "$out_file" ]
    require_rotation_id
    credential_kind=$(rotation_credential_kind)
    [ "$credential_kind" = old ] && cmp -s "$token_file" "$LANE_TEST_ACTIVE_TOKEN"
    printf 'rotation-phase action=rotation-begin credential=%s rotation_id=%s\n' \
      "$credential_kind" "$rotation_id" >> "$LANE_TEST_LOG"
    [ "${LANE_TEST_FAIL_BEGIN:-0}" = 0 ]
    ;;
  rotation-complete)
    [ "$token_file_count" -eq 1 ] && [ -z "$expect" ] && [ -z "$out_file" ]
    require_rotation_id
    credential_kind=$(rotation_credential_kind)
    [ "$credential_kind" = new ] && cmp -s "$token_file" "$LANE_TEST_ACTIVE_TOKEN"
    printf 'rotation-phase action=rotation-complete credential=%s rotation_id=%s\n' \
      "$credential_kind" "$rotation_id" >> "$LANE_TEST_LOG"
    [ "${LANE_TEST_FAIL_COMPLETE:-0}" = 0 ]
    ;;
  authentication-check)
    [ "$token_file_count" -eq 1 ] && [ -n "$expect" ] && [ -z "$out_file" ] && \
      [ "$rotation_id_count" -eq 0 ]
    credential_kind=$(rotation_credential_kind)
    if cmp -s "$token_file" "$LANE_TEST_ACTIVE_TOKEN"; then accepted=true; else accepted=false; fi
    printf 'rotation-auth credential=%s expect=%s result=%s\n' \
      "$credential_kind" "$expect" "$accepted" >> "$LANE_TEST_LOG"
    if [ "${LANE_TEST_FAIL_NEW_AUTH:-0}" = 1 ] && [ "$expect" = accepted ] &&
      grep -Eq '^b{64}$' "$token_file"; then
      exit 1
    fi
    case "$expect:$accepted" in accepted:true|rejected:false) ;; *) exit 1 ;; esac
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
found_compose=false
found_up=false
found_detach=false
found_wait=false
found_recreate=false
found_no_deps=false
found_controller=false
for argument
do
  case "$argument" in
    compose) found_compose=true ;;
    up) found_up=true ;;
    -d) found_detach=true ;;
    --wait) found_wait=true ;;
    --force-recreate) found_recreate=true ;;
    --no-deps) found_no_deps=true ;;
    controller) found_controller=true ;;
  esac
done
if [ "$found_compose" != true ] || [ "$found_up" != true ] || [ "$found_detach" != true ] || \
  [ "$found_wait" != true ] || [ "$found_recreate" != true ] || [ "$found_no_deps" != true ] || \
  [ "$found_controller" != true ]; then
  exit 1
fi
cp "$LANEWAY_DEPLOY_DIR/generated/secrets/admin.token" "$LANE_TEST_ACTIVE_TOKEN"
EOF
chmod 0755 "$fake_bin/laneway" "$fake_bin/docker"

sudo install -d -m 0700 -o 0 -g 0 "$compose_dir/generated" "$compose_dir/generated/secrets"
printf '%s\n' "$old_token" > "$test_dir/admin.token"
sudo install -m 0400 -o 65532 -g 65532 "$test_dir/admin.token" "$compose_dir/generated/secrets/admin.token"
cp "$test_dir/admin.token" "$active_token"
rm "$test_dir/admin.token"

run_root() {
  sudo -n env PATH="$fake_bin:/usr/bin:/bin" LANEWAY_COMMAND="$fake_bin/laneway" \
    LANEWAY_DEPLOY_DIR="$compose_dir" LANE_TEST_LOG="$log" LANE_TEST_ACTIVE_TOKEN="$active_token" \
    "$@"
}

assert_no_secret_leak() {
  if grep -F "$old_token" "$stdout_log" "$stderr_log" "$log" >/dev/null 2>&1 ||
    grep -F "$new_token" "$stdout_log" "$stderr_log" "$log" >/dev/null 2>&1 ||
    grep -F "$partial_token" "$stdout_log" "$stderr_log" "$log" >/dev/null 2>&1; then
    echo "administrator root-token workflow leaked credential material" >&2
    exit 1
  fi
}

expect_nonroot_wrapper_rejection() {
  rejection_label=$1
  shift
  : > "$log"
  if env PATH="$fake_bin:/usr/bin:/bin" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" \
    LANEWAY_DEPLOY_DIR="$compose_dir" LANE_TEST_ACTIVE_TOKEN="$active_token" \
    "$compose_dir/laneway-control" "$@" >"$stdout_log" 2>"$stderr_log"; then
    echo "$rejection_label accepted a non-root caller" >&2
    exit 1
  fi
  [ ! -s "$log" ] || { echo "$rejection_label invoked a child command before non-root rejection" >&2; exit 1; }
  sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock" || {
    echo "$rejection_label left an operator lock after non-root rejection" >&2
    exit 1
  }
}

expect_invalid_wrapper_arguments() {
  rejection_label=$1
  shift
  : > "$log"
  if run_root "$compose_dir/laneway-control" "$@" >"$stdout_log" 2>"$stderr_log"; then
    echo "$rejection_label accepted invalid arguments" >&2
    exit 1
  fi
  [ ! -s "$log" ] || { echo "$rejection_label invoked a child command before argument rejection" >&2; exit 1; }
  sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock" || {
    echo "$rejection_label left an operator lock after argument rejection" >&2
    exit 1
  }
}

# Privilege and shared-lock checks precede all child invocations.
expect_nonroot_wrapper_rejection "administrator bootstrap" administrator bootstrap --username owner
expect_nonroot_wrapper_rejection "administrator recovery" administrator recover --username owner
expect_nonroot_wrapper_rejection "administrator root-token rotation" administrator root-token rotate
sudo install -d -m 0700 -o 0 -g 0 "$compose_dir/generated/lifecycle/operator.lock"
assert_lock_rejection() {
  : > "$log"
  if run_root "$compose_dir/laneway-control" "$@" >"$stdout_log" 2>"$stderr_log"; then
    echo "lifecycle token consumer ignored the shared lock: $*" >&2
    exit 1
  fi
  [ ! -s "$log" ] || { echo "lock rejection invoked a child command: $*" >&2; exit 1; }
}
assert_lock_rejection administrator root-token rotate
assert_lock_rejection administrator bootstrap --username owner
assert_lock_rejection administrator recover --username owner
assert_lock_rejection user-token --name owner
assert_lock_rejection api-token --name owner
assert_lock_rejection invite --name connector
assert_lock_rejection route add --connector connector --to 192.0.2.1/32
# Status intentionally remains lock-free so it can diagnose a stale lock and
# so production-check can call run_status while already holding the lock. It
# must reach a child command even with the simulated lock present.
: > "$log"
run_root "$compose_dir/laneway-control" status >"$stdout_log" 2>"$stderr_log" || true
grep -E '^(docker|laneway) ' "$log" >/dev/null || {
  echo "status was blocked by the shared lifecycle lock" >&2
  exit 1
}
sudo rmdir "$compose_dir/generated/lifecycle/operator.lock"

# Missing, malformed, or extra username input is rejected by the wrapper before
# the root credential or hidden lifecycle process is touched.
expect_invalid_wrapper_arguments "administrator bootstrap without username" administrator bootstrap
expect_invalid_wrapper_arguments "administrator bootstrap without username value" administrator bootstrap --username
expect_invalid_wrapper_arguments "administrator bootstrap uppercase username" administrator bootstrap --username Owner
expect_invalid_wrapper_arguments "administrator recovery short username" administrator recover --username ab
expect_invalid_wrapper_arguments "administrator recovery edge punctuation" administrator recover --username owner_
expect_invalid_wrapper_arguments "administrator recovery extra argument" administrator recover --username owner extra
expect_invalid_wrapper_arguments "administrator bootstrap caller token" \
  administrator bootstrap --username owner --admin-token-file forbidden
expect_invalid_wrapper_arguments "administrator recovery password" \
  administrator recover --username owner --password forbidden

# Bootstrap and recovery pass only nonsecret username and controller metadata
# to the single hidden process while using the same shared lock.
: > "$log"
run_root "$compose_dir/laneway-control" administrator bootstrap --username owner >"$stdout_log" 2>"$stderr_log"
grep -F '<controller> <administrator> <bootstrap> <--username> <owner>' "$log" >/dev/null
: > "$log"
run_root "$compose_dir/laneway-control" administrator recover --username owner >"$stdout_log" 2>"$stderr_log"
grep -F '<controller> <administrator> <recover> <--username> <owner>' "$log" >/dev/null
assert_no_secret_leak

# Unsafe hardlinks must fail before generation, remote calls, controller
# recreation, or cleanup. The linked inode is retained for operator review.
expect_rotation_preflight_rejection() {
  rejection_label=$1
  : > "$log"
  if run_root "$compose_dir/laneway-control" administrator root-token rotate \
    >"$stdout_log" 2>"$stderr_log"; then
    echo "$rejection_label was accepted" >&2
    exit 1
  fi
  [ ! -s "$log" ] || { echo "$rejection_label reached a child command" >&2; exit 1; }
  sudo grep -Fx "$old_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
  grep -Fx "$old_token" "$active_token" >/dev/null
  sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock" || {
    echo "$rejection_label left an operator lock" >&2
    exit 1
  }
  assert_no_secret_leak
}

rotation_dir=$compose_dir/generated/lifecycle/administrator-root-token-rotation
create_prepared_rotation_fixture() {
  sudo install -d -m 0700 -o 0 -g 0 "$rotation_dir"
  printf '%s\n' "$old_token" > "$test_dir/rotation-old.token"
  printf '%s\n' "$new_token" > "$test_dir/rotation-new.token"
  printf 'version=1\nrotation_id=1234567890abcdef1234567890abcdef\nphase=prepared\n' \
    > "$test_dir/rotation-state"
  sudo install -m 0600 -o 0 -g 0 "$test_dir/rotation-old.token" "$rotation_dir/old.token"
  sudo install -m 0600 -o 0 -g 0 "$test_dir/rotation-new.token" "$rotation_dir/new.token"
  sudo install -m 0600 -o 0 -g 0 "$test_dir/rotation-state" "$rotation_dir/state"
  find "$test_dir/rotation-old.token" "$test_dir/rotation-new.token" \
    "$test_dir/rotation-state" -maxdepth 0 -delete
}

live_external=$test_dir/external-live-admin.token
sudo ln "$compose_dir/generated/secrets/admin.token" "$live_external"
live_checksum=$(sudo sha256sum "$live_external")
expect_rotation_preflight_rejection "hardlinked live administrator root token"
sudo test -f "$live_external" && sudo test -f "$compose_dir/generated/secrets/admin.token"
[ "$(sudo stat -c %h "$live_external")" -eq 2 ]
[ "$(sudo sha256sum "$live_external")" = "$live_checksum" ]
sudo find "$live_external" -maxdepth 0 -delete
[ "$(sudo stat -c %h "$compose_dir/generated/secrets/admin.token")" -eq 1 ]

for linked_member in old.token new.token state
do
  create_prepared_rotation_fixture
  linked_external=$test_dir/external-rotation-$linked_member
  sudo ln "$rotation_dir/$linked_member" "$linked_external"
  linked_checksum=$(sudo sha256sum "$linked_external")
  expect_rotation_preflight_rejection "hardlinked protected rotation $linked_member"
  sudo test -f "$linked_external" && sudo test -f "$rotation_dir/$linked_member"
  [ "$(sudo stat -c %h "$linked_external")" -eq 2 ]
  [ "$(sudo sha256sum "$linked_external")" = "$linked_checksum" ]
  for retained_member in old.token new.token state
  do
    sudo test -f "$rotation_dir/$retained_member"
  done
  sudo find "$linked_external" -maxdepth 0 -delete
  sudo find "$rotation_dir" -depth -delete
done

linked_residue=$compose_dir/generated/secrets/.admin.token.rotate.linked
residue_external=$test_dir/external-rotation-residue
sudo install -m 0600 -o 0 -g 0 /dev/null "$linked_residue"
sudo ln "$linked_residue" "$residue_external"
residue_checksum=$(sudo sha256sum "$residue_external")
expect_rotation_preflight_rejection "hardlinked root-token publication residue"
sudo test -f "$residue_external" && sudo test -f "$linked_residue"
[ "$(sudo stat -c %h "$residue_external")" -eq 2 ]
[ "$(sudo sha256sum "$residue_external")" = "$residue_checksum" ]
sudo find "$residue_external" "$linked_residue" -maxdepth 0 -delete

# A zero identity is not a canonical rotation correlation ID. Generation may
# prepare candidates, but rejection must occur before begin or publication.
: > "$log"
if run_root env LANE_TEST_ROTATION_ID=00000000000000000000000000000000 \
  "$compose_dir/laneway-control" administrator root-token rotate >"$stdout_log" 2>"$stderr_log"; then
  echo "zero administrator root-token rotation ID was accepted" >&2
  exit 1
fi
[ "$(grep -Fc '<root-token> <generate>' "$log")" -eq 1 ]
[ "$(grep -Fxc 'laneway <id>' "$log")" -eq 1 ]
if grep -q '^rotation-phase ' "$log" || grep -q '^docker ' "$log"; then
  echo "invalid root-token rotation ID reached begin or controller recreation" >&2
  exit 1
fi
sudo grep -Fx "$old_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
grep -Fx "$old_token" "$active_token" >/dev/null
sudo test ! -e "$rotation_dir"
[ "$(sudo find "$compose_dir/generated/lifecycle" -mindepth 1 -maxdepth 1 \
  -name '.administrator-root-token-rotation.*' -print | wc -l)" -eq 0 ]
sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock"
assert_no_secret_leak

# Successful rotation publishes a new inode, recreates the controller, proves
# both credentials, records completion, and removes all protected staging.
printf '%s\n' "$new_token" > "$test_dir/orphan.token"
sudo install -m 0400 -o 65532 -g 65532 "$test_dir/orphan.token" \
  "$compose_dir/generated/secrets/.admin.token.rotate.orphan"
rm "$test_dir/orphan.token"
printf '%s\n' "$partial_token" > "$test_dir/partial.token"
sudo install -m 0600 -o 0 -g 0 "$test_dir/partial.token" \
  "$compose_dir/generated/secrets/.admin.token.rotate.partial"
rm "$test_dir/partial.token"
[ "$(sudo stat -c %h "$compose_dir/generated/secrets/.admin.token.rotate.orphan")" -eq 1 ]
[ "$(sudo stat -c '%a:%u:%g:%h' "$compose_dir/generated/secrets/.admin.token.rotate.partial")" = 600:0:0:1 ]
old_inode=$(sudo stat -c %i "$compose_dir/generated/secrets/admin.token")
: > "$log"
run_root "$compose_dir/laneway-control" administrator root-token rotate >"$stdout_log" 2>"$stderr_log"
new_inode=$(sudo stat -c %i "$compose_dir/generated/secrets/admin.token")
[ "$old_inode" != "$new_inode" ] || { echo "root token publication did not replace the inode" >&2; exit 1; }
sudo grep -Fx "$new_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
grep -Fx "$new_token" "$active_token" >/dev/null
[ "$(sudo stat -c '%a:%u:%g:%h' "$compose_dir/generated/secrets/admin.token")" = 400:65532:65532:1 ]
sudo test ! -e "$compose_dir/generated/lifecycle/administrator-root-token-rotation"
sudo test ! -e "$compose_dir/generated/secrets/.admin.token.rotate.orphan"
sudo test ! -e "$compose_dir/generated/secrets/.admin.token.rotate.partial"
sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock"
[ "$(grep -c '^docker ' "$log")" -eq 1 ]
grep -F '<--force-recreate>' "$log" >/dev/null
[ "$(grep -c '^rotation-phase action=rotation-begin credential=old rotation_id=' "$log")" -eq 1 ] || {
  echo "root-token rotation begin did not use exactly one old credential" >&2
  exit 1
}
[ "$(grep -c '^rotation-phase action=rotation-complete credential=new rotation_id=' "$log")" -eq 1 ] || {
  echo "root-token rotation completion did not use exactly one new credential" >&2
  exit 1
}
successful_begin_id=$(sed -n 's/^rotation-phase action=rotation-begin credential=old rotation_id=//p' "$log")
successful_complete_id=$(sed -n 's/^rotation-phase action=rotation-complete credential=new rotation_id=//p' "$log")
[ "$successful_begin_id" = "$successful_complete_id" ] || {
  echo "root-token rotation begin and completion used different correlation IDs" >&2
  exit 1
}
assert_no_secret_leak

reset_old_token() {
  printf '%s\n' "$old_token" > "$test_dir/admin.token"
  sudo install -m 0400 -o 65532 -g 65532 "$test_dir/admin.token" "$compose_dir/generated/secrets/admin.token"
  cp "$test_dir/admin.token" "$active_token"
  rm "$test_dir/admin.token"
  sudo find "$compose_dir/generated/lifecycle" -mindepth 1 -depth -delete
  : > "$log"
}

# Terminal cleanup is recoverable after the active state is atomically renamed
# and after deletion has started. Reconciliation must not repeat any lifecycle
# or controller action after completion was already recorded.
find_complete_cleanup_tombstone() {
  sudo find "$compose_dir/generated/lifecycle" -mindepth 1 -maxdepth 1 -type d \
    -name '.administrator-root-token-rotation.cleanup.complete_recorded.*' -print
}

assert_cleanup_only_retry() {
  cleanup_label=$1
  : > "$log"
  run_root "$compose_dir/laneway-control" administrator root-token rotate \
    >"$stdout_log" 2>"$stderr_log"
  [ ! -s "$log" ] || {
    echo "$cleanup_label repeated a hidden lifecycle or controller action" >&2
    exit 1
  }
  grep -F 'rotation was already complete; protected cleanup reconciled' "$stdout_log" >/dev/null
  sudo test ! -e "$rotation_dir"
  [ -z "$(find_complete_cleanup_tombstone)" ] || {
    echo "$cleanup_label retained terminal cleanup state after retry" >&2
    exit 1
  }
  sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock"
  sudo grep -Fx "$new_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
  grep -Fx "$new_token" "$active_token" >/dev/null
  assert_no_secret_leak
}

for cleanup_failure in post-rename mid-delete
do
  reset_old_token
  if run_root env LANEWAY_TEST_ROOT_TOKEN_CLEANUP_FAIL=$cleanup_failure \
    "$compose_dir/laneway-control" administrator root-token rotate \
    >"$stdout_log" 2>"$stderr_log"; then
    echo "$cleanup_failure root-token terminal cleanup failure was reported as success" >&2
    exit 1
  fi
  sudo test ! -e "$rotation_dir" || {
    echo "$cleanup_failure root-token cleanup retained the active rotation name" >&2
    exit 1
  }
  cleanup_tombstones=$(find_complete_cleanup_tombstone)
  [ "$(printf '%s\n' "$cleanup_tombstones" | sed '/^$/d' | wc -l)" -eq 1 ] || {
    echo "$cleanup_failure root-token cleanup did not retain exactly one terminal tombstone" >&2
    exit 1
  }
  cleanup_tombstone=$cleanup_tombstones
  expected_cleanup_tombstone=$compose_dir/generated/lifecycle/.administrator-root-token-rotation.cleanup.complete_recorded.1234567890abcdef1234567890abcdef
  [ "$cleanup_tombstone" = "$expected_cleanup_tombstone" ] || {
    echo "$cleanup_failure root-token cleanup used a nondeterministic reservation name" >&2
    exit 1
  }
  sudo find "$cleanup_tombstone" -mindepth 1 -maxdepth 1 -print -quit | grep . >/dev/null || {
    echo "$cleanup_failure root-token cleanup left an empty reservation beside active state" >&2
    exit 1
  }
  [ "$(sudo stat -c '%a:%u:%g' "$cleanup_tombstone")" = 700:0:0 ]
  sudo grep -Fx "$new_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
  grep -Fx "$new_token" "$active_token" >/dev/null
  sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock"
  [ "$(grep -c '^rotation-phase action=rotation-complete credential=new rotation_id=' "$log")" -eq 1 ] || {
    echo "$cleanup_failure root-token cleanup was not reached after one recorded completion" >&2
    exit 1
  }
  assert_no_secret_leak

  if [ "$cleanup_failure" = mid-delete ]; then
    printf 'protected interrupted state publication\n' > "$test_dir/interrupted-state"
    sudo install -m 0600 -o 0 -g 0 "$test_dir/interrupted-state" \
      "$cleanup_tombstone/.state.A1b2C3"
    sudo install -m 0600 -o 0 -g 0 "$test_dir/interrupted-state" \
      "$cleanup_tombstone/.state.D4e5F6"
    rm "$test_dir/interrupted-state"
    [ "$(sudo stat -c '%a:%u:%g:%h' "$cleanup_tombstone/.state.A1b2C3")" = 600:0:0:1 ]
    [ "$(sudo stat -c '%a:%u:%g:%h' "$cleanup_tombstone/.state.D4e5F6")" = 600:0:0:1 ]
  fi
  assert_cleanup_only_retry "$cleanup_failure root-token cleanup retry"
done

# A terminal rollback tombstone is also cleanup-only, but preserves the
# rollback result: retry reaps it and returns failure without starting anew.
reset_old_token
rolled_back_tombstone=$compose_dir/generated/lifecycle/.administrator-root-token-rotation.cleanup.rolled_back.1234567890abcdef1234567890abcdef
sudo install -d -m 0700 -o 0 -g 0 "$rolled_back_tombstone"
printf '%s\n' "$old_token" > "$test_dir/rolled-back-old.token"
printf '%s\n' "$new_token" > "$test_dir/rolled-back-new.token"
printf 'version=1\nrotation_id=1234567890abcdef1234567890abcdef\nphase=rolled_back\n' \
  > "$test_dir/rolled-back-state"
sudo install -m 0600 -o 0 -g 0 "$test_dir/rolled-back-old.token" "$rolled_back_tombstone/old.token"
sudo install -m 0600 -o 0 -g 0 "$test_dir/rolled-back-new.token" "$rolled_back_tombstone/new.token"
sudo install -m 0600 -o 0 -g 0 "$test_dir/rolled-back-state" "$rolled_back_tombstone/state"
rm "$test_dir/rolled-back-old.token" "$test_dir/rolled-back-new.token" "$test_dir/rolled-back-state"
: > "$log"
if run_root "$compose_dir/laneway-control" administrator root-token rotate \
  >"$stdout_log" 2>"$stderr_log"; then
  echo "rolled-back root-token cleanup retry was reported as a new success" >&2
  exit 1
fi
[ ! -s "$log" ] || { echo "rolled-back cleanup retry invoked a child command" >&2; exit 1; }
sudo test ! -e "$rolled_back_tombstone"
sudo test ! -e "$rotation_dir"
sudo test ! -e "$compose_dir/generated/lifecycle/operator.lock"
sudo grep -Fx "$old_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
grep -Fx "$old_token" "$active_token" >/dev/null
grep -F 'was rolled back and verified; protected cleanup reconciled' "$stderr_log" >/dev/null
assert_no_secret_leak

# A failure before the logical commit restores and verifies the old token and
# recreates the controller a second time.
reset_old_token
# Redirect targets are intentionally nonsecret, user-owned test logs.
# shellcheck disable=SC2024
if sudo -n env PATH="$fake_bin:/usr/bin:/bin" LANEWAY_COMMAND="$fake_bin/laneway" \
  LANEWAY_DEPLOY_DIR="$compose_dir" LANE_TEST_LOG="$log" LANE_TEST_ACTIVE_TOKEN="$active_token" \
  LANE_TEST_FAIL_NEW_AUTH=1 "$compose_dir/laneway-control" administrator root-token rotate \
  >"$stdout_log" 2>"$stderr_log"; then
  echo "failed new-token authentication was reported as success" >&2
  exit 1
fi
sudo grep -Fx "$old_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
grep -Fx "$old_token" "$active_token" >/dev/null
[ "$(grep -c '^docker ' "$log")" -eq 2 ]
sudo test ! -e "$compose_dir/generated/lifecycle/administrator-root-token-rotation"
assert_no_secret_leak

# Once both authentication proofs commit, completion failure must retain the
# new authority and a secret-free marker. A retry reconciles with the same ID.
reset_old_token
# Redirect targets are intentionally nonsecret, user-owned test logs.
# shellcheck disable=SC2024
if sudo -n env PATH="$fake_bin:/usr/bin:/bin" LANEWAY_COMMAND="$fake_bin/laneway" \
  LANEWAY_DEPLOY_DIR="$compose_dir" LANE_TEST_LOG="$log" LANE_TEST_ACTIVE_TOKEN="$active_token" \
  LANE_TEST_FAIL_COMPLETE=1 "$compose_dir/laneway-control" administrator root-token rotate \
  >"$stdout_log" 2>"$stderr_log"; then
  echo "failed completion audit was reported as success" >&2
  exit 1
fi
sudo grep -Fx "$new_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
grep -Fx "$new_token" "$active_token" >/dev/null
sudo grep -Fx 'phase=committed_pending_complete' \
  "$compose_dir/generated/lifecycle/administrator-root-token-rotation/state" >/dev/null
[ "$(sudo stat -c %h "$compose_dir/generated/secrets/admin.token")" -eq 1 ]
for protected_member in old.token new.token state
do
  [ "$(sudo stat -c %h \
    "$compose_dir/generated/lifecycle/administrator-root-token-rotation/$protected_member")" -eq 1 ]
done
if sudo grep -F "$old_token" "$compose_dir/generated/lifecycle/administrator-root-token-rotation/state" >/dev/null ||
  sudo grep -F "$new_token" "$compose_dir/generated/lifecycle/administrator-root-token-rotation/state" >/dev/null; then
  echo "root-token rotation marker contains credential material" >&2
  exit 1
fi
[ "$(grep -c '^rotation-phase action=rotation-begin credential=old rotation_id=' "$log")" -eq 1 ] || {
  echo "pending root-token rotation did not record exactly one old-token begin" >&2
  exit 1
}
[ "$(grep -c '^rotation-phase action=rotation-complete credential=new rotation_id=' "$log")" -eq 1 ] || {
  echo "pending root-token rotation did not attempt exactly one new-token completion" >&2
  exit 1
}
pending_begin_id=$(sed -n 's/^rotation-phase action=rotation-begin credential=old rotation_id=//p' "$log")
pending_rotation_id=$(sed -n 's/^rotation-phase action=rotation-complete credential=new rotation_id=//p' "$log")
[ "$pending_begin_id" = "$pending_rotation_id" ] || {
  echo "pending root-token rotation changed correlation ID before completion" >&2
  exit 1
}
assert_no_secret_leak
: > "$log"
# An uncatchable termination conservatively leaves the shared lock. The
# wrapper must preserve committed rotation state until an operator validates
# and removes only the empty stale lock.
sudo install -d -m 0700 -o 0 -g 0 "$compose_dir/generated/lifecycle/operator.lock"
if run_root "$compose_dir/laneway-control" administrator root-token rotate >"$stdout_log" 2>"$stderr_log"; then
  echo "administrator rotation ignored a simulated stale lifecycle lock" >&2
  exit 1
fi
[ ! -s "$log" ] || { echo "stale lifecycle lock allowed a child invocation" >&2; exit 1; }
sudo rmdir "$compose_dir/generated/lifecycle/operator.lock"
run_root "$compose_dir/laneway-control" administrator root-token rotate >"$stdout_log" 2>"$stderr_log"
sudo grep -Fx "$new_token" "$compose_dir/generated/secrets/admin.token" >/dev/null
sudo test ! -e "$compose_dir/generated/lifecycle/administrator-root-token-rotation"
if grep -Fq '<root-token> <generate>' "$log" || grep -Fqx 'laneway <id>' "$log" ||
  grep -q '^rotation-phase action=rotation-begin ' "$log"; then
  echo "committed root-token retry started a new rotation generation" >&2
  exit 1
fi
[ "$(grep -c '^laneway ' "$log")" -eq 3 ] || {
  echo "committed root-token retry invoked an unexpected hidden lifecycle action" >&2
  exit 1
}
if [ "$(grep -c '^docker ' "$log")" -ne 1 ] || ! grep -F '<--force-recreate>' "$log" >/dev/null; then
  echo "committed root-token retry did not force-recreate the controller exactly once" >&2
  exit 1
fi
[ "$(grep -c '^rotation-auth credential=new expect=accepted result=true$' "$log")" -eq 1 ] || {
  echo "committed root-token retry did not prove the new credential" >&2
  exit 1
}
[ "$(grep -c '^rotation-auth credential=old expect=rejected result=false$' "$log")" -eq 1 ] || {
  echo "committed root-token retry did not prove rejection of the old credential" >&2
  exit 1
}
[ "$(grep -c '^rotation-phase action=rotation-complete credential=new rotation_id=' "$log")" -eq 1 ] || {
  echo "committed root-token retry did not record exactly one completion" >&2
  exit 1
}
retried_rotation_id=$(sed -n 's/^rotation-phase action=rotation-complete credential=new rotation_id=//p' "$log")
[ "$retried_rotation_id" = "$pending_rotation_id" ] || {
  echo "committed root-token retry changed the correlation ID" >&2
  exit 1
}
retry_order=$(awk '
  /^docker / { print "docker" }
  /^rotation-auth credential=new expect=accepted result=true$/ { print "new-accepted" }
  /^rotation-auth credential=old expect=rejected result=false$/ { print "old-rejected" }
  /^rotation-phase action=rotation-complete credential=new rotation_id=/ { print "complete" }
' "$log")
expected_retry_order=$(printf 'docker\nnew-accepted\nold-rejected\ncomplete\n')
[ "$retry_order" = "$expected_retry_order" ] || {
  echo "committed root-token retry used an unsafe reconciliation order" >&2
  exit 1
}
[ "$(sudo stat -c %h "$compose_dir/generated/secrets/admin.token")" -eq 1 ]
assert_no_secret_leak

echo "Administrator root-token lifecycle is atomic, fail-closed, and recoverable"
