#!/bin/sh
# Test the legacy wrapper's cutover guard without a Docker daemon.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/bin" "$work/deploy"
base=$work/deploy
cp "$root/deploy/compose/laneway-control" "$base/laneway-control"
printf 'services: {}\n' >"$base/compose.yaml"
printf 'LANEWAY_VERSION=0.2.72\n' >"$base/.env"
cat >"$base/recovery.sh" <<'EOF'
#!/bin/sh
set -eu
echo "recovery helper: $*"
EOF
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
  compose)
    for arg; do
      case "$arg" in ps) found=1 ;; stop|start|up|down|run|pull) exit 99 ;; esac
    done
    test "${found:-0}" = 1
    case "$GUARD_FIXTURE" in
      unreachable) exit 2 ;;
      stopped) exit 0 ;;
      mixed) printf '%s\n' 111111111111 222222222222 ;;
      *) printf '%s\n' 111111111111 ;;
    esac
    ;;
  inspect)
    [ "$#" -eq 6 ] && [ "$2" = --type ] && [ "$3" = container ] && [ "$4" = --format ]
    case "$GUARD_FIXTURE:$6" in
      mixed:222222222222|rust:*) echo 'rust local-image:preview' ;;
      older-rust:*) echo ' ghcr.io/doout/laneway-controller-rust:0.0.9100@sha256:pinned' ;;
      older-exit:*) echo ' ghcr.io/doout/laneway-exit-node-rust@sha256:pinned' ;;
      broken-inspect:*) exit 3 ;;
      *) echo ' ghcr.io/doout/laneway-controller:0.2.72@sha256:pinned' ;;
    esac
    ;;
  *) exit 99 ;;
esac
EOF
chmod 0700 "$base/recovery.sh" "$work/bin/docker"
export PATH="$work/bin:$PATH"
legacy() { sh "$base/laneway-control" "$@"; }
reject() {
  if legacy backup guard.age >"$work/result" 2>&1; then
    echo "unsafe legacy backup succeeded for $GUARD_FIXTURE" >&2
    return 1
  fi
  grep -F "$1" "$work/result" >/dev/null
  ! grep -q 'recovery helper' "$work/result"
  test ! -e "$base/generated/lifecycle/operator.lock"
}

# Ordinary Go installs don't become dependent on an extra Docker probe.
export GUARD_FIXTURE=unreachable
legacy backup go-only.age | grep -Fx 'recovery helper: backup go-only.age'
printf 'services: {}\n' >"$base/compose.rust.yaml"
reject 'cannot verify the running control-plane runtime'
for state in mixed rust older-rust older-exit; do
  export GUARD_FIXTURE=$state
  reject 'legacy Go maintenance refused'
done
export GUARD_FIXTURE=broken-inspect
reject 'cannot inspect a running control-plane service'
export GUARD_FIXTURE=go
legacy backup go-rollback.age | grep -Fx 'recovery helper: backup go-rollback.age'
export GUARD_FIXTURE=stopped
legacy check-go-runtime "$base"

# A removed overlay does not bypass the guard if the Rust pins remain.
mv "$base/compose.rust.yaml" "$work/staged-overlay"
printf 'LANEWAY_RUST_VERSION=0.0.9100\n' >>"$base/.env"
export GUARD_FIXTURE=older-rust
reject 'legacy Go maintenance refused'
echo 'Passed Go runtime guard, including mixed deployments, uncertain state and rollback.'
