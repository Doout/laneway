#!/bin/sh
set -eu
# Exercise the host-only command inside a throwaway root filesystem.
[ -f /.dockerenv ] && [ ! -e /var/run/docker.sock ] && [ ! -e /opt/laneway ]
rm /.dockerenv
[ "$(cat /proc/self/cgroup)" = '0::/' ]
case "$(uname -m)" in
  x86_64) LANEWAY_FIXTURE_ARCH=amd64 ;;
  aarch64) LANEWAY_FIXTURE_ARCH=arm64 ;;
  *) echo "unsupported Linux fixture architecture" >&2; exit 1 ;;
esac
asset=laneway_linux_${LANEWAY_FIXTURE_ARCH}.tar.gz
LANEWAY_FIXTURE_VERSION=$(tar -xOzf /lab/assets/archive.tar.gz laneway/VERSION)
printf '%s\n' "$LANEWAY_FIXTURE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
export LANEWAY_FIXTURE_VERSION LANEWAY_FIXTURE_ARCH
export LANEWAY_DEPLOY_DIR=/opt/laneway
LANEWAY_FIXTURE_LOG=/var/tmp/update-fixture.log
export LANEWAY_FIXTURE_LOG
mkdir -p /usr/local/libexec/laneway
mkdir -p /opt/laneway/generated/config /opt/laneway/generated/lifecycle /opt/laneway/generated/backups /opt/laneway/generated/recovery
chmod 0700 /opt/laneway /opt/laneway/generated/lifecycle
cp /lab/fixture/release.env /opt/laneway/.env
chmod 0600 /opt/laneway/.env
cp /lab/fixture/compose.yaml /opt/laneway/compose.yaml
sed -e 's/REPLACE_NETWORK_ID/000102030405060708090a0b0c0d0e0f/g' /lab/fixture/controller.toml.example > /opt/laneway/generated/config/controller.toml
sed -e 's/REPLACE_NETWORK_ID/000102030405060708090a0b0c0d0e0f/g' -e 's/REPLACE_CONTROLLER_SERVICE_ID/101112131415161718191a1b1c1d1e1f/g' -e 's/REPLACE_PUBLIC_HOSTNAME/lane.example.test/g' /lab/fixture/relay.toml.example > /opt/laneway/generated/config/relay.toml
chmod 0444 /opt/laneway/generated/config/*.toml
cp /opt/laneway/generated/config/controller.toml /var/tmp/controller-before.toml
cp /opt/laneway/generated/config/relay.toml /var/tmp/relay-before.toml
install -m 0755 /lab/laneway-source /usr/local/bin/laneway
ln -s /opt/laneway/laneway-control /usr/local/sbin/laneway-control
if [ -f /lab/laneway-compat-source ]; then
  install -m 0755 /lab/laneway-compat-source /usr/local/bin/laneway-compat
  if [ "$LANEWAY_FIXTURE_SCENARIO" = good ]; then
    # Inspect native setup routing before restoring the real installed operator.
    cat > /opt/laneway/laneway-control <<'SCRIPT'
#!/bin/sh
set -eu
[ "$PWD" = / ] && [ "$HOME" = /root ]
[ "${LANEWAY_AUTHENTICATED_RELEASE_BASE_URL+x}" != x ]
[ "${LANEWAY_DOMAIN+x}" != x ]
printf '%s\n' "$@" >> /var/tmp/configure-handoff
SCRIPT
    chmod 0755 /opt/laneway/laneway-control
    if /usr/local/bin/laneway configure server other.example.test > /var/tmp/configure-output 2>&1; then
      echo "configure server accepted a different domain" >&2
      exit 1
    fi
    grep -F 'differs from the installed control-plane domain' /var/tmp/configure-output >/dev/null
    [ ! -e /var/tmp/configure-handoff ]
    LANEWAY_AUTHENTICATED_RELEASE_BASE_URL=https://fixture.invalid LANEWAY_DOMAIN=other.example.test \
      /usr/local/bin/laneway configure server lane.example.test
    printf 'init\nproduction-check\n' > /var/tmp/configure-expected
    cmp /var/tmp/configure-expected /var/tmp/configure-handoff
    printf '%s\n' 'Protected configure server handoff passed.'
  fi
fi
install -m 0755 /lab/fixture/laneway-control /opt/laneway/laneway-control
ln -s laneway-control /opt/laneway/lane
: > /opt/laneway/volume.exists
printf 'fixture database before update\n' > /opt/laneway/database.state
cat > /opt/laneway/recovery.sh <<'SCRIPT'
#!/bin/sh
set -eu
[ "$1" = backup ]
[ -f /opt/laneway/generated/lifecycle/operator.lock/"$LANEWAY_LIFECYCLE_LOCK_TOKEN" ]
printf 'backup %s\n' "$2" >> "$LANEWAY_FIXTURE_LOG"
SCRIPT
cat > /opt/laneway/validate.sh <<'SCRIPT'
#!/bin/sh
set -eu
/usr/local/bin/laneway config validate -config /opt/laneway/generated/config/relay.toml
SCRIPT
chmod 0755 /opt/laneway/recovery.sh /opt/laneway/validate.sh
mkdir -p /var/tmp/fixture-assets
cp /lab/assets/archive.tar.gz "/var/tmp/fixture-assets/$asset"
cd /var/tmp/fixture-assets
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  os=${platform%_*}
  if [ "laneway_$platform.tar.gz" = "$asset" ]; then
    hash=$(sha256sum "$asset")
    hash=${hash%% *}
    size=$(wc -c < "$asset")
  else
    hash=$(printf '%064d' 1)
    size=1
  fi
  printf '[[bootstrap.artifacts]]\nos = "%s"\narch = "%s"\nurl = "https://github.com/Doout/laneway/releases/download/v%s/laneway_%s.tar.gz"\nsha256 = "%s"\nsize_bytes = %d\n' "$os" "${platform#*_}" "$LANEWAY_FIXTURE_VERSION" "$platform" "$hash" "$size"
done > bootstrap-artifacts.toml
while read -r repo setting; do
  digest=$(sed -n "s/^$setting=//p" /opt/laneway/.env)
  printf 'ghcr.io/doout/%s@%s\n' "$repo" "$digest"
done > image-digests.txt <<'DIGESTS'
laneway-controller LANEWAY_CONTROLLER_IMAGE_DIGEST
laneway-relay LANEWAY_RELAY_IMAGE_DIGEST
laneway-admin LANEWAY_ADMIN_IMAGE_DIGEST
lane-edge LANEWAY_CONNECTOR_IMAGE_DIGEST
laneway-exit-node LANEWAY_EXIT_NODE_IMAGE_DIGEST
DIGESTS
sha256sum "$asset" bootstrap-artifacts.toml image-digests.txt > checksums.txt
printf 'fixture only\n' > checksums.sigstore.json
install -m 0755 /lab/curl /usr/local/bin/curl
install -m 0755 /lab/docker /usr/local/bin/docker
install -m 0755 /lab/cosign /usr/local/libexec/laneway/cosign-v3.1.3
assert_original_deployment() {
  cmp /lab/fixture/release.env /opt/laneway/.env
  cmp /lab/fixture/compose.yaml /opt/laneway/compose.yaml
  cmp /var/tmp/controller-before.toml /opt/laneway/generated/config/controller.toml
  cmp /var/tmp/relay-before.toml /opt/laneway/generated/config/relay.toml
  grep -Fx 'fixture database before update' /opt/laneway/database.state >/dev/null
}

if [ "$LANEWAY_FIXTURE_SCENARIO" = bad-signature ] || [ "$LANEWAY_FIXTURE_SCENARIO" = bad-preflight ]; then
  source_tool=$(sha256sum /usr/local/bin/laneway)
  if /usr/local/bin/laneway update server > /var/tmp/update-output 2>&1; then
    echo "unexpected success for $LANEWAY_FIXTURE_SCENARIO" >&2
    exit 1
  fi
  cat /var/tmp/update-output
  case "$LANEWAY_FIXTURE_SCENARIO" in
    bad-signature) expected='release checksum signature verification failed' ;;
    bad-preflight) expected='verified release package failed control-plane preflight' ;;
  esac
  grep -F "$expected" /var/tmp/update-output >/dev/null
  if grep -Eq '^(backup|docker .* pull|docker .* stop)' "$LANEWAY_FIXTURE_LOG"; then
    echo "update mutated deployment after $LANEWAY_FIXTURE_SCENARIO" >&2
    exit 1
  fi
  test ! -e /opt/laneway/generated/lifecycle/operator.lock
  test ! -e /opt/laneway/generated/lifecycle/previous-release
  test "$(sha256sum /usr/local/bin/laneway)" = "$source_tool"
  test ! -e /usr/local/share/laneway/VERSION
  assert_original_deployment
  exit 0
fi
if [ "$LANEWAY_FIXTURE_SCENARIO" = bad-public-https ]; then
  printf '#!/bin/sh\n[ "$*" = 2 ]\n' > /usr/local/bin/sleep
  chmod 0755 /usr/local/bin/sleep
  if /usr/local/bin/laneway update server > /var/tmp/update-output 2>&1; then
    echo "unexpected success without public HTTPS readiness" >&2
    exit 1
  fi
  cat /var/tmp/update-output
  grep -F 'public HTTPS bootstrap did not become ready; the previous deployment was restored' /var/tmp/update-output >/dev/null
  test ! -e /opt/laneway/generated/lifecycle/operator.lock
  assert_original_deployment
  exit 0
fi
if ! /usr/local/bin/laneway update server > /var/tmp/update-output 2>&1; then
  cat /var/tmp/update-output >&2
  if [ -f "$LANEWAY_FIXTURE_LOG" ]; then
    cat "$LANEWAY_FIXTURE_LOG" >&2
  fi
  exit 1
fi
cat /var/tmp/update-output
grep -Fx "LANEWAY_VERSION=$LANEWAY_FIXTURE_VERSION" /opt/laneway/.env >/dev/null
tar -xOzf "$asset" laneway/bin/laneway | cmp - /usr/local/bin/laneway
if tar -tzf "$asset" laneway/bin/laneway-compat >/dev/null 2>&1; then
  tar -xOzf "$asset" laneway/bin/laneway-compat | cmp - /usr/local/bin/laneway-compat
fi
grep -F '[public_https]' /opt/laneway/generated/config/relay.toml >/dev/null
grep -F "v$LANEWAY_FIXTURE_VERSION/laneway_" /opt/laneway/generated/config/controller.toml >/dev/null
[ -f /opt/laneway/generated/lifecycle/previous-release ]
[ ! -e /opt/laneway/generated/lifecycle/operator.lock ]
