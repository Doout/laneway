#!/bin/sh
set -eu

image=${1:-lane-edge:ci}
work_dir=$(mktemp -d)
seal_container=lane-edge-bootstrap-seal-${work_dir##*/}
cleanup() {
  [ -z "${seal_container:-}" ] || docker rm -f "$seal_container" >/dev/null 2>&1 || :
  [ ! -e "$work_dir" ] || find "$work_dir" -depth -delete
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$work_dir"

ca_b64=$(printf '%s' fixture-ca | base64 | awk '{printf "%s", $0}')
setup_payload=$({
  printf '%s\n' office single_use_fixture https://lane.example.test:8443 \
    lane.example.test:8443 lane.example.test \
    11111111111111111111111111111111 22222222222222222222222222222222 \
    lane.example.test:4433 33333333333333333333333333333333 "$ca_b64"
} | base64 | awk '{printf "%s", $0}')
setup_token=st1.$setup_payload
expires_at=$(($(date +%s) + 600))

key=$(printf '%s\n' "$setup_token" | docker run --name "$seal_container" -i --network none \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true \
  --entrypoint /usr/local/bin/laneway "$image" connector bootstrap-seal \
  --out /var/lib/laneway/envelope --expires-at "$expires_at")
docker cp "$seal_container:/var/lib/laneway/envelope" "$work_dir/envelope"
docker rm "$seal_container" >/dev/null
seal_container=
printf '%s\n' "$key" | grep -Eq '^[A-Za-z0-9_-]{43}$'
test "$(stat -c %a "$work_dir/envelope")" = 600
if grep -E 'single_use_fixture|st1\.' "$work_dir/envelope" >/dev/null; then
  echo "encrypted envelope exposed its setup token" >&2
  exit 1
fi
chmod 0644 "$work_dir/envelope"

wrong_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set +e
output=$(printf '%s\n' "$wrong_key" | docker run --rm -i --network none \
  --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --volume "$work_dir/envelope:/run/bootstrap/envelope:ro" \
  --entrypoint /usr/local/bin/laneway "$image" connector bootstrap-activate \
  --envelope-file /run/bootstrap/envelope 2>&1)
status=$?
set -e
if [ "$status" -eq 0 ] || ! printf '%s\n' "$output" | grep -F 'invalid key or payload' >/dev/null; then
  echo "Connector accepted an unauthenticated bootstrap envelope" >&2
  exit 1
fi
if printf '%s\n' "$output" | grep -F 'single_use_fixture' >/dev/null; then
  echo "bootstrap authentication failure leaked its setup token" >&2
  exit 1
fi

echo "Connector bootstrap sealing is authenticated, bounded, and secret-free in image metadata"
