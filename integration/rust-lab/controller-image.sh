#!/usr/bin/env bash
# Run the Go reference and the binaries copied from the scratch image as its UID.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image=laneway-rust-controller:migration-lab
test "$(docker image inspect -f '{{.Config.User}}' "$image")" = 65532:65532
bin_volume="$(docker volume create --label laneway.test=rust-controller-image)"
test_volume=""
cleanup() {
  docker volume rm "$bin_volume" >/dev/null
  if [[ -n "$test_volume" ]]; then docker volume rm "$test_volume" >/dev/null; fi
}
trap cleanup EXIT
test_volume="$(docker volume create --label laneway.test=rust-controller-image)"
# Docker populates an empty volume with the files at the image's mount point.
# The CLI must run and reject missing arguments (not fail to start).
status=0
docker run --rm --network none --cap-drop ALL -v "$bin_volume:/usr/local/bin" "$image" || status=$?
test "$status" = 1
docker run --rm --network none -v "$root:/src:ro" -v "$test_volume:/tests" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -w /src/go laneway-rust-lab:local sh -ec '
    go test -tags=rustinterop -c -o /tests/https ./internal/controllerservice
    go test -tags=rustinterop -c -o /tests/sessions ./internal/controller'
docker run --rm --network none --read-only --tmpfs /tmp:exec --cap-drop ALL --user 65532:65532 \
  -v "$bin_volume:/packaged:ro" -v "$test_volume:/tests:ro" \
  -e LANEWAY_RUST_CONTROLLER=/packaged/laneway-controller laneway-rust-lab:local sh -ec '
    /tests/sessions -test.run "^TestRustControllerSessions$"
    /tests/https -test.run "^TestRustController(Inventory|HTTPS)$"'
