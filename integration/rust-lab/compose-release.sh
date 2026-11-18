#!/usr/bin/env bash
# Sourced by the marked, isolated Compose rehearsal.
# shellcheck disable=SC2034,SC2154

prepare_verified_release() {
  LANEWAY_COSIGN_BIN="$work/bin/compose-cosign" python3 prepare-rust.py --release-metadata "$work/release"
}

prepare_candidate_release() {
  local platform image
  candidate_url=https://github.com/Doout/laneway/releases/download/v0.0.9100
  mkdir -m 0700 "$work/release"
  for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
    printf '[[bootstrap.artifacts]]\nos = "%s"\narch = "%s"\nurl = "%s/laneway_%s.tar.gz"\nsha256 = "%s"\nsize_bytes = 321\n' \
      "${platform%_*}" "${platform#*_}" "$candidate_url" "$platform" "${digest#sha256:}"
  done >"$work/release/bootstrap-artifacts.toml"
  for image in controller relay exit-node; do
    printf 'ghcr.io/doout/laneway-%s-rust@%s\n' "$image" "$digest"
  done >"$work/release/image-digests.txt"
  (
    cd "$work/release"
    sha256sum bootstrap-artifacts.toml image-digests.txt >checksums.txt
    printf '%s\n' fixture-signature >checksums.sigstore.json
  )
  cat >"$work/bin/compose-cosign" <<'EOF'
#!/bin/sh
set -eu
identity=https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v0.0.9100
case "$1" in
  verify-blob) test "$(cat "$3")" = fixture-signature && test "$5" = "$identity" ;;
  verify) test "$3" = "$identity" ;;
  *) exit 1 ;;
esac
EOF
  chmod 0700 "$work/bin/compose-cosign"
  cp .env "$work/original.env"
  sed -i "s/^LANEWAY_RUST_RELAY_IMAGE_DIGEST=.*/LANEWAY_RUST_RELAY_IMAGE_DIGEST=sha256:$(printf '2%.0s' {1..64})/" .env
  if prepare_verified_release >"$work/wrong-candidate.out" 2>&1; then
    echo 'Rust prepare accepted images from a different candidate' >&2
    return 1
  fi
  grep -F 'Rust image settings do not match the signed release' "$work/wrong-candidate.out" >&2
  test ! -e generated/config/bootstrap.rust.json
  cp "$work/original.env" .env

  sha256sum generated/config/{controller,relay}.toml >"$work/go-config.sha256"
  prepare_verified_release
  sha256sum --check --status "$work/go-config.sha256"
  grep -Fq 'https://release.test/linux_amd64' generated/config/controller.toml
  jq -e --arg prefix "$candidate_url/" '
    .artifacts | length == 4 and all(.[]; .url | startswith($prefix))
  ' generated/config/bootstrap.rust.json >/dev/null
}
