#!/bin/sh
# Offline contract for metadata and cosign argument handling. The tagged
# release runs the same verifier against real keyless signatures.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT
trap 'exit 1' HUP INT TERM
cd "$work"
mkdir metadata
export LANEWAY_COSIGN_BIN="$work/cosign"
cat >"$LANEWAY_COSIGN_BIN" <<'EOF'
#!/bin/sh
set -eu
identity=https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v0.0.9103
issuer=https://token.actions.githubusercontent.com
case "$1" in
  verify-blob)
    [ "$#" -eq 8 ] && [ "$2" = --bundle ] && [ "$(cat "$3")" = fixture-signature ] &&
      [ "$4" = --certificate-identity ] && [ "$5" = "$identity" ] &&
      [ "$6" = --certificate-oidc-issuer ] && [ "$7" = "$issuer" ] &&
      [ -s "$8" ]
    ;;
  verify)
    [ "$#" -eq 6 ] && [ "$2" = --certificate-identity ] && [ "$3" = "$identity" ] &&
      [ "$4" = --certificate-oidc-issuer ] && [ "$5" = "$issuer" ] || exit 1
    case "$6" in
      "${REJECT_IMAGE:-}"@*) exit 1 ;;
      ghcr.io/doout/laneway-controller-rust@sha256:*|ghcr.io/doout/laneway-relay-rust@sha256:*|ghcr.io/doout/laneway-exit-node-rust@sha256:*) ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
EOF
chmod 0700 "$LANEWAY_COSIGN_BIN"
printf 'fixture-signature\n' > metadata/checksums.sigstore.json
one=$(printf '%064d' 1)
two=$(printf '%064d' 2)
three=$(printf '%064d' 3)
write_images() {
  printf 'ghcr.io/doout/laneway-controller-rust@sha256:%s\n' "$one"
  printf 'ghcr.io/doout/laneway-relay-rust@sha256:%s\n' "$two"
  printf 'ghcr.io/doout/laneway-exit-node-rust@sha256:%s\n' "$three"
}
write_checksums() (
  cd metadata
  if command -v sha256sum >/dev/null 2>&1; then sha256sum image-digests.txt;
  else shasum -a 256 image-digests.txt; fi > checksums.txt
)
write_images > metadata/image-digests.txt
write_checksums
verify() { sh "$root/deploy/compose/verify-rust-release.sh" "$1" metadata > settings 2> diagnostic; }
reject() {
  if verify "$1"; then echo "expected verification to fail: $2" >&2; exit 1; fi
  test ! -s settings
  grep -F "$2" diagnostic >/dev/null || { cat diagnostic >&2; return 1; }
}
verify v0.0.9103
printf '%s\n' LANEWAY_RUST_VERSION=0.0.9103 \
  "LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST=sha256:$one" "LANEWAY_RUST_RELAY_IMAGE_DIGEST=sha256:$two" \
  "LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST=sha256:$three" | diff - settings
reject v0.0.9104 'checksum signature did not match'
reject v0.0.9103-test 'expected a stable release tag'
printf '[bootstrap]\n' > metadata/bootstrap-artifacts.toml
(cd metadata
  if command -v sha256sum >/dev/null 2>&1; then sha256sum bootstrap-artifacts.toml;
  else shasum -a 256 bootstrap-artifacts.toml; fi >> checksums.txt
)
sh "$root/deploy/compose/verify-rust-release.sh" --prepare v0.0.9103 metadata > candidate
tail -n +5 candidate | diff - metadata/bootstrap-artifacts.toml
printf 'tampered bootstrap\n' >> metadata/bootstrap-artifacts.toml
if sh "$root/deploy/compose/verify-rust-release.sh" --prepare v0.0.9103 metadata > settings 2> diagnostic; then
  echo 'expected mismatched bootstrap metadata to fail verification' >&2
  exit 1
fi
test ! -s settings
grep -F 'bootstrap-artifacts.toml differs from its signed checksum' diagnostic >/dev/null
printf 'tampered after signing\n' >> metadata/image-digests.txt
reject v0.0.9103 'differs from its signed checksum'
write_images > metadata/image-digests.txt
write_checksums
(
  export REJECT_IMAGE=ghcr.io/doout/laneway-exit-node-rust
  reject v0.0.9103 'image signature did not match'
)
cp metadata/checksums.txt duplicate-checksum
cat duplicate-checksum >> metadata/checksums.txt
reject v0.0.9103 'expected exactly one signed checksum'
write_images | sed '/exit-node-rust/d' > metadata/image-digests.txt
write_checksums
reject v0.0.9103 'expected exactly one digest for ghcr.io/doout/laneway-exit-node-rust'
write_images > metadata/image-digests.txt
printf 'ghcr.io/doout/laneway-exit-node-rust@sha256:%s\n' "$three" >> metadata/image-digests.txt
write_checksums
reject v0.0.9103 'expected exactly one digest for ghcr.io/doout/laneway-exit-node-rust'
three=$(printf '%064d' 0)
write_images > metadata/image-digests.txt
write_checksums
reject v0.0.9103 'placeholder digest'
printf 'Unsigned\n' > metadata/checksums.sigstore.json
reject v0.0.9103 'checksum signature did not match'
mv metadata/image-digests.txt outside-manifest
ln -s ../outside-manifest metadata/image-digests.txt
reject v0.0.9103 'missing or unsafe metadata file'
echo 'Rust Compose release verification: legitimate inputs and fail-closed contracts passed.'
