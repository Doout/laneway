#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
version=${VERSION-dev}
package_goos=${PACKAGE_GOOS:-$(cd "$project_dir/go" && go env GOOS)}
package_goarch=${PACKAGE_GOARCH:-$(cd "$project_dir/go" && go env GOARCH)}

case "$package_goos" in linux|darwin) ;; *) echo "unsupported package operating system: $package_goos" >&2; exit 1;; esac
case "$package_goarch" in
  amd64|arm64) ;;
  *)
    echo "unsupported package architecture: $package_goarch" >&2
    exit 1
    ;;
esac
[ -n "$version" ] || { echo "version is empty" >&2; exit 1; }
case "$version" in
  *[!0-9A-Za-z._+-]*)
    echo "version contains unsupported characters" >&2
    exit 1
    ;;
esac

staging_dir=$(mktemp -d)
trap 'find "$staging_dir" -depth -delete' EXIT HUP INT TERM
package_dir="$staging_dir/laneway"
archive="laneway_${package_goos}_${package_goarch}.tar.gz"
standalone="laneway_${package_goos}_${package_goarch}"
mkdir -p "$package_dir/bin" "$package_dir/docs" "$project_dir/dist"
if [ "$package_goos" = linux ]; then
	mkdir -p "$package_dir/sbin" "$package_dir/examples" "$package_dir/systemd" \
		"$package_dir/nftables" "$package_dir/spec" "$package_dir/deploy" "$package_dir/integration"
fi

ldflags="-s -w -X github.com/Doout/laneway/go/internal/buildinfo.Version=$version"
(
  cd "$project_dir/go"
  CGO_ENABLED=0 GOOS="$package_goos" GOARCH="$package_goarch" \
    go build -trimpath -ldflags "$ldflags" -o "$package_dir/bin/laneway" ./cmd/laneway
	ln -s laneway "$package_dir/bin/lane"
	if [ "$package_goos" = linux ]; then
		for command in laneway-relay laneway-controller; do
			CGO_ENABLED=0 GOOS="$package_goos" GOARCH="$package_goarch" \
				go build -trimpath -ldflags "$ldflags" -o "$package_dir/sbin/$command" "./cmd/$command"
		done
		ln -s ../bin/laneway "$package_dir/sbin/lanewayd"
	fi
)

cp "$project_dir/README.md" "$package_dir/README.md"
cp "$project_dir/LICENSE-MIT" "$project_dir/LICENSE-APACHE" "$package_dir/"
cp "$project_dir/docs/operations.md" "$package_dir/docs/operations.md"
cp "$project_dir/docs/ephemeral-shared-host-exit.md" "$package_dir/docs/ephemeral-shared-host-exit.md"
if [ "$package_goos" = linux ]; then
cp "$project_dir/deploy/examples/controller.toml" \
  "$project_dir/deploy/examples/node-controller.toml" \
  "$project_dir/deploy/examples/node.toml" \
  "$project_dir/deploy/examples/relay-controller.toml" \
	"$project_dir/deploy/examples/relay.toml" \
	"$package_dir/examples/"
cp "$project_dir/deploy/systemd/lanewayd.service" \
  "$project_dir/deploy/systemd/laneway-relay.service" \
  "$project_dir/deploy/systemd/laneway-controller.service" \
  "$package_dir/systemd/"
cp "$project_dir"/deploy/nftables/* "$package_dir/nftables/"
cp "$project_dir/deploy/README.md" "$package_dir/docs/deployment.md"
cp "$project_dir/docs/benchmarks.md" "$package_dir/docs/benchmarks.md"
cp "$project_dir/docs/rust-controller-node.md" "$package_dir/docs/rust-controller-node.md"
cp "$project_dir/spec/threat-model.md" "$package_dir/docs/threat-model.md"
cp "$project_dir"/spec/*.md "$package_dir/spec/"
# Copy only reviewed deployment sources. Never traverse the ignored Compose
# runtime tree: a package build on an operator host must not read or archive
# .env, generated credentials, databases, or recovery bundles.
for directory in containers ephemeral-exit examples nftables systemd; do
	cp -R "$project_dir/deploy/$directory" "$package_dir/deploy/$directory"
done
install -m 0644 "$project_dir/deploy/README.md" "$package_dir/deploy/README.md"
install -d -m 0755 "$package_dir/deploy/compose/generated/config"
for name in .env.example README.md compose.dev.yaml compose.yaml; do
	install -m 0644 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
for name in bootstrap.sh install-control-plane.sh prepare-control-plane.sh upgrade-control-plane.sh preflight.sh prepare.sh recovery.sh validate.sh laneway-control; do
	install -m 0755 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
install -m 0644 "$project_dir"/deploy/compose/generated/config/*.example \
	"$package_dir/deploy/compose/generated/config/"
cp "$project_dir/integration/README.md" "$package_dir/integration/README.md"
cp "$project_dir/scripts/setup-node.sh" "$package_dir/sbin/laneway-setup-node"
fi
cp "$project_dir/SECURITY.md" "$package_dir/SECURITY.md"
cp "$project_dir/scripts/install-package.sh" "$package_dir/install.sh"
printf '%s\n' "$version" > "$package_dir/VERSION"
find "$package_dir" -type f -exec chmod 0644 {} +
find "$package_dir" -type d -exec chmod 0755 {} +
chmod 0755 "$package_dir/install.sh" "$package_dir/bin/laneway"
if [ "$package_goos" = linux ]; then
	chmod 0755 "$package_dir"/sbin/* "$package_dir"/deploy/compose/*.sh \
		"$package_dir"/deploy/compose/laneway-control \
		"$package_dir"/deploy/containers/update-connector.sh \
		"$package_dir"/deploy/ephemeral-exit/bootstrap.sh
fi

tmp_archive="$staging_dir/$archive"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  -C "$staging_dir" -cf - laneway | gzip -n > "$tmp_archive"
mv "$tmp_archive" "$project_dir/dist/$archive"
if [ "$package_goos" = darwin ]; then
	cp "$package_dir/bin/laneway" "$project_dir/dist/$standalone"
	chmod 0755 "$project_dir/dist/$standalone"
fi
(
  cd "$project_dir/dist"
  sha256sum "$archive" > "$archive.sha256"
)
echo "$project_dir/dist/$archive"
