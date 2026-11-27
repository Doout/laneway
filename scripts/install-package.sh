#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
destination_root=${DESTDIR:-}
prefix=${PREFIX:-/usr/local}
bindir="$destination_root$prefix/bin"
sbindir="$destination_root$prefix/sbin"
sharedir="$destination_root$prefix/share/laneway"
unitdir="$destination_root$prefix/lib/systemd/system"

if [ "$(uname -s)" = Darwin ]; then
  case "$#:${1:-}" in
    0:|1:--rust-preview) ;;
    *) echo "usage: sudo sh install.sh" >&2; exit 2 ;;
  esac
  [ -z "$destination_root" ] || { echo "DESTDIR is not supported by the macOS client installer" >&2; exit 1; }
  [ "$(id -u)" -eq 0 ] || { echo "run this installer with sudo" >&2; exit 1; }
  [ "$(cat "$script_dir/macos-runtime")" = rust-v1 ] || { echo 'expected the macOS Rust package' >&2; exit 1; }
  "$script_dir/bin/lanewayd-rs" _mac-setup "$script_dir/bin/laneway" --yes
  "$script_dir/bin/lanewayd-rs" _mac-setup "$script_dir/bin/laneway" --check
  ln -sfn laneway "$bindir/lane"
  echo "Laneway $(cat "$script_dir/VERSION") macOS client installed."
  echo "Run as your normal user: laneway login DOMAIN"
  echo "Then connect in the foreground: laneway connect DOMAIN"
  exit 0
fi

control_tools=false
case "$#:${1:-}" in
  0:) ;;
  1:--rust-preview) ;;
  1:--control-tools) control_tools=true ;;
  *) echo "usage: sh install.sh [--rust-preview | --control-tools]" >&2; exit 2 ;;
esac

if [ -z "$destination_root" ] && [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root, or set DESTDIR for a staged install" >&2
  exit 1
fi
if [ "$prefix" != /usr/local ]; then
  echo "PREFIX must be /usr/local because the packaged systemd units use that path" >&2
  exit 1
fi

if [ "$control_tools" = true ]; then
  for member in bin/laneway VERSION deploy/compose/install-control-plane.sh deploy/compose/compose.rust.yaml \
    deploy/compose/prepare-rust.py deploy/compose/verify-rust-release.sh; do
    [ -f "$script_dir/$member" ] && [ ! -L "$script_dir/$member" ] ||
      { echo "control-plane tools missing packaged $member" >&2; exit 1; }
  done
  install -d -m 0755 "$bindir" "$sharedir/deploy/compose"
  install -m 0755 "$script_dir/bin/laneway" "$bindir/laneway"
  ln -sfn laneway "$bindir/lane"
  install -m 0644 "$script_dir/VERSION" "$sharedir/VERSION"
  cp -R "$script_dir/deploy/compose/." "$sharedir/deploy/compose/"
  echo "Laneway $(cat "$script_dir/VERSION") control-plane tools installed; no host daemon or service unit installed."
  exit 0
fi

rust_commands='laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs'
rust_units='lanewayd-rs.service laneway-relay-rs.service laneway-rust-updater.service laneway-rust-updater.timer'
rust_examples='node-rust.toml node-rust-controller.toml relay-rust.toml managed-updates-rust.toml'
version=$(cat "$script_dir/VERSION")
for command in $rust_commands; do
    candidate=$script_dir/sbin/$command
    if [ ! -f "$candidate" ] || [ -L "$candidate" ] || [ ! -x "$candidate" ] ||
       ! candidate_version=$("$candidate" --version) || [ "$candidate_version" != "$version" ]; then
      echo "the Linux package requires a packaged $command at version $version" >&2
      exit 1
    fi
done
# Check the entire Rust package before creating accounts or writing files.
for unit in $rust_units; do
    [ -f "$script_dir/systemd/$unit" ] && [ ! -L "$script_dir/systemd/$unit" ] ||
      { echo "missing Rust unit: $unit" >&2; exit 1; }
done
for example in $rust_examples; do
    [ -f "$script_dir/examples/$example" ] && [ ! -L "$script_dir/examples/$example" ] ||
      { echo "missing Rust example: $example" >&2; exit 1; }
done

if [ -z "$destination_root" ]; then
  if ! getent group laneway >/dev/null 2>&1; then
    groupadd --system laneway
  fi
	group_entry=$(getent group laneway)
	group_gid=$(printf '%s\n' "$group_entry" | cut -d: -f3)
	group_members=$(printf '%s\n' "$group_entry" | cut -d: -f4)
	case "$group_gid" in *[!0-9]*|'') group_gid=999999;; esac
	case "$group_members" in ''|laneway) ;; *)
		echo "existing laneway group has unexpected supplementary members" >&2
		exit 1
		;;
	esac
	if [ "$group_gid" -ge 1000 ]; then
		echo "existing laneway group is not a system group" >&2
		exit 1
	fi
  if ! id laneway >/dev/null 2>&1; then
    useradd --system --gid laneway --home-dir /var/lib/laneway \
      --shell /usr/sbin/nologin laneway
	else
		account=$(getent passwd laneway)
		account_uid=$(printf '%s\n' "$account" | cut -d: -f3)
		account_home=$(printf '%s\n' "$account" | cut -d: -f6)
		account_shell=$(printf '%s\n' "$account" | cut -d: -f7)
		case "$account_uid" in *[!0-9]*|'') account_uid=999999;; esac
		case "$account_shell" in */nologin|*/false) locked_shell=true;; *) locked_shell=false;; esac
		if [ "$account_uid" -ge 1000 ] || [ "$account_home" != /var/lib/laneway ] || \
		  [ "$(id -gn laneway)" != laneway ] || [ "$(id -Gn laneway)" != laneway ] || \
		  [ "$locked_shell" != true ]; then
			echo "existing laneway account is not a locked system service account" >&2
			exit 1
		fi
  fi
  install -d -m 0750 -o root -g laneway /etc/laneway
fi

install -d -m 0755 "$bindir" "$sbindir" "$sharedir/examples" \
	"$sharedir/docs" "$sharedir/nftables" "$sharedir/spec" \
	"$sharedir/deploy" "$sharedir/integration" "$unitdir"
install -m 0755 "$script_dir/bin/laneway" "$bindir/laneway"
ln -sfn laneway "$bindir/lane"
ln -sfn lanewayd-rs "$sbindir/lanewayd"
install -m 0755 "$script_dir/sbin/laneway-setup-node" "$sbindir/laneway-setup-node"
install -m 0755 "$script_dir/deploy/containers/update-connector.sh" \
  "$sbindir/laneway-update-connector"
install -m 0644 "$script_dir"/examples/*.toml "$sharedir/examples/"
install -m 0644 "$script_dir"/docs/*.md "$sharedir/docs/"
install -m 0644 "$script_dir"/nftables/* "$sharedir/nftables/"
cp -R "$script_dir/spec/." "$sharedir/spec/"
cp -R "$script_dir/deploy/." "$sharedir/deploy/"
cp -R "$script_dir/integration/." "$sharedir/integration/"
for command in $rust_commands; do
  install -m 0755 "$script_dir/sbin/$command" "$sbindir/$command"
done
for unit in $rust_units; do
  install -m 0644 "$script_dir/systemd/$unit" "$unitdir/"
done
install -m 0644 "$script_dir/README.md" "$script_dir/SECURITY.md" \
  "$script_dir/LICENSE-MIT" "$script_dir/LICENSE-APACHE" \
  "$script_dir/VERSION" "$sharedir/"

if [ -z "$destination_root" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

echo "Laneway $(cat "$script_dir/VERSION") installed."
echo "Rust runtimes and service units installed. No service or updater was enabled."
echo "Examples: $prefix/share/laneway/examples"
echo "Next for a managed Node: sudo laneway node install DOMAIN"
echo "Compatibility alias: laneway-setup-node DOMAIN"
echo "Connector updater: laneway-update-connector laneway-connector-NAME"
