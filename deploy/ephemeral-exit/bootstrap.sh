#!/bin/bash
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS=$' \t\n'
umask 077

die() { printf 'laneway ephemeral Exit: %s\n' "$*" >&2; exit 1; }

version=
authority=
name=
max_runtime=8h
while (($#)); do
	case "$1" in
		--version) (($# >= 2)) || die '--version requires a value'; version=$2; shift 2 ;;
		--authority) (($# >= 2)) || die '--authority requires a value'; authority=$2; shift 2 ;;
		--name) (($# >= 2)) || die '--name requires a value'; name=$2; shift 2 ;;
		--max-runtime) (($# >= 2)) || die '--max-runtime requires a value'; max_runtime=$2; shift 2 ;;
		*) die "unknown option: $1" ;;
	esac
done

[[ $(id -u) == 0 ]] || die 'run this bootstrap through sudo'
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die 'invalid immutable release version'
[[ $authority =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die 'invalid controller authority'
[[ $name =~ ^[A-Za-z0-9._-]{1,253}$ ]] || die 'invalid Exit name'
[[ $max_runtime =~ ^([1-9][0-9]*(ms|s|m|min|h|d|w))+$ ]] || die 'invalid maximum runtime'
[[ -d /run && ! -L /run ]] || die '/run must be a real directory'
[[ $(stat -f -c %T /run) == tmpfs ]] || die '/run is not RAM-backed tmpfs'
[[ $(stat -c '%u:%g:%a' /run) == 0:0:755 ]] || die '/run has unsafe ownership or mode'

for variable in TAR_OPTIONS CURL_HOME CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH \
	COSIGN_REPOSITORY SIGSTORE_ROOT_FILE SIGSTORE_REKOR_PUBLIC_KEY SIGSTORE_CT_LOG_PUBLIC_KEY_FILE TUF_MIRROR TUF_ROOT TUF_ROOT_JSON; do
	[[ ! -v $variable ]] || die "refusing ambient $variable"
done
for command in awk curl find grep install ip nft nsenter od readlink rm sed seq sha256sum stat stty sysctl systemctl systemd-run tar tr uname; do
	command -v "$command" >/dev/null || die "required command is unavailable: $command"
done
systemd_state=$(systemctl is-system-running 2>/dev/null || true)
[[ $systemd_state == running || $systemd_state == degraded ]] || die 'systemd is not the active service manager'
[[ -c /dev/net/tun ]] || die '/dev/net/tun is unavailable'
[[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]] || die 'host IPv4 forwarding must already be enabled'

architecture=$(uname -m)
case "$architecture" in
	x86_64) release_arch=amd64; cosign_sha=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
	aarch64|arm64) release_arch=arm64; cosign_sha=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
	*) die "unsupported architecture: $architecture" ;;
esac

random=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
runtime_name=laneway-ephemeral-exit-$random
runtime_dir=/run/$runtime_name
unit=$runtime_name.service
cleanup_unit=$runtime_name-cleanup.service
cleanup_path=/run/.$runtime_name.cleanup
host_if=lxe${random:0:12}
peer_if=lxp${random:0:12}
nft_table=lxe_${random:0:12}
marker=laneway:$runtime_name
carrier_index=$((16#${random:0:4} & 0x3fff))
carrier_third=$((carrier_index / 64))
carrier_base=$(((carrier_index % 64) * 4))
carrier_prefix=169.254.$carrier_third.$carrier_base/30
carrier_host=169.254.$carrier_third.$((carrier_base + 1))
carrier_peer=169.254.$carrier_third.$((carrier_base + 2))
work=$(mktemp -d /run/.laneway-ephemeral-exit.XXXXXXXX)
mkdir "$work/home"
HOME=$work/home
export HOME
claimed_runtime=false
unit_started=false
carrier_created=false
terminal_echo_disabled=false

cleanup_failed_bootstrap() {
	status=$?
	trap - EXIT HUP INT TERM
	if [[ $terminal_echo_disabled == true ]]; then stty echo </dev/tty >/dev/null 2>&1 || true; fi
	if [[ $unit_started == true ]]; then systemctl stop "$unit" >/dev/null 2>&1 || true; fi
	if [[ $carrier_created == true ]]; then
		if nft list chain inet "$nft_table" owner 2>/dev/null | grep -F -- "comment \"$marker\"" >/dev/null; then
			nft delete table inet "$nft_table" >/dev/null 2>&1 || true
		fi
		ip link delete "$host_if" >/dev/null 2>&1 || true
	fi
	find "$work" -depth -delete >/dev/null 2>&1 || true
	if [[ $claimed_runtime == true ]]; then find "$runtime_dir" -depth -delete >/dev/null 2>&1 || true; fi
	rm -f "$cleanup_path" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup_failed_bootstrap EXIT HUP INT TERM
[ ! -e "$cleanup_path" ] && [ ! -L "$cleanup_path" ] || die 'random cleanup path already exists'
cat > "$work/cleanup" <<EOF
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
while kill -0 $$ >/dev/null 2>&1 && ! systemctl show $unit >/dev/null 2>&1; do
  sleep 0.1
done
if systemctl show $unit >/dev/null 2>&1; then
  while :; do
    state=\$(systemctl is-active $unit 2>/dev/null || true)
    case "\$state" in active|activating) sleep 1 ;; *) break ;; esac
  done
fi
if [ -e /sys/class/net/$host_if/ifalias ] && [ "\$(cat /sys/class/net/$host_if/ifalias)" = '$marker' ]; then
  ip link delete $host_if || true
fi
if nft list chain inet $nft_table owner 2>/dev/null | grep -F -- 'comment "$marker"' >/dev/null; then
  nft delete table inet $nft_table || true
fi
find $runtime_dir -depth -delete 2>/dev/null || true
find $work -depth -delete 2>/dev/null || true
rm -f $cleanup_path
EOF
install -m 0500 "$work/cleanup" "$cleanup_path"
systemd-run --unit="$cleanup_unit" --collect --quiet --property=Type=exec --property=StandardOutput=null \
	--property=StandardError=null --property=NoNewPrivileges=yes "$cleanup_path"
mkdir "$runtime_dir"
claimed_runtime=true
chmod 0700 "$runtime_dir"

base=https://github.com/Doout/laneway/releases/download/$version
archive=laneway_linux_${release_arch}.tar.gz
for asset in checksums.txt checksums.sigstore.json "$archive"; do
	curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' "$base/$asset" -o "$work/$asset"
done
cosign=$work/cosign-v3.1.3
curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
	"https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$release_arch" -o "$cosign"
printf '%s  %s\n' "$cosign_sha" "$cosign" | sha256sum -c - >/dev/null || die 'pinned Cosign checksum failed'
chmod 0500 "$cosign"
[[ $($cosign version --json 2>/dev/null | sed -n 's/.*"gitVersion":"\([^"]*\)".*/\1/p' | head -1) == v3.1.3 ]] || die 'pinned Cosign reported an unexpected version'
"$cosign" verify-blob --bundle "$work/checksums.sigstore.json" \
	--certificate-identity 'https://github.com/Doout/laneway/.github/workflows/release.yml@refs/heads/main' \
	--certificate-oidc-issuer 'https://token.actions.githubusercontent.com' "$work/checksums.txt" >/dev/null 2>&1 || die 'release checksum signature verification failed'
(
	cd "$work"
	grep -E "  ${archive}$" checksums.txt > selected-checksum
	[[ $(wc -l < selected-checksum) == 1 ]] || exit 1
	sha256sum -c selected-checksum >/dev/null
) || die 'release archive checksum verification failed'
entries=$(tar -tzf "$work/$archive")
[[ $(printf '%s\n' "$entries" | grep -Fxc 'laneway/bin/laneway') == 1 ]] || die 'release archive has no unique laneway executable'
tar -xzf "$work/$archive" -C "$work" laneway/bin/laneway
install -m 0555 "$work/laneway/bin/laneway" "$runtime_dir/laneway"

printf 'One-use Exit invitation: ' >&2
stty -echo </dev/tty
terminal_echo_disabled=true
IFS= read -r invitation </dev/tty || { stty echo </dev/tty; printf '\n' >&2; die 'could not read invitation'; }
stty echo </dev/tty
terminal_echo_disabled=false
printf '\n' >&2
[[ $invitation =~ ^[A-Za-z0-9_-]{1,128}$ ]] || die 'invitation has an invalid shape'
printf '%s' "$invitation" > "$work/invitation"
exec 3< "$work/invitation"
rm -f "$work/invitation"
"$runtime_dir/laneway" node ephemeral-exit-prepare --authority "$authority" --runtime-dir "$runtime_dir" \
	--runtime-name "$runtime_name" --name "$name" --token-fd 3 > "$work/prepared.json"
exec 3<&-
invitation=
grep -Fq '"runtime_name":"'"$runtime_name"'"' "$work/prepared.json" || die 'preparation returned an unexpected runtime identity'

resolver_source=/etc/resolv.conf
if [[ -f /run/systemd/resolve/resolv.conf && ! -L /run/systemd/resolve/resolv.conf ]]; then
	resolver_source=/run/systemd/resolve/resolv.conf
fi
awk '$1 == "nameserver" && $2 !~ /^(127\.|0\.0\.0\.0$)/ && $2 ~ /^[0-9.]+$/ { print "nameserver " $2; count++; if (count == 3) exit }' \
	"$resolver_source" > "$runtime_dir/resolv.conf"
[[ -s $runtime_dir/resolv.conf ]] || die 'no non-loopback DNS resolver is available to the private namespace'
chmod 0444 "$runtime_dir/resolv.conf"

cat > "$runtime_dir/entrypoint" <<EOF
#!/bin/sh
set -eu
attempt=0
while [ ! -e /run/$runtime_name/network.ready ]; do
  attempt=\$((attempt + 1))
  [ \$attempt -le 600 ] || exit 1
  sleep 0.05
done
exec /run/$runtime_name/laneway node run -config \"\$CREDENTIALS_DIRECTORY/config\"
EOF
chmod 0555 "$runtime_dir/entrypoint"
systemd-run --unit="$unit" --collect --quiet \
	--property=Type=exec --property=DynamicUser=yes --property=PrivateNetwork=yes \
	--property=RuntimeDirectory="$runtime_name" --property=RuntimeDirectoryMode=0700 \
	--property=LoadCredential=ca.crt:"$runtime_dir/ca.crt" \
	--property=LoadCredential=node.crt:"$runtime_dir/node.crt" \
	--property=LoadCredential=node.key:"$runtime_dir/node.key" \
	--property=LoadCredential=wireguard.key:"$runtime_dir/wireguard.key" \
	--property=LoadCredential=config:"$runtime_dir/laneway.toml" \
	--property=BindReadOnlyPaths="$runtime_dir/resolv.conf:/etc/resolv.conf" \
	--property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=ProtectSystem=strict \
	--property=ProtectHome=yes --property=ProtectKernelTunables=no --property=ProtectKernelModules=yes \
	--property=ProtectControlGroups=yes --property=LockPersonality=yes --property=MemoryDenyWriteExecute=yes \
	--property=RestrictSUIDSGID=yes --property=RestrictRealtime=yes --property=RemoveIPC=yes \
	--property=CapabilityBoundingSet='CAP_NET_ADMIN CAP_IPC_LOCK' \
	--property=AmbientCapabilities='CAP_NET_ADMIN CAP_IPC_LOCK' \
	--property=DevicePolicy=closed --property=DeviceAllow='/dev/net/tun rw' \
	--property=RestrictAddressFamilies='AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
	--property=LimitCORE=0 --property=LimitMEMLOCK=infinity --property=MemoryMax=512M --property=TasksMax=128 --property=UMask=0077 \
	--property=StandardOutput=null --property=StandardError=null --property=RuntimeMaxSec="$max_runtime" \
	--property=TimeoutStopSec=15s --property=KillMode=mixed "$runtime_dir/entrypoint"
unit_started=true

pid=
for _ in $(seq 1 100); do
	pid=$(systemctl show --property=MainPID --value "$unit")
	[[ $pid =~ ^[1-9][0-9]*$ ]] && break
	sleep 0.05
done
[[ $pid =~ ^[1-9][0-9]*$ ]] || die 'transient unit did not enter its private network namespace'
[[ ! -e /sys/class/net/$host_if ]] || die 'random carrier interface already exists'
nft list table inet "$nft_table" >/dev/null 2>&1 && die 'random carrier firewall state already exists'
ip link add "$host_if" type veth peer name "$peer_if"
carrier_created=true
ip link set dev "$host_if" alias "$marker"
ip address add "$carrier_host/30" dev "$host_if"
ip link set "$host_if" up
ip link set "$peer_if" netns "$pid"
nsenter -t "$pid" -n ip link set lo up
nsenter -t "$pid" -n ip link set "$peer_if" name uplink0
nsenter -t "$pid" -n ip address add "$carrier_peer/30" dev uplink0
nsenter -t "$pid" -n ip link set uplink0 up
nsenter -t "$pid" -n ip route add default via "$carrier_host" dev uplink0
nft add table inet "$nft_table"
nft add chain inet "$nft_table" owner || { nft delete table inet "$nft_table" >/dev/null 2>&1 || true; die 'could not claim carrier firewall state'; }
nft add rule inet "$nft_table" owner counter comment "$marker" || { nft delete table inet "$nft_table" >/dev/null 2>&1 || true; die 'could not mark carrier firewall ownership'; }
nft "add chain inet $nft_table forward { type filter hook forward priority 100; policy accept; }"
nft add rule inet "$nft_table" forward iifname "$host_if" accept
nft add rule inet "$nft_table" forward oifname "$host_if" ct state established,related accept
nft "add chain inet $nft_table postrouting { type nat hook postrouting priority srcnat; policy accept; }"
nft add rule inet "$nft_table" postrouting ip saddr "$carrier_prefix" masquerade
touch "$runtime_dir/network.ready"

executed=false
for _ in $(seq 1 200); do
	if [[ $(readlink "/proc/$pid/exe" 2>/dev/null || true) == "$runtime_dir/laneway" ]]; then
		executed=true
		break
	fi
	systemctl is-active --quiet "$unit" || break
	sleep 0.05
done
[[ $executed == true ]] || die 'transient Exit did not exec the verified binary'

rm -f "$runtime_dir/ca.crt" "$runtime_dir/node.crt" "$runtime_dir/node.key" "$runtime_dir/wireguard.key" "$runtime_dir/laneway.toml" "$runtime_dir/resolv.conf" \
	"$runtime_dir/entrypoint" "$runtime_dir/laneway" "$runtime_dir/network.ready"
find "$work" -depth -delete
claimed_runtime=false
carrier_created=false
unit_started=false
trap - EXIT HUP INT TERM
printf 'Ephemeral Exit started as transient unit %s; it will stop no later than %s.\n' "$unit" "$max_runtime" >&2
