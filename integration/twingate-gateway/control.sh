#!/bin/sh
# Runs inside the disposable Linux Docker engine; the bridge gateway is reachable only in this fixture.
set -eu
umask 077
cd /test
connector=$(python3 -B -c 'import worker;print(worker.CONNECTOR)')
extract() {
  docker pull "$1" >/dev/null
  container=$(docker create "$1" /unused)
  docker cp "$container:/usr/local/bin/$2" "$3"
  docker rm "$container" >/dev/null
}
extract "$connector" laneway ./cli
extract ghcr.io/doout/laneway-controller-rust@sha256:8eba2a567aac6f71c89cf6940799d43522ef958cffd6259af568bcfd398417fa laneway-controller ./controller
extract ghcr.io/doout/laneway-relay-rust@sha256:b511935642504998b4c0395f41368f75c26c905ac6745114edc9140530500fb7 laneway-relay ./relay
network=71000000000000000000000000000001
controller=71000000000000000000000000000002
relay=71000000000000000000000000000003
addr=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
endpoint=https://$addr:8443
./cli pki init -out-dir pki >/dev/null
./cli pki intermediate --ca-cert pki/ca.crt --ca-key pki/ca.key --out-cert pki/issuer.crt --out-key pki/issuer.key >/dev/null
for role in controller relay; do
  if [ "$role" = controller ]; then id=$controller; else id=$relay; fi
  ./cli pki "$role" -ca-cert pki/issuer.crt -ca-key pki/issuer.key -network-id "$network" -service-id "$id" \
    -dns localhost -ip "$addr" -out-cert "pki/$role.crt" -out-key "pki/$role.key" >/dev/null
done
printf 'gateway-fixture-admin-token-disposable\n' >admin.token
./controller init controller.db pki/controller.crt gateway-fixture 100.115.2.0/24 >/dev/null
./controller serve controller.db "$addr:8443" pki/controller.crt pki/controller.key --listen-on-network \
  --node-issuer pki/issuer.crt pki/issuer.key 604800 --node-client-ca pki/ca.crt --node-quic \
  --root-token-file admin.token >controller.log 2>&1 </dev/null &
set -- --controller "$endpoint" --ca pki/ca.crt --controller-network-id "$network" --controller-service-id "$controller" --admin-token-file admin.token
for _ in $(seq 1 40); do ./cli controller network list "$@" >/dev/null 2>&1 && break; sleep 1; done
./cli controller relay register --network-id "$network" --service-id "$relay" --name local-relay --endpoint "$addr:4433" "$@" >/dev/null
cat >relay.toml <<EOF
mode = "relay"
state_dir = "/test/relay-state"
[tls]
certificate = "/test/pki/relay.crt"
private_key = "/test/pki/relay.key"
ca = "/test/pki/ca.crt"
[relay]
listen = "$addr:4433"
[tcp_fallback]
listen = "$addr:443"
[controller]
endpoint = "$endpoint"
quic_endpoint = "$addr:8443"
server_name = "$addr"
network_id = "$network"
service_id = "$controller"
poll_interval = "500ms"
EOF
./relay --config relay.toml >relay.log 2>&1 </dev/null &
for name in gateway-a gateway-b; do
  ./cli controller enrollment-token issue --network-id "$network" --label "$name" --connector "$@" >invite.json
  python3 -B - "$name" "$addr" "$network" "$controller" "$relay" <<'PY2'
import base64, json, sys
from pathlib import Path
name, addr, network, ctrl, relay = sys.argv[1:]
token = json.loads(Path('invite.json').read_bytes())['enrollment_token']
ca = base64.b64encode(Path('pki/ca.crt').read_bytes()).decode()
fields = [name, token, f'https://{addr}:8443', f'{addr}:8443', addr, network, ctrl, f'{addr}:4433', relay, ca]
Path(name+'.setup').write_bytes(b'st1.' + base64.b64encode(('\n'.join(fields)+'\n').encode()))
PY2
done
rm invite.json
