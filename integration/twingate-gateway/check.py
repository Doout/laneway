"""Runs only inside the disposable nested Docker engine started by run.sh."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location("gateway", "/test/worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
worker.ROOT = Path("/var/lib/laneway-gateways")
worker.CLIENT = "lw-fixture:local"
worker.UID = 65532
for child in ("spool/status", "spool/requests", "work"):
    (worker.ROOT / child).mkdir(parents=True)

docker = lambda *args: subprocess.check_output(["docker", *args], text=True).strip()
def address(name):
    return docker("inspect", "--format", "{{.NetworkSettings.IPAddress}}", name)
def reconcile(tenant):
    worker.reconcile(tenant)
    return json.loads((worker.ROOT / "spool/status" / tenant).read_text())["status"]

def fetch(provider, target):
    view = worker.container(provider, tenant)
    with worker.network_namespace(view) as inside:
        return inside("curl", "--noproxy", "*", "-fsS", "-m", "2", f"http://{target}:8080/")
def node_id(node):
    return json.loads(docker("exec", node, "/usr/local/bin/laneway", "status", "--socket",
                             "/run/laneway/lanewayd.sock", "--json"))["node_id"]


def ready(tenant):
    for _ in range(60):
        if reconcile(tenant) == "online":
            return
        time.sleep(1)
    raise AssertionError("connector did not obtain a lease and live path")


def request(who, enabled=True):
    payload = {"generation": "a" * 32, "enabled": enabled}
    if enabled:
        payload.update(address=target,port=8080,service_key={"peer": address("fixture-remote"),
                       "synthetic":"test-only","target":target},enrollment_token=Path("/test", "gateway-a.setup" if who == tenant else "gateway-b.setup").read_text())
    worker.atomic(worker.ROOT / "spool/requests" / who, json.dumps(payload).encode(), uid=worker.UID)

docker("run", "-d", "--name=fixture-bypass", "lw-fixture:local", "http", "bypass")
target = address("fixture-bypass")
# The remote loopback simulates the protected copy of the same IPv4 address.
# Disable ARP flux so the bridge only learns the direct-bypass container MAC.
docker("run", "-d", "--cap-add=NET_ADMIN", "--device=/dev/net/tun",
       "--sysctl=net.ipv4.conf.all.arp_ignore=1", "--sysctl=net.ipv4.conf.all.arp_announce=2",
       "--name=fixture-remote",
       "lw-fixture:local", "remote", target)
tenant = hashlib.sha256(b"tenant A").hexdigest()
other = hashlib.sha256(b"tenant B").hexdigest()
request(tenant)
provider, node = worker.names(tenant)
ready(tenant)
assert fetch(provider,target) == b"provider"
first = node_id(node)
assert reconcile(tenant) == "online"
assert node_id(node) == first
docker("stop", "-t", "1", node)
assert reconcile(tenant) == "starting"
ready(tenant)
assert node_id(node) == first
request(other)
ready(other)
assert node_id(worker.names(other)[1]) != first
assert subprocess.check_output(["curl","--noproxy","*","-fsS",f"http://{target}:8080/"]) == b"bypass"
# A normal default route would deliver this exact address to the bypass service.
# The isolated provider namespace must drop that traffic before reconciliation.
with worker.network_namespace(worker.container(provider, tenant)) as inside:
    inside("ip", "link", "del", "fixture0")
    assert b"eth0" in inside("ip", "route", "get", target)
try:
    fetch(provider,target)
except worker.ReconcileError:
    pass
else:
    raise AssertionError("protected target leaked over the default route")
assert reconcile(tenant) in ("error", "starting")
assert worker.container(node,tenant) is None
assert reconcile(other) == "online"
request(tenant,False)
assert reconcile(tenant) == "disabled"
assert reconcile(tenant) == "disabled"
assert worker.container(provider,tenant) is None
assert not (worker.ROOT / "work" / tenant).exists()
# Simulate advancing to the next scheduled probe while the provider tunnel and
# local route still exist. An unreachable service must take the node offline.
docker("stop", "-t", "1", "fixture-remote")
probe_file = worker.ROOT / "work" / other / "probe.json"
probe = json.loads(probe_file.read_bytes())
probe["next"] = 0
probe_file.write_text(json.dumps(probe))
assert reconcile(other) == "error"
assert worker.container(worker.names(other)[1], other) is None
request(other,False)
assert reconcile(other) == "disabled"
print("PASS gateway apply, protected TCP, duplicate apply, restart, tenant isolation, provider loss, and idempotent delete.")
