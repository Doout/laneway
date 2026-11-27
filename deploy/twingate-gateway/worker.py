#!/usr/bin/env python3
"""Reconcile the local controller's private gateway spool on a Linux Docker host."""
import concurrent.futures
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/laneway-gateways")
UID = int(os.getenv("LANEWAY_CONTROLLER_UID", "65532"))
CLIENT = "twingate/client@sha256:6b868c3fd395f8b2bc7421359ceab65eda89a5d32884346322a6c533c931ec7b"
CONNECTOR = "ghcr.io/doout/lane-edge-rust@sha256:f8b3ac366679d9f1067139b3d51c68a87108d5930a58cf8faa5edaa432f7ea7c"
LABEL = "io.laneway.gateway"
TENANT = re.compile(r"[0-9a-f]{64}")
GENERATION = re.compile(r"[A-Za-z0-9_-]{1,96}")
MAX_REQUEST = 160 * 1024


class ReconcileError(Exception):
    """A fixed diagnostic safe to report without command lines or provider output."""


def run(*args, data=None, passed=(), timeout=12):
    try:
        return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              check=True, pass_fds=passed, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        raise ReconcileError("runtime command unavailable") from None


def atomic(path, data, *, uid=0, gid=0, mode=0o600):
    temporary = path.with_name("." + secrets.token_hex(12))
    try:
        with temporary.open("xb") as file:
            os.fchown(file.fileno(), uid, gid)
            os.fchmod(file.fileno(), mode)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def publish(name, data):
    atomic(ROOT / "spool/status" / name, json.dumps(data).encode(), gid=UID, mode=0o640)


def read_request(tenant):
    try:
        fd = os.open(ROOT / "spool/requests" / tenant, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        meta = os.fstat(fd)
        if not (stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == UID
                and meta.st_mode & 0o077 == 0):
            raise ReconcileError("invalid request permissions")
        raw = file.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise ReconcileError("request too large")
    value = json.loads(raw)
    fields = {"generation", "enabled"}
    if value["enabled"] is True:
        fields |= {"address", "port", "service_key", "enrollment_token"}
        addr = ipaddress.IPv4Address(value["address"])
        if (not isinstance(value["address"], str) or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or int(addr) >> 24 == 0):
            raise ReconcileError("invalid resource address")
        if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
            raise ReconcileError("invalid resource port")
        if not isinstance(value["service_key"], dict) or not value["service_key"]:
            raise ReconcileError("invalid service key")
        if not re.fullmatch(r"st1\.[A-Za-z0-9+/]+={0,2}", value["enrollment_token"]):
            raise ReconcileError("invalid connector setup token")
    if set(value) != fields or type(value["enabled"]) is not bool or not GENERATION.fullmatch(value["generation"]):
        raise ReconcileError("invalid request")
    return value


def container(name, tenant):
    # List first to distinguish absence from a Docker failure.
    ids = run("docker", "ps", "-aq", "--filter", "name=^/" + name + "$").split()
    if not ids:
        return None
    value = json.loads(run("docker", "inspect", ids[0]))[0]
    if value["Config"]["Labels"].get(LABEL) != tenant or value["Name"] != "/" + name:
        raise ReconcileError("container ownership mismatch")
    return value


def names(tenant):
    return ("lw-gw-" + tenant + "-client", "lw-gw-" + tenant + "-node")


def remove(name, tenant):
    found = container(name, tenant)
    if found:
        run("docker", "rm", "-f", found["Id"])


def cleanup(tenant, work):
    client, node = names(tenant)
    remove(node, tenant)
    remove(client, tenant)
    if work.exists():
        shutil.rmtree(work)


def launch(name, tenant, *args):
    run("docker", "run", "-d", "--pull=never", "--name", name, "--label", LABEL + "=" + tenant,
        "--restart=no", "--security-opt", "no-new-privileges", "--log-driver=none",
        "--pids-limit", "192", *args)


@contextlib.contextmanager
def network_namespace(client):
    if client["HostConfig"]["NetworkMode"] not in ("default", "bridge"):
        raise ReconcileError("unexpected gateway namespace")
    pid = client["State"]["Pid"]
    if pid <= 1:
        raise ReconcileError("gateway not running")
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        if os.path.samestat(os.fstat(fd), os.stat("/proc/1/ns/net")):
            raise ReconcileError("host network namespace rejected")
        # Pin the FD across commands. Reject a PID reused between inspect and open.
        current = json.loads(run("docker", "inspect", client["Id"]))[0]
        if not current["State"]["Running"] or current["State"]["Pid"] != pid:
            raise ReconcileError("gateway namespace changed")

        def inside(*args, data=None):
            return run("nsenter", f"--net=/proc/self/fd/{fd}", "--", *args, data=data, passed=(fd,))

        yield inside
    finally:
        os.close(fd)


def guard_and_probe(inside, addr, port, work, client_id):
    route = json.loads(inside("ip", "-j", "route", "get", addr))[0]
    device = route.get("dev", "")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", device):
        raise ReconcileError("protected route unavailable")
    link = json.loads(inside("ip", "-j", "-d", "link", "show", "dev", device))[0]
    if link.get("linkinfo", {}).get("info_kind") != "tun":
        raise ReconcileError("protected resource has no provider tunnel")
    # An independent output hook also guards established flows during loss of
    # the provider route. nft commits the entire replacement in one transaction.
    rules = f'''add table inet laneway_gateway
flush table inet laneway_gateway
add chain inet laneway_gateway output {{ type filter hook output priority 100; policy accept; }}
add rule inet laneway_gateway output ip daddr {addr} oifname "{device}" tcp dport {port} accept
add rule inet laneway_gateway output ip daddr {addr} drop
add chain inet laneway_gateway input {{ type filter hook input priority 100; policy drop; }}
add rule inet laneway_gateway input iifname "lo" accept
add rule inet laneway_gateway input ct state established,related accept
'''
    inside("nft", "-f", "-", data=rules.encode())
    # Probe once on readiness, then once a minute. Revalidate the local
    # kernel route and filter on every pass. Back off failed connection attempts.
    marker = work / "probe.json"
    previous = json.loads(marker.read_bytes()) if marker.exists() else {}
    now = int(time.time())
    same_tunnel = previous.get("client") == client_id and previous.get("ifindex") == link["ifindex"]
    if same_tunnel and 0 < previous.get("next", 0) - now <= 600:
        if previous["ok"]:
            return
        raise ReconcileError("resource unavailable")
    try:
        inside(sys.executable, "-c",
               "import socket,sys; socket.create_connection((sys.argv[1],int(sys.argv[2])),2).close()",
               addr, str(port))
        ok = True
    except ReconcileError:
        ok = False
    failures = 0 if ok else min(5, (previous.get("failures", 0) if same_tunnel else 0) + 1)
    interval = 60 if ok else min(300, 15 * 2 ** failures)
    atomic(marker, json.dumps({"client": client_id, "ifindex": link["ifindex"], "ok": ok,
                               "failures": failures, "checked_at": now, "next": now + interval}).encode())
    if not ok:
        raise ReconcileError("resource unavailable")



def initialize(tenant, work, desired):
    fingerprint = hashlib.sha256(json.dumps(desired, sort_keys=True).encode()).hexdigest()
    marker = work / "request.sha256"
    if marker.is_file() and marker.read_text() == fingerprint:
        return
    cleanup(tenant, work)
    work.mkdir(mode=0o700)
    (work / "identity").mkdir(mode=0o700)
    os.chown(work / "identity", 65532, 65532)
    atomic(work / "key", json.dumps(desired["service_key"]).encode(), mode=0o400)
    atomic(work / "setup", desired["enrollment_token"].encode(), uid=65532, gid=65532, mode=0o400)
    atomic(work / "request.sha256", fingerprint.encode())


def mount(source, destination, readonly=True):
    return "type=bind,source=" + str(source) + ",target=" + destination + (",readonly" if readonly else "")


def apply(tenant, work, desired):
    initialize(tenant, work, desired)
    client, node = names(tenant)
    provider = container(client, tenant)
    if not provider or not provider["State"]["Running"]:
        remove(node, tenant)
        remove(client, tenant)
        launch(client, tenant, "--network=bridge", "--cap-drop=ALL", "--cap-add=NET_ADMIN", "--device=/dev/net/tun",
               "--mount", mount(work / "key", "/etc/twingate/service_key.json"), CLIENT)
        return "starting"
    with network_namespace(provider) as inside:
        guard_and_probe(inside, desired["address"], desired["port"], work, provider["Id"])
    current = container(node, tenant)
    if current and current["HostConfig"]["NetworkMode"] != "container:" + provider["Id"]:
        remove(node, tenant)
        current = None
    if not current or not current["State"]["Running"]:
        remove(node, tenant)
        launch(node, tenant, "--network=container:" + provider["Id"], "--cap-drop=ALL",
               "--user=65532:65532", "--read-only", "--tmpfs",
               "/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=65532,gid=65532,size=16m", "--tmpfs",
               "/run/laneway:rw,nosuid,nodev,noexec,mode=0700,uid=65532,gid=65532,size=4m",
               "--mount", mount(work / "identity", "/var/lib/laneway", False),
               "--mount", mount(work / "setup", "/run/laneway-setup"),
               CONNECTOR, "connector", "run", "--setup-token-file", "/run/laneway-setup")
        return "starting"
    try:
        status = json.loads(run("docker", "exec", current["Id"], "/usr/local/bin/laneway", "status",
                            "--socket", "/run/laneway/lanewayd.sock", "--json"))
    except ReconcileError:
        return "starting"
    controller = status["controller"]
    online = (status["running"] and status["interface"] == "userspace" and status["selected_path"] in
              ("direct", "relay-quic", "tcp-fallback") and controller["configuration_lease_expired"] is False
              and controller["configuration_lease_valid_until_unix_seconds"] > time.time())
    return "online" if online else "starting"


def reconcile(tenant):
    work = ROOT / "work" / tenant
    generation = ""
    try:
        desired = read_request(tenant)
        if desired:
            generation = desired["generation"]
        if desired and desired["enabled"]:
            status = apply(tenant, work, desired)
        else:
            cleanup(tenant, work)
            status = "disabled"
    except (ReconcileError, ValueError, TypeError, AttributeError, KeyError, IndexError, OSError):
        # Losing the route or failing to validate its guard stops the node. Keep
        # its identity and provider client for a later reconciliation.
        status = "error"
        remove(names(tenant)[1], tenant)
    observed_at = int(time.time())
    if status == "online":
        # A worker which stops refreshing never extends the last successful
        # remote TCP observation beyond the controller's freshness limit.
        observed_at = min(observed_at, json.loads((work / "probe.json").read_bytes())["checked_at"])
    publish(tenant, {"generation": generation, "status": status, "updated_at": observed_at})


def main():
    os.umask(0o077)
    with (ROOT / "worker.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            while True:
                run("docker", "info", "--format", "{{.ServerVersion}}")
                publish("heartbeat", int(time.time()))
                tenants = set(os.listdir(ROOT / "spool/requests")) | set(os.listdir(ROOT / "work"))
                for tenant in sorted(tenants):
                    if TENANT.fullmatch(tenant) and tenant not in pending:
                        pending[tenant] = pool.submit(reconcile, tenant)
                time.sleep(5)
                for tenant, task in list(pending.items()):
                    if task.done():
                        # Suppress raw request contents and command diagnostics.
                        if task.exception():
                            print("Gateway reconciliation could not publish status.", file=sys.stderr, flush=True)
                        del pending[tenant]


if __name__ == "__main__":
    main()
