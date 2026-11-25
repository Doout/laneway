#!/usr/bin/env python3
"""Verify the privileged helper inside an isolated loopback-only Linux namespace."""

import argparse
import array
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time

PREFIX = "203.0.113.0/24"
V6_PREFIX = "2001:db8:1::/64"
IP = "/usr/sbin/ip"

def ip(*args):
    return subprocess.check_output((IP, *args), text=True).strip()

def route(prefix=PREFIX):
    family = "-6" if ":" in prefix else "-4"
    return ip("-N", family, "-o", "route", "show", "table", "254", "exact", prefix)

class Helper:
    def __init__(self, launcher):
        self.client, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.proc = subprocess.Popen([launcher, "_network-helper", "--control-fd=0"],
                                     stdin=endpoint, stdout=subprocess.DEVNULL)
        endpoint.close()
        self.client.settimeout(15)
        self.id = 0
        self.packet = None

    def request(self, operation, **options):
        self.id += 1
        self.client.send(json.dumps(dict(version=1, id=self.id, op=operation, **options)).encode())
        data, control, _, _ = self.client.recvmsg(8192, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        result = json.loads(data)
        assert result["id"] == self.id, result
        if control:
            assert len(control) == 1 and control[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS), control
            transferred = array.array("i")
            transferred.frombytes(control[0][2])
            assert len(transferred) == 1
            self.packet = transferred[0]
            assert os.fstat(self.packet).st_rdev == os.stat("/dev/net/tun").st_rdev
        return result

    def setup(self, name="lane-fixture", routes=()):
        result = self.request("setup", setup={"name": name, "mtu": 1280, "addresses": ["100.96.0.1/32"],
                                               "routes": {"routes": list(routes)}})
        assert result["ok"], result
        assert result["interface_name"] == name and self.packet is not None, result

    def apply(self, routes=(), bypasses=()):
        result = self.request("apply-routes", routes={"routes": list(routes), "bypasses": list(bypasses)})
        assert result["ok"], result

    def close(self):
        result = self.request("close")
        assert result["ok"], result
        assert self.proc.wait(timeout=5) == 0

    def cleanup(self):
        self.client.close()
        if self.packet is not None:
            os.close(self.packet)
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

@contextlib.contextmanager
def helper(launcher):
    session = Helper(launcher)
    try:
        yield session
    finally:
        session.cleanup()

def plan(prefix=PREFIX, metric=25):
    return {"prefix": prefix, "metric": metric}

def check_routes(launcher):
    interfaces = {link["ifname"] for link in json.loads(ip("-j", "link", "show"))}
    if interfaces != {"lo"}:
        raise RuntimeError("the fixture requires a disposable loopback-only Linux network namespace")
    ip("link", "add", "uplink-fixture", "type", "dummy")
    ip("link", "set", "uplink-fixture", "up")
    ip("-4", "route", "add", PREFIX, "dev", "uplink-fixture", "proto", "static", "metric", "9")
    old = route()
    ip("-6", "route", "add", V6_PREFIX, "dev", "uplink-fixture", "proto", "static", "metric", "9")
    old6 = route(V6_PREFIX)
    with helper(launcher) as session:
        session.setup(routes=[plan(), plan(V6_PREFIX, 0)])
        assert "lane-fixture" in route() and "metric 25" in route(), route()
        assert "lane-fixture" in route(V6_PREFIX) and "metric 1024" in route(V6_PREFIX), route(V6_PREFIX)
        session.apply([plan(metric=27), plan(V6_PREFIX, 35)])
        assert "metric 27" in route() and "metric 35" in route(V6_PREFIX)
        session.apply([plan(metric=27)], ["203.0.113.10"])
        assert route() == old and route(V6_PREFIX) == old6, (route(), route(V6_PREFIX))
        session.apply([plan(), plan(V6_PREFIX, 10)])
        session.close()
    assert route() == old and route(V6_PREFIX) == old6
    print("Restored exact displaced IPv4 and IPv6 routes, including metrics and bypass updates.")

    with helper(launcher) as session:
        session.setup(routes=[plan(), plan(V6_PREFIX, 10)])
        session.proc.terminate()
        assert session.proc.wait(timeout=15) == 0
        assert route() == old and route(V6_PREFIX) == old6
    print("Restored displaced routes on SIGTERM while the requester kept its socket and TUN open.")

    with helper(launcher) as session:
        session.setup(routes=[plan()])
        session.proc.kill()
        assert session.proc.wait(timeout=5) < 0
    assert route() == ""
    with helper(launcher) as session:
        session.setup(name="lane-recovery")
        assert route() == old
        session.close()
    print("Recovered the journal of a killed helper even when its successor used another interface.")

    with helper(launcher) as session:
        session.setup(routes=[plan()])
        ip("-4", "route", "del", PREFIX, "dev", "lane-fixture", "proto", "250", "metric", "25")
        ip("-4", "route", "add", PREFIX, "dev", "uplink-fixture", "proto", "static", "metric", "19")
        foreign = route()
        result = session.request("close")
        assert not result["ok"] and "externally modified" in result["error"], result
        assert session.proc.wait(timeout=5) != 0
        assert route() == foreign
    ip("-4", "route", "del", PREFIX, "dev", "uplink-fixture", "metric", "19")
    with helper(launcher) as session:
        session.setup()
        assert route() == old
        session.close()
    print("Left an external replacement untouched and retained the journal for later recovery.")


def configure_exit(session, bypass):
    result = session.request("apply-exit-routes", exit_routes={
        "tunnel_prefixes": ["0.0.0.0/1", "128.0.0.0/1"],
        "transport_bypasses": [bypass],
    })
    assert result["ok"], result


def check_exit(launcher):
    with helper(launcher) as session:
        session.setup()
        with subprocess.Popen([IP, "-4", "monitor", "rule"], stdout=subprocess.PIPE) as monitor:
            try:
                # Start listening before the first rule is installed.
                time.sleep(0.1)
                configure_exit(session, "203.0.113.10")
                assert select.select([monitor.stdout], [], [], 2)[0], "missing initial exit rule"
                assert "11000" in monitor.stdout.readline().decode()
                assert "dev uplink-fixture" in ip("-4", "route", "get", "203.0.113.10")
                assert "dev lane-fixture" in ip("-4", "route", "get", "198.51.100.1")
                configure_exit(session, "203.0.113.11")
                assert "dev uplink-fixture" in ip("-4", "route", "get", "203.0.113.11")
                assert "unreachable default" in ip("-4", "route", "show", "table", "51820")
                assert not select.select([monitor.stdout], [], [], 0.1)[0], "exit refresh changed the policy rule"
            finally:
                monitor.terminate()
        session.close()
    assert ip("-4", "rule", "show", "pref", "11000") == ""
    print("Refreshed an exit bypass without changing the active policy rule and restored the table.")

    with helper(launcher) as session:
        session.setup()
        configure_exit(session, "203.0.113.10")
        session.proc.kill()
        assert session.proc.wait(timeout=5) < 0
    assert "lookup 51820" in ip("-4", "rule", "show", "pref", "11000")
    assert "unreachable default" in ip("-4", "route", "show", "table", "51820")
    with helper(launcher) as session:
        session.setup(name="lane-recovery")
        assert ip("-4", "rule", "show", "pref", "11000") == ""
        session.close()
    print("The closed guard survived helper death and the successor recovered its exit journal.")

    with helper(launcher) as session:
        session.setup()
        result = session.request("apply-exit-routes", exit_routes={
            "tunnel_prefixes": ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
            "transport_bypasses": ["203.0.113.10", "2001:db8:1::10"],
        })
        assert result["ok"], result
        assert "lookup 51820" in ip("-6", "rule", "show", "pref", "11000")
        table = ip("-6", "route", "show", "table", "51820")
        assert "unreachable default" in table and "2001:db8:1::10 dev uplink-fixture" in table, table
        session.close()
    assert ip("-4", "rule", "show", "pref", "11000") == ""
    assert ip("-6", "rule", "show", "pref", "11000") == ""
    print("Installed and restored exit rules and bypasses for IPv4 and IPv6.")


def check_dns(launcher):
    def resolver(*args):
        return subprocess.check_output(("resolvectl", *args), text=True).strip()

    name = "lane-fixture"
    with helper(launcher) as session:
        session.setup()
        configure_exit(session, "203.0.113.10")
        resolver("dns", name, "192.0.2.10")
        resolver("domain", name, "prior.example")
        resolver("default-route", name, "no")
        for server in ["192.0.2.20", "192.0.2.21"]:
            result = session.request("apply-dns", dns={"servers": [server]})
            assert result["ok"], result
            assert resolver("dns", name).endswith(f": {server}")
            assert resolver("domain", name).endswith(": ~.")
            assert resolver("default-route", name).endswith(": yes")
        result = session.request("restore-exit-routes")
        assert result["ok"], result
        assert resolver("dns", name).endswith(": 192.0.2.10")
        assert resolver("domain", name).endswith(": prior.example")
        assert resolver("default-route", name).endswith(": no")
        assert ip("-4", "rule", "show", "pref", "11000") == ""
        configure_exit(session, "203.0.113.10")
        result = session.request("apply-dns", dns={"servers": ["192.0.2.22"]})
        assert result["ok"], result
        resolver("dns", name, "192.0.2.99")
        result = session.request("close")
        assert not result["ok"] and "outside its helper owner" in result["error"], result
        assert session.proc.wait(timeout=5) != 0
        assert resolver("dns", name).endswith(": 192.0.2.99")
        assert ip("-4", "rule", "show", "pref", "11000") == ""
    print("Restored owned DNS and cleared exit routing even when DNS ownership was lost.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("launcher", type=Path)
    parser.add_argument("--exit", action="store_true", help="also test live exit route policy and refresh")
    parser.add_argument("--resolved", action="store_true", help="also test DNS with systemd-resolved running in this namespace")
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/dev/net/tun").exists():
        parser.error("root and /dev/net/tun are required in the isolated namespace")
    launcher = args.launcher.resolve()
    check_routes(launcher)
    if args.exit or args.resolved:
        check_exit(launcher)
    if args.resolved:
        check_dns(launcher)


if __name__ == "__main__":
    main()
