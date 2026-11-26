#!/usr/bin/env python3
"""Exercise packaged rootless nodes with the production Rust controller and relay."""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


LOOPBACK = "127.0.0.1"
NETWORK = "21000000000000000000000000000001"
CONTROLLER = "21000000000000000000000000000002"
RELAY = "21000000000000000000000000000003"


def binary(root, name, directory):
    for path in (root / directory / name, root / name):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise FileNotFoundError(f"missing executable {directory}/{name} in {root}")


def run(*args, env, input_text=None):
    options = {"input": input_text} if input_text is not None else {"stdin": subprocess.DEVNULL}
    result = subprocess.run(args, **options, capture_output=True, text=True, timeout=25, env=env)
    if result.returncode:
        # Arguments contain public paths and flags only. Secrets are submitted on stdin.
        raise RuntimeError(f"{Path(args[0]).name} {args[1]} exited {result.returncode}: {result.stderr}")
    return result.stdout


@contextlib.contextmanager
def process(work, name, *args, env):
    path = work / f"{name}.log"
    with path.open("w") as output:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=output, env=env)
        try:
            yield child
        except BaseException:
            print(f"--- {name} ---\n{path.read_text()[-8000:]}", file=sys.stderr)
            raise
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(5)
                except subprocess.TimeoutExpired:
                    child.kill()
            child.wait()


def wait_for(test, description, *children, timeout=20):
    limit = time.monotonic() + timeout
    while time.monotonic() < limit:
        if any(child.poll() is not None for child in children):
            raise RuntimeError(f"a service exited before {description}")
        try:
            if test():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}")


def reachable(address):
    with socket.create_connection(address, timeout=0.5):
        return True


def privileges(pid):
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    return tuple(int(value) for value in fields["Uid"].split()), tuple(
        int(fields[name], 16) for name in ("CapEff", "CapPrm", "CapAmb")
    )


def network_state():
    # Ignore volatile counters. Compare interface names and the route attributes
    # that describe forwarding, along with the kernel forwarding controls.
    ipv4 = [line.split() for line in Path("/proc/net/route").read_text().splitlines()[1:]]
    ipv6 = [line.split() for line in Path("/proc/net/ipv6_route").read_text().splitlines()]
    return (
        sorted(name for _, name in socket.if_nameindex()),
        sorted(tuple(row[:4] + row[6:]) for row in ipv4),
        sorted(tuple(row[:6] + row[8:]) for row in ipv6),
        Path("/proc/sys/net/ipv4/ip_forward").read_text(),
        Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text(),
    )


def usable_address(address):
    return (0 < address.packed[0] < 240 and not address.is_loopback
            and not address.is_link_local and not address.is_multicast)


def local_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            try:
                # SIOCGIFADDR reads the interface's primary IPv4 address.
                result = fcntl.ioctl(probe, 0x8915, struct.pack("256s", name.encode()))
            except OSError:
                continue
            address = ipaddress.IPv4Address(result[20:24])
            if usable_address(address):
                return str(address)
    raise RuntimeError("provide --target-ip for a non-loopback IPv4 address on this host")

def ports(count):
    # Hold TCP and UDP reservations together to avoid choosing a port already in use.
    with contextlib.ExitStack() as scope:
        chosen = []
        while len(chosen) != count:
            tcp = scope.enter_context(socket.socket())
            tcp.bind((LOOPBACK, 0))
            port = tcp.getsockname()[1]
            udp = scope.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            try:
                udp.bind((LOOPBACK, port))
            except OSError:
                continue
            chosen.append(port)
        return chosen


def b64(data):
    return base64.b64encode(data).decode("ascii")


def read_exact(stream, count):
    received = bytearray()
    while len(received) < count:
        data = stream.recv(count - len(received))
        if not data:
            raise ConnectionError("SOCKS connection closed early")
        received.extend(data)
    return bytes(received)


def session_closed(stream):
    try:
        return stream.recv(1) == b""
    except ConnectionResetError:
        return True

def socks_login(address, user, password, accepted=True):
    stream = socket.create_connection(address, timeout=2)
    try:
        stream.sendall(b"\x05\x01\x02")
        assert read_exact(stream, 2) == b"\x05\x02", "RFC 1929 authentication was not selected"
        user, password = user.encode(), password.encode()
        stream.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
        version, status = read_exact(stream, 2)
        assert version == 1 and (status == 0) == accepted, "unexpected SOCKS authentication result"
        return stream
    except BaseException:
        stream.close()
        raise


def socks_request(stream, command, host, port):
    stream.sendall(b"\x05" + bytes((command,)) + b"\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
    version, status, reserved, family = read_exact(stream, 4)
    assert (version, reserved) == (5, 0), "invalid SOCKS response"
    assert family in (1, 4), "SOCKS product returned an unexpected response address type"
    host = socket.inet_ntop(socket.AF_INET if family == 1 else socket.AF_INET6, read_exact(stream, 4 if family == 1 else 16))
    port, = struct.unpack("!H", read_exact(stream, 2))
    return status, (host, port)


@contextlib.contextmanager
def echoes(host):
    stop = threading.Event()
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as denied:
        for server in (tcp, udp, denied):
            server.bind((host, 0))
            server.settimeout(0.2)
        tcp.listen()
        denied.listen()

        def tcp_echo(connection):
            with connection:
                connection.settimeout(0.2)
                while not stop.is_set():
                    try:
                        data = connection.recv(4096)
                        if not data:
                            return
                        connection.sendall(data)
                    except socket.timeout:
                        continue
                    except OSError:
                        return

        def accept_tcp():
            while not stop.is_set():
                try:
                    connection, _ = tcp.accept()
                    threading.Thread(target=tcp_echo, args=(connection,), daemon=True).start()
                except socket.timeout:
                    continue

        def echo_udp():
            while not stop.is_set():
                try:
                    data, peer = udp.recvfrom(4096)
                    udp.sendto(data, peer)
                except socket.timeout:
                    continue

        threads = [threading.Thread(target=handler, daemon=True) for handler in (accept_tcp, echo_udp)]
        for thread in threads:
            thread.start()
        try:
            yield tcp.getsockname()[1], udp.getsockname()[1], denied
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=1)


@contextlib.contextmanager
def enrollment_transport(work, controller_port):
    """Connect two loopback TLS sockets and selectively withhold enrollment replies."""
    ca = ssl.create_default_context(cafile=str(work / "ca.crt"))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(work / "controller.crt", work / "controller.key")
    deliver = threading.Event()
    exchanges = []

    class EnrollmentForwarder(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/v1/enroll" or not 0 < length <= 128 << 10:
                self.send_error(400)
                return
            self.connection.settimeout(8)
            request = self.rfile.read(length)
            backend = http.client.HTTPSConnection(LOOPBACK, controller_port, context=ca, timeout=8)
            try:
                backend.request("POST", self.path, request, {"Content-Type": self.headers["Content-Type"]})
                upstream = backend.getresponse()
                status = upstream.status
                content_type = upstream.getheader("Content-Type")
                response = upstream.read(128 << 10)
            finally:
                backend.close()
            exchanges.append((status, hashlib.sha256(request).digest(), hashlib.sha256(response).digest()))
            if not deliver.is_set():
                # Read the complete committed response, then close without sending it.
                self.close_connection = True
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format, *_args):
            pass

    with http.server.ThreadingHTTPServer((LOOPBACK, 0), EnrollmentForwarder) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, deliver, exchanges
        finally:
            server.shutdown()
            thread.join(timeout=5)


def enrollment_rows(database):
    with contextlib.closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        return tuple(set(connection.execute(query)) for query in (
            "SELECT lower(hex(id)) FROM nodes",
            "SELECT lower(hex(node_id)), serial FROM certificates",
            "SELECT id, lower(hex(consumed_by)) FROM enrollment_tokens WHERE consumed_at IS NOT NULL",
        ))

def interrupted_enrollment(call, cli, flags, invite, state, database, env, fault):
    _, deliver, exchanges = fault
    deliver.clear()
    exchanges.clear()
    baseline = enrollment_rows(database)
    first = subprocess.run((cli, "configure", *flags), input=invite + "\n",
                           capture_output=True, text=True, timeout=25, env=env)
    assert first.returncode != 0 and "enrollment remains pending" in first.stderr, (
        "the initial configure did not stop with an actionable recovery error"
    )
    assert exchanges and all(request == exchanges[0] for request in exchanges), (
        "the controller did not send a consistent committed enrollment response"
    )
    assert exchanges[0][0] == 201, f"upstream enrollment returned HTTP {exchanges[0][0]}"
    committed = enrollment_rows(database)
    assert all(before <= after and len(after - before) == 1
               for before, after in zip(baseline, committed)), "the initial attempt did not commit one enrollment"
    pending = state / "pending-enrollment.json"
    assert pending.stat().st_mode & 0o777 == 0o600, "pending enrollment secret is not private"
    assert not (state / "identity.json").exists(), "the withheld identity was published locally"
    attempts = len(exchanges)
    deliver.set()
    configured = call(cli, "configure", *flags, input_text=invite + "\n")
    assert len(exchanges) > attempts and all(request == exchanges[0] for request in exchanges), (
        "configure did not replay the same request and recover the original response"
    )
    assert enrollment_rows(database) == committed, "configure retry changed controller enrollment rows"
    assert not pending.exists(), "successful configure left the pending enrollment file behind"
    identity = json.loads((state / "identity.json").read_bytes())
    assert committed[0] - baseline[0] == {(identity["node_id"],)}, "configure persisted a different node ID"
    print(f"Recovered {identity['name']} after a dropped TLS response without creating another node.")
    return configured


def exercise(work, root, host, check_renewal):
    cli = binary(root, "laneway", "bin")
    controller = binary(root, "laneway-controller-rs", "sbin")
    relay = binary(root, "laneway-relay-rs", "sbin")
    binary(root, "lanewayd-rs", "sbin")  # Public commands must find the packaged sibling.
    controller_port, relay_port, metric_port, sender_port, receiver_port = ports(5)
    controller_addr, relay_addr = f"{LOOPBACK}:{controller_port}", f"{LOOPBACK}:{relay_port}"
    cli_env = {**os.environ, "HOME": str(work), "XDG_STATE_HOME": str(work / "xdg")}

    def call(*args, **options):
        return run(*args, env=cli_env, **options)

    call(cli, "pki", "init", "--out-dir", work)
    for role, identifier in (("controller", CONTROLLER), ("relay", RELAY)):
        call(cli, "pki", role, "--ca-cert", work / "ca.crt", "--ca-key", work / "ca.key",
             "--network-id", NETWORK, "--service-id", identifier, "--ip", LOOPBACK,
             "--out-cert", work / f"{role}.crt", "--out-key", work / f"{role}.key")
    token_file = work / "admin.token"
    token_file.write_text(secrets.token_hex(32) + "\n")
    database = work / "controller.db"
    call(controller, "init", database, work / "controller.crt", "rootless-fixture", "100.115.0.0/24")
    relay_config = work / "relay.toml"
    relay_config.write_text(f'''mode = "relay"
state_dir = "{work / "relay-state"}"
socket_path = "{work / "relay.sock"}"
[tls]
certificate = "{work / "relay.crt"}"
private_key = "{work / "relay.key"}"
ca = "{work / "ca.crt"}"
[relay]
listen = "{relay_addr}"
metrics_listen = "{LOOPBACK}:{metric_port}"
[controller]
endpoint = "https://{controller_addr}"
quic_endpoint = "{controller_addr}"
server_name = "{LOOPBACK}"
network_id = "{NETWORK}"
service_id = "{CONTROLLER}"
poll_interval = "100ms"
''')
    connection = ("--controller", f"https://{controller_addr}", "--ca", work / "ca.crt",
                  "--server-name", LOOPBACK, "--controller-network-id", NETWORK,
                  "--controller-service-id", CONTROLLER)

    def admin(*args):
        return json.loads(call(cli, "controller", *args, *connection, "--admin-token-file", token_file))

    states = {"sender": work / "xdg/laneway/rootless", "receiver": work / "receiver"}
    open_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def connected_nodes():
        with open_http.open(f"http://{LOOPBACK}:{metric_port}/metrics", timeout=1) as response:
            return b"\nlaneway_relay_sessions 2\n" in response.read()

    with contextlib.ExitStack() as scope:
        controller_proc = scope.enter_context(process(
            work, "controller", controller, "serve", database, controller_addr,
            work / "controller.crt", work / "controller.key", "--root-token-file", token_file,
            "--node-client-ca", work / "ca.crt", "--node-issuer", work / "ca.crt", work / "ca.key",
            "90" if check_renewal else "3600",
            "--node-quic", "--quic-listen", controller_addr, env=cli_env))
        wait_for(lambda: reachable((LOOPBACK, controller_port)), "controller HTTPS", controller_proc)
        admin("relay", "register", "--network-id", NETWORK, "--service-id", RELAY,
              "--name", "rootless-relay", "--endpoint", relay_addr)

        initial_passwords = {}
        fault = scope.enter_context(enrollment_transport(work, controller_port))
        for name, state in states.items():
            capabilities = () if name == "sender" else ("--connector",)
            reservation = admin("enrollment-token", "issue", "--network-id", NETWORK, *capabilities,
                                "--label", name, "--requested-name", name, "--expires-in", "10m")
            enrollment_addr = f"{LOOPBACK}:{fault[0]}"
            fields = [name, reservation["enrollment_token"], f"https://{enrollment_addr}",
                      controller_addr, LOOPBACK, NETWORK, CONTROLLER, relay_addr, RELAY,
                      b64((work / "ca.crt").read_bytes())]
            invite = "st1." + b64(("\n".join(fields) + "\n").encode())
            flags = () if name == "sender" else ("--state-dir", state)
            configure = interrupted_enrollment(call, cli, flags, invite, state, database, cli_env, fault)
            password_label = "SOCKS5 password (shown once): "
            generated = [line.removeprefix(password_label) for line in configure.splitlines()
                         if line.startswith(password_label)]
            assert len(generated) == 1 and generated[0], "missing initial local credential"
            initial_passwords[name] = generated[0]
            for leaf in ("identity.json", "credentials.json"):
                assert ((state / leaf).stat().st_mode & 0o777) == 0o600, f"{leaf} is not private"
            assert state.stat().st_mode & 0o077 == 0, "state directory is not private"

        identity = (states["sender"] / "identity.json").read_bytes()
        credentials = (states["sender"] / "credentials.json").read_bytes()
        repeat = call(cli, "configure")
        assert "SOCKS5 password" not in repeat, "repeat configure printed an existing password"
        assert identity == (states["sender"] / "identity.json").read_bytes(), "repeat configure rewrote identity"
        assert credentials == (states["sender"] / "credentials.json").read_bytes(), "repeat configure rewrote credentials"

        operator_route = admin("route", "assign", "--network-id", NETWORK, "--connector", "receiver",
                               "--to", f"{host}/32", "--allow", "sender")
        route = operator_route["route"]
        admin("acl", "add", "--network-id", NETWORK, "--priority", "200", "--action", "accept",
              "--selector", '{"ip_protocol":"IP_PROTOCOL_ANY"}', "--description", "fixture return traffic")
        tcp_port, udp_port, denied = scope.enter_context(echoes(host))
        blocked_port = denied.getsockname()[1]
        selector = json.dumps({
            "ip_protocol": "IP_PROTOCOL_TCP",
            "destination_prefixes": [{"address": b64(socket.inet_aton(host)), "prefix_length": 32}],
            "destination_ports": [{"first": blocked_port, "last": blocked_port}],
        })
        admin("acl", "add", "--network-id", NETWORK, "--priority", "10", "--action", "deny",
              "--selector", selector, "--description", "fixture denied listener")

        password, spare = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        for user, secret in (("integration", password), ("spare", spare)):
            call(cli, "credential", "add", user, "--password-stdin", input_text=secret + "\n")
        assert set(call(cli, "credential", "list").splitlines()) == {"local", "integration", "spare"}
        relay_proc = scope.enter_context(process(work, "relay", relay, "--config", relay_config, env=cli_env))
        receiver = scope.enter_context(process(work, "receiver", cli, "start", "--state-dir", states["receiver"],
                                               "--listen", f"{LOOPBACK}:{receiver_port}", env=cli_env))
        sender_start = (cli, "start", "--listen", f"{LOOPBACK}:{sender_port}", "--proxy-only")
        with process(work, "sender", *sender_start, env=cli_env) as sender:
            wait_for(connected_nodes, "both authenticated relay sessions", controller_proc, relay_proc, receiver, sender)
            for child in (controller_proc, relay_proc, receiver, sender):
                assert privileges(child.pid) == privileges("self"), "a service changed UID or capability set"
            sender_addr = (LOOPBACK, sender_port)
            with socks_login(sender_addr, "integration", "invalid", accepted=False):
                pass
            with socks_login(sender_addr, "local", initial_passwords["sender"]) as stream:
                assert socks_request(stream, 1, host, tcp_port)[0] == 0, "generated local credential failed"

            live = scope.enter_context(socks_login(sender_addr, "integration", password))
            assert socks_request(live, 1, host, tcp_port)[0] == 0, "TCP connect failed"
            live.sendall(b"rootless-tcp")
            assert read_exact(live, 12) == b"rootless-tcp"

            with socks_login(sender_addr, "spare", spare) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind((LOOPBACK, 0))
                udp.settimeout(3)
                status, endpoint = socks_request(control, 3, *udp.getsockname())
                assert status == 0, "UDP association failed"
                header = b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", udp_port)
                udp.sendto(header + b"rootless-udp", endpoint)
                assert udp.recvfrom(4096)[0] == header + b"rootless-udp"

            with socks_login(sender_addr, "spare", spare) as stream:
                assert socks_request(stream, 1, host, blocked_port)[0] != 0, "controller ACL was ignored"
            try:
                unexpected, _ = denied.accept()
            except TimeoutError:
                pass
            else:
                unexpected.close()
                raise AssertionError("denied attempt reached its TCP listener")
            with socks_login(sender_addr, "spare", spare) as remaining:
                assert socks_request(remaining, 1, host, tcp_port)[0] == 0, "second credential failed"
                call(cli, "credential", "remove", "integration")
                wait_for(lambda: session_closed(live), "revoked credential's active session to close", sender)
                assert set(call(cli, "credential", "list").splitlines()) == {"local", "spare"}
                with socks_login(sender_addr, "integration", password, accepted=False):
                    pass
                remaining.sendall(b"retained")
                assert read_exact(remaining, 8) == b"retained", "unrevoked active session was interrupted"
        with process(work, "sender-restart", *sender_start, env=cli_env) as sender:
            def credentials_survive_restart():
                with socks_login(sender_addr, "spare", spare) as stream:
                    if socks_request(stream, 1, host, tcp_port)[0] != 0:
                        return False
                    stream.sendall(b"restart")
                    return read_exact(stream, 7) == b"restart"

            wait_for(credentials_survive_restart, "traffic after restart", relay_proc, receiver, sender)
            before = json.loads(identity)
            after = json.loads((states["sender"] / "identity.json").read_bytes())
            stable_fields = ("node_id", "network_id", "wireguard_private_key")
            assert all(before[field] == after[field] for field in stable_fields), "restart changed enrolled identity"
            if check_renewal:
                def renewed_identity():
                    current = json.loads((states["sender"] / "identity.json").read_bytes())
                    assert all(before[field] == current[field] for field in stable_fields), "renewal changed enrolled identity"
                    return all(before[field] != current[field]
                               for field in ("certificate_pem", "private_key_pem"))

                wait_for(renewed_identity, "controller certificate renewal", controller_proc, relay_proc, receiver,
                         sender, timeout=90)
                wait_for(credentials_survive_restart, "TCP traffic after certificate renewal",
                         controller_proc, relay_proc, receiver, sender)
                print("Controller renewed the live rootless identity and retained the node ID and WireGuard key.")
            else:
                assert before == after, "restart unexpectedly rewrote the enrolled identity"
            receiver_identity = json.loads((states["receiver"] / "identity.json").read_text())
            cert, key = work / "withdraw.crt", work / "withdraw.key"
            cert.write_text(receiver_identity["certificate_pem"])
            key.write_text(receiver_identity["private_key_pem"])
            with socks_login(sender_addr, "spare", spare) as affected:
                assert socks_request(affected, 1, host, tcp_port)[0] == 0, "TCP route failed before withdrawal"
                call(cli, "controller", "route", "withdraw", "--route-id", route["route_id"],
                     *connection, "--cert", cert, "--key", key)
                wait_for(lambda: session_closed(affected), "route withdrawal to close the active session",
                         relay_proc, receiver, sender, timeout=45)

            def withdrawn():
                with socks_login(sender_addr, "spare", spare) as stream:
                    return socks_request(stream, 1, host, tcp_port)[0] != 0

            wait_for(withdrawn, "controller route withdrawal to stop new connections",
                     relay_proc, receiver, sender, timeout=45)

    print("Production Rust control plane and packaged CLI passed SOCKS5 TCP/UDP, ACL, credentials, restart, and route withdrawal.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True, help="extracted Linux package or flat binary directory")
    parser.add_argument("--target-ip", help="non-loopback IPv4 address assigned to this disposable runner")
    parser.add_argument("--check-renewal", action="store_true", help="also exercise automatic renewal with short-lived certificates")
    args = parser.parse_args()
    if not __debug__:
        parser.error("run without Python optimization so test assertions remain enabled")
    if sys.platform != "linux" or os.geteuid() == 0 or privileges("self") != ((os.getuid(),) * 4, (0, 0, 0)):
        parser.error("run on Linux as an ordinary user with no effective, permitted, or ambient capabilities")
    try:
        target = ipaddress.IPv4Address(args.target_ip or local_address())
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    if not usable_address(target):
        parser.error("--target-ip must be a non-loopback, non-link-local unicast interface address")
    # Confirm the target is local before publishing its route.
    with socket.socket() as probe:
        try:
            probe.bind((str(target), 0))
        except OSError as error:
            parser.error(f"--target-ip is not bindable locally: {error}")
    os.umask(0o077)
    initial = network_state()
    try:
        with tempfile.TemporaryDirectory(prefix="laneway-rootless-") as directory:
            exercise(Path(directory), args.bin_dir.resolve(), str(target), args.check_renewal)
    finally:
        assert network_state() == initial, "host interfaces, routes, or forwarding sysctls changed"
    print("Host interfaces, routes, and forwarding sysctls matched before and after.")


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    main()
