#!/usr/bin/env python3
"""Unprivileged real-controller, real-relay rootless connector smoke test."""

import argparse
import base64
import contextlib
import errno
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import struct
import sys
import subprocess
import tempfile
import threading
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = "127.0.0.1"
LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def b64(value):
    return base64.b64encode(value).decode("ascii")


def free_port():
    while True:
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind((LOOPBACK, 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind((LOOPBACK, port))
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
            else:
                return port


def local_address():
    # Connecting a UDP socket selects the interface without sending a datagram.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=30, **kwargs)


@contextlib.contextmanager
def process(work, name, *args, env=None):
    with tempfile.NamedTemporaryFile(prefix=f"{name}-", suffix=".log", dir=work, mode="w") as log:
        child = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            yield child
        except Exception:
            print(f"=== {name} ===\n{Path(log.name).read_text()}", file=sys.stderr, flush=True)
            raise
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def wait_for(check, description, *children, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(child.poll() is not None for child in children):
            raise RuntimeError(f"child exited while waiting for {description}")
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}")


def reachable(port):
    with socket.create_connection((LOOPBACK, port), timeout=0.3):
        return True


def metric(port, name):
    with LOCAL_HTTP.open(f"http://{LOOPBACK}:{port}/metrics", timeout=1) as response:
        lines = response.read().decode("ascii").splitlines()
    prefix = f"laneway_{name} "
    return int(next(line[len(prefix):] for line in lines if line.startswith(prefix)))


def take(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("proxy closed before sending a complete reply")
        result += chunk
    return bytes(result)


def expect(actual, expected, description):
    if actual != expected:
        raise RuntimeError(f"unexpected {description}: {actual!r}, expected {expected!r}")


def addr(host, port):
    return b"\x01" + socket.inet_aton(host) + struct.pack("!H", port)


def authenticate(sock, password, allowed=True, name="integration"):
    sock.sendall(b"\x05\x02\x00\x02")
    expect(take(sock, 2), b"\x05\x02", "SOCKS method selection")
    member = name.encode("ascii")
    key = password.encode("ascii")
    sock.sendall(bytes([1, len(member)]) + member + bytes([len(key)]) + key)
    expect(take(sock, 2), b"\x01\x00" if allowed else b"\x01\x01", "SOCKS authentication reply")


def request(sock, command, host, port):
    sock.sendall(bytes([5, command, 0]) + addr(host, port))
    version, status, reserved, family = take(sock, 4)
    expect((version, reserved, family), (5, 0, 1), "SOCKS command reply header")
    endpoint = (socket.inet_ntoa(take(sock, 4)), struct.unpack("!H", take(sock, 2))[0])
    return status, endpoint


def echo_once(listener, kind, payload, result):
    try:
        if kind == socket.SOCK_STREAM:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(10)
                data = take(connection, len(payload))
                connection.sendall(data)
        else:
            data, source = listener.recvfrom(65535)
            listener.sendto(data, source)
        result.append(data)
    except (OSError, RuntimeError) as error:
        result.append(error)


def echo_stream(listener):
    try:
        connection, _ = listener.accept()
        with connection:
            while data := connection.recv(4096):
                connection.sendall(data)
    except (OSError, RuntimeError):
        # The fixture tears down some sockets through revocation or reconnect.
        pass


def echo_round_trip(sock):
    payload = secrets.token_bytes(97)
    sock.sendall(payload)
    expect(take(sock, len(payload)), payload, "persistent TCP echo")


def expect_closed(sock, description):
    try:
        received = sock.recv(1)
    except ConnectionResetError:
        return
    except socket.timeout as error:
        raise RuntimeError(f"{description} did not terminate the socket") from error
    expect(received, b"", description)


def stop(child):
    child.send_signal(signal.SIGINT)
    expect(child.wait(timeout=5), 0, f"clean shutdown of {Path(child.args[0]).name}")


def network_state():
    def routes(family):
        result = json.loads(run("ip", family, "-j", "route", "show", "table", "all"))
        for route in result:
            # Lifetime countdowns can change during an otherwise idle run.
            route.pop("expires", None)
        return result

    settings = (
        "ipv4/ip_forward", "ipv4/conf/all/forwarding", "ipv4/conf/default/forwarding",
        "ipv6/conf/all/forwarding", "ipv6/conf/default/forwarding",
    )
    firewall = None
    if shutil.which("nft"):
        rules = subprocess.run(["nft", "list", "ruleset"], text=True, capture_output=True, timeout=5)
        if rules.returncode == 0:
            firewall = rules.stdout
    return {
        "interfaces": json.loads(run("ip", "-j", "link", "show")),
        "IPv4 routes": routes("-4"),
        "IPv6 routes": routes("-6"),
        "forwarding sysctls": {key: Path("/proc/sys/net", key).read_text() for key in settings},
        "nftables": firewall,
    }


def sample_connectors(label, nodes, action):
    clock_ticks = os.sysconf("SC_CLK_TCK")

    def sample(node):
        fields = Path(f"/proc/{node.pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        memory = int(Path(f"/proc/{node.pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        return ticks, memory

    started = time.monotonic()
    before = {name: sample(node)[0] for name, node in nodes.items()}
    action()
    elapsed = time.monotonic() - started
    for name, node in nodes.items():
        ticks, resident = sample(node)
        cpu = (ticks - before[name]) / clock_ticks / elapsed * 100
        print(f"Sample {label} {name}: {resident / 2**20:.2f} MiB RSS, {cpu:.2f}% of one CPU "
              f"over {elapsed:.2f}s", flush=True)


def safe_identity(pid):
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    uids = {int(uid) for uid in fields["Uid"].split()}
    dropped = all(int(fields[name], 16) == 0 for name in ("CapEff", "CapPrm", "CapAmb"))
    root_isolated = int(fields["CapBnd"], 16) == 0 and int(fields["NoNewPrivs"]) == 1
    return uids == {os.geteuid()} and dropped and (os.geteuid() != 0 or root_isolated)


def check_system_config(daemon, work, identity_dir, ca_file, relay_address, relay_id):
    identity = json.loads((identity_dir / "identity.json").read_text())
    fixture = work / "system-check"
    fixture.mkdir()
    certificate = fixture / "node.crt"
    key = fixture / "node.key"
    certificate.write_text(identity["certificate_pem"])
    key.write_text(identity["private_key_pem"])
    config = fixture / "system.toml"
    config.write_text(f"""
mode = "node"
socket_path = "{fixture / 'system.sock'}"
exit_intent_path = "{fixture / 'exit-intent.json'}"
[identity]
network_id = "{identity['network_id']}"
node_id = "{identity['node_id']}"
[tls]
certificate = "{certificate}"
private_key = "{key}"
ca = "{ca_file}"
[tun]
name = "lanecheck"
addresses = ["100.115.0.1/32"]
configure = true
[relay]
address = "{relay_address}"
server_name = "{LOOPBACK}"
service_id = "{relay_id}"
[forwarding]
dns_state_file = "{fixture / 'dns-state.json'}"
[[routes]]
prefix = "100.115.0.2/32"
via_node = "21000000000000000000000000000004"
kind = "overlay"
""")
    protected = {entry.name: entry.read_bytes() for entry in fixture.iterdir()}
    network_before = network_state()
    isolated_env = {**os.environ, "HOME": str(fixture / "home"), "XDG_STATE_HOME": str(fixture / "state")}
    result = run(daemon, "run", "--system", "--config", config, "--check-config", env=isolated_env)
    expect(result.strip(), "configuration is valid", "explicit system config validation")
    expect({entry.name for entry in fixture.iterdir()}, set(protected), "system check fixture paths")
    if any((fixture / name).read_bytes() != data for name, data in protected.items()):
        raise RuntimeError("system check rewrote fixture state")
    if network_state() != network_before:
        raise RuntimeError("system check changed host networking")
    print("Explicit system config validation left state and networking unchanged.", flush=True)



def prepare_public_cache(work, server_name):
    cache = work / "autocert"
    cache.mkdir(mode=0o700)
    key = work / "public.key"
    cert = work / "public.crt"
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    run("openssl", "req", "-new", "-x509", "-config", "/dev/null", "-key", key, "-days", "365",
        "-subj", f"/CN={server_name}", "-addext", f"subjectAltName=DNS:{server_name}", "-out", cert)
    key_pem = key.read_bytes()
    expect(key_pem.splitlines()[0], b"-----BEGIN EC PRIVATE KEY-----", "legacy autocert key format")
    (cache / server_name).write_bytes(key_pem + cert.read_bytes())
    (cache / "acme_account+key").write_bytes(key_pem)
    return cache, cert


def inspect_public_relay(port, cert, ca, server_name, network, relay_id, admin):
    metadata_path = "/.well-known/laneway/bootstrap.json"
    public_tls = ssl.create_default_context(cafile=str(cert))
    public_tls.minimum_version = ssl.TLSVersion.TLSv1_3
    public_tls.set_alpn_protocols(["http/1.1"])

    def probe(method, path):
        with socket.create_connection((LOOPBACK, port), timeout=5) as tcp:
            with public_tls.wrap_socket(tcp, server_hostname=server_name) as stream:
                expect(stream.selected_alpn_protocol(), "http/1.1", "public HTTPS ALPN")
                expect(stream.getpeercert(binary_form=True),
                       ssl.PEM_cert_to_DER_cert(cert.read_text()), "legacy cached certificate")
                stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n".encode())
                with contextlib.closing(http.client.HTTPResponse(stream, method=method)) as response:
                    response.begin()
                    return response.status, response.headers, response.read()

    status, headers, contents = probe("GET", metadata_path)
    expect(status, 200, "public discovery status")
    expect(headers.get_content_type(), "application/json", "public discovery content type")
    expect(headers["Cache-Control"], "no-store", "public discovery cache control")
    metadata = json.loads(contents)
    expect(metadata["network_id"], network, "discovery network ID from Go controller")
    if not any(relay["service_id"] == relay_id for relay in metadata["relays"]):
        raise RuntimeError("controller discovery omitted the registered Rust relay")

    for method, path in (("GET", "/healthz"), ("GET", "/metrics"), ("GET", "/v1/admin/networks"),
                         ("POST", metadata_path), ("GET", metadata_path + "?unexpected=1")):
        expect(probe(method, path)[0], 404, f"public allowlist for {method} {path}")

    payload = cert.parent / "one-time-bootstrap.sh"
    payload.write_bytes(b"#!/bin/bash -p\nprintf 'bootstrap fixture\\n'\n")
    result = admin("bootstrap-bundle", "create", "--payload-file", payload,
                   "--expires-at", str(int(time.time()) + 300))
    bundle_path = result["public_path"]
    expect(probe("GET", "/v1/bootstrap-bundles/" + result["bundle_id"])[0], 404,
           "private controller bundle URL on public relay")
    status, headers, contents = probe("GET", bundle_path)
    expect(status, 200, "one-time bundle delivery")
    expect(headers.get_content_type(), "text/x-shellscript", "one-time bundle content type")
    expect(contents, payload.read_bytes(), "one-time body from Go controller")
    expect(probe("GET", bundle_path)[0], 404, "consumed one-time bundle")

    denied_tls = ssl.create_default_context(cafile=str(cert))
    denied_tls.load_verify_locations(cafile=str(ca))
    denied_tls.check_hostname = False
    invalid_hellos = (
        ("wrong.example.test", ["http/1.1"]),
        (None, ["http/1.1"]),
        (server_name, ["h2"]),
        (server_name, ["laneway-fallback/1", "http/1.1"]),
    )
    for name, protocols in invalid_hellos:
        denied_tls.set_alpn_protocols(protocols)
        try:
            with socket.create_connection((LOOPBACK, port), timeout=5) as tcp:
                with denied_tls.wrap_socket(tcp, server_hostname=name) as stream:
                    stream.sendall(f"GET {metadata_path} HTTP/1.1\r\nHost: {server_name}\r\n\r\n".encode())
                    response = stream.recv(1)
        except (ssl.SSLError, ConnectionResetError):
            continue
        expect(response, b"", f"rejected TLS SNI and ALPN {name}, {protocols}")
    print("Rust relay served the legacy-cached TLS certificate, public discovery, and one-time bootstrap only.",
          flush=True)


def exercise(work, bins, target, measure, tcp_fallback, public_https, product_cli):
    network = "21000000000000000000000000000001"
    controller_id = "21000000000000000000000000000002"
    relay_id = "21000000000000000000000000000003"
    cli, controller, relay, daemon = (bins / binary for binary in (
        "laneway", "laneway-controller", "laneway-relay", "lanewayd"
    ))
    # Keep the temporary services on different ephemeral ports.
    sender_port = 1080
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((LOOPBACK, sender_port))
        except OSError as error:
            raise RuntimeError(f"the implicit startup test requires an unused {LOOPBACK}:{sender_port}") from error
    ports = set()
    while len(ports) < (5 if tcp_fallback or public_https else 4):
        port = free_port()
        if port != sender_port:
            ports.add(port)
    controller_port, relay_port, metric_port, receiver_port, *reserved = sorted(ports)
    xdg_state = work / "state"
    sender_env = {**os.environ, "HOME": str(work), "XDG_STATE_HOME": str(xdg_state)}
    states = {"sender": xdg_state / "laneway/rootless", "receiver": work / "receiver"}
    controller_addr = f"{LOOPBACK}:{controller_port}"
    relay_addr = f"{LOOPBACK}:{relay_port}"
    admin_token = work / "admin.token"
    admin_token.write_text(secrets.token_hex(32) + "\n")
    run(cli, "pki", "init", "--out-dir", work)
    for role, service_id in (("controller", controller_id), ("relay", relay_id)):
        run(cli, "pki", role, "--ca-cert", work / "ca.crt", "--ca-key", work / "ca.key",
            "--network-id", network, "--service-id", service_id,
            "--dns", "localhost", "--ip", LOOPBACK,
            "--out-cert", work / f"{role}.crt", "--out-key", work / f"{role}.key")

    def config(role, settings):
        path = work / f"{role}.toml"
        path.write_text(f"""
mode = "{role}"
state_dir = "{work / (role + '-state')}"
socket_path = "{work / (role + '.sock')}"
[tls]
certificate = "{work / (role + '.crt')}"
private_key = "{work / (role + '.key')}"
ca = "{work / 'ca.crt'}"
{settings}
""")
        return path

    public_settings = ""
    bootstrap_settings = ""
    if public_https:
        public_name = "relay.example.test"
        cache, public_cert = prepare_public_cache(work, public_name)
        public_settings = f"""
[public_https]
server_name = "{public_name}"
cache_dir = "{cache}"
"""
        bootstrap_settings = f"""
[controller.initial_network]
network_id = "{network}"
name = "rootless-integration"
ipv4_pool = "100.115.0.0/24"

[bootstrap]
network_id = "{network}"
controller_endpoint = "https://{controller_addr}"
controller_quic_endpoint = "{controller_addr}"
controller_server_name = "localhost"
"""
    controller_config = config("controller", f"""
[controller]
listen = "{controller_addr}"
quic_listen = "{controller_addr}"
database = "{work / 'controller.db'}"
ca_private_key = "{work / 'ca.key'}"
admin_token_file = "{admin_token}"
{bootstrap_settings}
""")
    fallback_port = None
    if tcp_fallback:
        fallback_port = 443
    elif public_https:
        fallback_port = reserved[0]
    fallback_settings = ""
    if fallback_port is not None:
        fallback_settings = f'\n[tcp_fallback]\nlisten = "{LOOPBACK}:{fallback_port}"\n'
    relay_config = config("relay", f"""
[relay]
listen = "{relay_addr}"
[controller]
endpoint = "https://{controller_addr}"
quic_endpoint = "{controller_addr}"
server_name = "localhost"
network_id = "{network}"
service_id = "{controller_id}"
poll_interval = "100ms"
{fallback_settings}
{public_settings}
""")

    run(relay, "--check-config", "--config", relay_config)

    def admin(*args):
        return json.loads(run(cli, "controller", *args,
                              "--controller", f"https://{controller_addr}",
                              "--server-name", "localhost", "--ca", work / "ca.crt",
                              "--controller-network-id", network,
                              "--controller-service-id", controller_id,
                              "--admin-token-file", admin_token))

    def manage(*args):
        return admin(*args, "--network-id", network)

    with contextlib.ExitStack() as scope:
        advertised_relay = relay_addr
        if tcp_fallback:
            # Keep the advertised UDP address unavailable without changing firewall rules.
            blackhole = scope.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            blackhole.bind((LOOPBACK, reserved[0]))
            advertised_relay = f"{LOOPBACK}:{reserved[0]}"
        controller_process = scope.enter_context(process(
            work, "controller", controller, "-config", controller_config))
        wait_for(lambda: reachable(controller_port), "HTTPS controller", controller_process)
        if not public_https:
            manage("network", "create", "--name", "rootless-integration", "--ipv4-pool", "100.115.0.0/24")
        manage("relay", "register", "--service-id", relay_id, "--name", "rootless-relay",
               "--endpoint", advertised_relay)

        def invitation(name):
            token = manage("enrollment-token", "issue", "--label", name, "--requested-name",
                           name, "--expires-in", "10m", "--connector")["enrollment_token"]
            fields = [name, token, f"https://{controller_addr}", controller_addr,
                      LOOPBACK, network, controller_id, advertised_relay, relay_id,
                      b64((work / "ca.crt").read_bytes())]
            return "st1." + b64(("\n".join(fields) + "\n").encode("ascii"))

        configure = [cli, "configure"]
        initial_password = None
        for name in ("sender", "receiver"):
            invite = invitation(name)
            if name == "sender" and product_cli:
                network_before = network_state()
                output = run(*configure, input=invite + "\n", env=sender_env)
                prefix = "SOCKS5 password (shown once): "
                passwords = [line[len(prefix):] for line in output.splitlines()
                             if line.startswith(prefix)]
                if ("SOCKS5 username: local" not in output or len(passwords) != 1
                        or len(passwords[0]) != 64):
                    raise RuntimeError("configure did not print exactly one initial SOCKS5 credential")
                initial_password = passwords[0]
                expect(network_state(), network_before, "networking after product configure")
            else:
                run(daemon, "enroll", "--state-dir", states[name], input=invite + "\n")
        check_system_config(daemon, work, states["sender"], work / "ca.crt", relay_addr, relay_id)
        route = manage("route", "assign", "--connector", "receiver", "--to", target + "/32",
                       "--allow", "sender")["route"]
        manage("acl", "add", "--priority", "200", "--action", "accept",
               "--selector", '{"ip_protocol":"IP_PROTOCOL_ANY"}', "--description", "allow return traffic")

        def target_socket(kind):
            sock = scope.enter_context(socket.socket(socket.AF_INET, kind))
            sock.bind((target, 0))
            sock.settimeout(15)
            if kind == socket.SOCK_STREAM:
                sock.listen()
            return sock

        denied_tcp = target_socket(socket.SOCK_STREAM)
        denied_udp = target_socket(socket.SOCK_DGRAM)
        for protocol, listener in (("TCP", denied_tcp), ("UDP", denied_udp)):
            port = listener.getsockname()[1]
            selector = json.dumps({
                "ip_protocol": f"IP_PROTOCOL_{protocol}",
                "destination_prefixes": [{"address": b64(socket.inet_aton(target)), "prefix_length": 32}],
                "destination_ports": [{"first": port, "last": port}],
            })
            manage("acl", "add", "--priority", "10", "--action", "deny",
                   "--selector", selector, "--description", f"deny the live {protocol} service")

        def credential(*args, **kwargs):
            if product_cli:
                return run(cli, "credential", *args, env=sender_env, **kwargs)
            return run(daemon, "credential", *args, "--state-dir", states["sender"],
                       env=sender_env, **kwargs)

        password = secrets.token_urlsafe(24)
        credential("add", "integration", "--password-stdin", input=password + "\n")
        if product_cli:
            network_before = network_state()
            files = [states["sender"] / name for name in ("identity.json", "credentials.json")]
            original = [path.read_bytes() for path in files]
            output = run(*configure, stdin=subprocess.DEVNULL, env=sender_env)
            if "Configured sender" not in output or "SOCKS5 password" in output:
                raise RuntimeError("repeat configure did not reuse the existing identity without printing a key")
            if [path.read_bytes() for path in files] != original:
                raise RuntimeError("repeat configure rewrote identity or credential files")
            expect(network_state(), network_before, "networking after repeat configure")
            expect(set(credential("list").splitlines()), {"local", "integration"},
                   "product credential list")
            print("Product configure enrolled once and kept both credentials on repeat with closed stdin.",
                  flush=True)

        def start_relay():
            return scope.enter_context(process(
                work, "relay", relay, "--config", relay_config, "--diagnostics", f"{LOOPBACK}:{metric_port}"))

        def start_node(name, port, implicit=False):
            args = [daemon]
            if name == "sender" and product_cli:
                args = [cli, "start"]
            elif not implicit:
                args.extend(("run", "--state-dir", states[name], "--listen", f"{LOOPBACK}:{port}"))
                if name == "sender":
                    args.append("--proxy-only")
            node = scope.enter_context(process(work, name, *args, env=sender_env))
            wait_for(lambda: reachable(port), f"{name} SOCKS listener", node)
            if not safe_identity(node.pid):
                raise RuntimeError(f"{name} connector changed user or started with elevated privileges")
            return node

        def wait_sessions(relay_process):
            wait_for(lambda: metric(metric_port, "relay_sessions") == 2,
                     "two authenticated relay sessions", relay_process, *nodes.values(), timeout=40)

        relay_process = start_relay()
        nodes = {"sender": start_node("sender", sender_port, implicit=True),
                 "receiver": start_node("receiver", receiver_port)}
        wait_sessions(relay_process)
        sender_mode = "Product start" if product_cli else "Implicit lanewayd"
        print(f"{sender_mode} and explicit lanewayd run established relay sessions as UID {os.geteuid()}.",
              flush=True)
        if tcp_fallback:
            connections = run("ss", "-Htn", "state", "established", "( sport = :443 )")
            expect(len(connections.splitlines()), 2, "established TCP relay connections on port 443")
            print("Both connectors reached the relay over TCP port 443 with relay QUIC unavailable.", flush=True)
        if public_https:
            inspect_public_relay(fallback_port, public_cert, work / "ca.crt", public_name, network, relay_id, admin)
        if measure:
            print(f"lanewayd executable size: {daemon.stat().st_size} bytes", flush=True)
            sample_connectors("idle", nodes, lambda: time.sleep(3))

        def connect():
            return socket.create_connection((LOOPBACK, sender_port), timeout=17)

        with connect() as sock:
            sock.sendall(b"\x05\x01\x00")
            expect(take(sock, 2), b"\x05\xff", "SOCKS no-auth rejection")
        with connect() as sock:
            authenticate(sock, "incorrect-key", allowed=False)

        if initial_password is not None:
            with connect() as sock:
                authenticate(sock, initial_password, name="local")

        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            listener = target_socket(kind)
            port = listener.getsockname()[1]
            payload = secrets.token_bytes(97)
            observed = []
            threading.Thread(target=echo_once, args=(listener, kind, payload, observed), daemon=True).start()
            before = metric(metric_port, "relay_forwarded_packets_total")
            with connect() as sock:
                authenticate(sock, password)
                if kind == socket.SOCK_STREAM:
                    status, _ = request(sock, 1, target, port)
                    expect(status, 0, "SOCKS CONNECT status")
                    sock.sendall(payload)
                    expect(take(sock, len(payload)), payload, "TCP echo")
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.bind((LOOPBACK, 0))
                        udp.settimeout(10)
                        status, associate = request(sock, 3, LOOPBACK, udp.getsockname()[1])
                        expect(status, 0, "SOCKS UDP ASSOCIATE status")
                        datagram = b"\x00\x00\x00" + addr(target, port) + payload
                        udp.sendto(datagram, associate)
                        reply, source = udp.recvfrom(65535)
                        expect(source, associate, "SOCKS UDP source")
                        expect(reply, datagram, "SOCKS UDP echo")
            wait_for(lambda: bool(observed), "target listener observation")
            expect(observed[0], payload, "target listener payload")
            wait_for(lambda: metric(metric_port, "relay_forwarded_packets_total") > before,
                     "relayed application packets", relay_process)

        with connect() as sock:
            authenticate(sock, password)
            status, _ = request(sock, 1, target, denied_tcp.getsockname()[1])
            expect(status, 2, "ACL denial for a live TCP target")
        denied_tcp.settimeout(0.3)
        try:
            connection, _ = denied_tcp.accept()
        except socket.timeout:
            pass
        else:
            connection.close()
            raise RuntimeError("ACL-denied TCP traffic reached the live destination")

        with connect() as sock, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            authenticate(sock, password)
            udp.bind((LOOPBACK, 0))
            status, associate = request(sock, 3, LOOPBACK, udp.getsockname()[1])
            expect(status, 0, "SOCKS UDP ASSOCIATE status for negative control")
            denied_port = denied_udp.getsockname()[1]
            udp.sendto(b"\x00\x00\x00" + addr(target, denied_port) + secrets.token_bytes(32), associate)
            denied_udp.settimeout(0.5)
            try:
                denied_udp.recvfrom(65535)
            except socket.timeout:
                pass
            else:
                raise RuntimeError("ACL-denied UDP traffic reached the live destination")

        def flow(local_scope, key, name="integration"):
            listener = local_scope.enter_context(socket.socket())
            listener.bind((target, 0))
            listener.listen()
            listener.settimeout(12)
            threading.Thread(target=echo_stream, args=(listener,), daemon=True).start()
            sock = local_scope.enter_context(connect())
            authenticate(sock, key, name=name)
            status, _ = request(sock, 1, target, listener.getsockname()[1])
            expect(status, 0, "persistent SOCKS CONNECT")
            echo_round_trip(sock)
            return sock

        generated_key = credential("add", "secondary").strip()
        # The foreground proxy reloads its credential database once per second.
        def added_key_works():
            with connect() as sock:
                try:
                    authenticate(sock, generated_key, name="secondary")
                except RuntimeError:
                    return False
                return True

        wait_for(added_key_works, "live credential addition", nodes["sender"])
        with contextlib.ExitStack() as flows:
            revoked = flow(flows, password)
            unaffected = flow(flows, generated_key, "secondary")
            credential("remove", "integration")
            revoked.settimeout(6)
            expect_closed(revoked, "revoked credential session")
            echo_round_trip(unaffected)
            with connect() as sock:
                authenticate(sock, password, allowed=False)
        print("Live credential removal closed only the revoked session.", flush=True)

        before_restart = (states["sender"] / "identity.json").read_bytes()
        stop(nodes["sender"])
        nodes["sender"] = start_node("sender", sender_port)
        wait_sessions(relay_process)
        if (states["sender"] / "identity.json").read_bytes() != before_restart:
            raise RuntimeError("sender identity changed across restart")
        with contextlib.ExitStack() as flows:
            flow(flows, generated_key, "secondary")
        print("Restarted the sender with its saved identity and credential.", flush=True)

        stop(relay_process)
        relay_process = start_relay()
        wait_sessions(relay_process)
        with contextlib.ExitStack() as flows:
            flow(flows, generated_key, "secondary")
        print("Re-established both relay sessions after relay interruption.", flush=True)

        if measure:
            with contextlib.ExitStack() as flows:
                burst = [flow(flows, generated_key, "secondary") for _ in range(16)]

                def traffic():
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        for sock in burst:
                            echo_round_trip(sock)

                sample_connectors("16 concurrent TCP flows", nodes, traffic)

        with contextlib.ExitStack() as flows:
            affected = flow(flows, generated_key, "secondary")
            identity = json.loads((states["receiver"] / "identity.json").read_text())
            certificate, private_key = work / "withdraw.crt", work / "withdraw.key"
            certificate.write_text(identity["certificate_pem"])
            private_key.write_text(identity["private_key_pem"])
            run(cli, "controller", "route", "withdraw", "--route-id", route["route_id"],
                "--controller", f"https://{controller_addr}", "--ca", work / "ca.crt",
                "--cert", certificate, "--key", private_key, "--controller-network-id", network,
                "--controller-service-id", controller_id)
            affected.settimeout(42)
            expect_closed(affected, "withdrawn-route session")
        target_after_withdrawal = target_socket(socket.SOCK_STREAM).getsockname()[1]

        def route_unavailable():
            with connect() as sock:
                authenticate(sock, generated_key, name="secondary")
                status, _ = request(sock, 1, target, target_after_withdrawal)
                return status == 2

        wait_for(route_unavailable, "withdrawn route denial", nodes["sender"], timeout=35)
        print("Controller route withdrawal closed the established TCP session and denied a new one.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     epilog="Run on Linux with Python 3, iproute2, Go, and Cargo.")
    parser.add_argument("--bin-dir", type=Path, help="directory with prebuilt laneway binaries")
    parser.add_argument("--target-ip", default=None, help="non-loopback IPv4 address on this host")
    parser.add_argument("--allow-root", action="store_true",
                        help="test UID 0 in a disposable namespace with no capabilities and no-new-privileges")
    parser.add_argument("--product-cli", action="store_true",
                        help="configure and run the sender with the laneway product commands")
    parser.add_argument("--measure", action="store_true", help="report idle and concurrent TCP resource use")
    parser.add_argument("--tcp-fallback", action="store_true",
                        help="test without relay QUIC, requires an unprivileged bind to 127.0.0.1:443")
    parser.add_argument("--public-https", action="store_true",
                        help="test public HTTPS with a legacy cached TLS certificate, requires OpenSSL")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("the controller administration commands used by this fixture require Linux")
    if not safe_identity("self") or (os.geteuid() == 0 and not args.allow_root):
        parser.error("use an ordinary user with zero capabilities, or explicitly allow isolated UID 0")
    if args.product_cli and os.geteuid() == 0:
        parser.error("--product-cli requires an ordinary user")
    try:
        target_address = ipaddress.IPv4Address(args.target_ip.strip() if args.target_ip else local_address())
    except ipaddress.AddressValueError as error:
        parser.error(str(error))
    if target_address.is_loopback or target_address.is_unspecified:
        parser.error("--target-ip must be a non-loopback host IPv4 address")
    target = str(target_address)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="lanewayd-userspace-") as temp:
        work = Path(temp)
        bins = args.bin_dir.resolve() if args.bin_dir else work
        if args.bin_dir is None:
            subprocess.run(["go", "build", "-o", str(bins) + "/", "./cmd/laneway-controller"],
                           cwd=ROOT / "go", check=True)
            subprocess.run(["cargo", "build", "--locked", "-p", "laneway-cli", "-p", "lanewayd",
                            "-p", "laneway-relay", "--target-dir", work / "target"],
                           cwd=ROOT / "rust", check=True)
            for binary in ("laneway", "lanewayd", "laneway-relay"):
                (bins / binary).symlink_to(work / "target" / "debug" / binary)
        initial_network = network_state()
        exercise(work, bins, target, args.measure, args.tcp_fallback, args.public_https, args.product_cli)
    final_network = network_state()
    for name, state in initial_network.items():
        if final_network[name] != state:
            raise RuntimeError(f"host {name} changed during the test")
    print("Host interfaces, routes, and forwarding sysctls matched before and after the test.")
    if initial_network["nftables"] is None:
        print("The unprivileged user could not read nftables rules.")
    else:
        print("Host nftables rules matched before and after the test.")
    print("Rootless connector integration passed.")


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    main()
