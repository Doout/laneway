#!/usr/bin/env python3
"""Exercise public Rust login and optional privileged connect against loopback services."""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request

sys.dont_write_bytecode = True
from rootless import (
    LOOPBACK, expect, free_port, metric, network_state, process, reachable, run, wait_for,
)


NETWORK = "32000000000000000000000000000001"
CONTROLLER = "32000000000000000000000000000002"
RELAY = "32000000000000000000000000000003"


def bootstrap_certificate(work):
    ca, ca_key = work / "discovery-ca.crt", work / "discovery-ca.key"
    leaf, key, request = (work / name for name in ("discovery.crt", "discovery.key", "discovery.csr"))
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
    run("openssl", "req", "-new", "-x509", "-config", "/dev/null", "-key", ca_key, "-days", "365",
        "-subj", "/CN=Local bootstrap CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-out", ca)
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    run("openssl", "req", "-new", "-config", "/dev/null", "-key", key,
        "-subj", "/CN=localhost", "-out", request)
    extensions = work / "discovery-ext.cnf"
    extensions.write_text("subjectAltName=DNS:localhost\n"
                          "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
                          "keyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\n")
    run("openssl", "x509", "-req", "-in", request, "-CA", ca, "-CAkey", ca_key, "-set_serial", "1",
        "-days", "365", "-extfile", extensions, "-out", leaf)
    cache = work / "autocert"
    cache.mkdir()
    (cache / "localhost").write_bytes(key.read_bytes() + leaf.read_bytes())
    return ca, cache


def service_config(work, role, settings):
    target = work / f"{role}.toml"
    target.write_text(f"""
mode = "{role}"
state_dir = "{work / (role + '-state')}"
socket_path = "{work / (role + '.sock')}"
[tls]
certificate = "{work / (role + '.crt')}"
private_key = "{work / (role + '.key')}"
ca = "{work / 'ca.crt'}"
{settings}
""")
    return target


def rejected(command, *args, env, reason=None):
    result = subprocess.run([command, *args], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=30, check=False)
    if result.returncode == 0 or (reason and reason not in result.stderr):
        raise AssertionError(f"unexpected command outcome: {result.returncode}\n{result.stderr}")
    if "laneway-compat" in result.stderr:
        raise AssertionError(f"public command tried the companion: {result.stderr}")


def profile_manifest(root, authority):
    name = hashlib.sha256(authority.lower().encode()).hexdigest()[:32]
    return json.loads((root / name / "profile.json").read_text())


def exercise(work, launcher, go_cli, controller, relay, with_connect, helper_connect):
    if helper_connect:
        command = launcher
        assert command.with_name("laneway-compat").is_file()
    else:
        isolated = work / "native"
        isolated.mkdir()
        command = isolated / "laneway"
        shutil.copy2(launcher, command)
        # An omitted companion makes accidental use of the Go command observable.
        assert not command.with_name("laneway-compat").exists()
    discovery_ca, cache = bootstrap_certificate(work)
    run(go_cli, "pki", "init", "--out-dir", work)
    for role, identity in (("controller", CONTROLLER), ("relay", RELAY)):
        run(go_cli, "pki", role, "--ca-cert", work / "ca.crt", "--ca-key", work / "ca.key",
            "--network-id", NETWORK, "--service-id", identity, "--dns", "localhost",
            "--ip", LOOPBACK, "--out-cert", work / f"{role}.crt", "--out-key", work / f"{role}.key")
    admin_token = work / "admin.token"
    admin_token.write_text(secrets.token_hex(32) + "\n")
    ports = set()
    while len(ports) < 4:
        ports.add(free_port())
    control_port, relay_port, public_port, metrics_port = sorted(ports)
    control = f"{LOOPBACK}:{control_port}"
    relay_addr = f"{LOOPBACK}:{relay_port}"
    authority = f"localhost:{public_port}"
    go_root, rust_root = work / "saved-go", work / "saved-rust"
    clean = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
    env = clean | {"SSL_CERT_FILE": str(discovery_ca), "HOME": str(work),
                   "LANEWAY_PROFILE_DIR": str(rust_root), "NO_PROXY": "localhost,127.0.0.1"}
    go_env = env | {"LANEWAY_PROFILE_DIR": str(go_root)}
    rejected(command, "connect", "--remembered", "--ephemeral", env=env, reason="usage:")
    artifact_settings = "".join(f"""
[[bootstrap.artifacts]]
os = "linux"
arch = "{arch}"
url = "https://github.com/Doout/laneway/releases/download/v0.0.1/laneway_linux_{arch}.tar.gz"
sha256 = "{"a" * 64}"
size_bytes = 1
""" for arch in ("amd64", "arm64"))

    config = service_config(work, "controller", f"""
[controller]
listen = "{control}"
quic_listen = "{control}"
database = "{work / 'controller.db'}"
ca_private_key = "{work / 'ca.key'}"
admin_token_file = "{admin_token}"
leaf_validity = "{'55s' if with_connect else '24h'}"
[controller.initial_network]
network_id = "{NETWORK}"
name = "login-connect-fixture"
ipv4_pool = "100.117.0.0/24"
[bootstrap]
network_id = "{NETWORK}"
controller_endpoint = "https://{control}"
controller_quic_endpoint = "{control}"
controller_server_name = "localhost"
{artifact_settings}
""")
    relay_config = service_config(work, "relay", f"""
[relay]
listen = "{relay_addr}"
metrics_listen = "{LOOPBACK}:{metrics_port}"
[controller]
endpoint = "https://{control}"
quic_endpoint = "{control}"
server_name = "localhost"
network_id = "{NETWORK}"
service_id = "{CONTROLLER}"
poll_interval = "100ms"
[tcp_fallback]
listen = "{LOOPBACK}:{public_port}"
[public_https]
server_name = "localhost"
cache_dir = "{cache}"
""")

    def admin(*args):
        return json.loads(run(go_cli, "controller", *args, "--controller", f"https://{control}",
                              "--server-name", "localhost", "--ca", work / "ca.crt",
                              "--controller-network-id", NETWORK, "--controller-service-id", CONTROLLER,
                              "--admin-token-file", admin_token, "--network-id", NETWORK))

    def token(label, enrollment_class):
        result = admin("enrollment-token", "issue", "--label", label, "--class", enrollment_class,
                       "--requested-name", label, "--expires-in", "5m")
        file = work / f"{label}.token"
        file.write_text(result["enrollment_token"] + "\n")
        return file

    with contextlib.ExitStack() as scope:
        controller_process = scope.enter_context(process(work, "controller", controller, "-config", config))
        wait_for(lambda: reachable(control_port), "controller TLS", controller_process)
        admin("relay", "register", "--service-id", RELAY, "--name", "login-connect", "--endpoint", relay_addr)
        relay_process = scope.enter_context(process(work, "relay", relay, "--config", relay_config))
        wait_for(lambda: reachable(public_port), "relay discovery TLS", relay_process)
        context = ssl.create_default_context(cafile=str(discovery_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        discovery = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                               urllib.request.HTTPSHandler(context=context))
        def bootstrap_ready():
            with discovery.open(f"https://{authority}/.well-known/laneway/bootstrap.json", timeout=2) as response:
                expect(json.load(response)["network_id"], NETWORK, "live bootstrap network")
                return True

        wait_for(bootstrap_ready, "published bootstrap metadata", controller_process, relay_process)
        inspected = json.loads(run(command, "bootstrap", "inspect", authority, env=env))
        expect(inspected["metadata"]["controller"]["service_id"], CONTROLLER, "discovery service identity")
        expect(inspected["current_platform_artifact"]["os"], "linux", "discovered native artifact")

        native_token = token("native-login", "remembered")
        rejected(command, "login", authority, "--token-file", native_token,
                 env=env | {"SSL_CERT_FILE": str(work / "ca.crt")})
        assert not rust_root.exists() or not list(rust_root.glob("*/profile.json"))
        run(command, "login", authority, "--token-file", native_token, env=env)
        rust_profile = profile_manifest(rust_root, authority)
        expect(rust_profile["network_id"], NETWORK, "native login network")
        expect(rust_profile["controller_service_id"], CONTROLLER, "native login controller")
        rejected(go_cli, "login", authority, env=env, reason="already logged in")
        rejected(command, "login", authority, env=env, reason="already logged in")
        rejected(command, "login", authority, "--token-file", native_token,
                 env=env | {"LANEWAY_PROFILE_DIR": str(work / "reused-token")})

        legacy_token = token("legacy-login", "remembered")
        run(go_cli, "login", authority, "--token-file", legacy_token, env=go_env)
        go_profile = profile_manifest(go_root, authority)
        assert go_profile["node_id"] != rust_profile["node_id"]
        rejected(command, "login", authority, env=go_env, reason="already logged in")
        print("Native and Go login both read profiles written by the other CLI.", flush=True)
        if with_connect:
            run_connect(work, command, authority, go_env, go_root, go_profile, token, metrics_port,
                        helper_connect)


def run_connect(work, command, authority, env, profile_root, saved, token, metrics_port,
                helper_connect):
    before = network_state()
    with process(work, "saved-connect", command, "connect", env=env) as child:
        wait_for(lambda: metric(metrics_port, "relay_sessions") > 0, "saved login relay session", child)
        if helper_connect:
            wait_for(lambda: uses_network_helper(child.pid, command), "installed Rust network helper", child)
        wait_for(lambda: profile_manifest(profile_root, authority)["generation"] != saved["generation"],
                 "saved profile renewal", child, timeout=50)
        expect(profile_manifest(profile_root, authority)["node_id"], saved["node_id"], "renewed profile node ID")
        wait_for(lambda: metric(metrics_port, "relay_sessions") > 0, "renewed login relay session", child)
    wait_for(lambda: metric(metrics_port, "relay_sessions") == 0, "saved connect cleanup")
    ephemeral_root = work / "ephemeral"
    ephemeral_token = token("ephemeral-connect", "ephemeral")
    with process(work, "ephemeral-connect", command, "connect", authority, "--ephemeral",
                 "--token-file", ephemeral_token, env=env | {"LANEWAY_PROFILE_DIR": str(ephemeral_root)}) as child:
        wait_for(lambda: metric(metrics_port, "relay_sessions") > 0, "ephemeral relay session", child)
    wait_for(lambda: metric(metrics_port, "relay_sessions") == 0, "ephemeral connect cleanup")
    assert not ephemeral_root.exists() or not list(ephemeral_root.glob("*/profile.json"))
    expect(network_state(), before, "network state after connect shutdown")
    print("Saved login renewed in place and ephemeral connect left no saved profile.", flush=True)


def uses_network_helper(parent, launcher):
    """Follow sudo through exec and require the installed Rust helper."""
    found = False
    pending = [parent]
    while pending:
        pid = pending.pop()
        proc = Path("/proc") / str(pid)
        try:
            args = (proc / "cmdline").read_bytes().split(b"\x00")
            assert b"_connect-session" not in args, "Go dataplane was started"
            found = found or args[:2] == [os.fsencode(launcher), b"_network-helper-native"]
            for thread in (proc / "task").iterdir():
                pending.extend(map(int, (thread / "children").read_text().split()))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            # A subprocess can exit or detach while procfs is being read.
            continue
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--go-cli", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--relay", type=Path, required=True)
    connect = parser.add_mutually_exclusive_group()
    connect.add_argument("--native-connect", action="store_true",
                         help="also exercise connect in a disposable CAP_NET_ADMIN/TUN namespace")
    connect.add_argument("--helper-connect", action="store_true",
                         help="exercise ordinary-user Rust split tunneling through the installed sudo helper")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("fixture requires Linux")
    if args.native_connect and (os.geteuid() != 0 or not Path("/dev/net/tun").exists()):
        parser.error("--native-connect requires root and /dev/net/tun in a disposable network namespace")
    if args.helper_connect and (os.geteuid() == 0 or not Path("/dev/net/tun").exists()):
        parser.error("--helper-connect requires an ordinary user, /dev/net/tun and a preauthorized installed helper in a disposable network namespace")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="login-connect-") as directory:
        exercise(Path(directory), args.launcher.resolve(), args.go_cli.resolve(), args.controller.resolve(),
                 args.relay.resolve(), args.native_connect or args.helper_connect, args.helper_connect)


if __name__ == "__main__":
    main()
