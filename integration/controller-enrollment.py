#!/usr/bin/env python3
"""Exercise candidate enrollment using a disposable Go backup and both clients."""

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time


NETWORK = "21000000000000000000000000000001"
SERVICE = "21000000000000000000000000000002"
NAME = "pinned.controller.test"


def run(binary, *args, status=0):
    completed = subprocess.run((binary, *args), capture_output=True, text=True, timeout=30)
    if completed.returncode != status:
        raise AssertionError(f"{args[:2]} returned {completed.returncode}: {completed.stderr}")
    return completed.stdout, completed.stderr


@contextlib.contextmanager
def listening(work, port, binary, *args):
    with (work / "service.log").open("w") as out:
        proc = subprocess.Popen((binary, *args), stdout=out, stderr=out)
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError((work / "service.log").read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.25):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError("controller did not listen")
            yield
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=15)


def exercise(work, reference, candidate, go_cli, rust_cli):
    # Keep the Rust CLI isolated from its Go companion to catch accidental delegation.
    native_directory = work / "native"
    native_directory.mkdir()
    rust = native_directory / "laneway"
    shutil.copy2(rust_cli, rust)
    with socket.socket() as reserver:
        reserver.bind(("127.0.0.1", 0))
        port = reserver.getsockname()[1]
    address = f"127.0.0.1:{port}"
    endpoint = f"https://{address}"
    run(go_cli, "pki", "init", "--out-dir", work)
    ca, ca_key = work / "ca.crt", work / "ca.key"
    intermediate, intermediate_key = work / "issuer.crt", work / "issuer.key"
    run(go_cli, "pki", "intermediate", "--ca-cert", ca, "--ca-key", ca_key,
        "--out-cert", intermediate, "--out-key", intermediate_key, "--validity", "1200h")
    server, server_key = work / "server.crt", work / "server.key"
    run(go_cli, "pki", "controller", "--ca-cert", intermediate, "--ca-key", intermediate_key,
        "--network-id", NETWORK, "--service-id", SERVICE, "--dns", NAME,
        "--out-cert", server, "--out-key", server_key, "--validity", "720h")
    root_token = work / "admin.token"
    root_token.write_text(secrets.token_hex(32) + "\n")
    root_token.chmod(0o600)
    go_db, rust_db = work / "go.db", work / "rust.db"
    go_config, rust_config = work / "go-controller.toml", work / "rust-controller.toml"
    for conf, database in ((go_config, go_db), (rust_config, rust_db)):
        conf.write_text(f'''
mode = "controller"
state_dir = "{work / 'controller-state'}"
socket_path = "{work / 'controller.sock'}"
[tls]
certificate = "{server}"
private_key = "{server_key}"
ca = "{ca}"
[controller]
listen = "{address}"
quic_listen = "{address}"
database = "{database}"
issuer_certificate = "{intermediate}"
ca_private_key = "{intermediate_key}"
admin_token_file = "{root_token}"
''')
    common = (
        "--controller", endpoint, "--ca", ca, "--controller-network-id", NETWORK,
        "--controller-service-id", SERVICE, "--server-name", NAME,
    )
    admin = (*common, "--admin-token-file", root_token, "--network-id", NETWORK)
    tokens = {}
    expected_hashes = {}

    def issue(binary, name, *options, admin_flags=admin, status=0):
        text, error = run(
            binary, "controller", "enrollment-token", "issue",
            "--requested-name", name, "--label", name,
            "--expires-in", "10m", *admin_flags, *options, status=status,
        )
        if status != 0:
            return error
        issued = json.loads(text)
        assert issued["enrollment_class"] == "durable", issued["enrollment_class"]
        secret = issued["enrollment_token"]
        decoded = base64.urlsafe_b64decode(secret + "=")
        expected_hashes[name] = hashlib.sha256(decoded).digest()
        invite_path = work / f"{name}.invite"
        invite_path.write_text(secret + "\n")
        invite_path.chmod(0o600)
        tokens[name] = invite_path

    with listening(work, port, reference, "-config", go_config):
        run(go_cli, "controller", "network", "create", "--name", "interop",
            "--ipv4-pool", "100.115.0.0/28", "--ipv6-pool", "fd00:115::/120", *admin)
        for name in ("go-client", "rust-client"):
            issue(go_cli, name)
        backup = work / "from-go.db"
        run(reference, "-config", go_config, "-backup", backup)
    run(candidate, "-config", rust_config, "-restore", backup)

    def join(binary, name, suffix, code=0):
        return run(binary, "join", "--token-file", tokens[name], "--name", name, *common,
                   "--out-cert", work / f"{name}-{suffix}.crt", "--out-key", work / f"{name}-{suffix}.key",
                   "--out-wireguard-key", work / f"{name}-{suffix}.wg", status=code)

    with listening(work, port, candidate, "-config", rust_config, "-serve-readonly"):
        _, missing = join(go_cli, "go-client", "readonly", code=1)
        assert "404" in missing, missing
        missing = issue(go_cli, "readonly-issue", status=1)
        assert "route not found" in missing, missing
    native_node = None
    with listening(work, port, candidate, "-config", rust_config, "-serve-enrollment-candidate"):
        wrong_token = work / "wrong.token"
        wrong_token.write_text(secrets.token_hex(32) + "\n")
        wrong = (*common, "--admin-token-file", wrong_token, "--network-id", NETWORK)
        denied = issue(go_cli, "wrong-root", admin_flags=wrong, status=1)
        assert "authentication failed" in denied, denied
        invalid_lifetime = issue(go_cli, "too-long", "--expires-in", "721h", status=1)
        assert "invalid request" in invalid_lifetime, invalid_lifetime

        # Even a valid root secret cannot authorize this mutation from a browser context.
        context = ssl.create_default_context(cafile=ca)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            with context.wrap_socket(conn, server_hostname=NAME) as tls:
                authorization = root_token.read_text().strip()
                message = (
                    "POST /v1/admin/enrollment-tokens HTTP/1.1\r\n"
                    f"Host: {NAME}\r\n"
                    f"Authorization: Bearer {authorization}\r\n"
                    "Origin: https://pinned.controller.test\r\n"
                    "Content-Type: application/json\r\nContent-Length: 2\r\n"
                    "Connection: close\r\n\r\n{}"
                )
                tls.sendall(message.encode())
                with tls.makefile("rb") as reply:
                    assert b" 401 " in reply.readline()

        issue(go_cli, "candidate-go")
        issue(rust, "candidate-rust")
        for binary, name in (
            (go_cli, "go-client"), (rust, "rust-client"),
            (go_cli, "candidate-go"), (rust, "candidate-rust"),
        ):
            text, _ = join(binary, name, "accepted")
            assert f"enrolled network={NETWORK}" in text
            if name == "candidate-rust":
                native_node = text.split("node=", 1)[1].split()[0]
            assert len((work / f"{name}-accepted.wg").read_bytes()) == 32
            assert (work / f"{name}-accepted.crt").read_bytes().count(b"BEGIN CERTIFICATE") == 2
            verified = subprocess.run(("openssl", "verify", "-CAfile", ca, "-untrusted", intermediate,
                                       work / f"{name}-accepted.crt"), capture_output=True, text=True)
            assert verified.returncode == 0, verified.stderr
            _, replay = join(binary, name, "replayed", code=1)
            expected = "already been used" if binary == go_cli else "HTTP 409 Conflict"
            assert expected in replay, replay
            assert not list(work.glob(f"{name}-replayed.*"))
    # Exercise both authenticated renewal transports and both client implementations.
    assert native_node is not None
    active = tuple(work / f"candidate-rust-accepted.{ext}" for ext in ("crt", "key", "wg"))
    with listening(work, port, candidate, "-config", rust_config, "-serve-controller-candidate"):
        for binary, name, transport in (
            (rust, "renewed-rust-quic", ("--controller-quic", address)),
            (rust, "renewed-rust-https", ("--allow-legacy-controller-https",)),
            (go_cli, "renewed-go-quic", ("--controller-quic", address)),
        ):
            cert, key, wireguard = active
            updated = tuple(work / f"{name}.{ext}" for ext in ("crt", "key", "wg"))
            text, _ = run(
                binary, "renew", *common, *transport, "--cert", cert, "--key", key,
                "--out-cert", updated[0], "--out-key", updated[1], "--out-wireguard-key", updated[2],
            )
            assert f"node={native_node}" in text
            assert updated[1].read_bytes() != key.read_bytes()
            assert len(updated[2].read_bytes()) == 32 and updated[2].read_bytes() != wireguard.read_bytes()
            run("openssl", "verify", "-CAfile", ca, "-untrusted", intermediate, updated[0])
            active = updated

    with contextlib.closing(sqlite3.connect(rust_db)) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        nodes = db.execute("SELECT name,enrollment_class,length(wireguard_public_key) FROM nodes ORDER BY name").fetchall()
        assert nodes == [(name, "durable", 32) for name in sorted(tokens)], nodes
        hashes = dict(db.execute(
            "SELECT requested_name,token_hash FROM enrollment_tokens WHERE consumed_at IS NOT NULL"
        ).fetchall())
        assert hashes == expected_hashes
        assert db.execute("SELECT count(*) FROM enrollment_tokens").fetchone() == (4,)
        assert db.execute(
            "SELECT count(*) FROM overlay_addresses WHERE released_at IS NULL"
        ).fetchone() == (8,)
        audits = db.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE action IN ('node.enroll','certificate.issue') AND actor_kind='node'"
        ).fetchone()
        assert audits == (11,)
        rotations = db.execute(
            "SELECT count(*) FROM audit_events WHERE action='node.wireguard_key.rotate' "
            "AND actor_kind='node'"
        ).fetchone()
        assert rotations == (3,)
        token_audits = db.execute(
            "SELECT count(*) FROM audit_events WHERE action='enrollment_token.issue' "
            "AND actor_kind='service_principal'"
        ).fetchone()
        assert token_audits == (4,)
    with listening(work, port, reference, "-config", rust_config):
        observed = json.loads(run(go_cli, "controller", "node", "list", *admin)[0])
        assert all(name in json.dumps(observed) for name in tokens), observed
        cert, key, _ = active
        text, _ = run(
            go_cli, "renew", *common, "--controller-quic", address,
            "--cert", cert, "--key", key, "--out-cert", work / "go-reopened.crt",
            "--out-key", work / "go-reopened.key", "--out-wireguard-key", work / "go-reopened.wg",
        )
        assert f"node={native_node}" in text
    print("Go backup restored. Both clients issued and consumed tokens, replay was rejected, "
          "both clients renewed against Rust, and Go renewed after reopening the database.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-controller", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--go-cli", required=True, type=Path)
    parser.add_argument("--rust-cli", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="controller-enrollment-") as directory:
        exercise(Path(directory), args.go_controller.resolve(), args.candidate.resolve(),
                 args.go_cli.resolve(), args.rust_cli.resolve())


if __name__ == "__main__":
    main()
