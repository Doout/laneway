#!/usr/bin/env python3
"""Stage an opt-in Rust overlay from the standard, already prepared Compose stack."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib

CONVENTIONAL_TLS = {
    "certificate": "/run/laneway-secrets/controller.crt",
    "private_key": "/run/laneway-secrets/controller.key",
    "ca": "/run/laneway-secrets/ca.crt",
}
CONVENTIONAL_CONTROLLER = {
    "listen": ":8443",
    "quic_listen": ":8443",
    "database": "/var/lib/laneway-controller/controller.db",
    "ca_private_key": "/run/laneway-secrets/intermediate.key",
    "issuer_certificate": "/run/laneway-secrets/intermediate-chain.crt",
    "admin_token_file": "/run/laneway-secrets/admin.token",
    "leaf_validity": "720h",
}
RELAY_ENDPOINT = "https://controller:8443"
RENEWAL_PATH = "/var/lib/laneway-renewal"
RELEASE_SETTINGS = {
    "LANEWAY_RUST_VERSION",
    "LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST",
    "LANEWAY_RUST_RELAY_IMAGE_DIGEST",
    "LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_config(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), encoding="utf-8") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= 1 << 20 and
                meta.st_uid == 0 and not meta.st_mode & 0o022,
                f"{path.name} must be a protected, bounded regular file")
        return stream.read((1 << 20) + 1)


def convert(controller_text, relay_text):
    controller = tomllib.loads(controller_text)
    bootstrap = controller.pop("bootstrap", None)
    settings = controller.get("controller", {})
    require(isinstance(settings, dict), "expected a controller settings table")
    initial = settings.pop("initial_network", None)
    expected = {
        "mode": "controller",
        "state_dir": "/var/lib/laneway-controller",
        "socket_path": "/tmp/controller.sock",
        "tls": CONVENTIONAL_TLS,
        "controller": CONVENTIONAL_CONTROLLER,
    }
    require(controller == expected, "custom controller configuration requires a reviewed Rust cutover")
    require(isinstance(bootstrap, dict) and set(bootstrap) == {
        "network_id", "controller_endpoint", "controller_quic_endpoint", "controller_server_name", "artifacts",
    }, "expected the standard Compose bootstrap configuration")
    require(initial is None or (isinstance(initial, dict)
            and set(initial) <= {"network_id", "name", "ipv4_pool", "ipv6_pool"}
            and initial.get("network_id") == bootstrap["network_id"]),
            "the Go initial network does not match bootstrap")
    name = bootstrap["controller_server_name"]
    require(isinstance(name, str) and len(name) <= 253 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in name.split(".")
    ), "expected the canonical controller certificate DNS name")
    require(isinstance(bootstrap["artifacts"], list) and bootstrap["artifacts"],
            "bootstrap has no release artifacts; verify and prepare the signed release first")
    profile = {
        "enrollment_endpoint": bootstrap["controller_endpoint"],
        "quic_endpoint": bootstrap["controller_quic_endpoint"],
        "server_name": name,
        "artifacts": bootstrap["artifacts"],
    }

    relay = tomllib.loads(relay_text)
    upstream = relay.get("controller", {})
    tls = relay.get("tls", {})
    require(relay.get("mode") == "relay" and upstream.get("endpoint") == RELAY_ENDPOINT
            and upstream.get("quic_endpoint") == "controller:8443"
            and upstream.get("server_name") == name
            and upstream.get("network_id") == bootstrap["network_id"]
            and relay.get("public_https", {}).get("server_name") == name
            and "renewal_dir" not in tls,
            "relay must use the matching standard controller and public HTTPS settings")
    # Preserve all other relay fields, including ACME and packet rate settings.
    endpoint = f"https://{name}:8443"
    converted, count = re.subn(r'(?m)^endpoint = "https://controller:8443"$',
                               f'endpoint = "{endpoint}"', relay_text)
    require(count == 1, "cannot identify the standard relay endpoint assignment")
    converted, count = re.subn(r"(?m)^\[tls\]$", f'[tls]\nrenewal_dir = "{RENEWAL_PATH}"', converted)
    require(count == 1, "cannot identify the relay TLS table")
    upstream["endpoint"] = endpoint
    tls["renewal_dir"] = RENEWAL_PATH
    require(tomllib.loads(converted) == relay, "relay conversion changed extra configuration")
    return profile, converted


def read_release_settings(text):
    result = {}
    for line in text.splitlines():
        raw_key, _, value = line.partition("=")
        key = re.sub(r"^export[ \t]+", "", raw_key.strip()).strip()
        if key in RELEASE_SETTINGS:
            require(raw_key == key, f"expected canonical {key}=VALUE in .env")
            require(key not in result, f"duplicate {key}")
            result[key] = value
    require(result.keys() == RELEASE_SETTINGS, "expected all four verified Rust release settings in .env")
    return result


def candidate_artifacts(base, metadata):
    pinned = read_release_settings(read_config(base / ".env"))
    tag = f'v{pinned["LANEWAY_RUST_VERSION"]}'
    envelope = subprocess.run(
        ["/bin/sh", "-s", "--", "--prepare", tag, str(metadata)],
        input=read_config(base / "verify-rust-release.sh"),
        check=True, stdout=subprocess.PIPE, text=True,
    ).stdout
    fields = envelope.split("\n", 4)
    require(len(fields) == 5, "verified release did not supply bootstrap artifacts")
    require(read_release_settings("\n".join(fields[:4])) == pinned,
            "Rust image settings do not match the signed release; update the staged .env")
    contents = tomllib.loads(fields[4])
    bootstrap = contents.get("bootstrap")
    require(set(contents) == {"bootstrap"} and isinstance(bootstrap, dict)
            and set(bootstrap) == {"artifacts"}, "expected a signed bootstrap artifacts manifest")
    artifacts = bootstrap["artifacts"]
    expected_platforms = {(os_name, arch) for os_name in ("linux", "darwin") for arch in ("amd64", "arm64")}
    require(isinstance(artifacts, list) and len(artifacts) == len(expected_platforms),
            "expected exactly four signed bootstrap artifacts")
    for entry in artifacts:
        require(isinstance(entry, dict) and set(entry) == {"os", "arch", "url", "sha256", "size_bytes"}
                and isinstance(entry["os"], str) and isinstance(entry["arch"], str),
                "invalid bootstrap artifact")
        platform = (entry["os"], entry["arch"])
        require(platform in expected_platforms, "unexpected or duplicate bootstrap platform")
        expected_platforms.remove(platform)
        asset = f'laneway_{entry["os"]}_{entry["arch"]}.tar.gz'
        require(entry["url"] == f"https://github.com/Doout/laneway/releases/download/{tag}/{asset}"
                and isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                and entry["sha256"] != "0" * 64
                and type(entry["size_bytes"]) is int and entry["size_bytes"] > 0,
                f"invalid signed artifact for {asset}")
    return artifacts


def prepare(base, metadata):
    generated = base / "generated"
    config = generated / "config"
    for directory in (generated, config):
        meta = directory.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                "expected protected, real generated directories")
    profile, relay = convert(read_config(config / "controller.toml"), read_config(config / "relay.toml"))
    if metadata is not None:
        profile["artifacts"] = candidate_artifacts(base, metadata)
    workload = generated / "rust-relay-workload"
    outputs = {
        config / "bootstrap.rust.json": json.dumps(profile, indent=2) + "\n",
        config / "relay.rust.toml": relay,
    }
    require(not any(os.path.lexists(p) for p in outputs),
            "Rust overlay material already exists; refusing to replace it")
    created = []
    new_workload = not os.path.lexists(workload)
    if not new_workload:
        meta = workload.lstat()
        require(stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o700
                and (meta.st_uid, meta.st_gid) == (65532, 65532),
                "relay workload directory must be owned by UID/GID 65532 and mode 0700")
    created_workload = False
    try:
        with tempfile.TemporaryDirectory(prefix=".prepare-rust.", dir=generated) as staging:
            for path, contents in outputs.items():
                source = Path(staging) / path.name
                source.write_text(contents, encoding="utf-8")
                source.chmod(0o444)
                os.link(source, path)
                created.append(path)
            if new_workload:
                workload.mkdir(mode=0o700)
                created_workload = True
                os.chmod(workload, 0o700)
                os.chown(workload, 65532, 65532)
    except OSError:
        for path in created:
            path.unlink()
        if created_workload:
            workload.rmdir()
        raise


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        selection = parser.add_mutually_exclusive_group(required=True)
        selection.add_argument("--release-metadata", type=Path, metavar="DIRECTORY",
                               help="read signed artifact metadata for the verified release in .env")
        selection.add_argument("--lab", action="store_true",
                               help="reuse the Go bootstrap artifacts on an isolated, unsigned lab only")
        args = parser.parse_args()
        require(os.geteuid() == 0, "run as root")
        prepare(Path(__file__).resolve().parent, args.release_metadata)
    except subprocess.CalledProcessError:
        sys.exit("prepare Rust Compose: release verification failed")
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"prepare Rust Compose: {error}")
    print("Staged Rust Compose inputs; the running stack and Go configuration are unchanged.")
