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
RUST_SERVICES = {
    "controller": "LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST",
    "relay": "LANEWAY_RUST_RELAY_IMAGE_DIGEST",
    "exit-node": "LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST",
}
INSTALL_SETTINGS = RELEASE_SETTINGS | {
    "LANEWAY_ADMIN_IMAGE_DIGEST", "LANEWAY_RUST_CONNECTOR_IMAGE_DIGEST",
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


def read_release_settings(text, required=RELEASE_SETTINGS):
    result = {}
    for line in text.splitlines():
        raw_key, _, value = line.partition("=")
        key = re.sub(r"^export[ \t]+", "", raw_key.strip()).strip()
        if key in required:
            require(raw_key == key, f"expected canonical {key}=VALUE in .env")
            require(key not in result, f"duplicate {key}")
            result[key] = value
    require(result.keys() == required, "missing verified Rust release settings")
    return result


def candidate_release(base, metadata):
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
    return pinned, bootstrap_artifacts(fields[4], tag)


def bootstrap_artifacts(text, tag):
    contents = tomllib.loads(text)
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


def stage_update(base, stage, tag, volume):
    require(re.fullmatch(r"laneway-rust-update-[0-9a-f]{20}", volume), "invalid candidate volume name")
    verified = command_output([
        "/bin/sh", str(base / "verify-rust-release.sh"), "--install", tag, str(stage / "metadata"),
    ])
    updates = read_release_settings(verified, INSTALL_SETTINGS)
    require(updates["LANEWAY_RUST_VERSION"] == tag[1:], "unexpected verified release version")
    updates.update(LANEWAY_VERSION=tag[1:], LANEWAY_RUST_CONTROLLER_STATE_VOLUME=volume)
    source_env = read_config(base / ".env")
    updated = []
    seen = set()
    for line in source_env.splitlines():
        key = re.sub(r"^export[ \t]+", "", line.partition("=")[0].strip()).strip()
        require(key not in seen, f"duplicate {key} in .env")
        if key in updates:
            require(line.startswith(f"{key}="), f"expected canonical {key}=VALUE in .env")
            updated.append(f"{key}={updates.pop(key)}")
            seen.add(key)
        else:
            updated.append(line)
    require(not (updates.keys() - {"LANEWAY_RUST_CONTROLLER_STATE_VOLUME"}),
            "update requires a standard fresh Rust install with pinned image settings")
    updated.extend(f"{key}={value}" for key, value in updates.items())
    profile = json.loads(read_config(base / "generated/config/bootstrap.rust.json"))
    profile["artifacts"] = bootstrap_artifacts(read_config(stage / "metadata/bootstrap-artifacts.toml"), tag)
    (stage / "candidate.env").write_text("\n".join(updated) + "\n", encoding="utf-8")
    (stage / "candidate.json").write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")


def command_output(argv):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, text=True).stdout


def active_images(base, pinned):
    compose = [
        "docker", "compose", "--project-directory", str(base), "--env-file", str(base / ".env"),
        "-f", str(base / "compose.yaml"), "-f", str(base / "compose.rust.yaml"), "--profile", "exit-node",
    ]
    plan = json.loads(command_output(compose + ["config", "--format", "json"]))["services"]
    version = pinned["LANEWAY_RUST_VERSION"]
    for role, key in RUST_SERVICES.items():
        expected = f"ghcr.io/doout/laneway-{role}-rust:{version}@{pinned[key]}"
        require(plan[role]["image"] == expected, f"{role}: Compose does not select the signed release image")
        active = command_output(compose + ["ps", "--status", "running", "-q", role]).strip()
        if not active and role == "exit-node":
            print("exit-node: optional service not running", file=sys.stderr)
            continue
        require(re.fullmatch("[0-9a-f]{12,64}", active), f"{role}: expected one running container")
        observed = json.loads(command_output(["docker", "inspect", "--type", "container", active]))
        require(isinstance(observed, list) and len(observed) == 1,
                f"{role}: could not identify the running container")
        container = observed[0]
        require(container["Config"]["Image"] == expected,
                f"{role}: running container does not use the signed release image")
        local_id = command_output(["docker", "image", "inspect", "--format", "{{.Id}}", expected]).strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", local_id) and local_id == container["Image"],
                f"{role}: running image content differs from the verified reference")
        state = container["State"]
        require(state["Running"] is True and state.get("Health", {}).get("Status") == "healthy",
                f"{role}: release container is not healthy")
        print(f"{role}: signed release image is healthy", file=sys.stderr)


def check_public_discovery(base, artifacts):
    wanted = {"LANEWAY_CONTROLLER_SERVER_NAME", "LANEWAY_RELAY_TCP_PORT", "LANEWAY_NETWORK_ID",
              "LANEWAY_CONTROLLER_SERVICE_ID"}
    settings = {}
    for line in read_config(base / ".env").splitlines():
        key, _, value = line.partition("=")
        if key in wanted:
            require(key not in settings, f"duplicate {key}")
            settings[key] = value
    require(settings.keys() == wanted, "missing public discovery settings in .env")
    name = settings["LANEWAY_CONTROLLER_SERVER_NAME"]
    port = settings["LANEWAY_RELAY_TCP_PORT"]
    require(len(name) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                     for label in name.split(".")), "invalid public controller DNS name")
    require(re.fullmatch("[0-9]{1,5}", port) and 0 < int(port) <= 65535, "invalid public HTTPS port")
    authority = name if port == "443" else f"{name}:{port}"
    metadata = json.loads(command_output([
        "curl", "--disable", "--noproxy", "*", "--proto", "=https", "--fail", "--silent", "--show-error",
        "--connect-timeout", "5", "--max-time", "15", "--max-filesize", "1048576",
        f"https://{authority}/.well-known/laneway/bootstrap.json",
    ]))
    require(metadata["network_id"] == settings["LANEWAY_NETWORK_ID"]
            and metadata["controller"]["server_name"] == name
            and metadata["controller"]["service_id"] == settings["LANEWAY_CONTROLLER_SERVICE_ID"],
            "public discovery belongs to a different controller or network")
    require(metadata.get("artifacts") == artifacts, "public discovery is not serving the signed release artifacts")
    print("public HTTPS discovery: signed release artifacts and controller identity match", file=sys.stderr)


def check_readiness(base, metadata):
    pinned, artifacts = candidate_release(base, metadata)
    profile = json.loads(read_config(base / "generated/config/bootstrap.rust.json"))
    require(profile.get("artifacts") == artifacts, "staged Rust profile differs from the signed release")
    active_images(base, pinned)
    check_public_discovery(base, artifacts)


def prepare(base, metadata):
    generated = base / "generated"
    config = generated / "config"
    for directory in (generated, config):
        meta = directory.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                "expected protected, real generated directories")
    profile, relay = convert(read_config(config / "controller.toml"), read_config(config / "relay.toml"))
    if metadata is not None:
        _, profile["artifacts"] = candidate_release(base, metadata)
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
        selection.add_argument("--readiness", type=Path, metavar="DIRECTORY",
                               help="verify the active Rust release without starting or changing services")
        selection.add_argument("--stage-update", nargs=3, metavar=("DIRECTORY", "TAG", "VOLUME"))
        args = parser.parse_args()
        require(os.geteuid() == 0, "run as root")
        base = Path(__file__).resolve().parent
        if args.readiness is not None:
            check_readiness(base, args.readiness)
        elif args.stage_update is not None:
            stage, tag, volume = args.stage_update
            stage_update(base, Path(stage), tag, volume)
        else:
            prepare(base, args.release_metadata)
            print("Staged Rust Compose inputs; the running stack and Go configuration are unchanged.")
    except subprocess.CalledProcessError:
        sys.exit("Rust Compose: an external verification command failed")
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(f"Rust Compose: {error}")
