#!/usr/bin/env python3
"""Exercise the installed launcher, native helper dispatch, and Go reference offline."""

import argparse
import hashlib
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile


def run(binary, *args, env, stdin=b"", status=0):
    result = subprocess.run(
        [binary, *args], input=stdin, env=env, capture_output=True, timeout=15, check=False,
    )
    if (status is None and result.returncode == 0) or (
        status is not None and result.returncode != status
    ):
        raise AssertionError(
            f"{binary} {args}: exit {result.returncode}\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
    return result


def script(path, body):
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)


def require_output(result, expected):
    if result.stdout != expected:
        raise AssertionError(f"expected stdout {expected!r}, received {result.stdout!r}")


def check_help(binary, env):
    cases = [
        ((), (b"configure", b"start", b"credential", b"update", b"login")),
        (("--help",), (b"configure", b"start", b"credential", b"update", b"login")),
        (("help", "configure"), (b"configure", b"server")),
        (("help", "start"), (b"start", b"--system")),
        (("credential", "-h"), (b"credential", b"add")),
        (("update", "client", "--help"), (b"update", b"client")),
        (("configure", "server", "-h"), (b"configure", b"server")),
        (("help", "update", "server"), (b"update", b"server")),
        (("update", "connector", "--help"), (b"update", b"connector")),
    ]
    if sys.platform == "linux":
        cases.append((("control", "administrator", "root-token", "rotate", "--help"), (b"rotate",)))
    for args, commands in cases:
        result = run(binary, *args, env=env)
        for command in commands:
            if command not in result.stdout:
                raise AssertionError(f"{binary.name} {args} help omitted {command!r}")


def check_version(binary, env, version):
    for arg, output in [
        ("version", version),
        ("-version", version),
        ("--version", b"laneway version " + version),
    ]:
        require_output(run(binary, arg, env=env), output + b"\n")


def check_native_helper(launcher, work, env):
    # The native helper never runs a companion to answer its own help.
    shadow = work / "path"
    shadow.mkdir()
    decoy = shadow / "laneway-compat"
    script(decoy, "exit 77\n")
    env = env | {
        "PATH": str(shadow),
        "LANEWAY_COMPAT_BIN": str(decoy),
        "LANEWAY_COMPAT_COMMAND": str(decoy),
    }
    for companion in (None, launcher.with_name("laneway-compat")):
        if companion:
            shutil.copy2(decoy, companion)
        result = run(launcher, "_network-helper", "--help", env=env)
        assert b"Usage of _network-helper:" in result.stderr, result.stderr
        assert not result.stdout, result.stdout
    unknown = run(launcher, "invalid-command-fixture", env=env, status=None)
    assert unknown.returncode != 77 and b"invalid-command-fixture" in unknown.stderr, unknown
    companion = launcher.with_name("laneway-compat")
    companion.unlink()


def check_legacy_node_dispatch(launcher, work, env):
    # An unrecognized configuration is still owned by the sealed Go runtime.
    companion = launcher.with_name("laneway-compat")
    shadow = work / "path" / companion.name
    env = env | {
        "PATH": str(shadow.parent),
        "LANEWAY_COMPAT_BIN": str(shadow),
        "LANEWAY_PROFILE_DIR": str(work / "selected profile"),
    }
    argv = (b"node", b"run", b"-config", b"missing config \xff.toml")
    args = tuple(map(os.fsdecode, argv))
    missing = run(launcher, *args, env=env, status=1)
    assert b"laneway-compat" in missing.stderr, missing.stderr
    script(companion, (
        'printf "%s\\000" "$@" "$HOME" "$LANEWAY_PROFILE_DIR"\n'
        '/bin/cat\n'
        'printf "fixture stderr\\n" >&2\n'
        'exit 23\n'
    ))
    result = run(launcher, *args, env=env, stdin=b"fixture stdin\n", status=23)
    forwarded = tuple(os.fsencode(env[key]) for key in ("HOME", "LANEWAY_PROFILE_DIR"))
    require_output(result, b"\0".join((*argv, *forwarded, b"fixture stdin\n")))
    assert result.stderr == b"fixture stderr\n", result.stderr
    if os.geteuid() == 0:
        companion.chmod(0o775)
        run(launcher, *args, env=env, status=1)
        companion.chmod(0o755)
        os.chown(companion, 65534, 65534)
        run(launcher, *args, env=env, status=1)
        os.chown(companion, 0, 0)
        launcher.parent.chmod(0o775)
        try:
            run(launcher, *args, env=env, status=1)
        finally:
            launcher.parent.chmod(0o700)
    companion.unlink()
    companion.symlink_to(shadow)
    run(launcher, *args, env=env, status=1)
    companion.unlink()
    os.link(launcher, companion)
    run(launcher, *args, env=env, status=1)
    companion.unlink()


def check_linux_helper_bridge(companion, launcher, old_cli, work, env, version):
    require_output(run(companion, "_network-helper-bridge-version", env=env), version + b"\n")
    require_output(run(launcher, "_network-helper-native", "--version", env=env), version + b"\n")
    if os.geteuid() != 0:
        return
    directory = work / "bridge"
    directory.mkdir(mode=0o755)
    bridge = directory / "laneway-compat"
    frontend = directory / "laneway"
    shutil.copy2(companion, bridge)
    operations = ("_network-helper", "--control-fd=0")
    # A root-owned old frontend must fail before any privileged fallback.
    shutil.copy2(old_cli, frontend)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"reinstall the signed Laneway package" in failed.stderr, failed.stderr
    frontend.unlink()
    # Protected owners and file types are checked before the version probe.
    frontend.symlink_to(launcher)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"missing or unsafe native Laneway helper" in failed.stderr, failed.stderr
    frontend.unlink()
    os.link(bridge, frontend)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"missing or unsafe native Laneway helper" in failed.stderr, failed.stderr
    frontend.unlink()
    shutil.copy2(launcher, frontend)
    frontend.chmod(0o775)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"root-owned regular file" in failed.stderr, failed.stderr
    frontend.chmod(0o755)
    os.chown(frontend, 65534, 65534)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"root-owned regular file" in failed.stderr, failed.stderr
    os.chown(frontend, 0, 0)
    directory.chmod(0o775)
    failed = run(bridge, *operations, env=env, status=1)
    assert b"root-owned directory" in failed.stderr, failed.stderr
    directory.chmod(0o755)
    # stdin is an empty pipe, so the matched native helper can only validate
    # and refuse it. Match the direct frontend's error without touching TUN.
    direct = run(frontend, *operations, env=env, status=1)
    installed = run(bridge, *operations, env=env, status=1)
    assert b"socket" in direct.stderr and direct.stderr == installed.stderr, installed.stderr


def check_node(launcher, env):
    # Exercise the launcher without an installed Go companion. The owned
    # daemon receives the original stdin and the translated public arguments.
    daemon = launcher.with_name("lanewayd")
    script(daemon, 'printf "%s\\000" "$@"\n/bin/cat\n')
    state = Path(env["HOME"]) / "isolated state"
    for args, translated, stdin in [
        (("configure", "--state-dir", str(state)), ("--state-dir", str(state), "configure"),
         b"fixture invitation\n"),
        (("start", "--state-dir", str(state), "--listen", "127.0.0.1:18080", "--proxy-only"),
         ("--state-dir", str(state), "run", "--listen", "127.0.0.1:18080", "--proxy-only"), b""),
        (("start", "--no-proxy"), ("run", "--no-proxy"), b""),
        (("credential", "add", "test-client", "--password-stdin"),
         ("credential", "add", "test-client", "--password-stdin"), b"fixture password\n"),
    ]:
        result = run(launcher, *args, env=env, stdin=stdin)
        require_output(result, b"\0".join((*map(os.fsencode, translated), stdin)))
    for args, diagnostic in [
        (("start", "--config", "node.toml"), b"--config requires --system"),
        (("configure", "--system", "--state-dir", str(state)), b"only used in userspace mode"),
        (("start", "--system", "--no-proxy"), b"only used in userspace mode"),
        (("start", "--no-proxy", "--proxy-only"), b"--no-proxy cannot be used"),
    ]:
        result = run(launcher, *args, env=env, status=None)
        assert diagnostic in result.stderr, result.stderr
    daemon.unlink()


def check_logout(launcher, old_cli, work, env):
    # Seed the same profile layout consumed by the original Go command.
    def profile_name(domain):
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:32]

    output = []
    for index, binary in enumerate((launcher, old_cli)):
        root = work / f"saved-profiles-{index}"
        root.mkdir(mode=0o700)
        selected = root / profile_name("example.invalid")
        selected.mkdir(mode=0o700)
        selected_manifest = selected / "profile.json"
        selected_manifest.write_text("fixture")
        selected_manifest.chmod(0o600)
        other = root / profile_name("other.invalid")
        other.mkdir(mode=0o700)
        other_manifest = other / "profile.json"
        other_manifest.write_text("leave this profile")
        other_manifest.chmod(0o600)
        link = root / profile_name("link.invalid")
        link.symlink_to(other)
        profile_env = env | {"LANEWAY_PROFILE_DIR": str(root)}
        rejected = run(binary, "logout", "link.invalid", env=profile_env, status=None)
        assert b"not a safe directory" in rejected.stderr, rejected.stderr
        removed = run(binary, "logout", "--", "EXAMPLE.INVALID", env=profile_env)
        output.append(removed.stdout)
        assert not selected.exists() and link.is_symlink()
        assert (other / "profile.json").read_text() == "leave this profile"
    assert output[0] == output[1], output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("launcher", type=Path)
    parser.add_argument("companion", type=Path)
    parser.add_argument("go_reference", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    # Root dispatch requires trusted ancestors even for the test fixture.
    parent = Path(pwd.getpwuid(0).pw_dir).resolve() if os.geteuid() == 0 else None
    with tempfile.TemporaryDirectory(prefix="laneway-cli-", dir=parent) as directory:
        work = Path(directory)
        launcher = work / "laneway"
        old_cli = work / "go" / "laneway"
        old_cli.parent.mkdir(mode=0o700)
        shutil.copy2(args.launcher, launcher)
        shutil.copy2(args.go_reference, old_cli)
        env = {
            "HOME": str(work / "home"),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
        }
        Path(env["HOME"]).mkdir(mode=0o700)
        for binary in (launcher, old_cli):
            check_help(binary, env)
            check_version(binary, env, args.version.encode("ascii"))
        for command, option in (("login", b"--token-file"), ("connect", b"--ephemeral")):
            help_output = run(launcher, "help", command, env=env).stdout
            assert option in help_output, help_output
        check_node(launcher, env)
        check_native_helper(launcher, work, env)
        check_logout(launcher, old_cli, work, env)
        if sys.platform == "linux":
            check_legacy_node_dispatch(launcher, work, env)
            node_id = run(launcher, "id", env=env).stdout
            assert re.fullmatch(rb"[0-9a-f]{32}\n", node_id), node_id
        # Keep the legacy wire entrypoint on the actual installed companion.
        companion = launcher.with_name("laneway-compat")
        shutil.copy2(args.companion, companion)
        require_output(run(companion, "version", env=env), args.version.encode("ascii") + b"\n")
        for public_only in (("configure", "--help"), ("control", "--help")):
            run(companion, *public_only, env=env, status=None)
        helper_help = ("_network-helper", "--help")
        expected = run(old_cli, *helper_help, env=env)
        installed_help = run(companion, *helper_help, env=env)
        assert (installed_help.stdout, installed_help.stderr) == (expected.stdout, expected.stderr)
        if sys.platform == "linux":
            check_linux_helper_bridge(companion, launcher, old_cli, work, env, args.version.encode("ascii"))
        alias = launcher.with_name("lane")
        alias.symlink_to(launcher.name)
        check_version(alias, env, args.version.encode("ascii"))
        for binary in (launcher, alias):
            result = run(binary, *helper_help, env=env)
            assert (result.stdout, result.stderr) == (expected.stdout, expected.stderr)
    print("Rust/Go CLI parity, native helper, and compatibility dispatch passed.")


if __name__ == "__main__":
    main()
