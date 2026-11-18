import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("prepare_rust", Path(__file__).with_name("prepare-rust.py"))
RUST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUST)
BASE = Path("/fixture")
PINNED = {"LANEWAY_RUST_VERSION": "0.0.9100", **{
    key: "sha256:" + str(number) * 64
    for number, key in enumerate(RUST.RUST_SERVICES.values(), 1)
}}
ARTIFACTS = [{"os": "linux", "arch": "arm64", "url": "candidate"}]
RELEASE_IMAGES = {role: f"ghcr.io/doout/laneway-{role}-rust:0.0.9100@{PINNED[key]}"
                  for role, key in RUST.RUST_SERVICES.items()}
ENV = """LANEWAY_CONTROLLER_SERVER_NAME=lane.test
LANEWAY_RELAY_TCP_PORT=443
LANEWAY_NETWORK_ID=network
LANEWAY_CONTROLLER_SERVICE_ID=controller
"""


class RustReadiness(unittest.TestCase):
    def setUp(self):
        self.images = RELEASE_IMAGES.copy()
        self.ids = {role: str(index) * 12 for index, role in enumerate(RELEASE_IMAGES, 1)}
        self.states = {
            role: {"Config": {"Image": ref}, "Image": ref.split("@")[1],
                   "State": {"Running": True, "Health": {"Status": "healthy"}}}
            for role, ref in RELEASE_IMAGES.items()
        }
        self.discovery = {"network_id": "network", "artifacts": ARTIFACTS,
                          "controller": {"service_id": "controller", "server_name": "lane.test"}}

    def output(self, args):
        if args[:2] == ["docker", "compose"]:
            if args[-3:] == ["config", "--format", "json"]:
                return json.dumps({"services": {role: {"image": ref} for role, ref in self.images.items()}})
            if args[-5:-1] == ["ps", "--status", "running", "-q"]:
                return self.ids[args[-1]]
        if args[:4] == ["docker", "inspect", "--type", "container"]:
            role = next(key for key, container in self.ids.items() if container == args[-1])
            return json.dumps([self.states[role]])
        if args[:5] == ["docker", "image", "inspect", "--format", "{{.Id}}"]:
            self.assertIn(args[-1], RELEASE_IMAGES.values())
            return args[-1].split("@")[1]
        if args[:2] == ["curl", "--disable"]:
            self.assertEqual(args[-1], "https://lane.test/.well-known/laneway/bootstrap.json")
            self.assertNotIn("--insecure", args)
            return json.dumps(self.discovery)
        self.fail(f"unexpected command (including any write): {args}")

    def check_active(self):
        with patch.object(RUST, "command_output", side_effect=self.output):
            RUST.active_images(BASE, PINNED)

    def check_public(self):
        with patch.object(RUST, "command_output", side_effect=self.output), patch.object(RUST, "read_config", return_value=ENV):
            RUST.check_public_discovery(BASE, ARTIFACTS)

    def test_ready_and_optional_exit(self):
        self.check_active()
        self.check_public()
        self.ids["exit-node"] = ""
        self.check_active()

    def test_rendered_compose_override(self):
        self.images["relay"] = "other"
        with self.assertRaisesRegex(ValueError, "Compose does not select"):
            self.check_active()

    def test_running_wrong_digest(self):
        self.states["relay"]["Config"]["Image"] = "different@sha256:pretend"
        with self.assertRaisesRegex(ValueError, "running container does not use"):
            self.check_active()

    def test_running_wrong_content_or_health(self):
        self.states["relay"]["Image"] = "sha256:" + "9" * 64
        with self.assertRaisesRegex(ValueError, "running image content differs"):
            self.check_active()
        self.states["relay"]["Image"] = PINNED["LANEWAY_RUST_RELAY_IMAGE_DIGEST"]
        self.states["relay"]["State"]["Health"]["Status"] = "starting"
        with self.assertRaisesRegex(ValueError, "release container is not healthy"):
            self.check_active()

    def test_missing_required_controller(self):
        self.ids["controller"] = ""
        with self.assertRaisesRegex(ValueError, "expected one running container"):
            self.check_active()

    def test_public_wrong_network_or_artifacts(self):
        self.discovery["network_id"] = "other"
        with self.assertRaisesRegex(ValueError, "different controller or network"):
            self.check_public()
        self.discovery["network_id"] = "network"
        self.discovery["artifacts"] = []
        with self.assertRaisesRegex(ValueError, "not serving the signed release artifacts"):
            self.check_public()

    def test_check_rejects_stale_staged_artifacts_before_inspecting(self):
        with patch.object(RUST, "candidate_release", return_value=(PINNED, ARTIFACTS)), \
             patch.object(RUST, "read_config", return_value='{"artifacts": []}'), \
             patch.object(RUST, "command_output") as command:
            with self.assertRaisesRegex(ValueError, "staged Rust profile differs"):
                RUST.check_readiness(BASE, BASE / "metadata")
            command.assert_not_called()
