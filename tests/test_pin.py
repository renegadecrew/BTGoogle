#!/usr/bin/env python3
"""Tests for scripts/pin_hook.py: one gate name, content-only updates.

Every test installs into a throwaway HOME, so nothing here touches a real
Antigravity configuration.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = os.path.join(ROOT, "scripts", "pin_hook.py")

sys.path.insert(0, os.path.join(ROOT, "scripts"))
import pin_hook  # noqa: E402


class PinTest(unittest.TestCase):
    def setUp(self) -> None:
        self.home = tempfile.mkdtemp(prefix="btg-pin-")
        self.config = os.path.join(self.home, ".gemini", "config")
        self.hooks = os.path.join(self.config, "hooks")
        os.makedirs(self.hooks)

    def tearDown(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)

    def run_pin(self, *arguments: str) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment["HOME"] = self.home
        environment["USERPROFILE"] = self.home
        environment.pop("PYTHONPATH", None)
        return subprocess.run(
            [sys.executable, PIN, *arguments],
            capture_output=True,
            text=True,
            env=environment,
        )

    def digest(self, path: str) -> str:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def test_installs_under_the_pinned_name(self) -> None:
        result = self.run_pin()
        self.assertEqual(result.returncode, 0, result.stderr)

        gate = os.path.join(self.hooks, pin_hook.GATE_NAME)
        self.assertTrue(os.path.isfile(gate))
        self.assertTrue(os.path.isfile(os.path.join(self.hooks, pin_hook.STORE_NAME)))
        self.assertEqual(pin_hook.stray_versions(self.hooks), [])
        # Installed bytes are the repository bytes: same name, new content.
        self.assertEqual(
            self.digest(gate), self.digest(os.path.join(ROOT, "hooks", pin_hook.GATE_NAME))
        )

    def test_second_run_changes_nothing(self) -> None:
        self.assertEqual(self.run_pin().returncode, 0)
        gate = os.path.join(self.hooks, pin_hook.GATE_NAME)
        before = {name: self.digest(os.path.join(self.hooks, name))
                  for name in os.listdir(self.hooks) if not name.endswith(".pyc")}

        result = self.run_pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {name: self.digest(os.path.join(self.hooks, name))
                 for name in os.listdir(self.hooks) if not name.endswith(".pyc")}

        self.assertEqual(before, after)
        self.assertNotIn("backup", result.stdout)
        self.assertNotIn("install", result.stdout)

    def test_content_change_reuses_the_same_name(self) -> None:
        self.assertEqual(self.run_pin().returncode, 0)
        gate = os.path.join(self.hooks, pin_hook.GATE_NAME)
        with open(gate, "ab") as handle:
            handle.write(b"\n# locally patched\n")

        result = self.run_pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install", result.stdout)
        self.assertEqual(pin_hook.stray_versions(self.hooks), [])
        self.assertEqual(
            self.digest(gate), self.digest(os.path.join(ROOT, "hooks", pin_hook.GATE_NAME))
        )
        # The old content is kept aside, the name never forks.
        self.assertTrue(any(name.endswith(".bak") or ".bak-" in name for name in os.listdir(self.hooks)))

    def test_a_second_version_fails_loudly(self) -> None:
        with open(os.path.join(self.hooks, "scope_gate_v3.py"), "w", encoding="utf-8") as handle:
            handle.write("# a forbidden version bump\n")

        result = self.run_pin()
        self.assertEqual(result.returncode, 1)
        self.assertIn("scope_gate_v3.py", result.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.hooks, pin_hook.GATE_NAME)))

    def test_hooks_json_is_merged_not_replaced(self) -> None:
        path = os.path.join(self.config, "hooks.json")
        original = {
            "someone-elses-hook": {"enabled": True, "Stop": [{"type": "command", "command": "x"}]}
        }
        with open(path, "wb") as handle:
            handle.write(b"\xef\xbb\xbf" + json.dumps(original, indent=2).encode("utf-8"))

        self.assertEqual(self.run_pin().returncode, 0)

        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "the BOM must survive")
        document = json.loads(raw.decode("utf-8-sig"))

        self.assertEqual(document["someone-elses-hook"], original["someone-elses-hook"])
        entry = document[pin_hook.ENTRY_KEY]
        self.assertTrue(entry["enabled"])
        commands = [hook["command"] for group in entry["PreToolUse"] for hook in group["hooks"]]
        self.assertTrue(any(pin_hook.GATE_NAME in command for command in commands))
        self.assertFalse(any("scope_gate_v3" in command for command in commands))

    def test_existing_gate_command_is_kept_verbatim(self) -> None:
        path = os.path.join(self.config, "hooks.json")
        command = "C:/some/python.exe C:/Users/Admin/.gemini/config/hooks/%s" % pin_hook.GATE_NAME
        document = {
            pin_hook.ENTRY_KEY: {
                "enabled": True,
                "PreToolUse": [
                    {"matcher": "run_command", "hooks": [{"type": "command", "command": command}]}
                ],
            }
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)

        self.assertEqual(self.run_pin().returncode, 0)

        with open(path, encoding="utf-8-sig") as handle:
            merged = json.load(handle)
        hooks = merged[pin_hook.ENTRY_KEY]["PreToolUse"][0]["hooks"]
        self.assertEqual(len(hooks), 1, "the entry must not be duplicated")
        self.assertEqual(hooks[0]["command"], command)
        self.assertEqual(hooks[0]["timeout"], 15)

    def test_noise_list_is_never_shortened(self) -> None:
        path = os.path.join(self.hooks, "noise.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(["only.in.this.machine"], handle)

        self.assertEqual(self.run_pin().returncode, 0)

        with open(path, encoding="utf-8-sig") as handle:
            noise = json.load(handle)
        self.assertIn("only.in.this.machine", noise)

    def test_check_detects_drift_between_repo_and_install(self) -> None:
        self.assertEqual(self.run_pin().returncode, 0)
        self.assertEqual(self.run_pin("--check").returncode, 0)

        with open(os.path.join(self.hooks, pin_hook.GATE_NAME), "ab") as handle:
            handle.write(b"\n# drift\n")

        result = self.run_pin("--check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("differs from the repository copy", result.stdout)

    def test_installed_gate_keeps_its_decisions(self) -> None:
        """The pinned file, run as Antigravity runs it, must still decide."""
        self.assertEqual(self.run_pin().returncode, 0)
        gate = os.path.join(self.hooks, pin_hook.GATE_NAME)
        environment = dict(os.environ)
        environment["HOME"] = self.home
        environment["USERPROFILE"] = self.home

        def decide(command: str, bom: bool = False) -> dict:
            payload = json.dumps(
                {"toolCall": {"name": "run_command", "args": {"CommandLine": command}}}
            ).encode("utf-8")
            result = subprocess.run(
                [sys.executable, gate],
                input=(b"\xef\xbb\xbf" if bom else b"") + payload,
                capture_output=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout.decode("utf-8"))

        self.assertEqual(decide("rm -rf /")["decision"], "deny")
        self.assertEqual(decide("rm -rf /", bom=True)["decision"], "deny",
                         "a UTF-8 BOM must not fail the gate open")
        self.assertEqual(decide('python -c "import json; json.loads(s)"')["decision"], "allow")

    def test_install_paths_are_the_pinned_ones(self) -> None:
        self.assertTrue(pin_hook.GATE_NAME.endswith(".py"))
        self.assertEqual(pin_hook.GATE_NAME, "scope_gate_v2.py")
        self.assertEqual(pin_hook.stray_versions(os.path.join(ROOT, "hooks")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
