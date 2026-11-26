#!/usr/bin/env python3
"""pin_hook.py - install the BTGoogle gate under a pinned, never-versioned name.

WHY THIS EXISTS
    The gate used to be copied around by hand, so the file Antigravity actually
    ran (scope_gate_v2.py) drifted away from the file in this repository and a
    fix landed in one but not the other. Updating it also meant adopting a new
    version (v2 -> v3) and editing hooks.json every time.

THE RULE
    One name, forever: hooks/scope_gate_v2.py. The version is not bumped.
    A change to the gate is a change to the CONTENT of that file, then this
    script copies it over the pinned destination. scope_gate_v3.py would be a
    bug, and --check fails if one ever appears.

USAGE
    python scripts/pin_hook.py              install (copy content + merge hooks.json)
    python scripts/pin_hook.py --dry-run    show what would change, touch nothing
    python scripts/pin_hook.py --check      verify the pinning, exit 1 on drift
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The pinned name. Do not change this; change the content of the file instead.
GATE_NAME = "scope_gate_v2.py"
STORE_NAME = "scope_store.py"
PARSER_NAME = "scope_parser.py"
PAYLOAD_FILES = (GATE_NAME, STORE_NAME, PARSER_NAME)

ENTRY_KEY = "antigravity-osint"
MATCHER = (
    "run_command|manage_task|read_url_content|search_web|ask_permission|"
    "write_to_file|replace_file_content|multi_replace_file_content|browser_.*"
)


def config_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".gemini", "config")


def hooks_dir() -> str:
    return os.path.join(config_dir(), "hooks")


def hooks_json() -> str:
    return os.path.join(config_dir(), "hooks.json")


def digest(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def stray_versions(directory: str) -> list[str]:
    """Gate files in directory that carry a version but are not the pinned one."""
    found = []
    if not os.path.isdir(directory):
        return found
    for name in sorted(os.listdir(directory)):
        if not name.startswith("scope_gate_v") or not name.endswith(".py"):
            continue
        if name != GATE_NAME:
            found.append(name)
    return found


def install_file(source: str, destination: str, stamp: str, dry: bool) -> str:
    """Copy content only. Returns unchanged|updated|created."""
    if os.path.exists(destination) and digest(source) == digest(destination):
        print("same     %s" % destination)
        return "unchanged"
    if dry:
        print("would    %s" % destination)
        return "updated"
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    if os.path.exists(destination):
        backup = "%s.bak-%s" % (destination, stamp)
        shutil.copy2(destination, backup)
        print("backup   %s" % backup)
    shutil.copy2(source, destination)
    print("install  %s" % destination)
    return "updated"


def merge_hooks_json(gate_path: str, dry: bool) -> str:
    """Pin the PreToolUse entry of the gate inside hooks.json, leaving the rest alone."""
    path = hooks_json()
    if os.path.exists(path):
        with open(path, "rb") as handle:
            raw = handle.read()
        bom = raw.startswith(b"\xef\xbb\xbf")
        document = json.loads(raw.decode("utf-8-sig"))
    else:
        bom = False
        document = {}

    entry = document.setdefault(ENTRY_KEY, {})
    entry["enabled"] = True
    hooks = entry.setdefault("PreToolUse", [])

    # Find the matcher group that already runs the gate, if any.
    group = None
    for candidate in hooks:
        for hook in candidate.get("hooks", []):
            if GATE_NAME in str(hook.get("command", "")):
                group = candidate
                break
        if group is not None:
            break

    if group is None:
        group = {"matcher": MATCHER, "hooks": []}
        hooks.append(group)
        print("hooks.json: added the %s PreToolUse group" % ENTRY_KEY)

    group.setdefault("matcher", MATCHER)
    commands = [hook for hook in group.setdefault("hooks", []) if GATE_NAME in str(hook.get("command", ""))]

    if commands:
        for hook in commands:
            if "timeout" not in hook:
                hook["timeout"] = 15
            print("hooks.json: keeps  %s" % hook["command"])
    else:
        python = sys.executable
        if os.path.sep == "\\" and "python" in os.path.basename(python).lower():
            python = os.path.abspath(python)
        else:
            python = "python"
        command = "%s %s" % (python, gate_path.replace(os.path.sep, "/"))
        group["hooks"].append({"type": "command", "command": command, "timeout": 15})
        print("hooks.json: added  %s" % command)

    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    encoded = (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8")

    if os.path.exists(path):
        with open(path, "rb") as handle:
            if handle.read() == encoded:
                print("same     %s" % path)
                return "unchanged"
    if dry:
        print("would    %s" % path)
        return "updated"

    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

    # Write-then-rename: Antigravity must never read a half-written hooks.json.
    temporary = path + ".tmp"
    with open(temporary, "wb") as handle:
        handle.write(encoded)
    json.loads(encoded.decode("utf-8-sig"))
    os.replace(temporary, path)
    print("install  %s" % path)
    return "updated"


def merge_noise(source: str, destination: str, dry: bool) -> str:
    """Union of the shipped noise list and the installed one; the installed wins."""
    with open(source, "rb") as handle:
        shipped = json.loads(handle.read().decode("utf-8-sig"))
    if not os.path.exists(destination):
        return install_file(source, destination, "init", dry)

    with open(destination, "rb") as handle:
        raw = handle.read()
    installed = json.loads(raw.decode("utf-8-sig"))
    merged = sorted(set(shipped) | set(installed))
    if merged == sorted(installed):
        print("same     %s" % destination)
        return "unchanged"

    added = sorted(set(merged) - set(installed))
    print("noise.json: adds %s" % ", ".join(added))
    if dry:
        print("would    %s" % destination)
        return "updated"
    with open(destination, "wb") as handle:
        handle.write((json.dumps(merged, indent=4, ensure_ascii=False) + "\n").encode("utf-8"))
    print("install  %s" % destination)
    return "updated"


def install(dry: bool) -> int:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination_dir = hooks_dir()

    strays = stray_versions(destination_dir)
    if strays:
        print("error: extra gate versions next to the pinned one: %s" % ", ".join(strays))
        print("       the gate keeps one name; fold the change into %s instead" % GATE_NAME)
        return 1

    for name in PAYLOAD_FILES:
        source = os.path.join(REPO_ROOT, "hooks", name)
        if not os.path.isfile(source):
            print("error: missing %s in the repository" % source)
            return 1
        install_file(source, os.path.join(destination_dir, name), stamp, dry)

    # noise.json is a list of hosts that never count as targets, so a SHORTER
    # file makes the gate noisier. Merge it, never replace it.
    source_noise = os.path.join(REPO_ROOT, "hooks", "noise.json")
    if os.path.isfile(source_noise):
        merge_noise(source_noise, os.path.join(destination_dir, "noise.json"), dry)

    merge_hooks_json(os.path.join(destination_dir, GATE_NAME), dry)
    print("\ngate: %s" % os.path.join(destination_dir, GATE_NAME))
    print("sha256: %s" % digest(os.path.join(REPO_ROOT, "hooks", GATE_NAME)))
    return 0


def check() -> int:
    problems = []

    for name in PAYLOAD_FILES:
        path = os.path.join(REPO_ROOT, "hooks", name)
        if not os.path.isfile(path):
            problems.append("repository is missing hooks/%s" % name)

    strays = stray_versions(os.path.join(REPO_ROOT, "hooks"))
    if strays:
        problems.append("repository carries extra gate versions: %s" % ", ".join(strays))

    path = hooks_json()
    if os.path.exists(path):
        with open(path, "rb") as handle:
            document = json.loads(handle.read().decode("utf-8-sig"))
        entry = document.get(ENTRY_KEY) or {}
        commands = [
            str(hook.get("command", ""))
            for group in entry.get("PreToolUse", [])
            for hook in group.get("hooks", [])
        ]
        if not entry.get("enabled"):
            problems.append("hooks.json: %s is not enabled" % ENTRY_KEY)
        if not any(GATE_NAME in command for command in commands):
            problems.append("hooks.json: no PreToolUse command runs %s" % GATE_NAME)
        for command in commands:
            for name in stray_versions(destination_dir_of(command)):
                problems.append("hooks.json: command runs %s" % name)

    installed = os.path.join(hooks_dir(), GATE_NAME)
    if os.path.exists(installed):
        source = os.path.join(REPO_ROOT, "hooks", GATE_NAME)
        if digest(source) != digest(installed):
            problems.append("installed gate differs from the repository copy (run without --check)")

    if problems:
        for problem in problems:
            print("FAIL %s" % problem)
        return 1
    print("ok: gate pinned to %s" % GATE_NAME)
    return 0


def destination_dir_of(command: str) -> str:
    for token in command.replace('"', " ").split():
        if token.endswith(GATE_NAME):
            return os.path.dirname(token)
    return hooks_dir()


def main() -> int:
    arguments = set(sys.argv[1:])
    if "--check" in arguments:
        return check()
    return install(dry="--dry-run" in arguments)


if __name__ == "__main__":
    sys.exit(main())
