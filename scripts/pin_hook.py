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
    python scripts/pin_hook.py              install, then prove it behaves
    python scripts/pin_hook.py --dry-run    show what would change, touch nothing
    python scripts/pin_hook.py --check      verify the pinning, exit 1 on drift
    python scripts/pin_hook.py --no-verify  install without running the matrix

WHY IT RUNS THE MATRIX
    A matching hash says the installed file IS the repository file. It does not
    say the gate decides correctly there -- an import resolved from a stale copy
    next to it, a missing dependency, a different registry. So install and
    --check both pipe the difference matrix through the INSTALLED file
    (tests/test_gate.py with BTG_GATE set) and fail if a single case flips.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The pinned name. Do not change this; change the content of the file instead.
GATE_NAME = "scope_gate_v2.py"
STORE_NAME = "scope_store.py"
PARSER_NAME = "scope_parser.py"
PAYLOAD_FILES = (GATE_NAME, STORE_NAME, PARSER_NAME)

# Every hook file the repository ships. The reference gate is not the one
# hooks.json runs, but it IS the copy a reviewer installs first, and a stale
# copy of it decides by older rules without anyone noticing.
REFERENCE_NAME = "scope_gate.py"
SHIPPED = (REFERENCE_NAME,) + PAYLOAD_FILES

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


def install_programs(dry: bool) -> str:
    """Copy the shipped example programs only when the installed one is missing.

    The gate reads ~/.gemini/config/engagements/programs. A fresh install with
    an empty registry used to allow everything, so the default install has to
    leave at least one program behind. An operator's existing program is never
    overwritten.
    """
    source_dir = os.path.join(REPO_ROOT, "hooks", "programs")
    destination_dir = os.path.join(config_dir(), "engagements", "programs")
    if not os.path.isdir(source_dir):
        print("warn: no hooks/programs to install")
        return "missing"
    status = "unchanged"
    for name in sorted(os.listdir(source_dir)):
        if not name.endswith(".md"):
            continue
        source = os.path.join(source_dir, name)
        destination = os.path.join(destination_dir, name)
        if os.path.exists(destination):
            print("keep     %s" % destination)
            continue
        if dry:
            print("would    %s" % destination)
            status = "updated"
            continue
        os.makedirs(destination_dir, exist_ok=True)
        shutil.copy2(source, destination)
        print("install  %s" % destination)
        status = "updated"
    return status


def install(dry: bool, verify: bool = True) -> int:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination_dir = hooks_dir()

    strays = stray_versions(destination_dir)
    if strays:
        print("error: extra gate versions next to the pinned one: %s" % ", ".join(strays))
        print("       the gate keeps one name; fold the change into %s instead" % GATE_NAME)
        return 1

    for name in SHIPPED:
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

    install_programs(dry)
    merge_hooks_json(os.path.join(destination_dir, GATE_NAME), dry)
    print("\ngate: %s" % os.path.join(destination_dir, GATE_NAME))
    print("sha256: %s" % digest(os.path.join(REPO_ROOT, "hooks", GATE_NAME)))

    if dry:
        return 0
    if not verify:
        print("matrix: skipped (--no-verify)")
        return 0
    return report_matrix(os.path.join(destination_dir, GATE_NAME))


MATRIX = os.path.join(REPO_ROOT, "tests", "test_gate.py")


def run_matrix(gate_path: str) -> tuple[bool, str]:
    """Run the behaviour matrix against exactly this copy of the gate."""
    if not os.path.isfile(MATRIX):
        return True, "matrix not found, skipped"
    environment = dict(os.environ)
    environment["BTG_GATE"] = gate_path
    proc = subprocess.run(
        [sys.executable, MATRIX],
        capture_output=True,
        text=True,
        env=environment,
        timeout=900,
    )
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, output


def failing_lines(output: str) -> str:
    """Only the cases that broke, so a failed check stays readable."""
    lines = [line for line in output.splitlines() if "FAIL" in line]
    return chr(10).join(lines[:40])


def report_matrix(gate_path: str) -> int:
    ok, output = run_matrix(gate_path)
    summary = output.splitlines()[-1] if output else "no output"
    if ok:
        print("behaviour %s on the installed file" % summary)
        return 0
    print(output)
    print("error: the installed gate does not behave like the repository copy")
    return 1


def check() -> int:
    problems = []

    for name in PAYLOAD_FILES:
        path = os.path.join(REPO_ROOT, "hooks", name)
        if not os.path.isfile(path):
            problems.append("repository is missing hooks/%s" % name)

    strays = stray_versions(os.path.join(REPO_ROOT, "hooks"))
    if strays:
        problems.append("repository carries extra gate versions: %s" % ", ".join(strays))

    installed_dir = hooks_dir()
    have_install = os.path.isdir(installed_dir)
    if not have_install:
        # CI has no ~/.gemini; the repo-only checks still run, but there is
        # nothing installed to compare against.
        print("note: no installed gate at %s; repo-only check" % installed_dir)

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

    if have_install:
        programs_dir = os.path.join(config_dir(), "engagements", "programs")
        programs = (os.listdir(programs_dir)
                    if os.path.isdir(programs_dir) else [])
        if not any(name.endswith(".md") for name in programs):
            problems.append(
                "engagements/programs is empty (run without --check)")

    for name in SHIPPED:
        if not have_install:
            continue
        installed = os.path.join(hooks_dir(), name)
        source = os.path.join(REPO_ROOT, "hooks", name)
        if not os.path.exists(installed):
            problems.append("%s is not installed (run without --check)" % name)
            continue
        if digest(source) != digest(installed):
            problems.append("installed %s differs from the repository copy (run without --check)" % name)
        # A matching hash says the installed file IS the repository file; the
        # matrix says it still decides correctly. The modules are imported by a
        # gate, so the gate's own run covers them. The reference shim is covered
        # by the pinned gate's run, so it is not run twice.
        if name != GATE_NAME:
            continue
        ok, output = run_matrix(installed)
        summary = output.splitlines()[-1] if output else "no output"
        if ok:
            print("%s: behaviour %s" % (name, summary))
        else:
            print(failing_lines(output))
            problems.append("%s fails the behaviour matrix: %s" % (name, summary))

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
    return install(dry="--dry-run" in arguments,
                   verify="--no-verify" not in arguments)


if __name__ == "__main__":
    sys.exit(main())
