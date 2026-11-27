#!/usr/bin/env python3
"""Redact secrets from existing BTGoogle state files.

New log entries are redacted by the gate itself. This script cleans the files
that were written before that fix existed, without destroying them.

Usage:
    python scripts/redact_state.py --dry-run   # default: report only
    python scripts/redact_state.py --apply     # write .bak-<stamp> first

State directory defaults to ~/.gemini/config/.hook_state. Only *.log and
pending.json are touched; the capture cache stores hashes, not commands.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hooks"))

from scope_gate_v2 import redact  # noqa: E402

DEFAULT_STATE = os.path.join(
    os.path.expanduser("~"), ".gemini", "config", ".hook_state")


def _walk(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _walk(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_walk(item) for item in value]
    return value


def clean_text(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        original = fh.read()
    cleaned = redact(original)
    return original, cleaned


def clean_json(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        original = fh.read()
    data = json.loads(original)
    cleaned = json.dumps(_walk(data), indent=2, ensure_ascii=True) + "\n"
    return original, cleaned


def main() -> int:
    state = os.environ.get("ANTIGRAVITY_STATE_DIR") or DEFAULT_STATE
    apply = "--apply" in sys.argv
    if not os.path.isdir(state):
        print("no state directory: %s" % state)
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    changed = 0
    for name in sorted(os.listdir(state)):
        path = os.path.join(state, name)
        if not os.path.isfile(path):
            continue
        if name.endswith(".log"):
            try:
                original, cleaned = clean_text(path)
            except OSError as exc:
                print("skip %s: %s" % (name, exc))
                continue
        elif name == "pending.json":
            try:
                original, cleaned = clean_json(path)
            except (OSError, ValueError) as exc:
                print("skip %s: %s" % (name, exc))
                continue
        else:
            continue

        if original == cleaned:
            print("clean %s" % name)
            continue
        changed += 1
        print("dirty %s (%d -> %d bytes)" % (name, len(original), len(cleaned)))
        if not apply:
            continue
        backup = "%s.bak-%s" % (path, stamp)
        with open(backup, "w", encoding="utf-8", newline="") as fh:
            fh.write(original)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(cleaned)
        print("wrote %s (backup %s)" % (path, backup))

    if not changed:
        print("ok: no secrets found")
        return 0
    if not apply:
        print("dry-run: %d file(s) would change; re-run with --apply" % changed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
