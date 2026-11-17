#!/usr/bin/env python3
"""
Replication test matrix for the BTGoogle scope gate.

Run from the repository root:

    python tests/test_gate.py

Each case pipes a PreToolUse payload into hooks/scope_gate.py and asserts the
returned decision. The programs and noise list shipped in hooks/ are used, so
the test exercises the same files a reviewer would install.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "hooks", "scope_gate.py")
PROGRAMS = os.path.join(ROOT, "hooks", "programs")
NOISE = os.path.join(ROOT, "hooks", "noise.json")

ENV = dict(os.environ)
ENV["BTG_PROGRAMS_DIR"] = PROGRAMS
ENV["BTG_NOISE_FILE"] = NOISE
ENV["BTG_LOG_FILE"] = os.path.join(tempfile.gettempdir(), "btg-test.log")
ENV.pop("BTG_GATE_PRIVATE_IPS", None)


def payload(tool: str, field: str, value: str) -> dict:
    return {"toolCall": {"name": tool, "args": {field: value}}}


CASES = [
    # label, tool, field, value, expected
    ("python identifier", "run_command", "CommandLine",
     'python -c "import json; json.loads(s); urllib.request.urlopen(u)"', "allow"),
    ("file name", "run_command", "CommandLine",
     'Test-Path "C:\\samples\\release-2.ovpn"', "allow"),
    ("in-scope URL", "run_command", "CommandLine",
     "curl https://api.example.org/App.js", "allow"),
    ("out-of-scope URL", "run_command", "CommandLine",
     "curl https://evil.test.org/x", "force_ask"),
    ("bare host with nmap", "run_command", "CommandLine",
     "nmap evil.test.org", "force_ask"),
    ("private lab IP", "run_command", "CommandLine",
     "Test-Connection -ComputerName 10.0.0.5 -Count 2", "allow"),
    ("public IP", "run_command", "CommandLine",
     "nmap 8.8.8.8", "force_ask"),
    ("search query with a domain", "search_web", "query",
     "medium.com article about agents", "allow"),
    ("search query with a URL", "search_web", "query",
     "https://evil.test.org/x", "force_ask"),
    ("in-scope read", "read_url_content", "Url",
     "https://api.example.org/", "allow"),
    ("out-of-scope read", "read_url_content", "Url",
     "https://evil.test.org/", "force_ask"),
    ("noise reference", "run_command", "CommandLine",
     "curl https://medium.com/@x/y", "allow"),
    ("similar but not noise", "run_command", "CommandLine",
     "curl https://medium.org/x", "force_ask"),
    ("explicit exclusion wins", "run_command", "CommandLine",
     "curl https://legacy.example.org/x", "force_ask"),
    ("lab wildcard", "run_command", "CommandLine",
     "curl http://airways.htb/", "allow"),
    ("lab subdomain", "run_command", "CommandLine",
     "curl http://api.airways.htb/", "allow"),
    ("lab CIDR", "run_command", "CommandLine",
     "nmap 172.20.0.9", "allow"),
    ("destructive command", "run_command", "CommandLine",
     "rm -rf /", "deny"),
    ("relative hook config write", "write_to_file", "TargetFile",
     ".agents/hooks.json", "force_ask"),
    ("relative git hook write", "replace_file_content", "TargetFile",
     ".git/hooks/pre-commit", "force_ask"),
    ("ordinary relative write", "write_to_file", "TargetFile",
     "docs/notes.md", "allow"),
    ("paramiko class identifier", "run_command", "CommandLine",
     "python -c \"ssh = paramiko.SSHClient()\"", "allow"),
    ("paramiko connect identifier", "run_command", "CommandLine",
     "python -c \"ssh.connect('10.129.181.174')\"", "allow"),
    ("ssh close identifier", "run_command", "CommandLine",
     "python -c \"ssh.close()\"", "allow"),
    ("ssh user destination", "run_command", "CommandLine",
     "ssh user@evil.test.org", "force_ask"),
    ("ssh port and user destination", "run_command", "CommandLine",
     "ssh -p 22 user@evil.test.org", "force_ask"),
    ("ssh identity and destination", "run_command", "CommandLine",
     "ssh -i lab_key user@evil.test.org", "force_ask"),
    ("ssh -G user destination", "run_command", "CommandLine",
     "ssh -G user@evil.test.org", "force_ask"),
    ("ssh port and -G user destination", "run_command", "CommandLine",
     "ssh -p 22 -G user@evil.test.org", "force_ask"),
    ("ssh identity, -G and user destination", "run_command", "CommandLine",
     "ssh -i lab_key -G user@evil.test.org", "force_ask"),
]


def run_gate(body: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, GATE],
        input=json.dumps(body),
        capture_output=True,
        text=True,
        env=ENV,
        timeout=30,
    )
    return json.loads(proc.stdout.strip())


def main() -> int:
    failures = 0
    print(f"{'case':34} {'expected':10} {'actual':10} result")
    print("-" * 70)
    for label, tool, field, value, expected in CASES:
        result = run_gate(payload(tool, field, value))
        actual = result.get("decision")
        ok = actual == expected
        failures += 0 if ok else 1
        print(f"{label:34} {expected:10} {actual or '-':10} {'ok' if ok else 'FAIL'}")
    print("-" * 70)
    print(f"{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
