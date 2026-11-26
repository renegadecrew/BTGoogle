#!/usr/bin/env python3
"""
BTGoogle — a context-aware scope gate for Google Antigravity pre-tool hooks.

The gate receives a PreToolUse payload on stdin and returns a JSON decision on
stdout:

    stdin  : {"toolCall": {"name": "...", "args": {...}}, ...}
    stdout : {"decision": "allow" | "ask" | "force_ask" | "deny", "reason": "..."}

Design goal: enforce an explicit, file-based scope registry without turning
every dotted identifier, file name, or private lab address into a false
positive. The gate only inspects network contexts (URLs, network tool
arguments, host flags); everything else is allowed.

This file is dependency-free and can be dropped into a hooks directory.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import sys
from datetime import date, datetime, timezone

HOME = os.path.expanduser("~")
DEFAULT_PROGRAMS = os.path.join(HOME, ".gemini", "config", "engagements", "programs")
DEFAULT_NOISE = os.path.join(HOME, ".gemini", "config", "hooks", "noise.json")
DEFAULT_LOG = os.path.join(HOME, ".gemini", "config", ".hook_state", "scope-gate.log")

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_PROGRAMS = os.path.join(_SCRIPT_DIR, "programs")
_REPO_NOISE = os.path.join(_SCRIPT_DIR, "noise.json")

if "BTG_PROGRAMS_DIR" in os.environ:
    PROGRAMS_DIR = os.environ["BTG_PROGRAMS_DIR"]
elif os.path.isdir(_REPO_PROGRAMS):
    PROGRAMS_DIR = _REPO_PROGRAMS
else:
    PROGRAMS_DIR = DEFAULT_PROGRAMS

if "BTG_NOISE_FILE" in os.environ:
    NOISE_FILE = os.environ["BTG_NOISE_FILE"]
elif os.path.isfile(_REPO_NOISE):
    NOISE_FILE = _REPO_NOISE
else:
    NOISE_FILE = DEFAULT_NOISE

LOG_FILE = os.environ.get("BTG_LOG_FILE", DEFAULT_LOG)

# The gate answers "which copy of me is running?" itself: --whoami prints its
# path and content hash, and every log line carries the hash prefix. That
# replaces re-hashing files by hand when a fix "did not take".
GATE_PATH = os.path.abspath(__file__)


def _self_hash() -> str:
    try:
        with open(GATE_PATH, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except Exception:
        return "unknown"


GATE_HASH = _self_hash()

# "force_ask" always prompts (ignores cached Always-Allow); "ask" respects it.
OUT_OF_SCOPE = os.environ.get("BTG_OUT_OF_SCOPE", "force_ask")
if OUT_OF_SCOPE not in ("force_ask", "ask"):
    OUT_OF_SCOPE = "force_ask"

# Private / loopback / link-local addresses are treated as lab noise by default.
GATE_PRIVATE = os.environ.get("BTG_GATE_PRIVATE_IPS") == "1"

# Single-label wildcards are only accepted for these lab-style TLDs. A *.com
# wildcard would authorize a large part of the public Internet, so it is
# rejected at load time.
LAB_TLDS = {"htb", "local", "lab", "test", "internal"}
_lab_extra = os.environ.get("BTG_LAB_TLDS", "")
if _lab_extra:
    LAB_TLDS |= {item.strip().lower() for item in _lab_extra.split(",") if item.strip()}

CMD_TOOLS = {"run_command": "CommandLine", "manage_task": "Input"}
TEXT_TOOLS = {"read_url_content": "Url", "search_web": "query", "ask_permission": "Target"}
WRITE_TOOLS = {
    "write_to_file": "TargetFile",
    "replace_file_content": "TargetFile",
    "multi_replace_file_content": "TargetFile",
}

# Writing to these locations plants code that executes on every future tool
# call (hook config, git hooks, shell profiles, agent credentials).
PROTECTED_PATH = re.compile(
    r"(?:"
    r"/\.agents/hooks\.json$"
    r"|/\.gemini/config/hooks\.json$"
    r"|/\.gemini/config/hooks/"
    r"|/\.gemini/config/agents/"
    r"|/\.gemini/oauth_creds\.json$"
    r"|/\.gemini/mcp-oauth-tokens\.json$"
    r"|/\.git/hooks/"
    r"|/(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|\.bash_login)$"
    r"|/microsoft\.powershell_profile\.ps1$"
    r"|/start menu/programs/startup/"
    r"|/\.claude/settings\.json$"
    r")",
    re.I,
)

CATASTROPHIC = [
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+(/|~|\$HOME|\*)\s*$", "recursive delete of root/home"),
    (r"\bRemove-Item\b.*-Recurse.*\b(C:\\|C:/)\s*$", "recursive delete of C:\\"),
    (r"\bFormat-Volume\b|\bformat\s+[a-z]:", "volume format"),
    (r"\bdd\s+if=.*\bof=/dev/(sd|nvme)", "raw write to disk"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "database destruction"),
    (r"\bmkfs\.", "filesystem format"),
]

# A forced push rewrites remote history with no clean undo. It is rare, so
# asking costs no friction; --force-with-lease and --force-if-includes are the
# careful forms and pass.
FORCE_PUSH = re.compile(
    r"\bgit\s+push\b[^|;&\n]*(?:--force(?!-(?:with-lease|if-includes))|\s-f(?![\w-]))",
    re.I,
)

_TOKEN = r"((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24})"

URL_HOST = re.compile(r"https?://([^/\s:'\"<>)\]]+)", re.I)
NET_TOOL = re.compile(
    r"\b(?:nmap|masscan|curl|wget|ping|ping6|tracert|traceroute|nslookup|dig|"
    r"host|whois|scp|sftp|ftp|nc|netcat|telnet|"
    r"Test-Connection|Test-NetConnection|Resolve-DnsName|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
    r"(?:\s+(?:-\S+|\d+))*\s+" + _TOKEN,
    re.I,
)
HOST_FLAG = re.compile(
    r"-(?:Host|ComputerName|Uri|Url|Server|Target|Address)\s+[\"']?" + _TOKEN,
    re.I,
)
SSH_TOOL = re.compile(r"(?<![\w.-])ssh(?=\s)", re.I)
SSH_VALUE_OPTIONS = {
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L",
    "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}

EXT_RE = re.compile(
    r"\.(py|js|ts|jsx|tsx|json|md|txt|log|exe|dll|so|yaml|yml|toml|sh|ps1|"
    r"php|asp|aspx|jsp|html?|css|pdf|png|jpe?g|zip|ovpn|conf|cfg|ini|env|"
    r"bat|cmd|pem|crt|cer|key|p12|pfx|jks|der|csr|7z|rar|tar|gz|db|sql|"
    r"pcap|cap|csv|xml|map|lock)$",
    re.I,
)

LOG_MAX_BYTES = 2 * 1024 * 1024


def log(entry: dict) -> None:
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
            os.replace(LOG_FILE, LOG_FILE + ".1")
        entry["ts"] = datetime.now(timezone.utc).isoformat()
        entry.setdefault("gate", GATE_HASH[:12])
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        pass


def _valid_asset(asset: str) -> bool:
    asset = asset.strip().lower()
    if not asset or " " in asset or "\t" in asset:
        return False
    if asset.startswith("*."):
        base = asset[2:]
        # *.example.com is fine; *.htb is fine only for lab TLDs; *.com is not.
        if "." not in base and base not in LAB_TLDS:
            return False
    return True


def parse_program(path: str) -> dict | None:
    slug = os.path.splitext(os.path.basename(path))[0]
    in_scope: list[str] = []
    out_scope: list[str] = []
    section = None
    expires = None
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                if line.lower().startswith("expires:"):
                    match = re.search(r"\d{4}-\d{2}-\d{2}", line)
                    if match:
                        expires = match.group(0)
                    continue
                if line.startswith("##"):
                    low = line.lower()
                    if "in-scope" in low or "in scope" in low:
                        section = "in"
                    elif "out-of-scope" in low or "out of scope" in low:
                        section = "out"
                    else:
                        section = None
                    continue
                if line.startswith("#"):
                    continue
                if not _valid_asset(line):
                    continue
                if section == "in":
                    in_scope.append(line.lower())
                elif section == "out":
                    out_scope.append(line.lower())
    except OSError:
        return None
    if not in_scope:
        return None
    return {"slug": slug, "in": in_scope, "out": out_scope, "expires": expires}


def load_programs() -> list[dict]:
    if not os.path.isdir(PROGRAMS_DIR):
        return []
    programs = []
    today = date.today().isoformat()
    for name in sorted(os.listdir(PROGRAMS_DIR)):
        if not name.endswith(".md"):
            continue
        program = parse_program(os.path.join(PROGRAMS_DIR, name))
        if not program:
            continue
        if program["expires"] and program["expires"] < today:
            continue
        programs.append(program)
    return programs


def _host_pattern_match(host: str, patterns: list[str]) -> bool:
    if host in patterns:
        return True
    return any(p.startswith("*.") and host.endswith(p[1:]) for p in patterns)


def _ip_pattern_match(host: str, patterns: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for pattern in patterns:
        if "/" not in pattern:
            continue
        try:
            if ip in ipaddress.ip_network(pattern, strict=False):
                return True
        except ValueError:
            continue
    return False


def match_host(host: str, programs: list[dict]) -> dict:
    authorized: list[str] = []
    excluded: list[str] = []
    for program in programs:
        if _host_pattern_match(host, program["out"]) or _ip_pattern_match(host, program["out"]):
            excluded.append(program["slug"])
            continue
        if _host_pattern_match(host, program["in"]) or _ip_pattern_match(host, program["in"]):
            authorized.append(program["slug"])
    return {"authorized": authorized, "excluded": excluded}


def load_noise() -> set[str]:
    base = {
        "localhost", "127.0.0.1", "0.0.0.0", "schemas.android.com",
        "w3.org", "json-schema.org", "github.com", "pypi.org", "npmjs.com",
        "python.org", "microsoft.com", "google.com", "gstatic.com",
        "antigravity.google", "accounts.google.com", "oauth2.googleapis.com",
        "cloudcode-pa.googleapis.com", "raw.githubusercontent.com",
    }
    try:
        with open(NOISE_FILE, "r", encoding="utf-8-sig") as fh:
            extra = json.load(fh)
        if isinstance(extra, list):
            base |= {str(x).strip().lower() for x in extra if str(x).strip()}
    except Exception:
        pass
    return base


NOISE = load_noise()


def _is_noise(host: str) -> bool:
    return host in NOISE or any(host.endswith("." + n) for n in NOISE)


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _keep(host: str) -> bool:
    if not host:
        return False
    if EXT_RE.search(host):
        return False
    if _is_noise(host):
        return False
    if _is_private(host) and not GATE_PRIVATE:
        return False
    return True


def _host_from_url(raw: str) -> str:
    host = raw.rsplit("@", 1)[-1]
    host = host.split(":")[0]
    return host.strip(".").lower()


def _ssh_targets(text: str) -> set[str]:
    """Extract SSH destinations without treating dotted code identifiers as hosts."""
    targets: set[str] = set()
    for match in SSH_TOOL.finditer(text):
        tail = re.split(r"[\r\n;|&]", text[match.end():], maxsplit=1)[0]
        try:
            args = shlex.split(tail)
        except ValueError:
            continue

        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "--":
                index += 1
                break
            if not arg.startswith("-") or arg == "-":
                break

            option = arg.split("=", 1)[0]
            if option in SSH_VALUE_OPTIONS:
                if "=" not in arg:
                    index += 2
                else:
                    index += 1
            elif len(arg) > 2 and arg[:2] in SSH_VALUE_OPTIONS:
                # OpenSSH also accepts attached values such as -p2222 and -iKEY.
                index += 1
            else:
                index += 1

        if index >= len(args):
            continue
        destination = args[index].rsplit("@", 1)[-1]
        for token in re.finditer(_TOKEN, destination, re.I):
            targets.add(token.group(1).lower())
            break
    return targets


def extract_targets(text: str, is_cmd: bool, tool: str) -> set[str]:
    """Return target hosts found in network contexts only."""
    targets: set[str] = set()

    for match in URL_HOST.finditer(text):
        targets.add(_host_from_url(match.group(1)))

    if tool == "ask_permission":
        # Low volume and literally "what am I asking permission for": strict.
        for match in re.finditer(_TOKEN, text, re.I):
            targets.add(match.group(1).lower())
    elif is_cmd:
        targets.update(_ssh_targets(text))
        for match in NET_TOOL.finditer(text):
            targets.add(match.group(1).lower())
        for match in HOST_FLAG.finditer(text):
            targets.add(match.group(1).lower())

    return {host for host in targets if _keep(host)}


def decide_write(args: dict, tool: str) -> dict:
    raw_path = args.get(WRITE_TOOLS[tool]) or ""
    # Tool paths are often workspace-relative. Check the normalized absolute
    # path so `.agents/hooks.json` is protected just like its absolute form.
    path = ""
    if isinstance(raw_path, str) and raw_path.strip():
        path = os.path.realpath(os.path.abspath(os.path.expanduser(raw_path)))
        path = path.replace("\\", "/")
    if path and PROTECTED_PATH.search(path):
        log({"event": "protected-write", "tool": tool, "path": path})
        return {
            "decision": "force_ask",
            "reason": (
                f"{tool} is writing to {path}, a persistence point. Anything "
                "stored there runs on future tool calls. Approve only if this "
                "is your own edit."
            ),
        }
    log({"event": "write", "tool": tool, "path": path})
    return {"decision": "allow"}


def decide(payload: dict) -> dict:
    call = payload.get("toolCall") or {}
    tool = call.get("name", "")
    args = call.get("args") or {}

    if tool in WRITE_TOOLS:
        return decide_write(args, tool)

    if tool in CMD_TOOLS:
        text = args.get(CMD_TOOLS[tool]) or ""
        is_cmd = True
    elif tool in TEXT_TOOLS:
        text = args.get(TEXT_TOOLS[tool]) or ""
        is_cmd = False
    else:
        return {"decision": "allow"}

    if not text or not isinstance(text, str):
        return {"decision": "allow"}

    if is_cmd:
        for pattern, why in CATASTROPHIC:
            if re.search(pattern, text, re.I):
                log({"event": "deny", "why": why, "text": text})
                return {
                    "decision": "deny",
                    "reason": f"Blocked by scope gate: {why}. Run it manually if intentional.",
                }
        match = FORCE_PUSH.search(text)
        if match:
            log({"event": "force_push", "text": text})
            return {
                "decision": "force_ask",
                "reason": "Forced git push (%s): rewrites remote history and does "
                          "not undo itself. Prefer --force-with-lease on a shared "
                          "remote." % match.group(0).strip(),
            }

    programs = load_programs()
    if not programs:
        log({"event": "warn", "why": "empty registry", "text": text})
        return {
            "decision": "allow",
            "reason": "No programs registered; add a program file to enforce scope.",
        }

    targets = extract_targets(text, is_cmd, tool)
    if not targets:
        log({"event": "allow", "tool": tool, "targets": []})
        return {"decision": "allow", "reason": "no network targets in the text"}

    problems = []
    for target in sorted(targets):
        result = match_host(target, programs)
        if result["authorized"]:
            log({"event": "authorized", "target": target, "by": result["authorized"]})
            continue
        if result["excluded"]:
            problems.append(f"{target} is explicitly excluded by {', '.join(result['excluded'])}")
        else:
            problems.append(f"{target} is not covered by any program")

    if problems:
        log({"event": "ask", "problems": problems, "text": text})
        return {
            "decision": OUT_OF_SCOPE,
            "reason": (
                "No active authorization: " + "; ".join(problems) +
                f". Loaded programs: {', '.join(p['slug'] for p in programs)}. "
                "To authorize a host: echo <host> | python scope_add.py. "
                "For references (docs/social), add it to noise.json."
            ),
        }

    log({"event": "allow", "tool": tool, "targets": sorted(targets)})
    return {"decision": "allow", "reason": "target in scope"}


def read_stdin() -> str:
    """Read the PreToolUse payload, tolerating a byte-order mark on stdin.

    sys.stdin.read() decodes with the locale codec: on Windows that is cp1252,
    where the UTF-8 BOM Windows PowerShell 5.1 prepends to a pipe becomes
    "\u00ef\u00bb\u00bf" and the JSON parse fails open to allow -- a silently
    disarmed gate.
    """
    data = sys.stdin.buffer.read()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode(sys.stdin.encoding or "utf-8", "replace")


def main() -> None:
    if "--whoami" in sys.argv:
        print(json.dumps({"gate": GATE_PATH, "sha256": GATE_HASH,
                          "pinned": os.path.basename(GATE_PATH)}))
        return
    # Windows PowerShell 5.1 prepends a UTF-8 BOM when it pipes a string into a
    # native command (`Get-Content x | python scope_gate.py`). Left in place that
    # makes every such payload "invalid JSON payload", which fails open to allow --
    # a silently disarmed gate.
    raw = read_stdin()
    if not raw.strip():
        print(json.dumps({"decision": "allow"}))
        return
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print(json.dumps({"decision": "allow", "reason": "invalid JSON payload"}))
        return
    print(json.dumps(decide(payload)))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # fail open: a crashing gate must not brick the agent
        log({"event": "error", "error": repr(exc)})
        print(json.dumps({"decision": "allow", "reason": "scope gate error (fail open)"}))
