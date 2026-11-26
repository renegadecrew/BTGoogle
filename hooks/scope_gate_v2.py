#!/usr/bin/env python3
"""
scope_gate_v2.py - PreToolUse hook (extraccion por contexto).

POR QUE EXISTE
    La v1 corria DOMAIN_RE sobre TODO el texto. Eso convierte en "dominio"
    cualquier identificador con punto (json.loads, urllib.request, re.findall,
    obj.get, tempfile.mkdtemp) y cualquier archivo con extension no listada
    (release-2.ovpn, 4.ovpn). Resultado medido en gate.log: 256 force_ask
    contra 20 allow. El gate se vuelve ruido y el operador aprende a ignorarlo,
    que es peor que no tener gate.

QUE CAMBIA
    Solo se extraen candidatos de contextos donde de verdad hay un target:
      1. URL            https://host/...
      2. herramienta    nmap|curl|ping|Test-Connection|Invoke-WebRequest|...
      3. flag de host   -Host / -ComputerName / -Uri / -Url / -Server / -Target
    search_web solo mira URLs (buscar un dominio NO toca ese dominio).
    read_url_content mira la URL.
    ask_permission se mantiene estricto (poco volumen, mejor pecar de cauto).

    IPs: se ignoran las privadas / loopback / link-local por defecto (son ruido
    de lab/VPN). Con ANTIGRAVITY_GATE_PRIVATE_IPS=1 se vuelven a gatear.

LO QUE NO CAMBIA
    Un target real fuera de scope sigue dando force_ask. El registro, el match,
    los CATASTROPHIC y la proteccion de rutas de persistencia son identicos.
"""
import ipaddress
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
HOOKS = os.path.join(HOME, ".gemini", "config", "hooks")
for _p in (os.path.dirname(os.path.abspath(__file__)), HOOKS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scope_store import auto_capture, load_programs, match_target  # noqa: E402

STATE = os.path.join(HOME, ".gemini", "config", ".hook_state")
LOG = os.path.join(STATE, "gate-v2.log")

CATASTROPHIC = [
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+(/|~|\$HOME|\*)\s*$", "borrado recursivo de raiz/home"),
    (r"\bRemove-Item\b.*-Recurse.*\b(C:\\|C:/)\s*$", "borrado recursivo de C:\\"),
    (r"\bFormat-Volume\b|\bformat\s+[a-z]:", "formateo de volumen"),
    (r"\bdd\s+if=.*\bof=/dev/(sd|nvme)", "escritura cruda sobre disco"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "destruccion de base de datos"),
    (r"\bmkfs\.", "formateo de filesystem"),
]

# force_ask = pregunta SIEMPRE (ignora "Always Allow").
# ask       = pregunta pero respeta "Always Allow" del runtime (menos friccion).
# Solo se permiten esos dos: nunca "allow"/"deny" por variable de entorno.
_OUT = os.environ.get("ANTIGRAVITY_GATE_OUT_OF_SCOPE", "force_ask")
OUT_OF_SCOPE_DECISION = _OUT if _OUT in ("force_ask", "ask") else "force_ask"
GATE_PRIVATE_IPS = os.environ.get("ANTIGRAVITY_GATE_PRIVATE_IPS") == "1"
PENDING = os.path.join(STATE, "pending.json")

NOISE = {"localhost", "127.0.0.1", "0.0.0.0", "schemas.android.com",
         "w3.org", "json-schema.org", "github.com", "pypi.org", "npmjs.com",
         "python.org", "microsoft.com", "google.com", "gstatic.com",
         "antigravity.google", "accounts.google.com", "oauth2.googleapis.com",
         "cloudcode-pa.googleapis.com", "raw.githubusercontent.com"}

# Referencias (docs, social, registries) que nunca son target. Lista EXPLICITA
# del operador en noise.json. No se aprende del trafico del agente: un auto-scope
# que autoriza lo que el agente toca es, en la practica, apagar el gate.
NOISE_FILE = os.path.join(HOOKS, "noise.json")


def _load_noise():
    extra = set()
    try:
        with open(NOISE_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, list):
            extra = {str(x).strip().lower() for x in data if str(x).strip()}
    except Exception:
        pass
    return NOISE | extra


NOISE_SET = _load_noise()

EXT_RE = re.compile(
    r"\.(py|js|ts|jsx|tsx|json|md|txt|log|exe|dll|so|yaml|yml|toml|sh|ps1|"
    r"php|asp|aspx|jsp|html?|css|pdf|png|jpe?g|zip|ovpn|conf|cfg|ini|env|"
    r"bat|cmd|pem|crt|cer|key|p12|pfx|jks|der|csr|zip|7z|rar|tar|gz|"
    r"db|sql|pcap|cap|csv|xml|map|lock)$", re.I)

# token de target: IPv4 o dominio
_TOKEN = r"((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24})"

URL_HOST_RE = re.compile(r"https?://([^/\s:'\"<>)\]]+)", re.I)
NET_TOOL_RE = re.compile(
    r"\b(?:nmap|masscan|curl|wget|ping|ping6|tracert|traceroute|nslookup|dig|"
    r"host|whois|scp|sftp|ftp|nc|netcat|telnet|"
    r"Test-Connection|Test-NetConnection|Resolve-DnsName|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
    r"(?:\s+(?:-\S+|\d+))*\s+" + _TOKEN, re.I)
HOST_FLAG_RE = re.compile(
    r"-(?:Host|ComputerName|Uri|Url|Server|Target|Address)\s+[\"']?" + _TOKEN,
    re.I)

SSH_TOOL_RE = re.compile(r"(?<![\w.-])ssh(?=\s)", re.I)
SSH_VALUE_OPTIONS = {
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L",
    "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}


def _ssh_targets(text):
    """Extrae destinos SSH, incluidos user@host, sin leer identificadores de código."""
    targets = set()
    for match in SSH_TOOL_RE.finditer(text):
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
                index += 1 if "=" in arg else 2
            elif len(arg) > 2 and arg[:2] in SSH_VALUE_OPTIONS:
                index += 1
            else:
                index += 1

        if index < len(args):
            destination = args[index].rsplit("@", 1)[-1]
            token = re.search(_TOKEN, destination, re.I)
            if token:
                targets.add(token.group(1).lower())
    return targets
CMD_TOOLS = {"run_command": "CommandLine", "manage_task": "Input"}
TARGET_TEXT_TOOLS = {"read_url_content": "Url", "search_web": "query",
                     "ask_permission": "Target"}
WRITE_TOOLS = {"write_to_file": "TargetFile",
               "replace_file_content": "TargetFile",
               "multi_replace_file_content": "TargetFile"}

PROTECTED_PATH_RE = re.compile(
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
    r")", re.I)

LOG_MAX_BYTES = 2 * 1024 * 1024


def log(entry):
    try:
        os.makedirs(STATE, exist_ok=True)
        if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX_BYTES:
            os.replace(LOG, LOG + ".1")
        entry["ts"] = datetime.now(timezone.utc).isoformat()
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        pass


def record_pending(targets, text):
    """Cola de targets vistos fuera de scope, para revisar y autorizar en bloque."""
    try:
        os.makedirs(STATE, exist_ok=True)
        try:
            with open(PENDING, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        now = datetime.now(timezone.utc).isoformat()
        for t in targets:
            e = data.get(t) or {"count": 0}
            e["count"] = e.get("count", 0) + 1
            e["last"] = now
            e["sample"] = text[:200]
            data[t] = e
        with open(PENDING, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=True)
    except Exception:
        pass


def _host_from_url(raw):
    h = raw.rsplit("@", 1)[-1]
    h = h.split(":")[0]
    return h.strip(".").lower()


def _is_private(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _is_noise(host):
    return host in NOISE_SET or any(host.endswith("." + n) for n in NOISE_SET)


def _keep(host):
    if not host:
        return False
    if EXT_RE.search(host):
        return False
    if _is_noise(host):
        return False
    if _is_private(host) and not GATE_PRIVATE_IPS:
        return False
    return True


def extract_targets(text, is_cmd, tool):
    """Candidatos a target, solo desde contextos de red."""
    out = set()
    for m in URL_HOST_RE.finditer(text):
        out.add(_host_from_url(m.group(1)))

    if tool == "ask_permission":
        # Poco volumen y es literalmente "a que me autorizas": estricto.
        for m in re.finditer(_TOKEN, text, re.I):
            out.add(m.group(1).lower())
    elif is_cmd:
        out.update(_ssh_targets(text))
        for m in NET_TOOL_RE.finditer(text):
            out.add(m.group(1).lower())
        for m in HOST_FLAG_RE.finditer(text):
            out.add(m.group(1).lower())

    return {h for h in out if _keep(h)}


def decide_write(args, name):
    path = (args.get(WRITE_TOOLS[name]) or "").replace("\\", "/")
    if not path:
        print(json.dumps({"decision": "allow"}))
        return
    expanded = os.path.expanduser(path)
    if PROTECTED_PATH_RE.search(expanded):
        log({"event": "protected-write", "tool": name, "path": path})
        print(json.dumps({
            "decision": "force_ask",
            "reason": ("%s intenta escribir en %s, un punto de persistencia: lo "
                       "que quede ahi se ejecuta solo despues (hook config, git "
                       "hooks, perfil de shell). Aproba solo si es tu edicion."
                       % (name, path)),
        }))
        return
    log({"event": "write", "tool": name, "path": path})
    print(json.dumps({"decision": "allow"}))


def read_stdin():
    """Lee el payload tolerando el BOM de UTF-8.

    sys.stdin.read() decodifica con el codec locale: en Windows es cp1252, y el
    BOM UTF-8 que Windows PowerShell 5.1 antepone al pipe se convierte en
    "ï»¿"; el JSON no parsea y el gate falla abierto a allow.
    """
    data = sys.stdin.buffer.read()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode(sys.stdin.encoding or "utf-8", "replace")


def main():
    raw = read_stdin()
    if not raw.strip():
        print(json.dumps({"decision": "allow"}))
        return
    payload = json.loads(raw)
    call = payload.get("toolCall") or {}
    name = call.get("name", "")
    args = call.get("args") or {}

    if name in WRITE_TOOLS:
        decide_write(args, name)
        return

    if name in CMD_TOOLS:
        text = args.get(CMD_TOOLS[name]) or ""
        is_cmd = True
    elif name in TARGET_TEXT_TOOLS:
        text = args.get(TARGET_TEXT_TOOLS[name]) or ""
        is_cmd = False
    else:
        print(json.dumps({"decision": "allow"}))
        return

    if not text or not isinstance(text, str):
        print(json.dumps({"decision": "allow"}))
        return

    log({"event": "pre", "tool": name, "text": text,
         "cid": payload.get("conversationId")})

    if is_cmd:
        for pattern, why in CATASTROPHIC:
            if re.search(pattern, text, re.I):
                log({"event": "deny", "why": why, "text": text})
                print(json.dumps({
                    "decision": "deny",
                    "reason": "Bloqueado por scope_gate: " + why + ". Si es "
                              "intencional, corre el comando a mano fuera del "
                              "agente.",
                }))
                return

    if payload.get("transcriptPath"):
        try:
            for slug in auto_capture(payload["transcriptPath"]):
                log({"event": "capture", "slug": slug})
        except Exception as exc:
            log({"event": "capture-error", "error": repr(exc)})

    programs = load_programs()
    if not programs:
        log({"event": "warn", "why": "registro vacio", "text": text})
        print(json.dumps({
            "decision": "allow",
            "reason": "Sin programas registrados. Pega el alcance de un programa en "
                      "el chat o corre scope_add.py. Este comando pasa sin validar.",
        }))
        return

    candidates = extract_targets(text, is_cmd, name)
    if not candidates:
        log({"event": "allow", "tool": name, "targets": []})
        print(json.dumps({"decision": "allow", "reason": "sin targets de red en el texto"}))
        return

    problems = []
    for target in sorted(candidates):
        res = match_target(target)
        if res["authorized"]:
            log({"event": "authorized", "target": target, "by": res["authorized"]})
            continue
        if res["excluded"]:
            problems.append("%s excluido explicitamente en %s"
                            % (target, ", ".join(res["excluded"])))
        elif res["expired"]:
            problems.append("%s: el alcance de %s vencio"
                            % (target, ", ".join(res["expired"])))
        else:
            problems.append("%s sin programa que lo autorice" % target)

    if problems:
        record_pending(sorted(candidates), text)
        log({"event": "ask", "problems": problems, "text": text})
        print(json.dumps({
            "decision": OUT_OF_SCOPE_DECISION,
            "reason": ("Sin autorizacion vigente: " + "; ".join(problems) +
                       ". Programas cargados: " +
                       ", ".join(p["slug"] for p in programs) +
                       ". Para autorizar un host: echo <host> | python scope_add.py. "
                       "Si es una referencia (docs/social), agregalo a noise.json."),
        }))
        return

    log({"event": "allow", "tool": name, "targets": sorted(candidates)})
    print(json.dumps({"decision": "allow", "reason": "target in-scope"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log({"event": "error", "error": repr(exc)})
        print(json.dumps({"decision": "allow", "reason": "scope_gate error (fail-open)"}))
