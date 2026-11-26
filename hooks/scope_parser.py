#!/usr/bin/env python3
"""
scope_parser.py - Extrae assets in-scope / out-of-scope de texto pegado tal cual.

La idea: pegas el alcance del programa (HackerOne, Bugcrowd, Intigriti, un mail
del cliente, prosa en espanol) sin formatear nada, y esto saca los assets.

Formatos soportados:
  - Tablas de HackerOne/Bugcrowd con pipes, prioridades P1-P5 y bounties
  - Listas con - / * / checkboxes / backticks / bold
  - URLs con esquema, puerto y path
  - Wildcards (*.example.com), CIDRs (10.0.0.0/24), IPv4 sueltas
  - Secciones en espanol o ingles (In scope / Alcance / Out of scope / Excluido)
  - Sin encabezados: todo lo que parezca asset cuenta como in-scope

Uso:
    from scope_parser import parse_text, parse_file
    p = parse_file(path)
    p["in"]   -> ["*.example.com", "10.10.0.0/24", ...]
    p["out"]  -> ["blog.example.com", ...]
"""
import ipaddress
import re

# Dominios de plataformas y tooling: nunca son assets del cliente.
# OJO con la segunda mitad de la lista: los stores de apps y las redes aparecen
# como LINK de referencia en la tabla de assets ("1483903423 ->
# https://apps.apple.com/app/1483903423"). Sin filtrarlos, un solo paste
# autorizaba escanear apple.com, youtube.com y vimeo.com.
PLATFORM_NOISE = {
    "hackerone.com", "bugcrowd.com", "intigriti.com", "intigriti.me",
    "yeswehack.com", "synack.com", "openbugbounty.org", "huntr.dev",
    "github.com", "githubusercontent.com", "google.com", "gstatic.com",
    "microsoft.com", "python.org", "pypi.org", "npmjs.com", "w3.org",
    "json-schema.org", "antigravity.google", "accounts.google.com",
    "oauth2.googleapis.com", "cloudcode-pa.googleapis.com",
    "schemas.android.com",
    # stores de apps y referencias
    "apple.com", "itunes.apple.com", "youtube.com", "youtu.be", "vimeo.com",
    "linkedin.com", "facebook.com", "twitter.com", "medium.com",
    "gitlab.com", "bitbucket.org", "atlassian.net", "pastebin.com",
    "imgur.com", "wikipedia.org", "securitytxt.org", "slack.com",
    "discord.com", "discord.gg", "notion.so", "dropbox.com",
}

# Sufijos de segundo nivel: el apex es de 3 etiquetas, no 2.
TWO_LEVEL = {
    "com.ar", "com.br", "com.mx", "com.co", "com.pe", "com.cl", "com.au",
    "co.uk", "co.jp", "co.in", "co.za", "co.kr", "co.il", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.ua", "com.pl", "com.cn", "net.ar", "org.ar",
    "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
}

# Identificadores de app (Android/iOS) y valores de `id=`/`package=` en links de
# store. Son assets legitimos del programa, pero NO son hosts: si entran a la
# lista de hosts, el registro queda con basura tipo com.bitvavo.android.
PKG_RE = re.compile(
    r"\b(?:id|package|bundle(?:\s*id)?)\s*[=:]\s*"
    r"([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})", re.I)
PKG_HEAD = {"com", "org", "net"}

# A partir de esta longitud vale la pena buscar typos entre dominios.
TYPO_MIN_LEN = 8


SECTION_IN = re.compile(
    r"\b(in[\s\-_]?scope|in[\s\-_]?scope\s+assets?|scope|alcance|"
    r"targets?|assets?|dominios?\s+(?:incluidos|permitidos)|objetivos?)\b", re.I)
SECTION_OUT = re.compile(
    r"\b(out[\s\-_]?of[\s\-_]?scope|out[\s\-_]?scope|fuera\s+de\s+alcance|"
    r"excluid[oa]s?|no\s+(?:estan?|está|aplica)|not\s+in\s+scope|prohibit)", re.I)
# Secciones que NO son alcance: metadata, RoE, notas. Sus dominios no cuentan.
SECTION_IGNORE = re.compile(
    r"\b(datos|metadata|metadatos|programa|program|notas?|notes?|roe|"
    r"reglas\s+de\s+engagement|vigencia|contacto|autorizacion|autorización|"
    r"proveedor|cliente|historial)\b", re.I)

URL_RE = re.compile(r"https?://\s*([a-z0-9._\-]+)(?::\d+)?", re.I)
# Wildcard estricto: un solo '*', no parte de '**' (markdown), y detras tiene
# que haber un dominio real. Evita que "**texto**." se lea como wildcard.
# TLDs de laboratorio que sí valen como wildcard de una sola etiqueta (*.htb).
# Un *.com sigue sin parsear: eso autorizaria medio internet.
LAB_TLDS = r"htb|local|lab|test|internal"
WILD_RE = re.compile(
    r"(?<!\*)\*\s*\.((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24}"
    r"|(?:htb|local|lab|test|internal))", re.I)
CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
EXT_RE = re.compile(r"\.(py|js|ts|jsx|tsx|json|md|txt|log|exe|dll|so|yaml|yml|"
                    r"toml|sh|ps1|php|asp|aspx|jsp|html?|css|pdf|png|jpe?g|zip)$", re.I)

# Basura de tablas y listas que no aporta. OJO: el '*' NO se limpia, porque
# distingue un wildcard (*.example.com) de un dominio raiz.
STRIP_RE = re.compile(r"[|`_\[\]{}()<>#]|^\s*[-+]\s+|^\s*\d+[.)]\s+", re.M)


def _clean(line):
    line = STRIP_RE.sub(" ", line)
    line = re.sub(r"\bP[1-5]\b", " ", line)          # prioridades Bugcrowd
    line = re.sub(r"\$\s?[\d,]+(?:\.\d+)?", " ", line)  # bounties
    line = re.sub(r"\b(?:yes|no|true|false|n/?a)\b", " ", line, flags=re.I)
    return line


def _assets_in(line):
    """Assets plausibles de una linea, con su posicion: [(asset, pos), ...]."""
    out = []
    for m in URL_RE.finditer(line):
        out.append((m.group(1).lower(), m.start()))
    for m in WILD_RE.finditer(line):
        out.append(("*." + m.group(1).lower().strip("."), m.start()))
    for m in CIDR_RE.finditer(line):
        out.append((m.group(1), m.start()))
    for m in IP_RE.finditer(line):
        ip = m.group(1)
        if not any(ip == a.split("/")[0] for a, _ in out):
            out.append((ip, m.start()))
    for m in DOMAIN_RE.finditer(line):
        host = m.group(1).lower().strip(".")
        if not EXT_RE.search(host):
            out.append((host, m.start()))
    seen, uniq = set(), []
    for asset, pos in out:
        if asset not in seen:
            seen.add(asset)
            uniq.append((asset, pos))

    # Si la linea declara *.example.com, no agregar tambien example.com:
    # el wildcard cubre subdominios, no el raiz. Ensanchar el scope seria
    # autorizar algo que el programa no incluyo.
    wild_bases = {a[2:] for a, _ in uniq if a.startswith("*.")}
    return [(a, p) for a, p in uniq
            if a.startswith("*.") or a not in wild_bases]


def _is_noise(asset):
    host = asset.lstrip("*.").split("/")[0]
    if host in PLATFORM_NOISE:
        return True
    if any(host.endswith("." + n) for n in PLATFORM_NOISE):
        return True
    if host in ("localhost", "0.0.0.0", "127.0.0.1"):
        return True
    return False


def apex(host):
    """Dominio registrable aproximado: api.acme.com.ar -> acme.com.ar."""
    host = (host or "").lstrip("*.").split("/")[0].split(":")[0].strip(".").lower()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_package(value):
    """com.bitvavo.android / org.example.app -> identificador de app, no host."""
    v = (value or "").lstrip("*.").lower()
    parts = v.split(".")
    if len(parts) < 3:
        return False
    if not all(re.match(r"^[a-z][a-z0-9_]*$", p) for p in parts):
        return False
    return parts[0] in PKG_HEAD


def _near(a, b):
    """True si a y b difieren en <=1 edicion, o en un swap adyacente.

    Esto es lo que atrapa `api.bitavo.com` (falta una 'v') cuando el resto del
    programa dice bitvavo.com. Un dominio asi NO es del cliente: registrarlo como
    autorizado es apuntar el escaneo a un tercero.
    """
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        if (len(diff) == 2 and diff[1] == diff[0] + 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]):
            return True
        return False
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(s) and j < len(l):
        if s[i] == l[j]:
            i, j = i + 1, j + 1
        elif skipped:
            return False
        else:
            skipped, j = True, j + 1
    return True



def parse_text(text):
    """Devuelve {"in": [...], "out": [...], "suspect": [...], "packages": [...],
    "headers": True/False}.

    `suspect` son assets que parecen un typo del paste (near-miss de otro apex).
    No se autorizan: se listan para que el operador confirme.
    """
    in_assets, out_assets = [], []
    packages = set()
    section = None
    saw_header = False
    pending_out = 0  # prosa: "queda excluido X" puede caer en la linea siguiente

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Encabezado markdown: define la seccion ANTES de extraer assets. Si no,
        # un titulo como "# Programa: acme.com" mete "acme.com" en in-scope y
        # ensancha el alcance en silencio.
        m_head = re.match(r"^#{1,6}\s*(.*)$", line)
        if m_head:
            body = m_head.group(1)
            if SECTION_OUT.search(body):
                section, saw_header, pending_out = "out", True, 2
            elif SECTION_IGNORE.search(body):
                section, pending_out = "ignore", 0
            elif SECTION_IN.search(body):
                section, saw_header, pending_out = "in", True, 0
            else:
                section, pending_out = "ignore", 0
            line = body

        cleaned = _clean(line)

        # Identificadores de app: son assets, pero no hosts.
        pkgs = {m.group(1).lower() for m in PKG_RE.finditer(cleaned)}
        raw_found = _assets_in(cleaned)
        for a, _ in raw_found:
            if is_package(a):
                pkgs.add(a)
        packages |= pkgs

        found = [(a, p) for a, p in raw_found
                 if not _is_noise(a) and a not in pkgs]

        if found:
            if section == "ignore":
                pending_out = max(0, pending_out - 1)
                continue

            m_out = SECTION_OUT.search(cleaned)
            cut = m_out.start() if m_out else None
            carries = pending_out > 0 and not SECTION_IN.search(cleaned)

            for asset, pos in found:
                if cut is not None and pos < cut and section != "out":
                    in_assets.append(asset)
                elif section == "out" or cut is not None or carries:
                    out_assets.append(asset)
                else:
                    in_assets.append(asset)

            if cut is not None:
                pending_out = 2  # el excluido puede seguir en la linea proxima
            pending_out = max(0, pending_out - 1)
            continue

        # Sin assets: puede ser un encabezado de seccion.
        if len(line) < 90:
            if SECTION_OUT.search(line):
                section, saw_header, pending_out = "out", True, 2
            elif SECTION_IGNORE.search(line):
                section = "ignore"
            elif SECTION_IN.search(line):
                section, saw_header, pending_out = "in", True, 0
        pending_out = max(0, pending_out - 1)

    def dedupe(seq):
        seen, res = set(), []
        for a in seq:
            if a not in seen:
                seen.add(a)
                res.append(a)
        return res

    in_final = dedupe(in_assets)
    out_final = [a for a in dedupe(out_assets) if a not in in_final]

    # www.foo.com no aporta nada si ya esta foo.com. Suele venir de la prosa
    # ("Visit our website: www.bitvavo.com"), o sea que no es una declaracion de
    # alcance: mejor no ensanchar el registro con variantes que nadie listo.
    bases = {a for a in in_final if not a.startswith("*.")}
    in_final = [a for a in in_final
                if not (a.startswith("www.") and a[len("www."):] in bases)]

    in_final, suspect = _split_typos(in_final, out_final)
    out_final = [a for a in out_final if a not in suspect]

    return {
        "in": in_final,
        "out": out_final,
        "suspect": suspect,
        "packages": sorted(packages),
        "headers": saw_header,
    }


def _split_typos(in_assets, out_assets):
    """Separa los assets cuyo apex es un near-miss de otro apex del mismo paste.

    El caso real: un programa escribe `api.bitavo.com` donde el resto dice
    `bitvavo.com`. Ese dominio no es del cliente. Si el registro lo toma como
    autorizado, el gate manda escanear un dominio de un tercero y el operador
    queda expuesto; el paste no lo declara como out-of-scope porque nadie noto el
    typo. Ante la duda no se autoriza: queda en `suspect` y decide el operador.
    """
    hosts = [a for a in in_assets + out_assets if not a[0].isdigit()]
    counts = {}
    for a in hosts:
        ap = apex(a)
        if ap:
            counts[ap] = counts.get(ap, 0) + 1

    suspect_apex = set()
    for ap, n in counts.items():
        if len(ap) < TYPO_MIN_LEN:
            continue
        for rival, rn in counts.items():
            if rival == ap or len(rival) < TYPO_MIN_LEN:
                continue
            # n <= rn: el sospechoso es el menos frecuente. Si empatan, tambien
            # se marca: con dos grafias del mismo nombre no se elige a dedo.
            if _near(ap, rival) and n <= rn:
                suspect_apex.add(ap)
                break

    if not suspect_apex:
        return in_assets, []
    keep, suspect = [], []
    for a in in_assets:
        (suspect if apex(a) in suspect_apex else keep).append(a)
    return keep, suspect



def parse_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return parse_text(f.read())
    except FileNotFoundError:
        return {"in": [], "out": [], "headers": False}


def matches(host, patterns):
    """True si `host` cae dentro de algun patron.

    Semantica deliberada: *.example.com cubre subdominios, NO el dominio raiz.
    Un wildcard nunca autoriza su base por si solo.
    """
    host = (host or "").lower().strip(".")
    if not host:
        return False

    # IP / CIDR
    try:
        addr = ipaddress.ip_interface(host).ip if "/" in host else ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        for p in patterns:
            if "/" in p:
                try:
                    if addr in ipaddress.ip_network(p, strict=False):
                        return True
                except ValueError:
                    continue
            elif str(addr) == p:
                return True
        return False

    for p in patterns:
        if p.startswith("*."):
            if host.endswith(p[1:]):
                return True
        elif host == p or host.endswith("." + p):
            return True
    return False


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "~/.gemini/config/engagements/active.md"
    import os
    print(json.dumps(parse_file(os.path.expanduser(target)), indent=2, ensure_ascii=False))
