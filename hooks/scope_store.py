#!/usr/bin/env python3
"""
scope_store.py - Registro multi-programa de alcances autorizados.

EL PROBLEMA
    Un unico active.md obliga a editar un archivo por cada programa. Si evaluas
    decenas de programas, eso no escala: o lo abandonas, o el gate queda
    desactualizado (peor: con el alcance del programa anterior, que es un
    incumplimiento de contrato esperando a pasar).

EL MODELO CORRECTO
    La autorizacion es del ASSET, no de la sesion. Si api.acme.com figura en el
    alcance vigente del programa de Acme, esta autorizado sin importar en que
    conversacion lo escanees. Entonces el sistema no necesita "el programa
    activo": necesita el REGISTRO de todos, y matchea contra la union.

    engagements/programs/<slug>.md   un archivo por programa, generado solo
    engagements/programs/<slug>.raw.txt   el paste original, como evidencia

COMO ENTRA UN PROGRAMA (sin editar nada a mano)
    1. Lo pegas en el chat -> auto_capture() lo detecta en el transcript y lo
       registra automaticamente en el primer tool call.
    2. python scope_add.py -> toma el portapapeles (o stdin) y lo registra.
    3. Dejas un .md en engagements/programs/ -> lo levanta el proximo gate.

    Un target esta autorizado si CUALQUIER programa vigente lo incluye.
"""
import hashlib
import ipaddress
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scope_parser import apex, matches, parse_text  # noqa: E402

HOME = os.path.expanduser("~")
STATE = os.path.join(HOME, ".gemini", "config", ".hook_state")
ENG_DIR = (os.environ.get("ANTIGRAVITY_ENGAGEMENTS_DIR")
           or os.path.join(HOME, ".gemini", "config", "engagements", "programs"))
# Override de un solo archivo: lo usan las suites de test.
SINGLE = os.environ.get("ANTIGRAVITY_SCOPE_FILE")
CACHE = (os.environ.get("ANTIGRAVITY_CAPTURE_CACHE")
         or os.path.join(STATE, "capture_cache.json"))

# Sin fecha de vigencia en el paste, el alcance se asume valido 90 dias.
# Razon: los programas rotan alcance; un scope eterno es la forma mas comun de
# escanear algo que ya salio del programa. Vencido = force_ask, nunca deny, asi
# que el costo de equivocarse es una pregunta, no un bloqueo.
AUTO_EXPIRY_DAYS = 90

# Dominios de documentacion. Si un paste SOLO tiene estos, no es un programa:
# es el ejemplo de un tutorial. No se registra (evita autoregistrar basura).
DOC_EXAMPLES = {
    "example.com", "example.net", "example.org", "example.edu",
    "ejemplo.com", "ejemplo.net", "midominio.io", "acme-corp.io",
    "cliente.com", "dominio.com", "tudominio.com", "foo.com", "bar.com",
    "test.local", "invalid", "localhost",
}

SCOPE_HINT = re.compile(
    r"(in[-\s]?scope|out[-\s]?of[-\s]?scope|alcance|asset\s+identifier|"
    r"wildcard|fuera\s+de\s+alcance|scope\s+exclusion|bounty|prioridad|"
    r"asset\s+type|coverage)", re.I)

STRONG_HINT = re.compile(
    r"(in[-\s]?scope|out[-\s]?of[-\s]?scope|asset\s+identifier|"
    r"fuera\s+de\s+alcance|alcance\s+autorizado)", re.I)

# `apex()` y `TWO_LEVEL` viven en scope_parser: los necesita la deteccion de
# typos, que corre al parsear. `apex` se reexporta aca para no romper imports.
_CACHE = {}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
__all__ = ["add_program", "load_programs", "match_target", "registry_summary",
           "looks_like_scope", "auto_capture", "apex", "is_doc_example"]


def _section_items(text, key):
    """Items de la seccion '## ...<key>...' del archivo renderizado.

    Solo acepta lineas sin espacios: un asset nunca los tiene, y asi la prosa
    explicativa que acompana a la seccion no se toma como item.
    """
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = key.lower() in line.lower()
            continue
        if inside:
            s = line.strip()
            if s and " " not in s and "\t" not in s:
                out.append(s)
    return out



def is_doc_example(asset):
    host = (asset or "").lstrip("*.").split("/")[0].lower()
    return host in DOC_EXAMPLES or apex(host) in DOC_EXAMPLES


def _slug_for(assets):
    counts = {}
    for a in assets:
        if re.match(r"^\d", a):
            continue
        ap = apex(a)
        if ap:
            counts[ap] = counts.get(ap, 0) + 1
    if counts:
        return max(counts.items(), key=lambda kv: kv[1])[0]
    for a in assets:
        if re.match(r"^\d", a):
            return "ip-" + a.replace("/", "-").replace(".", "-")
    return None


def _parse_meta(text):
    meta = {}
    m = re.search(r"(?im)^\s*[-*]?\s*(?:programa|program|nombre|name)\s*:\s*(.+)$", text)
    if m:
        meta["name"] = m.group(1).strip()[:80]
    m = re.search(r"(?im)^\s*[-*]?\s*(?:plataforma|platform)\s*:\s*(.+)$", text)
    if m:
        meta["platform"] = m.group(1).strip()[:40]
    else:
        low = text.lower()
        for p in ("hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "huntr"):
            if p + ".com" in low or p + ".dev" in low:
                meta["platform"] = p.capitalize()
                break
    m = re.search(r"(?im)^\s*[-*]?\s*(?:id\s+de\s+autorizaci[oó]n|authorization\s+id|"
                  r"engagement\s+id|id\s+de\s+engagement)\s*:\s*(\S+)", text)
    if m:
        meta["auth_id"] = m.group(1).strip()[:60]

    expires = None
    for line in text.splitlines():
        if re.search(r"(?i)(expira|vigencia|valid\s+until|expires|vence)", line):
            for d in re.findall(r"\d{4}-\d{2}-\d{2}", line):
                if expires is None or d > expires:
                    expires = d
            for d in re.findall(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b", line):
                iso = "%s-%02d-%02d" % (d[2], int(d[1]), int(d[0]))
                if expires is None or iso > expires:
                    expires = iso
    meta["expires"] = expires
    return meta


def _content_text(value):
    """Normaliza el contenido de un step del transcript a texto plano."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for b in value:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict):
                parts.append(b.get("text") or b.get("content") or "")
        return "\n".join(p for p in parts if p)
    if isinstance(value, dict):
        return value.get("text") or value.get("content") or ""
    return ""


# --------------------------------------------------------------------------
# persistencia
# --------------------------------------------------------------------------
def _render(p):
    lines = ["# Programa: " + p["slug"], ""]
    lines.append("- Slug: " + p["slug"])
    lines.append("- Nombre: " + (p.get("name") or p["slug"]))
    lines.append("- Plataforma: " + (p.get("platform") or "desconocida"))
    lines.append("- ID autorizacion: " + (p.get("auth_id") or "-"))
    lines.append("- Creado: " + p.get("created", ""))
    lines.append("- Actualizado: " + p.get("updated", ""))
    if p.get("expires"):
        lines.append("- Expira: " + p["expires"])
    if p.get("auto_expiry"):
        lines.append("- Auto-expira: si (%d dias)" % AUTO_EXPIRY_DAYS)
    lines.append("- Origen: " + (p.get("origin") or "manual"))
    lines.append("")
    lines.append("## In-scope")
    lines.append("")
    for a in p["in"]:
        lines.append(a)
    lines.append("")
    lines.append("## Fuera de alcance")
    lines.append("")
    for a in p["out"]:
        lines.append(a)
    lines.append("")
    # Secciones informativas: el parser las ignora al releer (encabezado
    # desconocido -> ignore), asi que NO autorizan nada. Estan para que el
    # operador vea que el paste tenia esto y no se perdio.
    if p.get("suspect"):
        lines.append("## Sin confirmar (posible typo del paste: NO autoriza)")
        lines.append("")
        lines.append("El paste escribe uno de estos dominios distinto al resto. Si")
        lines.append("el cliente no lo declaro aparte, es un typo y el dominio es de")
        lines.append("un tercero: NO lo toques sin confirmar con el programa.")
        lines.append("")
        for a in p["suspect"]:
            lines.append(a)
        lines.append("")
    if p.get("packages"):
        lines.append("## Apps (identificadores, no hosts)")
        lines.append("")
        for a in p["packages"]:
            lines.append(a)
        lines.append("")
    return "\n".join(lines)


def _load_one(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_mtime, st.st_size)
    if key in _CACHE:
        return _CACHE[key]

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None

    parsed = parse_text(text)
    meta = _parse_meta(text)
    prog = {
        "slug": os.path.splitext(os.path.basename(path))[0],
        "file": path,
        "in": parsed["in"],
        "out": parsed["out"],
        "name": meta.get("name") or os.path.splitext(os.path.basename(path))[0],
        "platform": meta.get("platform") or "desconocida",
        "auth_id": meta.get("auth_id") or "-",
        "expires": meta.get("expires"),
        "auto_expiry": bool(re.search(r"(?im)^\s*-\s*auto-expira\s*:\s*si", text)),
        "origin": "file",
        "suspect": _section_items(text, "Sin confirmar"),
        "packages": _section_items(text, "Apps ("),
    }
    m = re.search(r"(?im)^\s*-\s*creado\s*:\s*(\S+)", text)
    prog["created"] = m.group(1) if m else ""
    m = re.search(r"(?im)^\s*-\s*origen\s*:\s*(\S+)", text)
    if m:
        prog["origin"] = m.group(1)
    _CACHE[key] = prog
    return prog


def load_programs():
    """Todos los programas del registro (o el override de un solo archivo)."""
    if SINGLE:
        p = _load_one(SINGLE)
        return [p] if p else []
    if not os.path.isdir(ENG_DIR):
        return []
    progs = []
    for name in sorted(os.listdir(ENG_DIR)):
        if not name.endswith(".md"):
            continue
        p = _load_one(os.path.join(ENG_DIR, name))
        if p and p["in"]:
            progs.append(p)
    return progs


def add_program(text, origin="manual"):
    """Registra (o amplia) un programa a partir de un paste crudo.

    Devuelve el dict del programa, o None si el texto no aporta ningun asset
    real (por ejemplo, un paste de ejemplo con example.com).
    """
    if not text or not text.strip():
        return None
    parsed = parse_text(text)
    ins = [a for a in parsed["in"] if not is_doc_example(a)]
    if not ins:
        return None

    slug = _slug_for(ins)
    if not slug:
        return None

    os.makedirs(ENG_DIR, exist_ok=True)
    path = os.path.join(ENG_DIR, slug + ".md")
    today = date.today().isoformat()
    meta = _parse_meta(text)

    prev = _load_one(path)
    prog = {
        "slug": slug,
        "name": meta.get("name") or (prev or {}).get("name") or slug,
        "platform": meta.get("platform") or (prev or {}).get("platform") or "desconocida",
        "auth_id": meta.get("auth_id") or (prev or {}).get("auth_id") or "-",
        "created": (prev or {}).get("created") or today,
        "updated": today,
        "origin": origin,
        "in": list((prev or {}).get("in") or []),
        "out": list((prev or {}).get("out") or []),
        "expires": meta.get("expires") or (prev or {}).get("expires"),
        "auto_expiry": (prev or {}).get("auto_expiry", False),
        "suspect": list((prev or {}).get("suspect") or []),
        "packages": list((prev or {}).get("packages") or []),
    }

    for a in ins:
        if a not in prog["in"]:
            prog["in"].append(a)
    for a in parsed["out"]:
        if a not in prog["out"]:
            prog["out"].append(a)
    for a in parsed.get("suspect") or []:
        if a not in prog["suspect"]:
            prog["suspect"].append(a)
    for a in parsed.get("packages") or []:
        if a not in prog["packages"]:
            prog["packages"].append(a)
    # Un asset no puede estar autorizado y excluido a la vez dentro del mismo
    # programa: si el paste se contradice, gana la exclusion (lado seguro).
    prog["out"] = [a for a in prog["out"] if a not in prog["in"]]
    # Y algo sospechoso nunca queda autorizado, ni aunque otro paste del mismo
    # programa lo haya listado: eso es exactamente el error que se quiere evitar.
    for a in prog["suspect"]:
        if a in prog["in"]:
            prog["in"].remove(a)

    if not prog["expires"]:
        prog["expires"] = (date.today() + timedelta(days=AUTO_EXPIRY_DAYS)).isoformat()
        prog["auto_expiry"] = True

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(_render(prog))

    # Evidencia: el paste original queda guardado, sin interpretar.
    raw = os.path.join(ENG_DIR, slug + ".raw.txt")
    with open(raw, "a", encoding="utf-8", newline="\n") as f:
        f.write("\n===== %s (%s) =====\n%s\n"
                % (datetime.now(timezone.utc).isoformat(), origin, text.strip()))

    _CACHE.pop((path, os.path.getmtime(path), os.path.getsize(path)), None)
    return prog


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------
def _specificity(host, patterns):
    """(exacto, wildcard) de un host contra una lista de patrones.

    "exacto" incluye IPs dentro de un CIDR: 10.20.0.5 es exacto contra
    10.20.0.0/24, y un CIDR es tan especifico como un host literal.
    """
    exact = any(p == host for p in patterns)
    wild = any(p.startswith("*.") and host.endswith(p[1:]) for p in patterns)
    if exact or wild:
        return exact, wild

    try:
        addr = ipaddress.ip_interface(host).ip if "/" in host else ipaddress.ip_address(host)
    except ValueError:
        return exact, wild
    for p in patterns:
        if "/" in p:
            try:
                if addr in ipaddress.ip_network(p, strict=False):
                    return True, wild
            except ValueError:
                continue
        elif str(addr) == p:
            return True, wild
    return exact, wild


def match_target(host):
    """Quien autoriza / excluye / tenia vencido este host.

    Precedencia (la misma que usan los programas reales):
      1. Un in-scope EXACTO le gana a un out-of-scope wildcard.
      2. Cualquier out-of-scope (exacto o wildcard) excluye.
      3. El resto de los in-scope autoriza.

    O sea: *.acme.com in-scope + legacy.acme.com out-of-scope = legacy queda
    fuera, aunque el wildcard lo cubra. La exclusion explicita siempre carvea.
    """
    host = (host or "").lower().strip(".")
    res = {"authorized": [], "excluded": [], "expired": []}
    if not host:
        return res
    today = date.today().isoformat()

    for p in load_programs():
        in_exact, in_wild = _specificity(host, p["in"])
        if not (in_exact or in_wild) and host.startswith("www."):
            # www.foo.com y foo.com son el mismo servicio web. Muchos programas
            # declaran solo el apex: pedir permiso por el www seria ruido puro en
            # el caso mas comun. El registro NO se ensancha: esto es semantica de
            # matching, y solo aplica a autorizacion (las exclusiones siguen
            # estrictas, para no sacar del alcance algo que el programa listo).
            in_exact, in_wild = _specificity(host[4:], p["in"])
        out_exact, out_wild = _specificity(host, p["out"])

        if out_exact:
            res["excluded"].append(p["slug"])
            continue
        if out_wild and not in_exact:
            res["excluded"].append(p["slug"])
            continue
        if not (in_exact or in_wild):
            continue
        if p.get("expires") and p["expires"] < today:
            res["expired"].append(p["slug"])
        else:
            res["authorized"].append(p["slug"])
    return res


def registry_summary():
    progs = load_programs()
    today = date.today()
    expiring = []
    for p in progs:
        try:
            exp = date.fromisoformat(p["expires"]) if p.get("expires") else None
        except (ValueError, TypeError):
            exp = None
        if exp:
            days = (exp - today).days
            if days <= 14:
                expiring.append((p["slug"], p["expires"], days))
    return {
        "programs": len(progs),
        "assets_in": sum(len(p["in"]) for p in progs),
        "assets_out": sum(len(p["out"]) for p in progs),
        "suspects": sum(len(p.get("suspect") or []) for p in progs),
        "expiring": sorted(expiring, key=lambda t: t[1]),
        "slugs": [p["slug"] for p in progs],
    }


# --------------------------------------------------------------------------
# autoregistro desde el transcript
# --------------------------------------------------------------------------
KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "asia", "tel", "travel", "jobs", "cat", "coop", "aero",
    "museum", "post", "xxx",
    "io", "ai", "app", "dev", "xyz", "online", "site", "tech", "store", "blog",
    "cloud", "digital", "agency", "solutions", "systems", "network", "security",
    "software", "services", "consulting", "global", "group", "world", "live",
    "life", "media", "news", "social", "email", "design", "studio", "works",
    "tools", "zone", "space", "host", "website", "press", "wiki", "academy",
    "school", "institute", "foundation", "charity", "community", "company",
    "enterprises", "industries", "ventures", "capital", "finance", "bank",
    "insurance", "legal", "realestate", "properties", "rentals", "tours",
    "hotel", "restaurant", "cafe", "bar", "pub", "shop", "market", "sale",
    "deals", "games", "play", "fun", "ninja", "guru", "expert", "rocks",
    "cool", "page", "link", "click", "download", "stream", "video", "audio",
    "music", "photo", "pics", "gallery", "art", "fashion", "style", "shoes",
    "clothing", "football", "soccer", "basketball", "tennis", "golf",
    "hockey", "cricket", "racing", "bike", "cars", "auto", "taxi", "flights",
    "holidays", "vacation", "camping", "fishing", "hiking", "yoga", "fitness",
    "health", "care", "clinic", "doctor", "dentist", "pharmacy", "hospital",
    "medical", "dental", "vision", "diet", "weight", "beauty", "spa",
    "massage", "wedding", "gifts", "flowers", "coffee", "tea", "beer", "wine",
    "pizza", "sushi", "recipes", "cooking", "kitchen", "garden", "home",
    "house", "realty", "estate", "apartments", "villas", "land", "farm",
    "ranch", "city", "town", "church", "faith", "bible", "islam", "jewish",
    "hindu", "buddhist", "meditation", "spiritual", "astrology", "tarot",
    "psychic", "magic", "poker", "casino", "betting", "lottery", "bingo",
    "slots", "vegas", "dating", "singles", "love", "romance", "baby", "kids",
    "family", "parents", "genealogy", "history", "camera", "film", "movie",
    "cinema", "theater", "band", "radio", "podcast", "tv", "streaming",
    "sports", "baseball", "boxing", "mma", "wrestling", "motors", "trucks",
    "boats", "yachts", "resort", "food", "organic", "vegan", "glutenfree",
    "credit", "loans", "mortgage", "attorney", "lawyer", "tax", "accounting",
    "marketing", "advertising", "web", "hosting", "apps", "mobile", "phone",
    "internet", "data", "ml", "blockchain", "crypto", "nft", "metaverse",
    "vr", "ar", "gaming", "esports",
    "us", "uk", "ca", "au", "nz", "de", "fr", "es", "it", "nl", "be", "ch",
    "at", "se", "no", "fi", "dk", "ie", "pt", "gr", "pl", "cz", "sk", "hu",
    "ro", "bg", "hr", "si", "rs", "ua", "ru", "by", "kz", "tr", "il", "sa",
    "ae", "eg", "za", "ng", "ke", "ma", "tn", "cn", "jp", "kr", "in", "pk",
    "bd", "lk", "np", "sg", "my", "id", "th", "vn", "ph", "hk", "tw", "mo",
    "br", "mx", "ar", "cl", "co", "pe", "ve", "ec", "uy", "py", "bo", "cr",
    "pa", "do", "gt", "sv", "hn", "ni", "cu", "pr", "tt", "jm", "bs", "bb",
    "gd", "lc", "vc", "ag", "dm", "kn", "ht",
}

CODE_HINT = re.compile(
    r"(?:import\s+\w|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*[:\(]|"
    r"self\.\w+|print\s*\(|json\.(?:loads|dumps|load|dump)|"
    r"os\.path\b|re\.(?:findall|finditer|search|compile|sub|match))")


def _plausible_asset(asset):
    """Un asset de scope es un host/IP/wildcard/CIDR, no un identificador."""
    a = (asset or "").strip().lower()
    if not a:
        return False
    if a.startswith("*.") or "/" in a or "://" in a:
        return True
    if a[0].isdigit():
        return True
    return a.rsplit(".", 1)[-1] in KNOWN_TLDS


def _looks_like_code(text):
    return len(CODE_HINT.findall(text)) >= 2


def looks_like_scope(text):
    """Heuristica: esto parece el alcance de un programa pegado en el chat."""
    if not text or len(text) < 60:
        return False
    if not SCOPE_HINT.search(text):
        return False
    if _looks_like_code(text):
        return False
    parsed = parse_text(text)
    real = [a for a in (parsed["in"] + parsed["out"] + parsed.get("suspect", []))
            if not is_doc_example(a) and _plausible_asset(a)]
    if len(real) >= 3:
        return True
    return len(real) >= 2 and bool(STRONG_HINT.search(text))


def _load_cache():
    try:
        with open(CACHE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(cache):
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        pass


def auto_capture(transcript_path, tail_bytes=512 * 1024):
    """Registra programas pegados en el chat. Devuelve los slugs nuevos.

    Solo relee el transcript cuando cambio de tamano, y solo la cola: el paste
    reciente esta ahi. Los hashes ya procesados se cachean, asi que es
    idempotente y barato (una lectura por turno como maximo).
    """
    if SINGLE or not transcript_path:
        return []
    # El doc escribe transcriptPath como "~/.gemini/antigravity/brain/..."; si el
    # payload llega con "~" literal, sin expandir no se autoregistra nada y el
    # fallo es silencioso.
    transcript_path = os.path.expanduser(transcript_path)
    if not os.path.exists(transcript_path):
        return []
    try:
        size = os.path.getsize(transcript_path)
    except OSError:
        return []

    cache = _load_cache()
    transcripts = cache.get("transcripts") or {}
    if (transcripts.get(transcript_path) or {}).get("size") == size:
        return []

    try:
        with open(transcript_path, "r", encoding="utf-8-sig", errors="replace") as f:
            if size > tail_bytes:
                f.seek(size - tail_bytes)
                f.readline()  # descartar linea partida
            lines = f.readlines()
    except OSError:
        return []

    registered = set(cache.get("registered") or [])
    added = []
    for line in lines:
        if not line.strip():
            continue
        try:
            step = json.loads(line)
        except Exception:
            continue
        kind = step.get("type") or ""
        source = step.get("source") or ""
        if not (kind == "USER_INPUT" or source == "USER_EXPLICIT"):
            continue
        content = _content_text(step.get("content"))
        if not looks_like_scope(content):
            continue
        digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:20]
        if digest in registered:
            continue
        prog = add_program(content, origin="transcript")
        registered.add(digest)
        if prog:
            added.append(prog["slug"])

    transcripts[transcript_path] = {"size": size}
    cache["transcripts"] = transcripts
    cache["registered"] = sorted(registered)[-2000:]
    _save_cache(cache)
    return added


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(registry_summary(), indent=2, ensure_ascii=False))
    for _p in load_programs():
        print("  %-28s %-12s %s  in=%d out=%d"
              % (_p["slug"], _p["platform"], _p["expires"], len(_p["in"]), len(_p["out"])))
