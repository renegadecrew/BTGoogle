#!/usr/bin/env python3
"""Add one or more assets to a BTGoogle program file.

Usage:
    python scripts/scope_add.py example.com 203.0.113.0/24
    echo example.com | python scripts/scope_add.py
    python scripts/scope_add.py --program hooks/programs/manual.md example.com

Accepted forms: domain, wildcard, IPv4, CIDR. The default program is
hooks/programs/manual.md next to this repository.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys

DOMAIN_RE = re.compile(
    r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}", re.I
)
LAB_TLDS = {"htb", "local", "lab", "test", "internal"}


def is_valid(asset: str) -> bool:
    asset = asset.strip().lower()
    if not asset:
        return False
    if "/" in asset:
        try:
            ipaddress.ip_network(asset, strict=False)
            return True
        except ValueError:
            return False
    try:
        ipaddress.ip_address(asset)
        return True
    except ValueError:
        pass
    if not DOMAIN_RE.fullmatch(asset):
        return False
    if asset.startswith("*."):
        base = asset[2:]
        if "." not in base and base not in LAB_TLDS:
            return False
    return True


def split_sections(text: str) -> tuple[str, list[str], list[str]]:
    """Return (header, in_assets, out_assets)."""
    header_lines: list[str] = []
    in_assets: list[str] = []
    out_assets: list[str] = []
    section = None
    seen_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("##"):
            low = line.lower()
            if "in-scope" in low or "in scope" in low:
                section = "in"
                seen_section = True
            elif "out-of-scope" in low or "out of scope" in low:
                section = "out"
                seen_section = True
            else:
                section = None
            continue
        if not seen_section:
            header_lines.append(raw)
            continue
        if not line or line.startswith("#") or " " in line or "\t" in line:
            continue
        if section == "in":
            in_assets.append(line.lower())
        elif section == "out":
            out_assets.append(line.lower())
    header = "\n".join(header_lines).rstrip("\n")
    return header, in_assets, out_assets


def main() -> int:
    args = sys.argv[1:]

    program = None
    if "--program" in args:
        index = args.index("--program")
        if index + 1 >= len(args):
            print("--program requires a path", file=sys.stderr)
            return 2
        program = args[index + 1]
        del args[index:index + 2]

    if not args:
        args = [item for item in re.split(r"[\s,]+", sys.stdin.read()) if item]

    assets = []
    rejected = []
    for raw in args:
        candidate = raw.strip().lower()
        if is_valid(candidate):
            assets.append(candidate)
        else:
            rejected.append(raw)

    if rejected:
        print("Ignored (not a domain, wildcard, IPv4, or CIDR): " + ", ".join(rejected),
              file=sys.stderr)
    if not assets:
        return 1

    if program is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        program = os.path.join(root, "hooks", "programs", "manual.md")

    os.makedirs(os.path.dirname(os.path.abspath(program)), exist_ok=True)

    if os.path.exists(program):
        with open(program, "r", encoding="utf-8-sig") as fh:
            text = fh.read()
    else:
        text = "# Program: manual\n"

    header, in_assets, out_assets = split_sections(text)
    known = {asset.lower() for asset in in_assets + out_assets}
    added = [asset for asset in assets if asset not in known]

    if not added:
        print("Nothing to add: every asset is already present.")
        return 0

    header = header or "# Program: manual"
    lines = [header, "", "## In-scope", ""]
    lines.extend(in_assets + added)
    lines.extend(["", "## Out-of-scope", ""])
    lines.extend(out_assets)
    lines.append("")

    with open(program, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))

    print(f"Added {len(added)} asset(s) to {program}")
    for asset in added:
        print(f"  {asset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
