#!/usr/bin/env python3
"""Watch official Antigravity hook docs and IDE extension changelog.

Dependabot handles declared package/action versions. This script separately
notifies maintainers when Google's hook contract or hook-related IDE notes
change, since those product docs are not package dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "antigravity-upstream-baseline.json"
SOURCES = {
    "hooks_contract": "https://antigravity.google/docs/hooks?tab=ide",
    "ide_changelog": "https://antigravity.google/docs/changelog?ide=vscode&tab=extensions",
}
HOOK_TERMS = (
    "pretooluse", "posttooluse", "hookeventname", "toolcall", "force_ask",
    "deny_unless_prior_grant", "permissionoverrides", "decision", "hook",
)
BLOCK_TAGS = {"address", "article", "blockquote", "dd", "div", "dt", "h1",
              "h2", "h3", "h4", "h5", "li", "p", "pre", "section", "td", "th"}
IGNORED_TAGS = {"script", "style", "noscript", "svg"}


class _BlockParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.blocks: list[str] = []
        self.ignored = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in IGNORED_TAGS:
            self.ignored += 1
        elif tag in BLOCK_TAGS:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if tag in IGNORED_TAGS and self.ignored:
            self.ignored -= 1
        elif tag in BLOCK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if not self.ignored:
            self.parts.append(data)

    def _flush(self) -> None:
        value = re.sub(r"\s+", " ", " ".join(self.parts)).strip()
        if value:
            self.blocks.append(value)
        self.parts.clear()


def html_blocks(document: str) -> list[str]:
    parser = _BlockParser()
    parser.feed(document)
    parser.close()
    parser._flush()
    return parser.blocks


def relevant_text(document: str, source: str) -> str:
    """Return normalized hook-related blocks, excluding unrelated page chrome."""
    blocks = html_blocks(document)
    selected: list[str] = []
    if source == "hooks_contract":
        selected = [block for block in blocks if any(term in block.casefold() for term in HOOK_TERMS)]
    elif source == "ide_changelog":
        for index, block in enumerate(blocks):
            if any(term in block.casefold() for term in HOOK_TERMS):
                selected.extend(blocks[max(0, index - 3): index + 1])
    else:
        raise ValueError(f"Unknown Antigravity source: {source}")
    # Preserve source order while avoiding duplicates from overlapping context windows.
    return "\n".join(dict.fromkeys(selected))


def fetch_source(name: str, url: str) -> dict[str, str]:
    request = Request(url, headers={"User-Agent": "BTGoogle-antigravity-watch/1.0",
                                    "Accept": "text/html"})
    try:
        with urlopen(request, timeout=30) as response:
            document = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not fetch {name} ({url}): {exc}") from exc
    text = relevant_text(document, name)
    if not text:
        raise RuntimeError(f"No hook-related content was extracted from {name}; review parser/source.")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {"url": url, "sha256": digest, "excerpt": text}


def fetch_all() -> dict[str, dict[str, str]]:
    return {name: fetch_source(name, url) for name, url in SOURCES.items()}


def update_baseline(current: dict[str, dict[str, str]]) -> None:
    data = {"schema_version": 1,
            "sources": {name: {"url": item["url"], "sha256": item["sha256"]}
                        for name, item in current.items()}}
    BASELINE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def changed_sources(current: dict[str, dict[str, str]], baseline: dict) -> dict[str, dict[str, str]]:
    old_sources = baseline.get("sources", {})
    return {
        name: {"old": old_sources.get(name, {}).get("sha256", "missing baseline"),
               "new": item["sha256"], "url": item["url"], "excerpt": item["excerpt"]}
        for name, item in current.items()
        if old_sources.get(name, {}).get("sha256") != item["sha256"]
    }


def _api_request(url: str, token: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "BTGoogle-antigravity-watch/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub API request failed: {exc}") from exc


def create_or_reuse_issue(changes: dict[str, dict[str, str]], token: str, repository: str) -> str:
    fingerprint = hashlib.sha256("".join(
        f"{name}:{item['new']}\n" for name, item in sorted(changes.items())
    ).encode("utf-8")).hexdigest()[:12]
    title = f"Review Antigravity upstream changes ({fingerprint})"
    query = urlencode({"q": f'repo:{repository} is:issue in:title "{title}"'})
    results = _api_request(f"https://api.github.com/search/issues?{query}", token)
    if any(issue.get("title") == title for issue in results.get("items", [])):
        return f"Issue already exists for fingerprint {fingerprint}: {title}"

    sections = []
    for name, item in sorted(changes.items()):
        excerpt = item["excerpt"][:5000]
        sections.append(
            f"### {name}\n\n- Source: {item['url']}\n"
            f"- Previous SHA-256: `{item['old']}`\n- Current SHA-256: `{item['new']}`\n\n"
            f"Relevant upstream text:\n\n```text\n{excerpt}\n```"
        )
    body = (
        "The daily watcher detected a change in Google's official Antigravity hook contract "
        "or IDE extension changelog. Review whether BTGoogle's hook and regression matrix "
        "need an update. The watcher does not change the baseline automatically.\n\n"
        + "\n\n".join(sections)
        + "\n\nAfter reviewing the upstream change, refresh the baseline with "
          "`python scripts/check_antigravity_upstream.py --update-baseline` and commit it."
    )
    issue = _api_request(f"https://api.github.com/repos/{repository}/issues", token,
                         method="POST", payload={"title": title, "body": body})
    return f"Created issue #{issue['number']}: {title}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true",
                        help="fetch official sources and write their reviewed baseline hashes")
    args = parser.parse_args(argv)
    try:
        current = fetch_all()
        if args.update_baseline:
            update_baseline(current)
            print(f"Updated {BASELINE.relative_to(ROOT)}")
            for name, item in current.items():
                print(f"{name}: {item['sha256']}")
            return 0

        if not BASELINE.exists():
            raise RuntimeError(f"Missing {BASELINE}; bootstrap it with --update-baseline after review.")
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        changes = changed_sources(current, baseline)
        if not changes:
            print("Official Antigravity hook docs and IDE changelog match the reviewed baseline.")
            return 0

        print("Detected upstream changes:")
        for name, item in changes.items():
            print(f"{name}: {item['old']} -> {item['new']}")
        token = os.environ.get("GITHUB_TOKEN")
        repository = os.environ.get("GITHUB_REPOSITORY")
        if not token or not repository:
            print("GITHUB_TOKEN and GITHUB_REPOSITORY are required to open the review issue.", file=sys.stderr)
            return 1
        print(create_or_reuse_issue(changes, token, repository))
        return 0
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"upstream watch failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())