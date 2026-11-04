# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""News in the UI: what has changed in the installed versions?

The source is the changelog shipped with the program (CHANGELOG.de.md or CHANGELOG.md in the program folder).
Nothing is loaded from the internet. An entry optionally starts with "Sicherheit:" / "Security:"
or "Behoben:" / "Fixed:"; everything else counts as a new feature.

Security updates without program changes have their own number: <program version>-s<counter>, e.g. 1.48.0-s2
(same program, only new packages). They rank above the program version and below the next one.
"""

import re

from fastapi import APIRouter, Depends

from ..config import BASE_DIR, VERSION
from ..sessions import get_current_user

router = APIRouter()

FILES = {"de": "CHANGELOG.de.md", "en": "CHANGELOG.md"}
MAX_ENTRIES = 12
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:-s\d+)?")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_KIND_RE = re.compile(r"^\*{0,2}(Sicherheit|Security|Behoben|Fixed)\s*:\s*\*{0,2}\s*", re.I)
_KINDS = {"sicherheit": "security", "security": "security", "behoben": "fix", "fixed": "fix"}


def version_key(text):
    """'1.44.0' -> (1, 44, 0, 0); '1.44.0-s2' -> (1, 44, 0, 2); unknown -> (0,)."""
    match = _VERSION_RE.search(str(text or ""))
    if not match:
        return (0,)
    base, _, counter = match.group(0).partition("-s")
    return tuple(int(p) for p in base.split(".")) + (int(counter or 0),)


def installed(entries, version=VERSION):
    """Installed release: the program version or its newest security update according to the changelog."""
    own = [e["version"] for e in entries if e["version"].split("-s")[0] == version]
    return max(own, key=version_key, default=version)


def parse(text, limit=MAX_ENTRIES):
    """Changelog (Markdown) -> [{version, title, date, items: [{kind, text, sub: [...]}]}], newest first.
    Sections without a version number (e.g. "Aeltere Versionen") are skipped."""
    entries, current = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("## "):
            title = line[3:].strip()
            versions = _VERSION_RE.findall(_DATE_RE.sub("", title))
            if not versions:
                current = None
                continue
            date = _DATE_RE.search(title)
            current = {
                "version": max(versions, key=version_key),
                "title": _DATE_RE.sub("", title).strip(" –-"),
                "date": date.group(0) if date else "",
                "items": [],
            }
            entries.append(current)
            continue
        if current is None:
            continue
        stripped = line.lstrip()
        if not stripped.startswith("- "):
            continue
        body = stripped[2:].strip()
        if len(line) - len(stripped) >= 2 and current["items"]:  # indented: sub-item
            current["items"][-1]["sub"].append(body)
            continue
        kind = "new"
        match = _KIND_RE.match(body)
        if match:
            kind = _KINDS[match.group(1).lower()]
            body = body[match.end() :]
        current["items"].append({"kind": kind, "text": body, "sub": []})
    entries.sort(key=lambda e: version_key(e["version"]), reverse=True)
    return entries[:limit]


@router.get("/api/news")
def news(lang: str = "de", user: dict = Depends(get_current_user)):
    name = FILES.get(lang, FILES["de"])  # only the fixed files, no path from the request
    try:
        text = (BASE_DIR / name).read_text(encoding="utf-8")
    except OSError:
        try:
            text = (BASE_DIR / FILES["de"]).read_text(encoding="utf-8")
        except OSError:
            text = ""
    entries = parse(text)
    return {"version": installed(entries), "program": VERSION, "entries": entries}
