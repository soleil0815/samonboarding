"""Neuigkeiten in der Oberflaeche: was hat sich in den installierten Versionen geaendert?

Quelle ist das Changelog, das mit dem Programm ausgeliefert wird (CHANGELOG.md bzw. CHANGELOG.en.md im
Programmordner). Es wird nichts aus dem Internet geladen. Ein Eintrag beginnt optional mit "Sicherheit:" / "Security:"
oder "Behoben:" / "Fixed:"; alles andere gilt als neue Funktion.
"""

import re

from fastapi import APIRouter, Depends

from ..config import BASE_DIR, VERSION
from ..sessions import get_current_user

router = APIRouter()

FILES = {"de": "CHANGELOG.md", "en": "CHANGELOG.en.md"}
MAX_ENTRIES = 12
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_KIND_RE = re.compile(r"^\*{0,2}(Sicherheit|Security|Behoben|Fixed)\s*:\s*\*{0,2}\s*", re.I)
_KINDS = {"sicherheit": "security", "security": "security", "behoben": "fix", "fixed": "fix"}


def version_key(text):
    """'1.44.0' -> (1, 44, 0); unbekannt -> (0,)."""
    match = _VERSION_RE.search(str(text or ""))
    return tuple(int(p) for p in match.group(0).split(".")) if match else (0,)


def parse(text, limit=MAX_ENTRIES):
    """Changelog (Markdown) -> [{version, title, date, items: [{kind, text, sub: [...]}]}], neueste zuerst.
    Abschnitte ohne Versionsnummer (z. B. "Aeltere Versionen") werden ausgelassen."""
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
        if len(line) - len(stripped) >= 2 and current["items"]:  # eingerueckt: Unterpunkt
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
    name = FILES.get(lang, FILES["de"])  # nur die festen Dateien, kein Pfad aus der Anfrage
    try:
        text = (BASE_DIR / name).read_text(encoding="utf-8")
    except OSError:
        try:
            text = (BASE_DIR / FILES["de"]).read_text(encoding="utf-8")
        except OSError:
            text = ""
    return {"version": VERSION, "entries": parse(text)}
