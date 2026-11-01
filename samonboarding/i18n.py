# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Sprache der Oberflaeche (Deutsch/Englisch).

Die Anwendung ist auf Deutsch geschrieben. Fuer Englisch uebersetzt tr() Texte ueber samonboarding/web/i18n.json:
'exact' (ganzer Text) und 'patterns' (Texte mit Platzhaltern {0}, {1} ...; Platzhalter werden ihrerseits
uebersetzt, falls sie bekannt sind). Dieselbe Datei nutzt die Oberflaeche im Browser. Auf dem Server wird nur fuer
E-Mails uebersetzt; die Sprache kommt per Header X-UI-Lang aus der Oberflaeche.
"""

import contextvars
import json
import logging
import re

from .config import WEB_DIR

log = logging.getLogger(__name__)
_lang = contextvars.ContextVar("ui_lang", default="de")
_cache = {}


def dictionary():
    if "data" not in _cache:
        try:
            data = json.loads((WEB_DIR / "i18n.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            log.warning("i18n.json nicht lesbar (%s) - nur Deutsch", e)
            data = {}
        _cache["data"] = {"exact": dict(data.get("exact") or {}), "patterns": list(data.get("patterns") or [])}
    return _cache["data"]


def _compiled():
    if "patterns" not in _cache:
        out = []
        for de, en in dictionary()["patterns"]:
            parts = re.split(r"\{(\d+)\}", str(de))
            src, order, weight = "^", [], 0
            for i, part in enumerate(parts):
                if i % 2:
                    src += r"([\s\S]+?)"
                    order.append(int(part))
                else:
                    src += re.escape(part)
                    weight += len(part)
            out.append((re.compile(src + "$"), str(en), order, weight))
        out.sort(key=lambda p: -p[3])
        _cache["patterns"] = out
    return _cache["patterns"]


def set_lang(value):
    return _lang.set("en" if str(value or "").lower().startswith("en") else "de")


def reset_lang(token):
    _lang.reset(token)


def current_lang():
    return _lang.get()


def _core(text, depth):
    exact = dictionary()["exact"]
    if text in exact:
        return exact[text]
    if depth > 3:
        return None
    for regex, en, order, _w in _compiled():
        m = regex.match(text)
        if not m:
            continue
        values = {}
        for pos, idx in enumerate(order):
            raw = m.group(pos + 1)
            t = _core(raw, depth + 1)
            values[idx] = raw if t is None else t
        return re.sub(r"\{(\d+)\}", lambda g, values=values: values.get(int(g.group(1)), ""), en)
    return _fallback(text, depth)


def _fallback(text, depth):
    """Zusammengesetzte Zeilen: '- Punkt', 'A · B', 'Name: Meldung' (der linke Teil bleibt, wenn unbekannt)."""
    if text.startswith("- "):
        rest = _core(text[2:], depth + 1)
        return None if rest is None else "- " + rest
    if " · " in text:
        parts = text.split(" · ")
        done = [_core(p, depth + 1) for p in parts]
        if any(d is not None for d in done):
            return " · ".join(p if d is None else d for p, d in zip(parts, done, strict=True))
    if ": " in text:
        left, right = text.split(": ", 1)
        r = _core(right, depth + 1)
        if r is not None:
            lt = _core(left, depth + 1)
            return (left if lt is None else lt) + ": " + r
    return None


def tr(text, lang=None):
    """Uebersetzt einen Text ins Englische, wenn die Sprache Englisch ist; sonst unveraendert."""
    if (lang or _lang.get()) != "en" or text is None:
        return text
    text = str(text)
    if not re.search(r"[A-Za-zÄÖÜäöüß]", text):
        return text
    if "\n" in text:
        return "\n".join(tr(line, "en") for line in text.split("\n"))
    m = re.match(r"^(\s*)([\s\S]*?)(\s*)$", text)
    if m is None:  # passt immer; nur fuer die Typpruefung
        return text
    out = _core(m.group(2), 0)
    return text if out is None else m.group(1) + out + m.group(3)
