"""Neuigkeiten in der Oberflaeche: Changelog lesen (routers/news.py) und Changelog aktuell halten."""

import os
import sys
import unittest
from pathlib import Path

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import config  # noqa: E402
from samonboarding.routers import news  # noqa: E402

ROOT = Path(_paths.ROOT)

SAMPLE = """# Changelog

Text oben wird ignoriert.

## 1.10.0 – 2026-01-02
- Neue Funktion mit `code`
  - Unterpunkt
- Sicherheit: Luecke geschlossen
- Behoben: Fehler beseitigt

## 1.9.0 / 1.9.1 – 2026-01-01
- **Security:** fixed in English

## Aeltere Versionen
- wird ausgelassen
"""


class ParseTests(unittest.TestCase):
    def test_eintraege_und_arten(self):
        entries = news.parse(SAMPLE)
        self.assertEqual([e["version"] for e in entries], ["1.10.0", "1.9.1"])  # neueste zuerst, hoechste Nummer
        first = entries[0]
        self.assertEqual(first["date"], "2026-01-02")
        self.assertEqual([i["kind"] for i in first["items"]], ["new", "security", "fix"])
        self.assertEqual(first["items"][0]["sub"], ["Unterpunkt"])
        self.assertEqual(first["items"][1]["text"], "Luecke geschlossen")
        self.assertEqual(entries[1]["items"][0]["kind"], "security")
        self.assertEqual(entries[1]["title"], "1.9.0 / 1.9.1")

    def test_versionsvergleich_numerisch(self):
        self.assertGreater(news.version_key("1.10.0"), news.version_key("1.9.9"))

    def test_begrenzt(self):
        text = "\n".join(f"## 1.0.{n}\n- x" for n in range(30))
        self.assertEqual(len(news.parse(text)), news.MAX_ENTRIES)


class ChangelogTests(unittest.TestCase):
    def test_changelog_zur_aktuellen_version(self):
        """Jede neue Version braucht einen Eintrag im Changelog (deutsch und englisch)."""
        for name in news.FILES.values():
            entries = news.parse((ROOT / name).read_text(encoding="utf-8"))
            self.assertEqual(entries[0]["version"], config.VERSION, name)
            self.assertTrue(entries[0]["items"], name)

    def test_beide_sprachen_gleiche_versionen(self):
        de, en = (news.parse((ROOT / n).read_text(encoding="utf-8")) for n in news.FILES.values())
        self.assertEqual([e["version"] for e in de], [e["version"] for e in en])
        self.assertEqual([[i["kind"] for i in e["items"]] for e in de], [[i["kind"] for i in e["items"]] for e in en])

    def test_nur_mit_anmeldung_und_feste_dateien(self):
        src = (ROOT / "samonboarding" / "routers" / "news.py").read_text(encoding="utf-8")
        self.assertIn("Depends(get_current_user)", src)
        self.assertIn('FILES.get(lang, FILES["de"])', src)
        self.assertNotIn("CHANGELOG", (ROOT / ".dockerignore").read_text(encoding="utf-8"))  # im Image


if __name__ == "__main__":
    unittest.main()
