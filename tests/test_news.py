"""News in the UI: reading the changelog (routers/news.py) and keeping the changelog up to date."""

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
    def test_entries_and_kinds(self):
        entries = news.parse(SAMPLE)
        self.assertEqual([e["version"] for e in entries], ["1.10.0", "1.9.1"])  # newest first, highest number
        first = entries[0]
        self.assertEqual(first["date"], "2026-01-02")
        self.assertEqual([i["kind"] for i in first["items"]], ["new", "security", "fix"])
        self.assertEqual(first["items"][0]["sub"], ["Unterpunkt"])
        self.assertEqual(first["items"][1]["text"], "Luecke geschlossen")
        self.assertEqual(entries[1]["items"][0]["kind"], "security")
        self.assertEqual(entries[1]["title"], "1.9.0 / 1.9.1")

    def test_version_comparison_numeric(self):
        self.assertGreater(news.version_key("1.10.0"), news.version_key("1.9.9"))

    def test_security_updates_with_own_number(self):
        """1.48.0-s2 = same program as 1.48.0 with newer packages: higher than -s1, lower than 1.48.1."""
        key = news.version_key
        self.assertTrue(key("1.48.0") < key("1.48.0-s1") < key("1.48.0-s2") < key("1.48.0-s10") < key("1.48.1"))
        text = (
            "## 1.48.0-s1 – 2026-11-02\n- Sicherheit: neue Pakete\n  - openssl `1` → `2`\n\n"
            "## 1.48.0 – 2026-10-26\n- x\n"
        )
        entries = news.parse(text)
        self.assertEqual([e["version"] for e in entries], ["1.48.0-s1", "1.48.0"])
        self.assertEqual(entries[0]["items"][0]["kind"], "security")
        self.assertEqual(entries[0]["items"][0]["sub"], ["openssl `1` → `2`"])
        self.assertEqual(news.installed(entries, "1.48.0"), "1.48.0-s1")  # installed state for the notice
        self.assertEqual(news.installed(entries, "1.49.0"), "1.49.0")

    def test_limited(self):
        text = "\n".join(f"## 1.0.{n}\n- x" for n in range(30))
        self.assertEqual(len(news.parse(text)), news.MAX_ENTRIES)


class ChangelogTests(unittest.TestCase):
    def test_changelog_for_current_version(self):
        """Every new version needs a changelog entry (German and English)."""
        for name in news.FILES.values():
            entries = news.parse((ROOT / name).read_text(encoding="utf-8"))
            # the top entry is the program version or a security update of it (<version>-s<counter>)
            self.assertEqual(entries[0]["version"].split("-s")[0], config.VERSION, name)
            self.assertTrue(entries[0]["items"], name)

    def test_both_languages_same_versions(self):
        de, en = (news.parse((ROOT / n).read_text(encoding="utf-8")) for n in news.FILES.values())
        self.assertEqual([e["version"] for e in de], [e["version"] for e in en])
        self.assertEqual([[i["kind"] for i in e["items"]] for e in de], [[i["kind"] for i in e["items"]] for e in en])

    def test_login_required_and_fixed_files(self):
        src = (ROOT / "samonboarding" / "routers" / "news.py").read_text(encoding="utf-8")
        self.assertIn("Depends(get_current_user)", src)
        self.assertIn('FILES.get(lang, FILES["de"])', src)
        self.assertNotIn("CHANGELOG", (ROOT / ".dockerignore").read_text(encoding="utf-8"))  # in the image


if __name__ == "__main__":
    unittest.main()
