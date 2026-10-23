"""Handbuch: Dateien vorhanden, nur ueber die Anmeldung abrufbar, keine Pfade aus der Anfrage."""

import os
import sys
import unittest
from pathlib import Path

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding.routers import manual  # noqa: E402

ROOT = Path(_paths.ROOT)


def body(resp):
    raw = getattr(resp, "body", None)
    if raw is None:
        raw = getattr(resp, "content", "")
    return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)


class ManualTests(unittest.TestCase):
    def test_beide_sprachen(self):
        self.assertIn("# SAMONBOARDING – Handbuch", body(manual.manual("de", user={})))
        self.assertIn("# SAMONBOARDING – Manual", body(manual.manual("en", user={})))

    def test_unbekannte_sprache_und_pfade(self):
        for lang in ("../../config", "fr", "", "/etc/passwd"):
            self.assertIn("Handbuch", body(manual.manual(lang, user={})))

    def test_nur_mit_anmeldung(self):
        src = (ROOT / "samonboarding" / "routers" / "manual.py").read_text(encoding="utf-8")
        self.assertIn("Depends(get_current_user)", src)
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(main.count("    manual,"), 2)  # importiert und eingebunden

    def test_im_image_und_ohne_externe_adressen(self):
        self.assertIn("COPY samonboarding/web ./samonboarding/web", (ROOT / "Dockerfile").read_text(encoding="utf-8"))
        for name in ("HANDBUCH.md", "MANUAL.en.md"):
            text = (ROOT / "samonboarding" / "web" / "manual" / name).read_text(encoding="utf-8")
            self.assertNotIn("http://", text)
            self.assertGreater(len(text), 5000)


if __name__ == "__main__":
    unittest.main()
