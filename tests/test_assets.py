"""Einbindung von CSS/Schriften: immer lokal aus dem Docker-Build, nie aus dem Internet."""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # ohne installierte Pakete: Ersatzmodule der Szenarien verwenden
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding.routers import ui  # noqa: E402

WEB = Path(_paths.ROOT) / "samonboarding" / "web"


class ThemeTests(unittest.TestCase):
    def test_theme_vollstaendig(self):
        theme = json.loads((WEB / "theme.json").read_text(encoding="utf-8"))
        for family in ("slate", "cyan"):
            self.assertEqual(
                sorted(theme["colors"][family], key=int),
                ["50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950"],
            )
            for value in theme["colors"][family].values():
                self.assertRegex(value, r"^#[0-9a-f]{6}$")
        self.assertEqual(theme["fontFamily"]["sans"][0], "Manrope")
        self.assertEqual(theme["fontFamily"]["mono"][0], "JetBrains Mono")

    def test_tailwind_config_liest_theme(self):
        config = (Path(_paths.ROOT) / "tailwind.config.js").read_text(encoding="utf-8")
        self.assertIn("samonboarding/web/theme.json", config)

    def test_dockerfile_baut_die_schriften(self):
        docker = (Path(_paths.ROOT) / "Dockerfile").read_text(encoding="utf-8")
        package = json.loads((Path(_paths.ROOT) / "package.json").read_text(encoding="utf-8"))["dependencies"]
        self.assertTrue(package["@fontsource/manrope"].startswith("5."))
        self.assertTrue(package["@fontsource/jetbrains-mono"].startswith("5."))
        self.assertIn("dist/vendor/fonts/fonts.css", docker)
        self.assertNotIn("@fontsource/inter", docker)


HOMEPAGE = "https://helfi.space"
SOURCE = "https://github.com/soleil0815/samonboarding"  # Quellcode-Link (AGPL Abschnitt 13)


class NoInternetTests(unittest.TestCase):
    def test_keine_externen_adressen_in_der_oberflaeche(self):
        texts = [(WEB / "index.html").read_text(encoding="utf-8"), Path(ui.__file__).read_text(encoding="utf-8")]
        for text in texts:
            found = [u for u in re.findall(r"https?://[^\s\"'<>)]+", text) if "www.w3.org" not in u]
            self.assertEqual(set(found) - {HOMEPAGE, SOURCE}, set())

    def test_homepage_nur_als_link(self):
        """Die Webseite des Autors ist nur ein Link (oeffnet erst beim Klick, in neuem Tab) - nichts wird geladen."""
        text = (WEB / "index.html").read_text(encoding="utf-8")
        uses = re.findall(r"(\S+)=\"" + re.escape(HOMEPAGE) + r"\"([^>]*)>", text)
        self.assertTrue(uses)
        for attr, rest in uses:
            self.assertEqual(attr, "href")
            self.assertIn('rel="noopener noreferrer"', rest)
        self.assertIn(f'href="{SOURCE}" target="_blank" rel="noopener noreferrer"', text)  # Quellcode fuer Nutzer

    def test_csp_nur_eigener_server(self):
        main = (Path(_paths.ROOT) / "samonboarding" / "main.py").read_text(encoding="utf-8")
        self.assertIn("default-src 'self'", main)
        self.assertIn("font-src 'self'", main)
        self.assertIn("connect-src 'self'", main)


class AssetHeadTests(unittest.TestCase):
    def setUp(self):
        self.orig = ui.STATIC_DIR
        self.tmp = tempfile.TemporaryDirectory()
        ui.STATIC_DIR = Path(self.tmp.name)

    def tearDown(self):
        ui.STATIC_DIR = self.orig
        self.tmp.cleanup()

    def test_kein_cdn_wenn_dateien_fehlen(self):
        head = ui.asset_head()
        self.assertNotIn("http", head)
        self.assertIn("/static/app.css", head)
        self.assertIn("docker compose up -d --build", head)

    def test_lokal_wenn_dateien_da(self):
        for name in ui.LOCAL_ASSETS:
            path = ui.STATIC_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        head = ui.asset_head()
        self.assertIn("/static/vendor/fonts/fonts.css", head)
        self.assertIn("/static/app.css", head)
        self.assertNotIn("http", head)
        self.assertNotIn("docker compose", head)


if __name__ == "__main__":
    unittest.main()
