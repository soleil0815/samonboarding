"""Englische Oberflaeche: Woerterbuch (i18n.json), Uebersetzer auf dem Server, Mails in der gewaehlten Sprache."""

import ast
import glob
import json
import os
import sys
import unittest

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import i18n, mailer  # noqa: E402

ROOT = _paths.ROOT


class DictionaryTests(unittest.TestCase):
    def test_datei_gueltig(self):
        data = json.load(open(os.path.join(ROOT, "samonboarding", "web", "i18n.json"), encoding="utf-8"))
        self.assertGreater(len(data["exact"]), 500)
        for de, en in data["patterns"]:
            self.assertEqual(sorted(set(_ph(de))), sorted(set(_ph(en))), de)

    def test_alle_fehlermeldungen_der_api_uebersetzt(self):
        """Jede feste Fehlermeldung (HTTPException detail) hat eine englische Fassung."""
        missing = []
        for path in glob.glob(os.path.join(ROOT, "samonboarding", "routers", "*.py")) + [
            os.path.join(ROOT, "samonboarding", "permissions.py"),
            os.path.join(ROOT, "samonboarding", "sessions.py"),
        ]:
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "HTTPException":
                    for kw in node.keywords:
                        if (
                            kw.arg == "detail"
                            and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                        ):
                            text = kw.value.value
                            if i18n.tr(text, "en") == text and text not in ("Template not found.", "Not logged in."):
                                missing.append(f"{os.path.basename(path)}: {text}")
        self.assertEqual(missing, [])


def _ph(text):
    import re

    return re.findall(r"\{\d+\}", text)


class TranslateTests(unittest.TestCase):
    def test_deutsch_bleibt(self):
        self.assertEqual(i18n.tr("Konto gelöscht", "de"), "Konto gelöscht")
        self.assertEqual(i18n.current_lang(), "de")

    def test_exakt_muster_verschachtelt(self):
        self.assertEqual(i18n.tr("Konto gelöscht", "en"), "Account deleted")
        self.assertEqual(
            i18n.tr("SAMONBOARDING - Offboarding für Anna (ab)", "en"), "SAMONBOARDING - Offboarding of Anna (ab)"
        )
        self.assertEqual(
            i18n.tr("Gruppe 'VPN' konnte nicht zugewiesen werden: insufficientAccessRights", "en"),
            "Group 'VPN' could not be assigned: insufficientAccessRights",
        )

    def test_zeilen_aufzaehlung_name(self):
        text = "NICHT offgeboardet:\n- Anna: Benutzer im AD nicht gefunden."
        self.assertEqual(i18n.tr(text, "en"), "NOT offboarded:\n- Anna: User not found in AD.")

    def test_daten_bleiben(self):
        for text in ("Hans von Berg", "OU=Vertrieb,DC=firma,DC=local", "\\\\fs01\\home$\\anna", "1234"):
            self.assertEqual(i18n.tr(text, "en"), text)


class MailTests(unittest.TestCase):
    def test_mail_auf_englisch(self):
        token = i18n.set_lang("en")
        try:
            text, html = mailer.render_mail(
                "admin",
                "Konto gelöscht",
                "#000",
                "Das Konto von Anna (ab) wurde endgültig gelöscht.",
                [("Mitarbeiter:", "Anna (ab)", "bold")],
            )
        finally:
            i18n.reset_lang(token)
        self.assertIn("Hello admin,", text)
        self.assertIn("The account of Anna (ab) was deleted permanently.", text)
        self.assertIn("Employee: Anna (ab)", text)
        self.assertIn("Kind regards", text)
        self.assertIn('<html lang="en">', html)
        self.assertIn("Account deleted", html)

    def test_mail_auf_deutsch_unveraendert(self):
        text, html = mailer.render_mail("admin", "Konto gelöscht", "#000", "Intro", [("Mitarbeiter:", "Anna", "bold")])
        self.assertIn("Hallo admin,", text)
        self.assertIn("Mit freundlichen Grüßen", text)
        self.assertIn('<html lang="de">', html)


if __name__ == "__main__":
    unittest.main()
