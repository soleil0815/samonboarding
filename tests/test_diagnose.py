"""Diagnostic package: anonymous, complete and kept up to date with the program."""

import ast
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import anonymize, config, diagnose, exchange, offboard_store, reports  # noqa: E402

PKG = Path(_paths.ROOT) / "samonboarding"

# Every made-up name contains "geheim" (secret): one look for that word finds any leak.
SECRETS = ("geheim", "Passwort123", "SmtpPass!", "UserPass!", "SessionToken")
DOMAIN = "geheimfirma.local"
BASE = "DC=geheimfirma,DC=local"
OU = f"OU=Geheimvertrieb,OU=Mitarbeiter-Geheim,{BASE}"


def _write(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _fill(data_dir):
    d = Path(data_dir)
    _write(d / "config.json", {"domain": DOMAIN, "dc_ip": "dc01-geheim.geheimfirma.local", "backend": "auto"})
    _write(
        d / "smtp_config.json",
        dict(
            config.default_smtp_config,
            enabled=True,
            displayName="Geheim IT",
            host="mail.geheimfirma.local",
            username="smtp-geheim",
            password="SmtpPass!",  # noqa: S106 - made-up test value
            fromEmail="noreply@geheimfirma.local",
            ccRecipients="chef.geheim@geheimfirma.local; it-geheim@geheimfirma.local",
        ),
    )
    _write(d / "offboarding_config.json", {"sourceOus": [OU], "targetOu": f"OU=Ausgeschieden-Geheim,{BASE}"})
    _write(d / "pwdreset_config.json", {"sourceOus": [OU]})
    _write(
        d / "usermgmt_config.json", {"sourceOus": [OU], "targetOus": [OU], "groupOus": [f"OU=Gruppen-Geheim,{BASE}"]}
    )
    _write(
        d / "deletion_config.json",
        dict(
            config.default_deletion_config,
            enabled=True,
            disabledOu=f"OU=Ausgeschieden-Geheim,{BASE}",
            profile={"enabled": True, "roots": ["\\\\fs-geheim\\profile$"], "useAdAttr": True, "suffixes": ["V6"]},
        ),
    )
    _write(
        d / "exchange_config.json",
        dict(
            exchange.default_exchange_config, enabled=True, server="ex-geheim.geheimfirma.local", database="DB-Geheim"
        ),
    )
    _write(d / "onboarding_config.json", {"mailMode": "required", "neuerSchluessel": "geheimer Wert"})
    _write(
        d / "templates.json",
        [
            {
                "id": 1,
                "name": "Geheimvertrieb",
                "naming": "%vorname%.%nachname%",
                "ouDn": OU,
                "pwdMode": "static",
                "staticPwd": "Passwort123",
                "city": "Geheimstadt",
                "company": "Geheim GmbH",
                "manager": f"CN=Chef Geheim,{OU}",
                "homeDirectory": "\\\\fs-geheim\\home$\\%username%",
                "groups": [f"CN=GG-Geheim,OU=Gruppen-Geheim,{BASE}"],
                "mailMode": "required",
                "unbekanntesFeld": "geheim",
            }
        ],
    )
    with sqlite3.connect(d / "reports.db") as conn:
        conn.executescript(reports.SCHEMA)
        conn.execute(
            "INSERT INTO audit (ts, ts_utc, actor, action, target, ok, details) VALUES (?,?,?,?,?,?,?)",
            ("t", "2099-01-01", "erika.geheim", "offboard", f"CN=Erika Geheim,{OU}", 0, '{"error": "geheim"}'),
        )
        conn.execute(
            "INSERT INTO audit (ts, ts_utc, actor, action, target, ok, details) VALUES (?,?,?,?,?,?,?)",
            ("t", "2099-01-01", "admin.geheim", "pwdreset", "hans.geheimnis", 1, "{}"),
        )
        for level, message in [
            ("WARNING", f"Suche in OU '{OU}' fehlgeschlagen: noSuchObject"),
            ("ERROR", "LDAP-Verbindung zu 10.20.30.40:636 fehlgeschlagen: dc01-geheim.geheimfirma.local timed out"),
            ("WARNING", "Anmeldung: DC meldet 'GEHEIMFIRMA\\max.geheim', gefunden wurde 'moritz.geheim' - abgelehnt"),
            ("WARNING", "E-Mail an ceo.geheim@geheimfirma.de geht UNVERSCHLUESSELT ueber smtp.geheimfirma.local"),
            ("ERROR", "Offboarding hans.geheimnis fehlgeschlagen: insufficientAccessRights"),
            ("WARNING", "Pfad \\\\fs-geheim\\profile$\\erika.geheim.V6 nicht erreichbar"),
            ("WARNING", "Anmeldung mit 'Peter Geheimrat' gehoert nicht zu dieser Domaene - abgelehnt"),
            ("WARNING", "Schutzpruefung fuer CN=Unbekannt Geheim,OU=Neu-Geheim,DC=geheimfirma,DC=local nicht moeglich"),
            ("ERROR", "Unerwarteter Fehler bei POST /api/offboarding/run\nTraceback ...\nKeyError: 'gisela.geheim'"),
            ("INFO", "Langsam: GET /api/offboarding/users 2.9 s (Verbindung 0.1 s, Suche 0.4 s)"),
        ]:
            conn.execute(
                "INSERT INTO applog (ts, ts_utc, level, source, message) VALUES (?,?,?,?,?)",
                ("t", "2099-01-01", level, "samonboarding.routers.offboarding", message),
            )
    with sqlite3.connect(d / "offboarding.db") as conn:
        conn.executescript(offboard_store.SCHEMA)
        conn.execute(
            "INSERT INTO offboarded (sam, name, original_dn, current_dn, original_ou, was_enabled, offboarded_at, "
            "offboarded_by) VALUES (?,?,?,?,?,?,?,?)",
            ("otto.geheim", "Otto Geheim", f"CN=Otto Geheim,{OU}", "CN=Otto Geheim,OU=Aus", OU, 1, "t", "admin.geheim"),
        )


USER = {
    "username": "erika.geheim",
    "role": "Administrator",
    "bind_user": "erika.geheim@geheimfirma.local",
    "password": "UserPass!",  # noqa: S106 - made-up test value
    "sid": "SessionToken",
}
BROWSER = {"userAgent": "Mozilla/5.0 Test", "sprache": "de", "seite": "https://samonboarding.geheimfirma.local/"}


class _WithData(unittest.TestCase):
    """A data folder full of made-up names, passwords and paths."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        _fill(d)
        patches = {
            "DATA_DIR": d,
            "TEMPLATES_FILE": str(d / "templates.json"),
            "CONFIG_FILE": str(d / "config.json"),
            "REPORTS_DB_FILE": str(d / "reports.db"),
            "OFFBOARD_DB_FILE": str(d / "offboarding.db"),
            "TLS_CERT_FILE": str(d / "tls" / "cert.pem"),
        }
        for name, value in patches.items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        env = mock.patch.dict(
            os.environ, {"AD_DOMAIN": DOMAIN, "TLS_HOSTNAMES": "samonboarding.geheimfirma.local,10.20.30.41"}
        )
        env.start()
        self.addCleanup(env.stop)

        # no DC in the tests: the connection test reports a failure that names the DC (must be anonymised too)
        def fake_connect(*_a, **_k):
            raise OSError("dc01-geheim.geheimfirma.local (10.20.30.40) unreachable")

        p = mock.patch("samonboarding.ldap_client.ldap_connection", side_effect=fake_connect)
        p.start()
        self.addCleanup(p.stop)

    def build(self):
        return diagnose.build(user=dict(USER), browser=dict(BROWSER))


class PackageTests(_WithData):
    def test_nothing_secret_or_personal_in_the_package(self):
        data = self.build()
        blob = diagnose.make_zip(data)
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            self.assertEqual(sorted(z.namelist()), ["diagnose.json", "diagnose.txt"])
            content = z.read("diagnose.txt").decode() + z.read("diagnose.json").decode()
        for word in SECRETS:
            self.assertNotIn(word.lower(), content.lower(), f"'{word}' im Diagnosepaket")
        for word in ("10.20.30.40", "10.20.30.41", "max.", "moritz", "Peter", "firma"):
            self.assertNotIn(word.lower(), content.lower(), word)

    def test_useful_content_stays(self):
        data = self.build()
        self.assertEqual(data["format"], diagnose.FORMAT)
        self.assertEqual(data["programm"]["version"], config.VERSION)
        smtp = data["einstellungen"]["smtp_config.json"]
        self.assertEqual(smtp["password"], "gesetzt")
        self.assertEqual(smtp["ccRecipients"], 2)
        self.assertTrue(smtp["enabled"])
        self.assertEqual(smtp["tlsMode"], "Auto")
        off = data["einstellungen"]["offboarding_config.json"]
        self.assertEqual(off["sourceOus"], ["OU=ou-1,OU=ou-2,DC=domain,DC=example"])
        # the same OU gets the same placeholder everywhere (connections stay visible)
        self.assertEqual(data["einstellungen"]["pwdreset_config.json"]["sourceOus"], off["sourceOus"])
        self.assertEqual(data["templates"]["templates"][0]["ouDn"], off["sourceOus"][0])
        self.assertEqual(data["templates"]["templates"][0]["staticPwd"], "gesetzt")
        self.assertRegex(
            data["templates"]["templates"][0]["homeDirectory"], r"^\\\\host-\d+\\freigabe-\d+\$\\%username%$"
        )
        # unknown keys: named, value left out
        self.assertIn("nicht eingeordnet", data["einstellungen"]["onboarding_config.json"]["neuerSchluessel"])
        self.assertIn("nicht eingeordnet", data["templates"]["templates"][0]["unbekanntesFeld"])
        log = data["protokoll"]
        self.assertEqual(len(log["eintraege"]), 9)
        self.assertIn("noSuchObject", log["eintraege"][-1]["text"])
        self.assertIn("insufficientAccessRights", json.dumps(log))
        self.assertEqual(len(log["langsam"]), 1)
        # only which actions ran and whether they worked - not who and on whom
        self.assertEqual(
            data["aenderungen"]["letzte30Tage"],
            {"offboard": {"ok": 0, "fehler": 1}, "pwdreset": {"ok": 1, "fehler": 0}},
        )
        self.assertEqual(data["wiederherstellung"]["eintraege"], {"open": 1})
        self.assertIn("fehler", data["verbindung"])
        self.assertTrue(any("Verbindungstest" in h for h in data["auffaelligkeiten"]))
        self.assertEqual(data["browser"]["userAgent"], "Mozilla/5.0 Test")
        names = [f["name"] for f in data["datenordner"]["dateien"]]
        self.assertIn("reports.db", names)
        text = diagnose.render_text(data)
        self.assertIn("AUFFÄLLIGKEITEN", text)
        self.assertTrue(diagnose.file_name(data).startswith(f"samonboarding-diagnose-{config.VERSION}-"))

    def test_package_changes_nothing(self):
        before = {p.name: p.stat().st_mtime_ns for p in Path(self.tmp.name).iterdir()}
        self.build()
        after = {p.name: p.stat().st_mtime_ns for p in Path(self.tmp.name).iterdir()}
        self.assertEqual(before, after)

    def test_without_data_files(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.object(config, "DATA_DIR", Path(empty)):
            with mock.patch.object(config, "REPORTS_DB_FILE", str(Path(empty) / "reports.db")):
                data = diagnose.build(source="kommandozeile")
            self.assertEqual(os.listdir(empty), [])  # nothing created
        self.assertIn("uebersprungen", data["verbindung"])
        self.assertEqual(data["programm"]["quelle"], "kommandozeile")

    def test_command_line(self):
        with mock.patch("builtins.print"):
            self.assertEqual(diagnose.main([]), 0)
        files = list((Path(self.tmp.name) / "diagnose").glob("samonboarding-diagnose-*.zip"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        with zipfile.ZipFile(files[0]) as z:
            self.assertNotIn("geheim", z.read("diagnose.json").decode().lower())


class UpToDateTests(unittest.TestCase):
    """A new part of the program, setting or environment variable must be classified - otherwise these fail."""

    def test_every_router_module_is_covered(self):
        modules = {p.stem for p in (PKG / "routers").glob("*.py") if p.stem != "__init__"}
        self.assertEqual(set(diagnose.ROUTER_SECTIONS), modules)
        for module, sections in diagnose.ROUTER_SECTIONS.items():
            for section in sections:
                self.assertIn(section, diagnose.SECTIONS, module)

    def test_every_setting_has_a_rule(self):
        defaults = {
            "config.json": config.default_config,
            "smtp_config.json": config.default_smtp_config,
            "offboarding_config.json": config.default_offboarding_config,
            "pwdreset_config.json": config.default_pwdreset_config,
            "onboarding_config.json": config.default_onboarding_config,
            "usermgmt_config.json": config.default_usermgmt_config,
            "deletion_config.json": config.default_deletion_config,
            "exchange_config.json": exchange.default_exchange_config,
        }
        self.assertEqual(set(defaults), set(diagnose.CONFIG_RULES))
        for name, default in defaults.items():
            keys = set(diagnose._flatten(default))
            self.assertEqual(keys - set(diagnose.CONFIG_RULES[name]), set(), name)
        # the fields of the settings forms (models) too - incl. nested locations of the deletion function
        from samonboarding import models

        for model, name in [
            (models.SmtpConfigModel, "smtp_config.json"),
            (models.OffboardingConfigModel, "offboarding_config.json"),
            (models.ExchangeConfigModel, "exchange_config.json"),
            (models.PwdResetConfigModel, "pwdreset_config.json"),
            (models.UserMgmtConfigModel, "usermgmt_config.json"),
        ]:
            fields = set(getattr(model, "model_fields", None) or getattr(model, "__annotations__", {}))
            self.assertEqual(fields - set(diagnose.CONFIG_RULES[name]), set(), name)
        location = set(getattr(models.DeletionLocationModel, "model_fields", None) or {}) or set(
            models.DeletionLocationModel.__annotations__
        )
        for loc in ("profile", "folderRedirection", "home"):
            self.assertEqual(
                {f"{loc}.{k}" for k in location} - set(diagnose.CONFIG_RULES["deletion_config.json"]), set()
            )
        for rules in [*diagnose.CONFIG_RULES.values(), diagnose.TEMPLATE_RULES, diagnose.ENV_RULES]:
            self.assertEqual(set(rules.values()) - set(diagnose.RULES), set())

    def test_every_settings_file_is_known(self):
        from samonboarding import references

        self.assertIn(os.path.basename(references.FILE), diagnose.KNOWN_DATA_FILES)
        for name in dir(config):
            if name.endswith("_FILE") and name not in ("TLS_CERT_FILE", "TLS_KEY_FILE", "LDAP_CA_FILE"):
                base = os.path.basename(str(getattr(config, name)))
                self.assertIn(base, diagnose.KNOWN_DATA_FILES, name)

    def test_every_template_field_has_a_rule(self):
        from samonboarding.routers import templates

        fields = set(templates.TEMPLATE_TEXT_FIELDS) | set(templates.sanitize_template({"name": "x"}))
        self.assertEqual(fields - set(diagnose.TEMPLATE_RULES), set())
        self.assertEqual(diagnose.TEMPLATE_RULES["staticPwd"], "secret")

    def test_every_environment_variable_has_a_rule(self):
        names = set()
        for path in PKG.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                    func = node.func
                    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                    owner = getattr(func, "value", None)
                    owner_name = getattr(owner, "attr", None) or getattr(owner, "id", None)
                    wanted = called in ("_env_int", "_env_bool") or (
                        called == "get" and owner_name in ("environ", "env")
                    )
                    value = node.args[0].value
                    if wanted and isinstance(value, str) and value.isupper():
                        names.add(value)
                environ = isinstance(node, ast.Subscript) and getattr(node.value, "attr", None) == "environ"
                if environ and isinstance(node.slice, ast.Constant):
                    names.add(node.slice.value)
        self.assertGreater(len(names), 15)
        self.assertEqual(names - set(diagnose.ENV_RULES), set())

    def test_secrets_are_never_shown(self):
        for rules in [*diagnose.CONFIG_RULES.values(), diagnose.TEMPLATE_RULES]:
            for key, rule in rules.items():
                if "password" in key.lower() or key in ("staticPwd",):
                    self.assertEqual(rule, "secret", key)


class AnonymizerTests(unittest.TestCase):
    def setUp(self):
        self.a = anonymize.Anonymizer()

    def test_patterns(self):
        cases = {
            "OU=Vertrieb,DC=firma,DC=local": "OU=ou-1,DC=domain,DC=example",
            "an max@firma.de": "an mail-1@example.invalid",
            "\\\\fs01\\profile$\\anna.V6": "\\\\host-1\\freigabe-1$\\wert-1",
            "zu 10.0.10.5:636": "zu 192.0.2.1:636",
            "zu 127.0.0.1": "zu 127.0.0.1",
            "Server dc01.firma.local antwortet nicht": "Server host-2.example antwortet nicht",
            "FIRMA\\anna.beispiel": "DOMAIN-1\\benutzer-1",
            "Konto anna.beispiel gesperrt": "Konto benutzer-1 gesperrt",
            "Gruppe 'Vertrieb Nord' fehlt": "Gruppe 'wert-2' fehlt",
        }
        for text, expected in cases.items():
            self.assertEqual(self.a.text(text), expected, text)

    def test_program_words_stay(self):
        for text in (
            'File "/app/samonboarding/routers/deletion.py", line 12, in run',
            "ldap3.core.exceptions.LDAPSocketOpenError: socket ssl wrapping error",
            "Langsam: GET /api/offboarding/users 2.9 s (Verbindung 0.1 s, Suche 0.4 s)",
            "Versionswechsel 2.4.0 -> 2.5.0: Daten gesichert nach vor-2.4.0-20261114-101010.tar.gz",
            "TLS-Modus 'Ohne Verschluesselung'",
            "CN=Users,DC=domain,DC=example",
        ):
            self.assertEqual(self.a.text(text), text)

    def test_same_value_same_placeholder(self):
        self.a.learn("dn", "OU=Vertrieb,DC=firma,DC=local")
        self.assertEqual(self.a.text("in OU=Vertrieb,DC=firma,DC=local"), "in OU=ou-1,DC=domain,DC=example")
        # the OU name alone, as some messages use it
        self.assertEqual(self.a.text("Vertrieb nicht gefunden"), "ou-1 nicht gefunden")

    def test_known_values_win(self):
        self.a.learn("user", "Hans")
        self.a.learn("domain", "firma.local")
        self.assertEqual(self.a.text("Hans an firma.local"), "benutzer-1 an domain-1.example")


class ApiTests(_WithData):
    def test_administrators_only(self):
        from fastapi import HTTPException

        from samonboarding.models import DiagnoseModel
        from samonboarding.routers import diagnose as route

        for fn in (route.diagnose_preview, route.diagnose_download):
            with self.assertRaises(HTTPException) as ctx:
                fn(DiagnoseModel(), user={"username": "op", "role": "Account Operator"})
            self.assertEqual(ctx.exception.status_code, 403)

    def test_preview_and_download(self):
        from samonboarding.models import DiagnoseModel
        from samonboarding.routers import diagnose as route

        with mock.patch.object(route, "audit") as audit:
            preview = route.diagnose_preview(DiagnoseModel(browser=BROWSER), user=dict(USER))
            resp = route.diagnose_download(DiagnoseModel(browser=BROWSER), user=dict(USER))
        self.assertIn("AUFFÄLLIGKEITEN", preview["text"])
        self.assertNotIn("geheim", json.dumps(preview, ensure_ascii=False).lower())
        self.assertEqual(resp.media_type, "application/zip")
        self.assertIn("samonboarding-diagnose-", resp.headers["Content-Disposition"])
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[1], "diagnose-package")


class TimingStatsTests(unittest.TestCase):
    def setUp(self):
        from samonboarding import timing

        self.timing = timing
        timing.reset_stats()
        self.addCleanup(timing.reset_stats)

    def test_summary_per_route_pattern(self):
        for total in (0.1, 0.2, 0.3, 4.0):
            self.timing.record("GET /api/templates/{tmpl_id}", total, {"search": total / 2, "unbekannt": 9})
        self.timing.record_error("GET /api/templates/{tmpl_id}")
        stats = self.timing.summary()["GET /api/templates/{tmpl_id}"]
        self.assertEqual(stats["count"], 4)
        self.assertEqual(stats["errors"], 1)
        self.assertEqual(stats["maxMs"], 4000)
        self.assertEqual(set(stats["stepsMedianMs"]), {"Suche"})  # only the known steps

    def test_keeps_only_the_newest(self):
        for _ in range(self.timing.KEEP_PER_ROUTE + 50):
            self.timing.record("GET /api/x", 0.01, {})
        self.assertEqual(self.timing.summary()["GET /api/x"]["count"], self.timing.KEEP_PER_ROUTE + 50)
        with self.timing._stats_lock:
            self.assertEqual(len(self.timing._stats["GET /api/x"]["totals"]), self.timing.KEEP_PER_ROUTE)


class FindingsTests(unittest.TestCase):
    """What the first real package (Samba, 13 s protection check) taught."""

    def test_browser_versions_are_not_addresses(self):
        a = anonymize.Anonymizer()
        ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
        self.assertEqual(a.text(ua), ua)
        self.assertEqual(a.text("https://10.1.2.3:9500/ und //10.1.2.3"), "https://192.0.2.1:9500/ und //192.0.2.1")

    def test_slow_hint_names_the_step(self):
        data = {
            "geschwindigkeit": {
                "anfragen": {
                    "GET /api/dashboard": {
                        "medianMs": 13966,
                        "p95Ms": 27593,
                        "stepsMedianMs": {"Verbindung": 67, "Suche": 13891, "Schutzpruefung": 13518},
                    },
                    "GET /api/me": {"medianMs": 2, "p95Ms": 14, "stepsMedianMs": {}},
                }
            },
            "verbindung": {"schutzpruefung": {"ms": 13200, "geschuetzteKonten": 4}},
        }
        hints = diagnose.hints(data)
        self.assertIn("Die Schutzprüfung (geschützte Konten in den Listen) dauert 13.2 s.", hints)
        self.assertIn("Langsam: GET /api/dashboard – üblich 14.0 s, bis 27.6 s, davon Schutzpruefung 13.5 s.", hints)
        self.assertFalse(any("/api/me" in h for h in hints))

    def test_connection_test_times_the_protection_check(self):
        from samonboarding import protection

        class Conn:
            server = mock.Mock(ssl=True, port=636)
            result = {}
            response = []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def search(self, *a, **k):
                return True

        with (
            mock.patch("samonboarding.ldap_client.ldap_connection", return_value=Conn()),
            mock.patch("samonboarding.ldap_client.detect_directory"),
            mock.patch.object(protection, "privileged_map", return_value={"cn=a": "x", "cn=b": "y"}) as pmap,
            mock.patch.object(diagnose, "_configured_ous", return_value=[]),
        ):
            out = diagnose.section_verbindung(anonymize.Anonymizer(), {"user": dict(USER)})
        self.assertEqual(out["schutzpruefung"]["geschuetzteKonten"], 2)
        self.assertIsInstance(out["schutzpruefung"]["ms"], int)
        self.assertTrue(pmap.call_args.args[1].startswith("DC="))

    def test_health_check_is_not_counted(self):
        source = (PKG / "main.py").read_text(encoding="utf-8")
        self.assertIn('route == "/api/public-config" and client in ("127.0.0.1", "::1")', source)
