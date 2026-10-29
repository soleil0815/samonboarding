"""Datenstand: Sicherung vor einem Versionswechsel, Migrationen, Abbruch bei Daten einer neueren Version,
Kennung der docker-compose.yml. Nur in temporaeren Ordnern."""

import datetime as dt
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path

import _paths

from samonboarding import config, datastate

ROOT = Path(_paths.ROOT)


class DataStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def state(self):
        return json.loads((self.data / "datenstand.json").read_text(encoding="utf-8"))

    def backups(self):
        folder = self.data / "backups"
        return sorted(p.name for p in folder.iterdir()) if folder.exists() else []

    def test_neue_installation_ohne_sicherung(self):
        self.assertEqual(datastate.prepare(self.data, "2.0.0", 1), "neue Installation")
        self.assertEqual(self.state()["datenstand"], 1)
        self.assertEqual(self.state()["version"], "2.0.0")
        self.assertEqual(self.backups(), [])

    def test_daten_einer_version_ohne_datenstand_werden_vorher_gesichert(self):
        (self.data / "config.json").write_text('{"domain": "firma.local"}', encoding="utf-8")
        result = datastate.prepare(self.data, "2.0.0", 1, now=dt.datetime(2026, 11, 2, 3, 0, 0))
        self.assertIn("vor 2.0 -> 2.0.0", result)
        self.assertEqual(self.backups(), ["vor-2.0.0-20261102-030000.tar.gz"])
        with tarfile.open(self.data / "backups" / self.backups()[0]) as tar:
            self.assertEqual(tar.getnames(), ["config.json"])
        self.assertEqual((self.data / "backups" / self.backups()[0]).stat().st_mode & 0o777, 0o600)

    def test_gleiche_version_keine_sicherung(self):
        datastate.prepare(self.data, "2.0.0", 1)
        (self.data / "config.json").write_text("{}", encoding="utf-8")
        self.assertEqual(datastate.prepare(self.data, "2.0.0", 1), "unverändert")
        self.assertEqual(self.backups(), [])

    def test_versionswechsel_sichert_und_migriert(self):
        datastate.prepare(self.data, "2.0.0", 1)
        (self.data / "config.json").write_text('{"alt": true}', encoding="utf-8")
        steps = []

        def to_2(data_dir):
            steps.append(2)
            (data_dir / "config.json").write_text('{"neu": true}', encoding="utf-8")

        result = datastate.prepare(self.data, "2.1.0", 2, migrations={2: to_2}, now=dt.datetime(2026, 12, 1, 4, 0, 0))
        self.assertEqual(steps, [2])
        self.assertEqual(self.state()["datenstand"], 2)
        self.assertIn("vor-2.1.0-20261201-040000.tar.gz", result)
        with tarfile.open(self.data / "backups" / "vor-2.1.0-20261201-040000.tar.gz") as tar:
            saved = tar.extractfile("config.json").read().decode()
        self.assertEqual(saved, '{"alt": true}')  # Sicherung VOR der Migration
        self.assertNotIn("backups", " ".join(tarfile.open(self.data / "backups" / self.backups()[0]).getnames()))

    def test_aeltere_version_auf_neueren_daten_bricht_mit_klarer_meldung_ab(self):
        datastate.prepare(self.data, "2.0.0", 1)
        datastate.prepare(self.data, "2.1.0", 2, migrations={2: lambda d: None}, now=dt.datetime(2026, 12, 1, 4, 0, 0))
        before = (self.data / "datenstand.json").read_text(encoding="utf-8")
        with self.assertRaises(datastate.DataTooNew) as ctx:
            datastate.prepare(self.data, "2.0.0", 1)
        message = str(ctx.exception)
        self.assertIn("SAMONBOARDING 2.1.0 (Datenstand 2)", message)
        self.assertIn("data/backups/vor-2.1.0-20261201-040000.tar.gz", message)  # welche Sicherung
        self.assertIn("sh update.sh --restore", message)
        self.assertEqual((self.data / "datenstand.json").read_text(encoding="utf-8"), before)  # nichts veraendert

    def test_aeltere_version_mit_gleichem_datenstand_startet(self):
        datastate.prepare(self.data, "2.1.0", 1)
        self.assertIn("2.1.0 -> 2.0.5", datastate.prepare(self.data, "2.0.5", 1))

    def test_nur_die_letzten_sicherungen_bleiben(self):
        (self.data / "config.json").write_text("{}", encoding="utf-8")
        for number in range(13):
            datastate.backup(self.data, f"2.0.{number}", now=dt.datetime(2026, 1, 1, 0, 0, number), keep=10)
        names = self.backups()
        self.assertEqual(len(names), 10)
        self.assertNotIn("vor-2.0.0-20260101-000000.tar.gz", names)
        self.assertIn("vor-2.0.12-20260101-000012.tar.gz", names)

    def test_beim_start_vor_dem_server(self):
        serve = (ROOT / "samonboarding" / "serve.py").read_text(encoding="utf-8")
        start = serve[serve.index("def main():") :]
        self.assertLess(start.index("data_writable()"), start.index("datastate.prepare()"))
        self.assertLess(start.index("datastate.prepare()"), start.index("uvicorn.Config("))
        self.assertIn("except datastate.DataTooNew", start)
        self.assertIn("sys.exit(3)", start)

    def test_programmversion_ohne_sicherheitszaehler(self):
        """Sicherheitsupdates (-s1, -s2) sind dasselbe Programm: VERSION hat keinen Zaehler, also keine Sicherung."""
        self.assertRegex(config.VERSION, r"^\d+\.\d+\.\d+$")


class ComposeVersionTests(unittest.TestCase):
    def test_kennung_der_compose_datei(self):
        self.assertIsNone(datastate.compose_notice({"SAMONBOARDING_COMPOSE": str(datastate.COMPOSE_REQUIRED)}))
        self.assertIsNone(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "99"}))
        self.assertEqual(datastate.compose_notice({}), {"have": 0, "need": datastate.COMPOSE_REQUIRED})
        self.assertEqual(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "1"})["have"], 1)
        self.assertEqual(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "x"})["have"], 0)

    def test_mitgelieferte_datei_hat_die_verlangte_kennung(self):
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        found = re.findall(r'SAMONBOARDING_COMPOSE: "(\d+)"', text)
        self.assertEqual(found, [str(datastate.COMPOSE_REQUIRED)])

    def test_compose_datei_stabil(self):
        """Keine Vorgaben in der Datei, die sich mit jeder Version aendern - die stehen im Programm."""
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for gone in ("build:", "PYTHON_IMAGE", "DEBIAN_SNAPSHOT", "@sha256", "healthcheck:", "SAMONBOARDING_IMAGE"):
            self.assertNotIn(gone, text, gone)
        self.assertIn("image: ghcr.io/soleil0815/samonboarding:${SAMONBOARDING_VERSION:-latest}", text)
        self.assertIn("- .env", text)
        self.assertIn("- ./data:/app/data", text)
        self.assertEqual(len(re.findall(r"^\s+- \./", text, re.M)), 1)  # nur ein Ordner auf dem Host: data
        self.assertFalse((ROOT / "docker-compose.image.yml").exists())
        # nur die drei Rechte zum Uebergeben von ./data, sonst nichts
        caps = text[text.index("cap_add:") : text.index("security_opt:")]
        self.assertEqual(re.findall(r"- (\w+)", caps), ["DAC_READ_SEARCH", "CHOWN", "SETUID", "SETGID"])
        # die Rechte der Ordner setzt das Programm als Besitzer - root hat dafuer kein FOWNER (frueherer Fehler)
        entry = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertNotIn("chmod", entry)
        self.assertIn("os.chmod(str(config.DATA_DIR), 0o700)", (ROOT / "samonboarding" / "serve.py").read_text())
        self.assertIn("no-new-privileges:true", text)
        self.assertIn('user: "0:0"', text)

    def test_hinweis_nur_fuer_administratoren(self):
        auth = (ROOT / "samonboarding" / "routers" / "auth.py").read_text(encoding="utf-8")
        block = auth[auth.index('@router.get("/api/host-notices")') :][:500]
        self.assertIn("Depends(get_current_user)", block)
        self.assertIn('user.get("role") != "Administrator"', block)
        html = (ROOT / "samonboarding" / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="host-notice"', html)
        self.assertIn("fetch('/api/host-notices')", html)


class EntrypointTests(unittest.TestCase):
    def test_startskript_gibt_rechte_ab(self):
        text = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn('exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --inh-caps=-all', text)
        self.assertIn("APP_UID=10001", text)
        self.assertIn('if [ "$(id -u)" = 0 ]; then', text)  # nur als root: Daten uebergeben, dann wechseln
        self.assertTrue(text.rstrip().endswith('exec "$@"'))  # sonst direkt starten (aeltere Compose-Datei)
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('ENTRYPOINT ["/app/docker-entrypoint.sh"]', docker)
        self.assertIn("ARG APP_UID=10001", docker)
        self.assertIn("USER ${APP_UID}:${APP_UID}", docker)  # Standard bleibt ohne root
        self.assertIn("test -x /usr/bin/setpriv", docker)


if __name__ == "__main__":
    unittest.main()
