"""Data state: backup before a version change, migrations, abort on data from a newer version,
docker-compose.yml marker. Only in temporary folders."""

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

    def test_new_installation_without_backup(self):
        self.assertEqual(datastate.prepare(self.data, "2.0.0", 1), "neue Installation")
        self.assertEqual(self.state()["datenstand"], 1)
        self.assertEqual(self.state()["version"], "2.0.0")
        self.assertEqual(self.backups(), [])

    def test_data_of_version_without_data_state_is_backed_up_first(self):
        (self.data / "config.json").write_text('{"domain": "firma.local"}', encoding="utf-8")
        result = datastate.prepare(self.data, "2.0.0", 1, now=dt.datetime(2026, 11, 2, 3, 0, 0))
        self.assertIn("vor 2.0 -> 2.0.0", result)
        self.assertEqual(self.backups(), ["vor-2.0.0-20261102-030000.tar.gz"])
        with tarfile.open(self.data / "backups" / self.backups()[0]) as tar:
            self.assertEqual(tar.getnames(), ["config.json"])
        self.assertEqual((self.data / "backups" / self.backups()[0]).stat().st_mode & 0o777, 0o600)

    def test_same_version_no_backup(self):
        datastate.prepare(self.data, "2.0.0", 1)
        (self.data / "config.json").write_text("{}", encoding="utf-8")
        self.assertEqual(datastate.prepare(self.data, "2.0.0", 1), "unverändert")
        self.assertEqual(self.backups(), [])

    def test_version_change_backs_up_and_migrates(self):
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
        self.assertEqual(saved, '{"alt": true}')  # backup BEFORE the migration
        self.assertNotIn("backups", " ".join(tarfile.open(self.data / "backups" / self.backups()[0]).getnames()))

    def test_older_version_on_newer_data_aborts_with_clear_message(self):
        datastate.prepare(self.data, "2.0.0", 1)
        datastate.prepare(self.data, "2.1.0", 2, migrations={2: lambda d: None}, now=dt.datetime(2026, 12, 1, 4, 0, 0))
        before = (self.data / "datenstand.json").read_text(encoding="utf-8")
        with self.assertRaises(datastate.DataTooNew) as ctx:
            datastate.prepare(self.data, "2.0.0", 1)
        message = str(ctx.exception)
        self.assertIn("SAMONBOARDING 2.1.0 (Datenstand 2)", message)
        self.assertIn("data/backups/vor-2.1.0-20261201-040000.tar.gz", message)  # which backup
        self.assertIn("sh update.sh --restore", message)
        self.assertEqual((self.data / "datenstand.json").read_text(encoding="utf-8"), before)  # nothing changed

    def test_older_version_with_same_data_state_starts(self):
        datastate.prepare(self.data, "2.1.0", 1)
        self.assertIn("2.1.0 -> 2.0.5", datastate.prepare(self.data, "2.0.5", 1))

    def test_only_the_latest_backups_remain(self):
        (self.data / "config.json").write_text("{}", encoding="utf-8")
        for number in range(13):
            datastate.backup(self.data, f"2.0.{number}", now=dt.datetime(2026, 1, 1, 0, 0, number), keep=10)
        names = self.backups()
        self.assertEqual(len(names), 10)
        self.assertNotIn("vor-2.0.0-20260101-000000.tar.gz", names)
        self.assertIn("vor-2.0.12-20260101-000012.tar.gz", names)

    def test_at_startup_before_the_server(self):
        serve = (ROOT / "samonboarding" / "serve.py").read_text(encoding="utf-8")
        start = serve[serve.index("def main():") :]
        self.assertLess(start.index("data_writable()"), start.index("datastate.prepare()"))
        self.assertLess(start.index("datastate.prepare()"), start.index("uvicorn.Config("))
        self.assertIn("except datastate.DataTooNew", start)
        self.assertIn("sys.exit(3)", start)

    def test_program_version_without_security_counter(self):
        """Security updates (-s1, -s2) are the same program: VERSION has no counter, so no backup."""
        self.assertRegex(config.VERSION, r"^\d+\.\d+\.\d+$")


class ComposeVersionTests(unittest.TestCase):
    def test_compose_file_marker(self):
        self.assertIsNone(datastate.compose_notice({"SAMONBOARDING_COMPOSE": str(datastate.COMPOSE_REQUIRED)}))
        self.assertIsNone(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "99"}))
        self.assertEqual(datastate.compose_notice({}), {"have": 0, "need": datastate.COMPOSE_REQUIRED})
        self.assertEqual(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "1"})["have"], 1)
        self.assertEqual(datastate.compose_notice({"SAMONBOARDING_COMPOSE": "x"})["have"], 0)

    def test_shipped_file_has_the_required_marker(self):
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        found = re.findall(r'SAMONBOARDING_COMPOSE: "(\d+)"', text)
        self.assertEqual(found, [str(datastate.COMPOSE_REQUIRED)])

    def test_compose_file_stable(self):
        """No settings in the file that change with every version - those live in the program."""
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for gone in ("build:", "PYTHON_IMAGE", "DEBIAN_SNAPSHOT", "@sha256", "healthcheck:", "SAMONBOARDING_IMAGE"):
            self.assertNotIn(gone, text, gone)
        self.assertIn("image: ghcr.io/soleil0815/samonboarding:${SAMONBOARDING_VERSION:-latest}", text)
        self.assertIn("- .env", text)
        self.assertIn("- ./data:/app/data", text)
        self.assertEqual(len(re.findall(r"^\s+- \./", text, re.M)), 1)  # only one folder on the host: data
        self.assertFalse((ROOT / "docker-compose.image.yml").exists())
        # only the three capabilities for handing over ./data, nothing else
        caps = text[text.index("cap_add:") : text.index("security_opt:")]
        self.assertEqual(re.findall(r"- (\w+)", caps), ["DAC_READ_SEARCH", "CHOWN", "SETUID", "SETGID"])
        # the program sets the folder permissions as owner - root has no FOWNER for that (earlier bug)
        entry = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertNotIn("chmod", entry)
        self.assertIn("os.chmod(str(config.DATA_DIR), 0o700)", (ROOT / "samonboarding" / "serve.py").read_text())
        self.assertIn("no-new-privileges:true", text)
        self.assertIn('user: "0:0"', text)

    def test_notice_for_administrators_only(self):
        auth = (ROOT / "samonboarding" / "routers" / "auth.py").read_text(encoding="utf-8")
        block = auth[auth.index('@router.get("/api/host-notices")') :][:500]
        self.assertIn("Depends(get_current_user)", block)
        self.assertIn('user.get("role") != "Administrator"', block)
        html = (ROOT / "samonboarding" / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="host-notice"', html)
        self.assertIn("fetch('/api/host-notices')", html)


class EntrypointTests(unittest.TestCase):
    def test_entrypoint_drops_privileges(self):
        text = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn('exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --inh-caps=-all', text)
        self.assertIn("APP_UID=10001", text)
        self.assertIn('if [ "$(id -u)" = 0 ]; then', text)  # only as root: hand over data, then switch
        self.assertTrue(text.rstrip().endswith('exec "$@"'))  # otherwise start directly (older compose file)
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('ENTRYPOINT ["/app/docker-entrypoint.sh"]', docker)
        self.assertIn("ARG APP_UID=10001", docker)
        self.assertIn("USER ${APP_UID}:${APP_UID}", docker)  # default stays non-root
        self.assertIn("test -x /usr/bin/setpriv", docker)


if __name__ == "__main__":
    unittest.main()
