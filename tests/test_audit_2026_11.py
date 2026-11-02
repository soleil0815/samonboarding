"""Code-Audit 2026-11: Regressionstests zu den bestaetigten Funden (ausser update.sh, siehe test_update_sh.py)."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # ohne installierte Pakete: Ersatzmodule der Szenarien verwenden
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

import datetime as dt  # noqa: E402
import tarfile  # noqa: E402

from samonboarding import datastate, fileshare, i18n, ldap_client, privacy  # noqa: E402


class LdapsCertificateTests(unittest.TestCase):
    """Ein abgelehntes Zertifikat auf 636 darf nie zum Klartext-Rueckfall auf 389 fuehren."""

    def test_kein_rueckfall_bei_abgelehntem_zertifikat(self):
        from ldap3.core.exceptions import LDAPSocketOpenError

        ports = []

        def server(host, port, **kwargs):
            ports.append(port)
            return mock.Mock(port=port)

        def connection(srv, **kwargs):
            if srv.port == 636:
                raise LDAPSocketOpenError(
                    "unable to open socket",
                    [("socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",)],
                )
            return mock.Mock()

        with (
            mock.patch.object(ldap_client, "LDAP_ALLOW_PLAIN", True),
            mock.patch.object(ldap_client.ldap3, "Server", side_effect=server),
            mock.patch.object(ldap_client.ldap3, "Connection", side_effect=connection),
            self.assertLogs("samonboarding", level="WARNING"),
        ):
            with self.assertRaises(ldap_client.DcUnreachable):
                with ldap_client.ldap_connection("dc01.firma.local", "admin@firma.local", "x"):
                    pass
        self.assertEqual(ports, [636])

    def test_rueckfall_bei_nicht_erreichbarem_ldaps_bleibt(self):
        from ldap3.core.exceptions import LDAPSocketOpenError

        ports = []

        def server(host, port, **kwargs):
            ports.append(port)
            return mock.Mock(port=port)

        def connection(srv, **kwargs):
            if srv.port == 636:
                raise LDAPSocketOpenError("unable to open socket", [("[Errno 111] Connection refused",)])
            return mock.Mock()

        with (
            mock.patch.object(ldap_client, "LDAP_ALLOW_PLAIN", True),
            mock.patch.object(ldap_client.ldap3, "Server", side_effect=server),
            mock.patch.object(ldap_client.ldap3, "Connection", side_effect=connection),
            self.assertLogs("samonboarding", level="WARNING"),
        ):
            with ldap_client.ldap_connection("dc01.firma.local", "admin@firma.local", "x"):
                pass
        self.assertEqual(ports, [636, 389])


def _row(dn, **attrs):
    row = mock.Mock()
    row.dn = dn
    row.text = lambda name: attrs.get(name, "")
    return row


class DeletionTargetTests(unittest.TestCase):
    OWN = "CN=Alt,OU=Disabled,DC=firma,DC=local"

    def test_ordner_eines_anderen_kontos_innerhalb_des_ziels(self):
        from samonboarding.routers import deletion

        rows = [
            _row(
                "CN=M,OU=A,DC=firma,DC=local",
                sAMAccountName="mueller",
                homeDirectory="\\\\fs01\\home$\\azubis\\mueller",
            )
        ]
        with mock.patch.object(deletion, "ldap_search", return_value=rows) as search:
            others = deletion._others_using(None, "DC=x", "homeDirectory", "\\\\fs01\\home$\\azubis", self.OWN, "home")
        self.assertEqual(others, ["mueller"])
        self.assertIn("(homeDirectory=*\\5cazubis\\5c*)", search.call_args[0][2])

    def test_woertliches_username_im_attribut_wird_gefunden(self):
        from samonboarding.routers import deletion

        rows = [_row("CN=C,OU=A,DC=firma,DC=local", sAMAccountName="chef", homeDirectory="\\\\fs01\\home$\\%username%")]
        with mock.patch.object(deletion, "ldap_search", return_value=rows) as search:
            others = deletion._others_using(
                None, "DC=x", "homeDirectory", "\\\\fs01\\home$\\chef\\mueller2", self.OWN, "home"
            )
        self.assertEqual(others, ["chef"])
        self.assertIn("(homeDirectory=*%username%*)", search.call_args[0][2])

    def test_kurzname_im_pfad_wird_nicht_geloescht(self):
        cfg = {"enabled": True, "roots": ["\\\\fs01\\home$"], "useAdAttr": True}
        targets = fileshare.build_targets("home", cfg, "anna", "\\\\fs01\\home$\\CHEF~1\\anna")
        from_attr = [t for t in targets if t["source"] == "AD-Attribut"]
        self.assertEqual(len(from_attr), 1)
        self.assertIn("~", from_attr[0]["skip"])
        self.assertEqual(i18n.tr(from_attr[0]["skip"], "en")[:20], "The path contains '~")

    def test_gleicher_ordner_in_zwei_speicherorten_nur_einmal(self):
        from samonboarding.routers import deletion

        root = {"enabled": True, "roots": ["\\\\fs01\\users$"], "useAdAttr": True, "suffixes": []}
        cfg = {"profile": {"enabled": False}, "folderRedirection": dict(root), "home": dict(root)}
        entry = _row(self.OWN, homeDirectory="\\\\fs01\\users$\\anna")
        with mock.patch.object(deletion, "ldap_search", return_value=[]):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        paths = [t["path"].lower() for t in targets if t["path"] and not t["skip"]]
        self.assertEqual(paths, ["\\\\fs01\\users$\\anna"])

    def test_gleicher_ordner_mit_anderem_konto_bleibt_ueberall_stehen(self):
        from samonboarding.routers import deletion

        root = {"enabled": True, "roots": ["\\\\fs01\\users$"], "useAdAttr": True, "suffixes": []}
        cfg = {"profile": {"enabled": False}, "folderRedirection": dict(root), "home": dict(root)}
        entry = _row(self.OWN, homeDirectory="\\\\fs01\\users$\\anna")
        other = _row("CN=B,OU=A,DC=firma,DC=local", sAMAccountName="bneu", homeDirectory="\\\\fs01\\users$\\anna")
        with mock.patch.object(deletion, "ldap_search", return_value=[other]):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        self.assertEqual([t for t in targets if t["path"] and not t["skip"]], [])


class TranslationTests(unittest.TestCase):
    def test_bestaetigung_ersetzter_objekte_englisch(self):
        text = (
            "Diese Objekte wurden gelöscht und unter gleichem Namen neu angelegt. Das neue Objekt übernehmen?\n\nCN=X"
        )
        self.assertTrue(i18n.tr(text, "en").startswith("These objects were deleted"))

    def test_test_mail_meldung_englisch(self):
        self.assertEqual(
            i18n.tr("Test-Mail erfolgreich an it@firma.local gesendet!", "en"), "Test mail sent to it@firma.local!"
        )


@unittest.skipIf(os.name != "posix" or not shutil.which("sh"), "nur unter Linux mit sh")
class HealthcheckTests(unittest.TestCase):
    """Gesundheitscheck: leeres HTTPS_PORT= heisst 9500, und als root werden vorher alle Rechte abgegeben."""

    def run_check(self, port_value):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp)
            log = bin_dir / "calls.log"
            for name in ("python", "setpriv"):
                tool = bin_dir / name
                tool.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\n', encoding="utf-8")
                tool.chmod(0o755)
            env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}", HTTPS_PORT=port_value)
            entry = Path(_paths.ROOT) / "docker-entrypoint.sh"
            done = subprocess.run(
                ["sh", str(entry), "healthcheck"], env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            return log.read_text(encoding="utf-8")

    def test_leerer_port_ist_standard(self):
        self.assertIn("https://localhost:9500/api/public-config", self.run_check(""))
        self.assertIn("https://localhost:9443/api/public-config", self.run_check("9443"))

    def test_als_root_ohne_rechte(self):
        calls = self.run_check("")
        if os.getuid() == 0:
            self.assertTrue(calls.startswith("setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all --"))
        else:
            self.assertTrue(calls.startswith("python -I -c"))
        docker = (Path(_paths.ROOT) / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('CMD ["/app/docker-entrypoint.sh", "healthcheck"]', docker)


class MigrationLoopTests(unittest.TestCase):
    """Eine abstuerzende Migration (Neustart in Schleife) darf die saubere Sicherung nicht wegkappen."""

    def test_absturzschleife_behaelt_die_saubere_sicherung(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            datastate.prepare(data, "2.0.0", 1)
            (data / "config.json").write_text('{"orig": true}', encoding="utf-8")

            def broken(d):
                (Path(d) / "config.json").write_text('{"halb": true}', encoding="utf-8")
                raise RuntimeError("Migration kaputt")

            for i in range(datastate.KEEP_BACKUPS + 2):
                with self.assertRaises(RuntimeError):
                    datastate.prepare(data, "2.1.0", 2, migrations={2: broken}, now=dt.datetime(2026, 12, 1, 4, 0, i))
            backups = sorted((data / "backups").iterdir())
            self.assertEqual(len(backups), 1)
            with tarfile.open(backups[0]) as tar:
                member = tar.extractfile("config.json")
                self.assertIsNotNone(member)
                self.assertEqual(member.read() if member else b"", b'{"orig": true}')
            # ist die Migration repariert, laeuft der Wechsel ohne weitere Sicherung durch
            self.assertIn("2.0.0 -> 2.1.0", datastate.prepare(data, "2.1.0", 2, migrations={2: lambda d: None}))
            self.assertFalse((data / datastate.PENDING_NAME).exists())
            self.assertEqual(len(list((data / "backups").iterdir())), 1)


@unittest.skipUnless(shutil.which("node"), "Node.js nicht installiert")
class UiTestRunnerTests(unittest.TestCase):
    def test_fehlgeschlagener_assert_setzt_exit_code(self):
        loader = Path(_paths.TESTS) / "ui" / "load_script.js"
        with tempfile.TemporaryDirectory() as tmp:
            test = Path(tmp) / "x.test.js"
            test.write_text(f"require({str(loader)!r});\nconsole.assert(false, 'absichtlich');\n", encoding="utf-8")
            done = subprocess.run(["node", str(test)], capture_output=True, text=True, check=False)
        self.assertNotEqual(done.returncode, 0)


class LoginMailTests(unittest.TestCase):
    """Ohne mail-Attribut im AD keine erratene Adresse (Mails enthalten Startpasswoerter)."""

    def login_as(self, user_mail):
        from contextlib import nullcontext

        from samonboarding.models import LoginModel
        from samonboarding.routers import auth

        captured = {}

        def create(data):
            captured.update(data)
            return "tok"

        request = mock.Mock()
        request.client.host = "10.0.10.5"
        with (
            mock.patch.object(auth, "load_json", return_value={"domain": "firma.local", "dc_ip": "dc01.firma.local"}),
            mock.patch.object(auth, "ldap_connection", return_value=nullcontext(mock.Mock())),
            mock.patch.object(auth, "check_user_role", return_value=("Administrator", "", user_mail, "admin")),
            mock.patch.object(auth, "detect_directory"),
            mock.patch.object(auth, "audit"),
            mock.patch.object(auth, "create_session", side_effect=create),
        ):
            auth.login(LoginModel(username="admin", password="x"), request, mock.Mock())
        return captured["email"]

    def test_ohne_mail_attribut_keine_erratene_adresse(self):
        self.assertEqual(self.login_as(""), "")

    def test_mail_attribut_wird_verwendet(self):
        self.assertEqual(self.login_as("it@firma.local"), "it@firma.local")


class BackupRetentionTests(unittest.TestCase):
    """Eigene Sicherungen halten die Fristen ein: weg, sobald sie aelter als die laengste Frist sind."""

    def test_alte_sicherungen_werden_entfernt(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "backups"
            folder.mkdir()
            now = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)
            old = folder / "vor-2.0.0-20250101-000000.tar.gz"
            new = folder / "vor-2.0.1-20261201-000000.tar.gz"
            other = folder / "notiz.txt"
            for path, age in ((old, 400), (new, 31), (other, 400)):
                path.write_text("x", encoding="utf-8")
                stamp = (now - dt.timedelta(days=age)).timestamp()
                os.utime(path, (stamp, stamp))
            self.assertEqual(privacy.purge_backups([365, 90, 180], now, tmp), 1)
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())
            self.assertTrue(other.exists())  # nur eigene Sicherungen

    def test_unbegrenzte_frist_behaelt_sicherungen(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "backups"
            folder.mkdir()
            old = folder / "vor-2.0.0-20200101-000000.tar.gz"
            old.write_text("x", encoding="utf-8")
            os.utime(old, (0, 0))
            self.assertEqual(privacy.purge_backups([365, 0, 180], None, tmp), 0)
            self.assertTrue(old.exists())

    def test_bereinigung_ruft_sicherungen_auf(self):
        with (
            mock.patch.object(privacy, "purge_audit", return_value=0),
            mock.patch.object(privacy, "purge_log", return_value=0),
            mock.patch.object(privacy, "purge_offboarding", return_value=0),
            mock.patch.object(privacy, "purge_backups", return_value=2) as backups,
            self.assertLogs("samonboarding", level="INFO"),
        ):
            self.assertEqual(privacy.run_retention()["backups"], 2)
        backups.assert_called_once()


class OffboardStoreTests(unittest.TestCase):
    def test_secure_delete_wie_dokumentiert(self):
        from samonboarding import config, offboard_store

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config, "OFFBOARD_DB_FILE", str(Path(tmp) / "offboarding.db")):
                with offboard_store._db() as conn:
                    self.assertEqual(conn.execute("PRAGMA secure_delete").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
