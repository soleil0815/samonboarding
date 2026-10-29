"""update.sh (Weg von Hand) mit nachgebautem docker: Update, Rueckkehr, Compose aus dem Image, offline,
Wiederherstellen und Aufraeumen. Alles in temporaeren Ordnern - nie im echten /etc oder in echten Daten."""

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)
SHELL = shutil.which("dash") or shutil.which("sh")  # update.sh muss mit /bin/sh (dash) laufen
REPO = "ghcr.io/soleil0815/samonboarding"
COMPOSE_V2 = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
COMPOSE_V1 = "services:\n  samonboarding:\n    image: ${SAMONBOARDING_IMAGE:-ghcr.io/soleil0815/samonboarding:latest}\n"
COMPOSE_V3 = COMPOSE_V2.replace('SAMONBOARDING_COMPOSE: "2"', 'SAMONBOARDING_COMPOSE: "3"')


@unittest.skipIf(os.name != "posix" or not SHELL, "nur unter Linux mit sh")
class UpdateShTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.dir = base / "samonboarding"
        self.dir.mkdir()
        shutil.copy(ROOT / "update.sh", self.dir / "update.sh")
        (self.dir / "docker-compose.yml").write_text(COMPOSE_V2, encoding="utf-8")
        (self.dir / ".env").write_text("AD_DOMAIN=firma.local\nSAMONBOARDING_VERSION=\n", encoding="utf-8")
        (self.dir / "data").mkdir()
        (self.dir / "data" / "config.json").write_text("{}", encoding="utf-8")
        self.bin = base / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(f'#!/bin/sh\nexec python3 {ROOT / "tests" / "fake_docker.py"} "$@"\n', encoding="utf-8")
        docker.chmod(0o755)
        self.state_file = base / "state.json"
        self.etc = base / "etc"
        self.write_state(
            registry={f"{REPO}:latest": "img-new", f"{REPO}:2.0": "img-20"},
            tags={f"{REPO}:latest": "img-old"},
            labels={"img-old": "1.48.1", "img-new": "2.0.0", "img-20": "2.0.0-s1"},
            compose={"img-new": COMPOSE_V2, "img-20": COMPOSE_V2},
            health={},
            container={"id": "cid0", "image": "img-old", "ref": f"{REPO}:latest", "running": True},
            mounts=[],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, **state):
        state.setdefault("calls", [])
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def state(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def change(self, **values):
        state = self.state()
        state.update(values)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

    def run_update(self, *args, stdin=None):
        env = dict(
            os.environ,
            PATH=f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            FAKE_DOCKER_STATE=str(self.state_file),
            SAMONB_WAIT="3",
            SAMONB_SLEEP="1",
            SAMONB_ETC=str(self.etc),
        )
        return subprocess.run(
            [SHELL, str(self.dir / "update.sh"), *args],
            capture_output=True,
            text=True,
            env=env,
            input=stdin,
            timeout=60,
            check=False,
        )

    def calls(self, first):
        return [c for c in self.state()["calls"] if c[0] == first]

    def env_text(self):
        return (self.dir / ".env").read_text(encoding="utf-8")

    # --- Update ------------------------------------------------------------------------------------------------------
    def test_update_merkt_vorherige_holt_und_startet(self):
        done = self.run_update()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        state = self.state()
        self.assertEqual(state["tags"]["samonboarding:previous"], "img-old")  # vorherige Version gemerkt
        self.assertIn(["pull", f"{REPO}:latest"], state["calls"])
        self.assertEqual(state["container"]["image"], "img-new")
        self.assertIn("2.0.0 is running", done.stdout)
        self.assertNotIn("SAMONBOARDING_VERSION=2", self.env_text())
        self.assertFalse((self.dir / ".env.update-bak").exists())
        # nie bauen, nie ZIP, keine Programmdateien
        self.assertFalse([c for c in state["calls"] if "build" in c])
        self.assertEqual(
            sorted(p.name for p in self.dir.iterdir()), [".env", "data", "docker-compose.yml", "update.sh"]
        )

    def test_version_festlegen_und_zurueck_auf_latest(self):
        done = self.run_update("--version", "2.0")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("SAMONBOARDING_VERSION=2.0\n", self.env_text())
        self.assertIn(["pull", f"{REPO}:2.0"], self.state()["calls"])
        self.assertEqual(self.env_text().count("SAMONBOARDING_VERSION="), 1)
        self.assertEqual(self.run_update("--latest").returncode, 0)
        self.assertIn("SAMONBOARDING_VERSION=\n", self.env_text())

    def test_fehlstart_vorherige_version_wieder_starten(self):
        (self.dir / ".env").write_text("SAMONBOARDING_VERSION=\n", encoding="utf-8")
        self.change(health={"img-20": "unhealthy"})
        done = self.run_update("--version", "2.0", "-y")
        self.assertEqual(done.returncode, 1)
        self.assertIn("previous one (1.48.1) is running again", done.stderr)
        state = self.state()
        self.assertEqual(state["container"]["image"], "img-old")  # wieder die vorherige Version
        self.assertEqual(state["tags"][f"{REPO}:latest"], "img-old")
        ups = [c for c in state["calls"] if c[:2] == ["compose", "up"]]
        self.assertIn("--force-recreate", ups[-1])
        self.assertIn("fake log line", done.stderr)  # Ursache sichtbar
        self.assertEqual(self.env_text(), "SAMONBOARDING_VERSION=\n")  # .env wie vorher

    def test_fehlstart_ohne_terminal_kehrt_zurueck_mit_nein_bleibt(self):
        self.change(health={"img-new": "unhealthy"})
        done = self.run_update()  # kein Terminal, kein -y: die sichere Wahl (zurueck) gilt
        self.assertEqual(done.returncode, 1)
        self.assertEqual(self.state()["container"]["image"], "img-old")
        # Neustarts in Schleife zaehlen als Fehlstart
        self.change(health={"img-new": "starting"}, restarts={"img-new": 5})
        self.change(container={"id": "cid0", "image": "img-old", "ref": f"{REPO}:latest", "running": True})
        done = self.run_update("-y")
        self.assertEqual(done.returncode, 1)
        self.assertIn("restarting", done.stderr)

    def test_pull_fehlgeschlagen_nichts_geaendert(self):
        done = self.run_update("--version", "9.9")
        self.assertEqual(done.returncode, 1)
        self.assertIn("docker pull failed - nothing changed", done.stderr)
        self.assertNotIn("9.9", self.env_text())
        self.assertFalse([c for c in self.state()["calls"] if c[:2] == ["compose", "up"]])
        self.assertEqual(self.state()["container"]["image"], "img-old")

    def test_neuere_compose_datei_aus_dem_image(self):
        self.change(compose={"img-new": COMPOSE_V3})
        done = self.run_update()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.dir / "docker-compose.yml").read_text(encoding="utf-8"), COMPOSE_V3)
        self.assertEqual((self.dir / "docker-compose.yml.alt").read_text(encoding="utf-8"), COMPOSE_V2)

    def test_gleiche_compose_version_bleibt(self):
        (self.dir / "docker-compose.yml").write_text(COMPOSE_V2 + "# eigene Notiz\n", encoding="utf-8")
        self.assertEqual(self.run_update().returncode, 0)
        self.assertIn("# eigene Notiz", (self.dir / "docker-compose.yml").read_text(encoding="utf-8"))
        self.assertFalse((self.dir / "docker-compose.yml.alt").exists())

    def test_fehlstart_nimmt_auch_die_neue_compose_datei_zurueck(self):
        self.change(compose={"img-new": COMPOSE_V3}, health={"img-new": "unhealthy"})
        self.assertEqual(self.run_update("-y").returncode, 1)
        self.assertEqual((self.dir / "docker-compose.yml").read_text(encoding="utf-8"), COMPOSE_V2)

    def test_umstieg_von_1_48_alte_compose_und_image_variable(self):
        """Erster Aufruf auf einer alten Installation: alte .env-Variable wird uebernommen, alte Datei ersetzt."""
        (self.dir / "docker-compose.yml").write_text(COMPOSE_V1, encoding="utf-8")
        (self.dir / ".env").write_text(f"AD_DOMAIN=firma.local\nSAMONBOARDING_IMAGE={REPO}:2.0\n", encoding="utf-8")
        tmpd = self.dir / ".update-abc123"
        tmpd.mkdir()
        env_tmp = {"SAMONB_TMP": str(tmpd), "SAMONB_IMAGE_GEHOLT": "1"}
        os.environ.update(env_tmp)
        try:
            done = self.run_update("--pull")  # so ruft das alte update.sh das neue auf
        finally:
            for key in env_tmp:
                os.environ.pop(key)
        self.assertEqual(done.returncode, 0, done.stderr)
        text = self.env_text()
        self.assertIn("SAMONBOARDING_VERSION=2.0\n", text)
        self.assertIn("# replaced by SAMONBOARDING_VERSION: SAMONBOARDING_IMAGE=", text)
        self.assertEqual((self.dir / "docker-compose.yml").read_text(encoding="utf-8"), COMPOSE_V2)
        self.assertTrue((self.dir / "docker-compose.yml.alt").exists())
        self.assertFalse(tmpd.exists())  # Zwischenordner des alten Skripts entfernt

    def test_ohne_internet_image_datei_laden(self):
        image_file = self.dir / "samonboarding-2.0.1-amd64.tar.gz"
        image_file.write_text(f"{REPO}:2.0.1 img-201 2.0.1", encoding="utf-8")
        self.change(compose={"img-201": COMPOSE_V2}, registry={})
        done = self.run_update("--offline", str(image_file))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("SAMONBOARDING_VERSION=2.0.1\n", self.env_text())
        self.assertFalse(self.calls("pull"))  # kein Internet noetig
        self.assertEqual(self.state()["container"]["image"], "img-201")

    def test_alte_optionen_und_fehler(self):
        done = self.run_update("samonboarding-1.48.1.zip")
        self.assertEqual(done.returncode, 1)
        self.assertIn("ZIP files are no longer used", done.stderr)
        self.assertIn("--lock no longer exists", self.run_update("--lock").stderr)
        self.assertIn("Version not understood", self.run_update("--version", "abc;rm").stderr)
        os.environ["FAKE_NO_COMPOSE"] = "1"
        try:
            self.assertIn("Docker Compose was not found", self.run_update().stderr)
        finally:
            os.environ.pop("FAKE_NO_COMPOSE")
        (self.dir / ".env").unlink()
        self.assertIn(".env is missing", self.run_update().stderr)
        help_text = self.run_update("--help").stdout
        for option in ("--version", "--offline", "--restore", "--cleanup", "-y"):
            self.assertIn(option, help_text)

    # --- Wiederherstellen ----------------------------------------------------------------------------------------------
    def make_backup(self, name, files):
        folder = self.dir / "data" / "backups"
        folder.mkdir(exist_ok=True)
        path = folder / name
        src = Path(self.tmp.name) / "src"
        shutil.rmtree(src, ignore_errors=True)
        src.mkdir()
        for file_name, text in files.items():
            (src / file_name).write_text(text, encoding="utf-8")
        with tarfile.open(path, "w:gz") as tar:
            for file_name in files:
                tar.add(src / file_name, arcname=file_name)
        return path

    def test_sicherung_zurueckspielen(self):
        self.change(tags={f"{REPO}:latest": "img-old", f"{REPO}:2.0.0": "img-new"})
        (self.dir / "data" / "datenstand.json").write_text('{"datenstand": 2}', encoding="utf-8")
        self.make_backup(
            "vor-2.1.0-20261101-030000.tar.gz", {"config.json": '{"alt": 1}', "datenstand.json": '{"datenstand": 1}'}
        )
        done = self.run_update("--restore", "data/backups/vor-2.1.0-20261101-030000.tar.gz", "--version", "2.0.0", "-y")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        data = self.dir / "data"
        self.assertEqual((data / "config.json").read_text(encoding="utf-8"), '{"alt": 1}')
        self.assertEqual((data / "datenstand.json").read_text(encoding="utf-8"), '{"datenstand": 1}')
        safety = [p.name for p in (data / "backups").iterdir() if p.name.startswith("vor-wiederherstellen-")]
        self.assertEqual(len(safety), 1)  # der Stand davor ist gesichert
        with tarfile.open(data / "backups" / safety[0]) as tar:
            self.assertEqual(sorted(tar.getnames()), ["config.json", "datenstand.json"])
        self.assertTrue((data / "backups" / "vor-2.1.0-20261101-030000.tar.gz").exists())
        self.assertIn("SAMONBOARDING_VERSION=2.0.0\n", self.env_text())

    def test_wiederherstellen_nur_sichere_sicherungen(self):
        outside = Path(self.tmp.name) / "fremd.tar.gz"
        outside.write_text("x", encoding="utf-8")
        self.assertIn("Only backups from data/backups", self.run_update("--restore", str(outside), "-y").stderr)
        bad = self.dir / "data" / "backups"
        bad.mkdir()
        evil = bad / "vor-9-20260101-000000.tar.gz"
        with tarfile.open(evil, "w:gz") as tar:
            info = tarfile.TarInfo("../../etc/passwd")
            info.size = 0
            tar.addfile(info)
        done = self.run_update("--restore", "data/backups/vor-9-20260101-000000.tar.gz", "-y")
        self.assertIn("unsafe paths", done.stderr)
        self.assertEqual((self.dir / "data" / "config.json").read_text(encoding="utf-8"), "{}")
        good = self.make_backup("vor-2.0.0-20260101-000000.tar.gz", {"config.json": "neu"})
        done = self.run_update("--restore", f"data/backups/{good.name}")  # ohne Terminal und ohne -y: nein
        self.assertIn("Nothing changed", done.stderr)
        self.assertEqual((self.dir / "data" / "config.json").read_text(encoding="utf-8"), "{}")

    # --- Aufraeumen ----------------------------------------------------------------------------------------------------
    def old_installation(self):
        d = self.dir
        for name in ("samonboarding/main.py", "tests/test_x.py", "scripts/internet-sperre.sh", ".github/workflows/a.yml",
                     "Dockerfile", "requirements.txt", "images.lock", "README.md", ".dateiliste", "LICENSE",
                     "samonboarding-1.40.0/update.sh", "docker-compose.image.yml", ".update-xyz/f"):  # fmt: skip
            path = d / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x", encoding="utf-8")
        (d / "samonboarding-1.48.1.zip").write_text("zip", encoding="utf-8")
        (d / "backups").mkdir()
        (d / "backups" / "data-20261020.tar.gz").write_text("b", encoding="utf-8")
        (d / "docker-compose.yml.alt").write_text("alt", encoding="utf-8")
        (d / "docker-compose.override.yml").write_text("override", encoding="utf-8")
        (d / "data" / "tls").mkdir()
        (d / "data" / "tls" / "key.pem").write_text("geheim", encoding="utf-8")
        units = self.etc / "systemd" / "system"
        units.mkdir(parents=True)
        (units / "samonboarding-internetsperre.service").write_text("[Unit]", encoding="utf-8")
        (units / "anderer.service").write_text("[Unit]", encoding="utf-8")

    def test_aufraeumen_entfernt_nur_programmdateien(self):
        self.old_installation()
        done = self.run_update("--cleanup", "-y")
        self.assertEqual(done.returncode, 0, done.stderr)
        left = sorted(p.name for p in self.dir.iterdir())
        self.assertEqual(
            left,
            [
                ".env",
                "backups",
                "data",
                "docker-compose.override.yml",
                "docker-compose.yml",
                "docker-compose.yml.alt",
                "update.sh",
            ],
        )
        self.assertEqual((self.dir / "data" / "tls" / "key.pem").read_text(encoding="utf-8"), "geheim")
        self.assertTrue((self.dir / "backups" / "data-20261020.tar.gz").exists())
        units = sorted(p.name for p in (self.etc / "systemd" / "system").iterdir())
        self.assertEqual(units, ["anderer.service"])  # nur die alte Internet-Sperre
        self.assertIn("Never touched: data/", done.stdout)

    def test_aufraeumen_fragt_und_loescht_ohne_ja_nichts(self):
        self.old_installation()
        done = self.run_update("--cleanup")  # ohne Terminal und ohne -y: nein
        self.assertEqual(done.returncode, 0)
        self.assertIn("Nothing deleted", done.stdout)
        self.assertTrue((self.dir / "Dockerfile").exists())
        self.assertIn("samonboarding-1.48.1.zip", done.stdout)  # die Liste wird gezeigt

    def test_aufraeumen_schont_daten_auch_ueber_links(self):
        d = self.dir
        # 1. ein bekannter Programmname ist ein Link auf die Daten
        os.symlink(d / "data", d / "samonboarding")
        # 2. ein Programmordner enthaelt einen Link in die Daten
        (d / "static").mkdir()
        os.symlink(d / "data" / "tls", d / "static" / "tls")
        (d / "data" / "tls").mkdir()
        (d / "data" / "tls" / "cert.pem").write_text("cert", encoding="utf-8")
        # 3. data selbst ist ein Link auf einen Ordner ausserhalb; ein Programmordner liegt darin verlinkt
        real_data = Path(self.tmp.name) / "echte-daten"
        real_data.mkdir()
        (real_data / "reports.db").write_text("db", encoding="utf-8")
        (real_data / "tests").mkdir()
        os.symlink(real_data / "tests", d / "tests")
        backups_real = Path(self.tmp.name) / "sicherungen"
        backups_real.mkdir()
        (backups_real / "x.tar.gz").write_text("s", encoding="utf-8")
        os.symlink(backups_real, d / "backups")
        os.symlink(real_data, d / "data-extern")
        # 4. ein Ordner, den ein Container eingebunden hat
        (d / "node_modules").mkdir()
        (d / "node_modules" / "wichtig.txt").write_text("w", encoding="utf-8")
        self.change(mounts=[str(d / "node_modules"), str(real_data)])
        # 5. bekannter Programmname, aber ein Link nach ausserhalb dieses Ordners
        os.symlink("/etc", d / "scripts")
        (d / "Dockerfile").write_text("x", encoding="utf-8")

        done = self.run_update("--cleanup", "-y")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((d / "data" / "config.json").exists())
        self.assertEqual((d / "data" / "tls" / "cert.pem").read_text(encoding="utf-8"), "cert")
        self.assertTrue(os.path.islink(d / "samonboarding"))  # Link auf Daten: unangetastet
        self.assertTrue((real_data / "reports.db").exists())
        self.assertTrue((real_data / "tests").exists())  # Link in eingebundene Daten: unangetastet
        self.assertTrue((backups_real / "x.tar.gz").exists())
        self.assertTrue((d / "node_modules" / "wichtig.txt").exists())  # Container-Mount: unangetastet
        self.assertTrue(os.path.islink(d / "scripts") and Path("/etc").is_dir())
        self.assertFalse((d / "Dockerfile").exists())  # echte Programmdatei: entfernt
        # Programmordner mit einem Link in die Daten: nur der Ordner samt Link verschwindet, die Daten bleiben
        self.assertFalse((d / "static").exists())
        self.assertIn("Left alone", done.stdout)

    def test_aufraeumen_ohne_altlasten(self):
        done = self.run_update("--cleanup", "-y")
        self.assertEqual(done.returncode, 0)
        self.assertIn("Nothing to clean up", done.stdout)


class UpdateShTextTests(unittest.TestCase):
    """Was update.sh nicht mehr tun darf (alte Wege) und was es fuer NAS und dash braucht."""

    def test_nur_posix_sh(self):
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        # Synology: "sh" kann eine aeltere bash im POSIX-Modus sein, sonst dash/busybox - nichts davon voraussetzen
        for bashism in ("[[", "local ", "${!", "declare ", "function ", "<<<", "$'", "pipefail", "BASH_", "<(", "+="):
            self.assertFalse(bashism in text, bashism)
        # auf einem NAS fehlen manche GNU-Werkzeuge (frueherer Fehler auf der Synology)
        for tool in ("cmp ", "sha256sum", "timeout ", "sort -V", "realpath", "readlink -f"):
            self.assertFalse(tool in text, tool)
        # keine alten Wege mehr: ZIP, Bauen, Festschreiben, Programmdateien ablegen
        for gone in ("unzip", "docker build", "dc build", "load_images", "pins.py", "lock_python", "zip_auspacken"):
            self.assertFalse(gone in text, gone)
        if shutil.which("dash"):
            subprocess.run(["dash", "-n", str(ROOT / "update.sh")], check=True)

    def test_im_image_und_ausfuehrbar(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("chmod 755 /app/docker-entrypoint.sh /app/update.sh", docker)
        ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        for needed in ("update.sh", "docker-compose.yml", "docker-entrypoint.sh"):
            self.assertNotIn(needed, ignore)
        self.assertIn("!.env.example", ignore)  # die Vorlage kommt mit ins Image


if __name__ == "__main__":
    unittest.main()
