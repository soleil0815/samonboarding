"""Reproduzierbarer Build: exakte Versionen (Python, npm, Basis-Images) und update.sh."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)


def lines(name):
    return [
        line.strip()
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


class PythonPinsTests(unittest.TestCase):
    def test_alle_pakete_exakt(self):
        reqs = lines("requirements.txt")
        self.assertGreater(len(reqs), 10)  # inklusive Abhaengigkeiten, nicht nur die direkten Pakete
        for req in reqs:
            self.assertRegex(req, r"^[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.+-]*$")
        names = {r.split("==")[0].lower().replace("_", "-") for r in reqs}
        for direct in ("fastapi", "uvicorn", "ldap3", "pydantic", "smbprotocol", "pypsrp", "starlette", "cryptography"):
            self.assertIn(direct, names)

    def test_direkte_pakete_stehen_in_der_sperrliste(self):
        locked = {r.split("==")[0].lower().replace("_", "-") for r in lines("requirements.txt")}
        for req in lines("requirements.in"):
            name = re.split(r"[<>=!~ ]", req, maxsplit=1)[0].lower().replace("_", "-")
            self.assertIn(name, locked)

    def test_dev_werkzeuge_exakt(self):
        for req in lines("requirements-dev.txt"):
            if not req.startswith("-r"):
                self.assertIn("==", req)

    def test_starlette_mindestens_1_3_1(self):
        """Sicherheitsluecken bis Starlette 1.3.0 (CVE-2025-62727, CVE-2026-54283 u. a.)."""
        text = (ROOT / "requirements.in").read_text(encoding="utf-8")
        self.assertIn("starlette>=1.3.1,<2", text)
        self.assertRegex(text, r"(?m)^fastapi>=0\.129")

    def test_festschreiben_nur_ueber_das_pins_skript(self):
        """update.sh --lock nutzt dasselbe Skript wie GitHub; ungepruefte Vorgaben werden nie gebaut."""
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/pins.py", text)
        self.assertIn("pins update ||", text)
        self.assertIn('pins os-lock "$IMAGE_NAME" --arch "$arch"', text)
        self.assertNotIn("lock_python", text)  # kein eigenes, abweichendes Festschreiben mehr
        self.assertIn('if [ "$IMAGE_GEHOLT" = 0 ] && [ "$DO_LOCK" = 0 ] && ! python_lock_in_sync; then\n    fail', text)
        # Fehlstart der neuen Version -> vorheriges Image wieder starten
        self.assertIn('docker tag "$OLD_IMAGE" "$IMAGE_NAME"', text)
        self.assertLess(text.index("OLD_IMAGE="), text.index("dc build ${BUILD_ARGS[@]+"))

    def test_dockerfile_installiert_nur_die_sperrliste(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("pip install --no-cache-dir --no-deps -r requirements.txt && pip check", docker)


class ImagePinsTests(unittest.TestCase):
    def test_basis_images_mit_version_und_digest(self):
        lock = dict(
            line.split("=", 1)
            for line in (ROOT / "images.lock").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )
        self.assertRegex(lock["PYTHON_IMAGE"], r"^python:3\.13\.\d+-slim-trixie@sha256:[0-9a-f]{64}$")
        self.assertRegex(lock["NODE_IMAGE"], r"^node:24\.\d+\.\d+-trixie-slim@sha256:[0-9a-f]{64}$")
        self.assertRegex(lock["DEBIAN_SNAPSHOT"], r"^\d{8}T\d{6}Z$")
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for key in ("PYTHON_IMAGE", "NODE_IMAGE", "DEBIAN_SNAPSHOT"):
            self.assertIn(f"ARG {key}\n", docker)  # ohne Vorgabe: kein Build mit einem wechselnden Tag
            self.assertIn(f"{key}: ${{{key}:-}}", compose)
        self.assertIn("FROM ${PYTHON_IMAGE}", docker)
        self.assertIn("FROM ${NODE_IMAGE} AS assets", docker)
        self.assertNotRegex(docker, r"FROM (python|node):")
        # alle Debian-Pakete (auch die des Basis-Images) aus dem festen Snapshot, nur aus dem eigenen Release
        self.assertIn("snapshot.debian.org/archive/%s/%s", docker)
        self.assertIn("full-upgrade", docker)
        self.assertIn("$VERSION_CODENAME-security", docker)
        self.assertNotIn("APT_REFRESH", docker + compose)
        packages = lines("os-packages.lock")
        self.assertGreater(len(packages), 50)
        for line in packages:
            self.assertRegex(line, r"^(amd64|arm64) [a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?=[0-9A-Za-z.+~:-]+$")
        self.assertEqual({line.split(" ")[0] for line in packages}, {"amd64", "arm64"})


class NpmPinsTests(unittest.TestCase):
    def test_package_json_und_sperrdatei_exakt(self):
        deps = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["dependencies"]
        self.assertTrue(deps["tailwindcss"].startswith("3."))  # Hauptversion bleibt
        self.assertTrue(deps["@fortawesome/fontawesome-free"].startswith("6."))
        for name, version in deps.items():
            self.assertRegex(version, r"^\d+\.\d+\.\d+$", name)
        lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["packages"][""]["dependencies"], deps)  # npm ci verlangt genau das
        for path, info in lock["packages"].items():
            if path:  # auch die indirekten Pakete mit exakter Version und Pruefsumme
                self.assertRegex(info["version"], r"^\d+\.\d+\.\d+", path)
                self.assertTrue(info.get("integrity", "").startswith("sha512-"), path)
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("npm ci --no-audit --no-fund --ignore-scripts", docker)


class UpdateScriptTests(unittest.TestCase):
    def test_update_sh(self):
        script = ROOT / "update.sh"
        text = script.read_text(encoding="utf-8")
        # Aufruf immer mit "sh update.sh": das Ausfuehrungsrecht geht z. B. beim Hochladen ueber die GitHub-Webseite
        # oder beim Entpacken unter Windows verloren - darauf darf nichts angewiesen sein
        self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
        for needed in ("--lock", "--no-backup", "dc build", "healthy", "KEEP_BACKUPS", "images.lock"):
            self.assertIn(needed, text)
        if shutil.which("bash"):
            subprocess.run(["bash", "-n", str(script)], check=True)
        if shutil.which("dash"):
            # "sh update.sh" (dash unter Debian/Ubuntu) muss sich selbst mit bash neu starten
            out = subprocess.run(["dash", str(script), "--help"], capture_output=True, text=True, check=True)
            self.assertIn("--lock", out.stdout)

    def test_alte_internet_sperre_wird_nach_dem_start_entfernt(self):
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        # erst wenn die neue Version laeuft: beim Zuruecksetzen braucht die vorherige Version ihre Sperre noch
        self.assertLess(text.index("NEUE_VERSION_LAEUFT=1"), text.index("\nsperre_entfernen\n"))
        alt = text[text.index("sperre_entfernen() {") : text.index("\nsperre_entfernen\n")]
        needed_all = ("systemctl disable --now", "/etc/systemd/system/$unit", "iptables -D", "-X", "SAMONB-HOST")
        for needed in needed_all:
            self.assertIn(needed, alt)
        self.assertNotIn("internet-sperre.sh an", text)
        self.assertNotIn("INTERNET_SPERRE", (ROOT / ".env.example").read_text(encoding="utf-8"))
        self.assertFalse((ROOT / "scripts" / "internet-sperre.sh").exists())

    def test_container_ohne_root(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER ${APP_UID}:${APP_UID}", docker)
        self.assertLess(docker.index("pip install"), docker.index("USER "))  # erst installieren, dann Rechte abgeben
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("- ALL", compose)
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertIn('as_root chown -R "$APP_UID:$APP_UID" data', text)
        self.assertLess(text.index('as_root chown -R "$APP_UID'), text.index('dc up "${UP_ARGS[@]}"'))
        self.assertIn("APP_UID=10001", text)
        self.assertIn("ARG APP_UID=10001", docker)

    def test_laeuft_mit_aelterer_bash_und_sh(self):
        """Synology: 'sh' ist dort eine bash im POSIX-Modus (aeltere Version) - keine <(...) und Neustart als bash."""
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertNotIn("<(", text)
        self.assertIn("*:posix:*", text)
        self.assertLess(text.index("*:posix:*"), text.index("set -euo pipefail"))
        if shutil.which("bash"):
            for args in (["bash", "--posix"], ["sh"], ["bash"]):
                if not shutil.which(args[0]):
                    continue
                done = subprocess.run([*args, str(ROOT / "update.sh"), "--help"], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("SAMONBOARDING", done.stdout)

    def test_abbruch_holt_vorherige_programmdateien(self):
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertIn("trap beim_beenden EXIT", text)
        # erst wenn die neue Version laeuft, bleibt sie bei einem spaeteren Fehler (z. B. beim Aufraeumen)
        self.assertLess(text.index("NEUE_VERSION_LAEUFT=1"), text.index("\nsperre_entfernen\n"))
        self.assertIn('if ! dc up "${UP_ARGS[@]}" || ! status=', text)  # auch "Port belegt" setzt zurueck
        self.assertIn('SAMONB_TMP="$tmpd"', text)  # Strg+C an der Rueckfrage: Zwischendateien weg
        self.assertIn('bash "$SELF" --no-backup', text)  # zweiter Durchgang auch bei relativem Aufruf

    def test_ohne_gnu_werkzeuge(self):
        """Synology: cmp, sha256sum, timeout, sort -V oder install koennen fehlen."""
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for helper in ("gleich() {", "sha256_16() {", "mit_zeitlimit() {", "neueste_zip() {"):
            self.assertIn(helper, code)
        body = code[code.index("neueste_zip() {") + 200 :]
        self.assertNotIn("install -m", body)
        self.assertNotIn("cmp -s", body)
        self.assertNotIn("timeout 1200", body)

    def test_aeltere_docker_compose_versionen(self):
        """Synology & Co.: keine Mindestversion, auch das eigenstaendige docker-compose wird verwendet."""
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertNotIn("2.24", text)
        self.assertIn("COMPOSE=(docker-compose)", text)
        self.assertNotIn('fail "Docker Compose fehlt', text)  # Compose ist keine Voraussetzung
        # ohne Compose: dieselben Einstellungen wie docker-compose.yml
        plain = text[text.index("dc_ohne_compose() {") : text.index("\ndc() {")]
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for needed in (
            "--cap-drop ALL",
            "no-new-privileges:true",
            "--restart unless-stopped",
            "com.docker.network.bridge.name=br-samonb",
            '-v "$PWD/data:/app/data"',
            "max-size=10m",
        ):
            self.assertIn(needed, plain)
        self.assertIn("br-samonb", compose)
        # Gesundheitspruefung im Image, damit sie auch ohne Compose gilt
        self.assertIn("HEALTHCHECK", (ROOT / "Dockerfile").read_text(encoding="utf-8"))
        # alle Compose-Aufrufe ueber dc (Plugin oder docker-compose)
        code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        calls = [line for line in code if "docker compose " in line and "version" not in line]
        self.assertEqual(calls, [])

    def test_fertiges_image_von_github(self):
        """GitHub baut das Image (fuer Dockhand & Co.) - erst nach bestandenen Tests im Image."""
        flow = (ROOT / ".github" / "workflows" / "image.yml").read_text(encoding="utf-8")
        self.assertLess(flow.index("pins.py test-image"), flow.index("--push"))
        self.assertIn("images.lock", flow)
        compose = (ROOT / "docker-compose.image.yml").read_text(encoding="utf-8")
        self.assertIn("image: ghcr.io/soleil0815/samonboarding:", compose)
        self.assertNotIn("build:", compose)
        for needed in ("no-new-privileges:true", "- ALL", "samonboarding-data:/app/data", "restart: unless-stopped"):
            self.assertIn(needed, compose)
        # jede Einstellung aus .env.example (ausser dem Docker-Netz) wird an den Container weitergegeben
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        keys = {line.split("=", 1)[0] for line in example.splitlines() if line and not line.startswith("#")}
        for key in keys - {"DOCKER_SUBNET"}:
            self.assertIn(f"      {key}: ${{{key}:", compose)

    def test_image_von_github_holen(self):
        """--pull holt das fertige Image von ghcr.io (kein git, kein Bauen) - mit Sicherung und Zuruecksetzen."""
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        block = text[text.index("image_holen() {") : text.index('if [ "$DO_PULL" = 1 ]')]
        self.assertIn('docker pull "$img"', block)
        self.assertIn("docker login ghcr.io", block)  # Hinweis, falls das Image privat ist
        self.assertIn("for f in update.sh docker-compose.yml", block)  # Skript passend zur Version des Images
        self.assertNotIn("git ", text.replace("GitHub", ""))  # kein git mehr noetig
        self.assertIn("UP_ARGS+=(--no-build)", text)  # nie ueber das Image von GitHub bauen
        self.assertIn("*.zip|*.ZIP|--pull)", text)  # laeuft aus einer Kopie, weil update.sh ersetzt werden kann
        self.assertIn('tar -xzf "$SAMONB_PULL_BACKUP"', text)  # beim Zuruecksetzen nur diese zwei Dateien
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("image: ${SAMONBOARDING_IMAGE:-ghcr.io/soleil0815/samonboarding:latest}", compose)
        self.assertNotIn("update.sh", (ROOT / ".dockerignore").read_text(encoding="utf-8").split())  # im Image

    def test_zip_einspielen(self):
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        # laeuft aus einer Kopie, weil es sich selbst ersetzt
        self.assertLess(text.index('exec env SAMONB_KOPIE="$_kopie"'), text.index('cd "${SAMONB_PROJEKT:-'))
        self.assertLess(text.index('cd "${SAMONB_PROJEKT:-'), text.index("zip_einspielen() {"))
        zip_block = text[text.index("zip_einspielen() {") : text.index('if [ "${#ZIPS[@]}" -gt 0 ]; then')]
        for needed in (
            "contains invalid paths",  # Zip-Slip
            "contains symbolic links",
            "Install the new version now? [y/N]",  # Bestaetigung
            "programm-",  # Sicherung der Programmdateien
            '"$tmpd/weg.liste"',  # Bereinigung entfallener Dateien
            'cp "$tmpd/neu.liste" .dateiliste',
        ):
            self.assertIn(needed, zip_block)
        # Einstellungen und Daten werden nie aus der ZIP uebernommen oder geloescht
        self.assertIn('rm -rf "$neu/data" "$neu/backups" "$neu/.env" "$neu/docker-compose.override.yml"', zip_block)
        geschuetzt = text[text.index("GESCHUETZT_RE=") : text.index("\n", text.index("GESCHUETZT_RE="))]
        for p in ("data", "backups", "\\.env", "docker-compose\\.override\\.yml"):
            self.assertIn(p, geschuetzt)
        # Fehlschlag: alte Programmdateien zurueck; Erfolg: ZIP und alte Images (nur mit Label) entfernen
        self.assertGreaterEqual(text.count("    programm_zurueck\n"), 2)
        self.assertIn('docker image prune -f --filter "label=de.helfi.samonboarding=1"', text)
        self.assertIn('LABEL de.helfi.samonboarding="1"', (ROOT / "Dockerfile").read_text(encoding="utf-8"))

    def test_sicherungen_und_skript_nicht_im_image_oder_git(self):
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        self.assertIn("backups/", dockerignore)
        self.assertIn("backups/", (ROOT / ".gitignore").read_text(encoding="utf-8").split())


if __name__ == "__main__":
    unittest.main()
