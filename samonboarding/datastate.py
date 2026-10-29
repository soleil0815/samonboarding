"""Datenstand: Sicherung vor einem Versionswechsel, Migrationen und Schutz vor einer aelteren Programmversion.

data/datenstand.json haelt fest, welche Programmversion die Daten zuletzt benutzt hat und welchen Datenstand
(Format der Dateien und Datenbanken) sie haben:  {"datenstand": 1, "version": "2.0.0", "seit": "..."}

Beim Start (vor dem Server):
  - neue Installation (data/ leer): Datenstand eintragen, nichts weiter
  - andere Programmversion als zuletzt: erst data/ sichern nach data/backups/vor-<Version>-<Zeitpunkt>.tar.gz,
    dann die Migrationen bis zum aktuellen Datenstand ausfuehren
  - Daten von einer NEUEREN Version (hoeherer Datenstand): Start abbrechen, mit Meldung, welche Sicherung
    zurueckzuspielen ist - statt mit Folgefehlern weiterzulaufen
Sicherheitsupdates (<Version>-s<Zaehler>) sind dasselbe Programm: VERSION bleibt gleich, also keine Sicherung.
"""

import datetime as dt
import json
import logging
import os
import re
import tarfile
from pathlib import Path

from .config import DATA_DIR, VERSION

log = logging.getLogger(__name__)

DATA_STATE = 1  # aktueller Datenstand; bei einer Format-Aenderung erhoehen und eine Migration eintragen
# Migrationen: {n: funktion(data_dir)} bringt die Daten von Stand n-1 auf Stand n
MIGRATIONS = {}
STATE_NAME = "datenstand.json"
BACKUP_DIR_NAME = "backups"
KEEP_BACKUPS = 10
_BACKUP_RE = re.compile(r"^vor-(.+)-(\d{8}-\d{6})\.tar\.gz$")


class DataTooNew(Exception):
    """Die Daten stammen von einer neueren Programmversion - Start abbrechen."""


def _version_key(text):
    parts = re.findall(r"\d+", str(text).split("-s")[0])[:3]
    return tuple(int(p) for p in parts) if parts else (0,)


def read_state(data_dir=DATA_DIR):
    path = Path(data_dir) / STATE_NAME
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(state, dict) or not isinstance(state.get("datenstand"), int):
        return None
    return state


def write_state(data_dir, version, data_state, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    path = Path(data_dir) / STATE_NAME
    tmp = path.with_suffix(".tmp")
    text = json.dumps({"datenstand": data_state, "version": version, "seit": now.isoformat(timespec="seconds")})
    tmp.write_text(text + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _has_data(data_dir):
    """Gibt es schon Daten (auch von einer Version vor 2.0, die noch keinen Datenstand kannte)?"""
    skip = {BACKUP_DIR_NAME, ".schreibtest"}
    return any(p.name not in skip for p in Path(data_dir).iterdir())


def backup(data_dir, version, now=None, keep=KEEP_BACKUPS):
    """data/ (ohne die Sicherungen selbst) nach data/backups/vor-<version>-<zeit>.tar.gz; alte Sicherungen kappen."""
    now = now or dt.datetime.now()
    data_dir = Path(data_dir)
    target_dir = data_dir / BACKUP_DIR_NAME
    target_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(target_dir, 0o700)
    name = f"vor-{version}-{now.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    target = target_dir / name
    tmp = target_dir / (name + ".tmp")
    with tarfile.open(tmp, "w:gz") as tar:
        for item in sorted(data_dir.iterdir()):
            if item.name in (BACKUP_DIR_NAME, ".schreibtest"):
                continue
            tar.add(item, arcname=item.name)
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    backups = sorted((p for p in target_dir.iterdir() if _BACKUP_RE.match(p.name)), key=lambda p: p.name[-22:])
    for old in backups[:-keep] if keep > 0 else []:
        old.unlink()
    return target


def find_backup(data_dir, version):
    """Neueste Sicherung, die beim Umstieg auf <version> angelegt wurde (der Datenstand davor)."""
    folder = Path(data_dir) / BACKUP_DIR_NAME
    if not folder.is_dir():
        return None
    matches = [p for p in folder.iterdir() if (m := _BACKUP_RE.match(p.name)) and m.group(1) == version]
    return max(matches, key=lambda p: p.name[-22:], default=None)


def prepare(data_dir=DATA_DIR, version=VERSION, data_state=DATA_STATE, migrations=None, now=None):
    """Beim Start aufrufen. Gibt eine kurze Beschreibung zurueck; wirft DataTooNew bei Daten einer neueren Version."""
    migrations = MIGRATIONS if migrations is None else migrations
    data_dir = Path(data_dir)
    state = read_state(data_dir)
    if state is None:
        if not _has_data(data_dir):
            write_state(data_dir, version, data_state, now)
            return "neue Installation"
        state = {"datenstand": 1, "version": "vor 2.0"}  # Daten einer Version ohne Datenstand (bis 1.48)
    stored, stored_version = state["datenstand"], str(state.get("version") or "?")
    if stored > data_state:
        found = find_backup(data_dir, stored_version)
        restore = (
            f"die Sicherung zurückspielen, die beim Umstieg auf {stored_version} angelegt wurde: "
            f"data/{BACKUP_DIR_NAME}/{found.name} (sh update.sh --restore data/{BACKUP_DIR_NAME}/{found.name})"
            if found
            else f"eine Sicherung aus data/{BACKUP_DIR_NAME} von vor {stored_version} zurückspielen"
        )
        raise DataTooNew(
            f"Die Daten stammen von SAMONBOARDING {stored_version} (Datenstand {stored}). Diese Version {version} "
            f"kennt nur Datenstand {data_state} und startet deshalb nicht, um nichts zu beschädigen. Entweder wieder "
            f"{stored_version} oder neuer verwenden (SAMONBOARDING_VERSION in der .env) oder {restore}."
        )
    if stored_version == version and stored == data_state:
        return "unverändert"
    saved = backup(data_dir, version, now)
    log.info("Versionswechsel %s -> %s: Daten gesichert nach %s", stored_version, version, saved)
    for step in range(stored + 1, data_state + 1):
        migrations[step](data_dir)
        write_state(data_dir, version, step, now)
        log.info("Daten auf Datenstand %s gebracht", step)
    write_state(data_dir, version, data_state, now)
    if _version_key(version) < _version_key(stored_version):
        log.warning(
            "Aeltere Programmversion %s auf Daten von %s (gleicher Datenstand) gestartet", version, stored_version
        )
    return f"{stored_version} -> {version}, gesichert: {saved.name}"


# ---------------------------------------------------------------------------------------------------------------------
# Kennung der docker-compose.yml: die Datei setzt SAMONBOARDING_COMPOSE. Ist sie aelter als hier verlangt, zeigt die
# Oberflaeche Administratoren einen Hinweis (Vorgaben stehen im Programm, die Datei aendert sich nur selten).
# ---------------------------------------------------------------------------------------------------------------------
COMPOSE_REQUIRED = 2


def compose_notice(env=None):
    """None, wenn die docker-compose.yml aktuell ist; sonst {"have": n, "need": m}."""
    env = os.environ if env is None else env
    raw = str(env.get("SAMONBOARDING_COMPOSE", "")).strip()
    have = int(raw) if raw.isdigit() else 0
    if have >= COMPOSE_REQUIRED:
        return None
    return {"have": have, "need": COMPOSE_REQUIRED}
