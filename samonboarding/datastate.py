# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Data state: backup before a version change, migrations and protection against an older program version.

data/datenstand.json records which program version last used the data and which data state
(format of the files and databases) it has:  {"datenstand": 1, "version": "2.0.0", "seit": "..."}

At startup (before the server):
  - new installation (data/ empty): record the data state, nothing else
  - different program version than last time: first back up data/ to data/backups/vor-<version>-<timestamp>.tar.gz,
    then run the migrations up to the current data state
  - data from a NEWER version (higher data state): abort startup with a message saying which backup to
    restore - instead of carrying on with follow-up errors
Security updates (<version>-s<counter>) are the same program: VERSION stays the same, so no backup.
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

DATA_STATE = 1  # current data state; increase on a format change and register a migration
# Migrations: {n: function(data_dir)} brings the data from state n-1 to state n
MIGRATIONS = {}
STATE_NAME = "datenstand.json"
BACKUP_DIR_NAME = "backups"
KEEP_BACKUPS = 10
PENDING_NAME = ".wechsel-laeuft"  # version change started (backup created), migrations not yet finished
_BACKUP_RE = re.compile(r"^vor-(.+)-(\d{8}-\d{6})\.tar\.gz$")


class DataTooNew(Exception):
    """The data comes from a newer program version - abort startup."""


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
    """Is there existing data (including from a version before 2.0 that had no data state yet)?"""
    skip = {BACKUP_DIR_NAME, ".schreibtest", PENDING_NAME}
    return any(p.name not in skip for p in Path(data_dir).iterdir())


def backup(data_dir, version, now=None, keep=KEEP_BACKUPS):
    """Back up data/ (except the backups themselves) to data/backups/vor-<version>-<time>.tar.gz; prune old ones."""
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
            if item.name in (BACKUP_DIR_NAME, ".schreibtest", PENDING_NAME):
                continue
            tar.add(item, arcname=item.name)
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    backups = sorted((p for p in target_dir.iterdir() if _BACKUP_RE.match(p.name)), key=lambda p: p.name[-22:])
    for old in backups[:-keep] if keep > 0 else []:
        old.unlink()
    return target


def find_backup(data_dir, version):
    """Newest backup created when switching to <version> (the data state before it)."""
    folder = Path(data_dir) / BACKUP_DIR_NAME
    if not folder.is_dir():
        return None
    matches = [p for p in folder.iterdir() if (m := _BACKUP_RE.match(p.name)) and m.group(1) == version]
    return max(matches, key=lambda p: p.name[-22:], default=None)


def prepare(data_dir=DATA_DIR, version=VERSION, data_state=DATA_STATE, migrations=None, now=None):
    """Call at startup. Returns a short description; raises DataTooNew for data from a newer version."""
    migrations = MIGRATIONS if migrations is None else migrations
    data_dir = Path(data_dir)
    state = read_state(data_dir)
    if state is None:
        if not _has_data(data_dir):
            write_state(data_dir, version, data_state, now)
            return "neue Installation"
        state = {"datenstand": 1, "version": "vor 2.0"}  # data from a version without data state (up to 1.48)
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
    # If a switch to this version was started but never finished (migration crashed, restart loop), keep the
    # backup from back then: otherwise half-migrated data would be backed up and, after KEEP_BACKUPS restarts,
    # the clean backup would be pruned
    pending = data_dir / PENDING_NAME
    try:
        pending_version = pending.read_text(encoding="utf-8").strip()
    except OSError:
        pending_version = ""
    found = find_backup(data_dir, version) if pending_version == version else None
    if found:
        saved = found
        log.warning("Wechsel auf %s war nicht abgeschlossen - es bleibt bei der Sicherung %s", version, saved.name)
    else:
        saved = backup(data_dir, version, now)
        pending.write_text(version + "\n", encoding="utf-8")
        os.chmod(pending, 0o600)
        log.info("Versionswechsel %s -> %s: Daten gesichert nach %s", stored_version, version, saved)
    for step in range(stored + 1, data_state + 1):
        migrations[step](data_dir)
        write_state(data_dir, version, step, now)
        log.info("Daten auf Datenstand %s gebracht", step)
    write_state(data_dir, version, data_state, now)
    pending.unlink(missing_ok=True)
    if _version_key(version) < _version_key(stored_version):
        log.warning(
            "Aeltere Programmversion %s auf Daten von %s (gleicher Datenstand) gestartet", version, stored_version
        )
    return f"{stored_version} -> {version}, gesichert: {saved.name}"


# ---------------------------------------------------------------------------------------------------------------------
# Revision of docker-compose.yml: the file sets SAMONBOARDING_COMPOSE. If it is older than required here, the UI
# shows administrators a notice (defaults live in the program, the file changes only rarely).
# ---------------------------------------------------------------------------------------------------------------------
COMPOSE_REQUIRED = 2


def compose_notice(env=None):
    """None if docker-compose.yml is up to date; otherwise {"have": n, "need": m}."""
    env = os.environ if env is None else env
    raw = str(env.get("SAMONBOARDING_COMPOSE", "")).strip()
    have = int(raw) if raw.isdigit() else 0
    if have >= COMPOSE_REQUIRED:
        return None
    return {"have": have, "need": COMPOSE_REQUIRED}
