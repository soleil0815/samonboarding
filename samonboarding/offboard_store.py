# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Offboarding memory (SQLite in data/offboarding.db).

Before offboarding, the program records where the account was located, which groups it belonged to and whether it was
enabled. This allows an account that was offboarded by mistake to be restored. An entry disappears as soon as the
account has been restored or deleted, an administrator discards it,
or the retention period (OFFBOARD_RETENTION_DAYS) has expired. Passwords are not stored.
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config
from .storage import restrict

log = logging.getLogger(__name__)
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS offboarded (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_guid     TEXT NOT NULL DEFAULT '',
    sam           TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    original_dn   TEXT NOT NULL,
    current_dn    TEXT NOT NULL,
    original_ou   TEXT NOT NULL,
    was_enabled   INTEGER NOT NULL,
    groups_json   TEXT NOT NULL DEFAULT '[]',
    offboarded_at TEXT NOT NULL,
    offboarded_by TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS offboarded_sam ON offboarded (sam);
"""


@contextmanager
def _db():
    """One short connection per operation; the lock prevents concurrent writes from multiple threads."""
    with _lock:
        conn = sqlite3.connect(config.OFFBOARD_DB_FILE, timeout=10)
        restrict(config.OFFBOARD_DB_FILE)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA secure_delete=ON")  # deleted entries are overwritten (like reports.db)
            conn.executescript(SCHEMA)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rows(rows) -> list[dict]:
    return [out for out in (_row(r) for r in rows) if out is not None]


def _row(r):
    if r is None:
        return None
    out = dict(r)
    try:
        out["groups"] = json.loads(out.pop("groups_json") or "[]")
    except ValueError:
        out["groups"] = []
    out["was_enabled"] = bool(out["was_enabled"])
    return out


def record(*, user_guid, sam, name, original_dn, original_ou, was_enabled, groups, actor):
    """Create an entry (before offboarding). An open entry for the same account is replaced."""
    with _db() as conn:
        if user_guid:
            conn.execute("DELETE FROM offboarded WHERE user_guid = ? AND state = 'open'", (user_guid,))
        conn.execute("DELETE FROM offboarded WHERE lower(sam) = lower(?) AND state = 'open'", (sam,))
        cur = conn.execute(
            "INSERT INTO offboarded (user_guid, sam, name, original_dn, current_dn, original_ou, was_enabled, "
            "groups_json, offboarded_at, offboarded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_guid or "",
                sam,
                name or "",
                original_dn,
                original_dn,
                original_ou,
                1 if was_enabled else 0,
                json.dumps(groups, ensure_ascii=False),
                _now(),
                actor or "",
            ),
        )
        return cur.lastrowid


def update_current_dn(record_id, dn):
    with _db() as conn:
        conn.execute("UPDATE offboarded SET current_dn = ? WHERE id = ?", (dn, record_id))


def remove(record_id):
    with _db() as conn:
        conn.execute("DELETE FROM offboarded WHERE id = ?", (record_id,))


def get(record_id):
    with _db() as conn:
        return _row(conn.execute("SELECT * FROM offboarded WHERE id = ?", (record_id,)).fetchone())


def list_open():
    with _db() as conn:
        rows = conn.execute("SELECT * FROM offboarded WHERE state = 'open' ORDER BY offboarded_at DESC, id DESC")
        return _rows(rows.fetchall())


def list_all():
    """All entries (including 'in progress') - for data subject access requests under Art. 15 GDPR."""
    with _db() as conn:
        return _rows(conn.execute("SELECT * FROM offboarded ORDER BY offboarded_at, id").fetchall())


def purge_older_than(cutoff_iso):
    """Delete open entries created before `cutoff_iso` (UTC, ISO format). Returns the count.
    A restore that is currently running is kept; stuck ones are reset by reset_stale_claims() at startup."""
    with _db() as conn:
        cur = conn.execute("DELETE FROM offboarded WHERE state = 'open' AND offboarded_at < ?", (cutoff_iso,))
        return cur.rowcount


def reset_stale_claims():
    """At startup: a restore that was running at shutdown was aborted - show the entry again."""
    with _db() as conn:
        return conn.execute("UPDATE offboarded SET state = 'open' WHERE state = 'restoring'").rowcount


def claim(record_id):
    """Mark the entry as 'in progress'. False if it is not (or no longer) open - prevents double execution."""
    with _db() as conn:
        cur = conn.execute("UPDATE offboarded SET state = 'restoring' WHERE id = ? AND state = 'open'", (record_id,))
        return cur.rowcount == 1


def release(record_id):
    """Release an entry again after an error."""
    with _db() as conn:
        conn.execute("UPDATE offboarded SET state = 'open' WHERE id = ? AND state = 'restoring'", (record_id,))


def forget_account(*, user_guid="", sam="", dn=""):
    """Remove entries of a deleted account. Returns the count."""
    with _db() as conn:
        n = 0
        if user_guid:
            n += conn.execute("DELETE FROM offboarded WHERE user_guid = ?", (user_guid,)).rowcount
        if dn:
            n += conn.execute("DELETE FROM offboarded WHERE lower(current_dn) = lower(?)", (dn,)).rowcount
        if sam and not n:
            n += conn.execute("DELETE FROM offboarded WHERE lower(sam) = lower(?)", (sam,)).rowcount
        return n
