# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Berichte in SQLite (data/reports.db): Aenderungen (Audit) und Protokoll (Programm-Meldungen).

  audit   wer hat wann was getan (ohne Passwoerter)       -> AUDIT_RETENTION_DAYS (Standard 365)
  applog  Meldungen des Programms ab Stufe INFO           -> LOG_RETENTION_DAYS   (Standard 90)

Geloeschte Eintraege werden in der Datei ueberschrieben (PRAGMA secure_delete), damit sie nicht wiederherstellbar sind.
"""

import json
import logging
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config
from .storage import restrict

log = logging.getLogger(__name__)
_lock = threading.RLock()
_state = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    ts_utc   TEXT NOT NULL,
    actor    TEXT NOT NULL DEFAULT '',
    action   TEXT NOT NULL DEFAULT '',
    target   TEXT NOT NULL DEFAULT '',
    ok       INTEGER NOT NULL DEFAULT 1,
    details  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts_utc);
CREATE TABLE IF NOT EXISTS applog (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    ts_utc   TEXT NOT NULL,
    level    TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT '',
    message  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS applog_ts ON applog (ts_utc);
"""

TABLES = ("audit", "applog")
LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")
MAX_MESSAGE = 4000


@contextmanager
def _db():
    with _lock:
        outer_busy = getattr(_state, "busy", False)
        _state.busy = True  # Meldungen waehrend eines Datenbankzugriffs nicht erneut in die Datenbank schreiben
        conn = sqlite3.connect(config.REPORTS_DB_FILE, timeout=10)
        restrict(config.REPORTS_DB_FILE)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA secure_delete = ON")
            conn.executescript(SCHEMA)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            _state.busy = outer_busy


def _stamp(ts=None):
    """(Ortszeit mit Zeitzone fuer die Anzeige, UTC fuer Fristen und Sortierung)."""
    ts = ts or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone().isoformat(timespec="seconds"), ts.astimezone(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Schreiben
# ---------------------------------------------------------------------------
def write_audit(actor, action, target="", ok=True, details=None, ts=None):
    local, utc = _stamp(ts)
    with _db() as conn:
        conn.execute(
            "INSERT INTO audit (ts, ts_utc, actor, action, target, ok, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                local,
                utc,
                str(actor or ""),
                str(action or ""),
                str(target or ""),
                1 if ok else 0,
                json.dumps(details or {}, ensure_ascii=False, default=str),
            ),
        )


def _shorten(message):
    """Lange Meldungen (Fehlerverlauf) kuerzen; Anfang und Ende bleiben, am Ende steht die eigentliche Ursache."""
    message = str(message)
    if len(message) <= MAX_MESSAGE:
        return message
    head = MAX_MESSAGE // 4
    return message[:head] + "\n[...]\n" + message[-(MAX_MESSAGE - head - 7) :]


def write_log(level, source, message, ts=None):
    local, utc = _stamp(ts)
    with _db() as conn:
        conn.execute(
            "INSERT INTO applog (ts, ts_utc, level, source, message) VALUES (?, ?, ?, ?, ?)",
            (local, utc, level, source, _shorten(message)),
        )


class DbLogHandler(logging.Handler):
    """Schreibt Programm-Meldungen (ab INFO) in die Tabelle applog. Fehler hier landen nie in einer Endlosschleife."""

    def __init__(self, level=logging.INFO):
        super().__init__(level)

    def emit(self, record):
        if getattr(_state, "busy", False):  # waehrend eines Datenbankzugriffs (verhindert Endlosschleifen)
            return
        _state.busy = True
        try:
            message = record.getMessage()
            if record.exc_info:
                message += "\n" + _FORMATTER.formatException(record.exc_info)
            ts = datetime.fromtimestamp(record.created, timezone.utc)
            write_log(record.levelname, record.name, message, ts=ts)
        except Exception:  # Protokollieren darf das Programm nie stoeren
            pass
        finally:
            _state.busy = False


_handler = None
_FORMATTER = logging.Formatter()


def install_log_handler():
    """Haengt den Datenbank-Handler einmalig an den Root-Logger."""
    global _handler
    if _handler is None:
        _handler = DbLogHandler()
        logging.getLogger().addHandler(_handler)
        # Unerwartete Fehler (HTTP 500) meldet uvicorn ueber einen eigenen Logger, der nicht beim Root-Logger ankommt
        logging.getLogger("uvicorn.error").addHandler(DbLogHandler(logging.WARNING))
    return _handler


# ---------------------------------------------------------------------------
# Lesen
# ---------------------------------------------------------------------------
def _audit_row(r):
    try:
        details = json.loads(r["details"] or "{}")
    except ValueError:
        details = {"raw": r["details"]}
    return {
        "id": r["id"],
        "ts": r["ts"],
        "actor": r["actor"],
        "action": r["action"],
        "target": r["target"],
        "ok": bool(r["ok"]),
        "details": details,
    }


def _log_row(r):
    return {"id": r["id"], "ts": r["ts"], "level": r["level"], "source": r["source"], "message": r["message"]}


def _like(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def query_audit(q="", result="all", before=None, limit=100):
    """Neueste zuerst. `before` = id fuer 'mehr laden'. Liefert (Eintraege, naechstes before oder None)."""
    where, args = [], []
    if q:
        where.append(
            "(actor LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' "
            "OR details LIKE ? ESCAPE '\\')"
        )
        args += [_like(q)] * 4
    if result in ("ok", "fail"):
        where.append("ok = ?")
        args.append(1 if result == "ok" else 0)
    return _page("audit", where, args, before, limit, _audit_row)


def query_log(q="", level="all", before=None, limit=100):
    where, args = [], []
    if q:
        where.append("(message LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')")
        args += [_like(q)] * 2
    if level == "warning":
        where.append("level IN ('WARNING', 'ERROR', 'CRITICAL')")
    elif level == "error":
        where.append("level IN ('ERROR', 'CRITICAL')")
    return _page("applog", where, args, before, limit, _log_row)


def _page(table, where, args, before, limit, convert):
    limit = max(1, min(int(limit or 100), 500))
    if before:
        where = where + ["id < ?"]
        args = args + [int(before)]
    sql = f"SELECT * FROM {table}" + (" WHERE " + " AND ".join(where) if where else "")
    sql += " ORDER BY id DESC LIMIT ?"
    with _db() as conn:
        rows = conn.execute(sql, args + [limit + 1]).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    return [convert(r) for r in rows], (rows[-1]["id"] if more and rows else None)


def counts():
    with _db() as conn:
        out = {}
        for table in TABLES:
            row = conn.execute(f"SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM {table}").fetchone()
            out[table] = {"count": row["n"], "oldest": row["oldest"]}
        return out


def _mention_re(sam):
    """Der Kontoname als ganzes Wort: 'max' passt zu 'max', 'MAX@firma.local', '\\\\fs\\home$\\max' und 'max.V6',
    aber nicht zu 'maximilian' oder 'max.mustermann' (Auskunft darf keine Daten anderer enthalten)."""
    word = re.escape(sam.strip())
    return re.compile(rf"(?<![A-Za-z0-9._-]){word}(?![A-Za-z0-9_-])(?!\.(?!V\d)[A-Za-z0-9])", re.IGNORECASE)


def _account_dns(rows, sam):
    """DNs, unter denen das Konto in den Aenderungen vorkommt (Eintraege mit sam im Detail und einem DN als Ziel)."""
    key = sam.strip().casefold()
    dns = set()
    for r in rows:
        target = str(r["target"] or "")
        if not target.lower().startswith("cn="):
            continue
        try:
            details = json.loads(r["details"] or "{}")
        except ValueError:
            continue
        if isinstance(details, dict) and str(details.get("sam", "")).casefold() == key:
            dns.add(target.casefold())
    return dns


def _audit_matches(r, word, sam, dns):
    target = str(r["target"] or "")
    if target.casefold() in dns or target.casefold() == sam.casefold():
        return True
    # Ein DN als Ziel enthaelt den Anzeigenamen, nicht den Kontonamen - darin nicht suchen ('muster' passt sonst
    # zu 'CN=Erika Muster', also zu einer anderen Person)
    if not target.lower().startswith("cn=") and word.search(target):
        return True
    return bool(word.search(str(r["actor"] or "")) or word.search(str(r["details"] or "")))


def audit_for_account(sam):
    """Alle Aenderungen zu einem Konto (Auskunft nach Art. 15 DSGVO), aelteste zuerst: als Ausfuehrender, als Ziel
    (Kontoname oder einer seiner DNs) oder in den Details. Vergleich in Python, damit auch Umlaute in Gross-/
    Kleinschreibung passen (SQLite vergleicht nur ASCII ohne Gross-/Kleinschreibung)."""
    with _db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
    word = _mention_re(sam)
    dns = _account_dns(rows, sam)
    return [_audit_row(r) for r in rows if _audit_matches(r, word, sam, dns)]


def account_dns(sam):
    with _db() as conn:
        return _account_dns(conn.execute("SELECT target, details FROM audit").fetchall(), sam)


def log_for_account(sam, dns=None):
    """Protokoll-Eintraege, in denen der Kontoname oder einer seiner DNs vorkommt (Auskunft), aelteste zuerst."""
    dns = account_dns(sam) if dns is None else dns
    with _db() as conn:
        rows = conn.execute("SELECT * FROM applog ORDER BY id").fetchall()
    word = _mention_re(sam)
    out = []
    for r in rows:
        message = str(r["message"] or "")
        folded = message.casefold()
        if word.search(message) or any(dn in folded for dn in dns):
            out.append(_log_row(r))
    return out


def audit_jsonl():
    """Alle Aenderungen als JSON-Zeilen wie im frueheren audit.log (fuer Tests und Export)."""
    with _db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
    lines = []
    for r in rows:
        e = _audit_row(r)
        entry = {"ts": e["ts"], "actor": e["actor"], "action": e["action"], "target": e["target"], "ok": e["ok"]}
        entry.update(e["details"])
        lines.append(json.dumps(entry, ensure_ascii=False, default=str))
    return "\n".join(lines) + ("\n" if lines else "")


# ---------------------------------------------------------------------------
# Loeschen
# ---------------------------------------------------------------------------
def delete_older_than(table, cutoff_utc_iso):
    if table not in TABLES:
        raise ValueError(table)
    with _db() as conn:
        return conn.execute(f"DELETE FROM {table} WHERE ts_utc < ?", (cutoff_utc_iso,)).rowcount


def delete_all(table):
    if table not in TABLES:
        raise ValueError(table)
    with _db() as conn:
        return conn.execute(f"DELETE FROM {table}").rowcount


# ---------------------------------------------------------------------------
# Uebernahme des alten audit.log (bis Version 1.22)
# ---------------------------------------------------------------------------
def _legacy_files():
    base = config.AUDIT_LOG_FILE
    rotated = [f"{base}.{n}" for n in range(9, 0, -1)]  # aelteste zuerst
    return [p for p in [*rotated, base] if os.path.isfile(p)]


def import_legacy_audit():
    """Uebernimmt audit.log (+ .1 ... ) in die Datenbank und entfernt die Dateien danach. Liefert die Anzahl."""
    files = _legacy_files()
    if not files:
        return 0
    rows = []
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts = datetime.fromisoformat(str(entry.pop("ts")))
                except (ValueError, KeyError, TypeError):
                    continue
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                actor, action = entry.pop("actor", ""), entry.pop("action", "")
                target, ok = entry.pop("target", ""), entry.pop("ok", True)
                local, utc = ts.isoformat(timespec="seconds"), ts.astimezone(timezone.utc).isoformat(timespec="seconds")
                rows.append((local, utc, actor, action, target, 1 if ok else 0, json.dumps(entry, ensure_ascii=False)))
    with _db() as conn:
        conn.executemany(
            "INSERT INTO audit (ts, ts_utc, actor, action, target, ok, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    for path in files:
        os.remove(path)
    log.info("Altes Audit-Log uebernommen: %s Eintraege aus %s Datei(en), Dateien entfernt", len(rows), len(files))
    return len(rows)
