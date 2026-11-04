# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Data protection (GDPR): retention periods and data access requests.

The application stores personal data only in data/:
  * reports.db, table audit     changes (who did what and when)       -> AUDIT_RETENTION_DAYS    (default 365)
  * reports.db, table applog    log (program messages)                -> LOG_RETENTION_DAYS      (default 90)
  * offboarding.db              restore entries                       -> OFFBOARD_RETENTION_DAYS (default 180)
0 means: keep indefinitely. The cleanup runs at startup and then once a day.
The application's own backups (data/backups/vor-*.tar.gz) also contain this data: they are removed once they are
older than the longest retention period (then everything in them has expired); if any period is 0, they are kept.
Administrators can delete manually under "Berichte".

Data access request under Art. 15 GDPR (in the container; in the UI under "Datenschutz"):
    docker compose exec samonboarding python -m samonboarding.privacy auskunft <sAMAccountName>
Run the cleanup immediately:
    docker compose exec samonboarding python -m samonboarding.privacy bereinigen
"""

import json
import logging
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config, datastate, offboard_store, reports

log = logging.getLogger(__name__)
INTERVAL_SECONDS = 24 * 3600


def _cutoff_iso(days, now=None):
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    return cutoff.astimezone(timezone.utc).isoformat(timespec="seconds")


def purge_audit(days, now=None):
    """Removes changes older than `days` days. Returns the count."""
    return reports.delete_older_than("audit", _cutoff_iso(days, now)) if days > 0 else 0


def purge_log(days, now=None):
    """Removes log entries older than `days` days."""
    return reports.delete_older_than("applog", _cutoff_iso(days, now)) if days > 0 else 0


def purge_offboarding(days, now=None):
    """Removes restore entries older than `days` days."""
    return offboard_store.purge_older_than(_cutoff_iso(days, now)) if days > 0 else 0


def purge_backups(days_list, now=None, data_dir=None):
    """Removes the application's own backups (data/backups/vor-*.tar.gz) older than the longest retention period -
    everything in them has expired by then. If any period is 0 (indefinite), every backup is kept. Returns the count."""
    if not days_list or any(d <= 0 for d in days_list):
        return 0
    folder = Path(data_dir or config.DATA_DIR) / datastate.BACKUP_DIR_NAME
    if not folder.is_dir():
        return 0
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=max(days_list))).timestamp()
    removed = 0
    for path in folder.iterdir():
        own = datastate._BACKUP_RE.match(path.name) and path.is_file() and not path.is_symlink()
        if own and path.stat().st_mtime < cutoff:
            path.unlink()
            removed += 1
    return removed


def run_retention(now=None):
    """Apply all retention periods; errors are logged, never raised."""
    result = {"audit": 0, "log": 0, "offboarding": 0, "backups": 0}
    jobs = (
        ("audit", purge_audit, config.AUDIT_RETENTION_DAYS),
        ("log", purge_log, config.LOG_RETENTION_DAYS),
        ("offboarding", purge_offboarding, config.OFFBOARD_RETENTION_DAYS),
    )
    for key, fn, days in jobs:
        try:
            result[key] = fn(days, now)
        except Exception as e:
            log.error("Bereinigung (%s) fehlgeschlagen: %s", key, e)
    try:
        result["backups"] = purge_backups([days for _, _, days in jobs], now)
    except Exception as e:
        log.error("Bereinigung (Sicherungen) fehlgeschlagen: %s", e)
    log.info(
        "Aufbewahrungsfristen geprueft: %s Aenderungen, %s Protokoll-Eintraege, %s Wiederherstellungs-Eintraege und "
        "%s Sicherungen entfernt",
        result["audit"],
        result["log"],
        result["offboarding"],
        result["backups"],
    )
    return result


def start_retention_thread():
    """Clean up now and then daily in the background."""
    stop = threading.Event()

    def loop():
        while True:
            run_retention()
            try:
                from . import tls

                tls.check_expiry()  # log a warning if the HTTPS certificate expires soon
            except Exception as e:
                log.error("Pruefung des HTTPS-Zertifikats fehlgeschlagen: %s", e)
            if stop.wait(INTERVAL_SECONDS):
                return

    threading.Thread(target=loop, name="retention", daemon=True).start()
    return stop


def subject_report(sam):
    """Everything the application itself has stored about an account (data access request under Art. 15 GDPR)."""
    needle = sam.strip()
    if not needle:
        raise ValueError("sAMAccountName fehlt")
    records = [r for r in offboard_store.list_all() if r["sam"].lower() == needle.lower()]
    return {
        "account": needle,
        "createdAt": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "retention": {
            "auditDays": config.AUDIT_RETENTION_DAYS,
            "logDays": config.LOG_RETENTION_DAYS,
            "offboardingDays": config.OFFBOARD_RETENTION_DAYS,
        },
        "note": (
            "Treffer fuer den Kontonamen (als ganzes Wort, ohne Beachtung der Gross-/Kleinschreibung) und fuer die "
            "DNs des Kontos in den Aenderungen (als Ausfuehrender, als Ziel, in den Details) und im Protokoll. Vor der "
            "Herausgabe pruefen und Angaben ueber andere Personen schwaerzen. Die Daten im Active Directory selbst "
            "sind nicht enthalten."
        ),
        "auditEntries": reports.audit_for_account(needle),
        "logEntries": reports.log_for_account(needle),
        "offboardingRecords": records,
    }


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["auskunft"] and len(args) == 2:
        print(json.dumps(subject_report(args[1]), ensure_ascii=False, indent=2, default=str))
        return 0
    if args == ["bereinigen"]:
        print(json.dumps(run_retention(), ensure_ascii=False))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
