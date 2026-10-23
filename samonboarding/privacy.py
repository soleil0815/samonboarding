"""Datenschutz (DSGVO): Aufbewahrungsfristen und Auskunft.

Personenbezogene Daten speichert die Anwendung nur in data/:
  * reports.db, Tabelle audit   Aenderungen (wer hat wann was getan)  -> AUDIT_RETENTION_DAYS    (Standard 365)
  * reports.db, Tabelle applog  Protokoll (Programm-Meldungen)        -> LOG_RETENTION_DAYS      (Standard 90)
  * offboarding.db              Wiederherstellungs-Eintraege          -> OFFBOARD_RETENTION_DAYS (Standard 180)
0 bedeutet: unbegrenzt aufbewahren. Die Bereinigung laeuft beim Start und danach einmal taeglich.
Manuell loeschen koennen Administratoren unter "Berichte".

Auskunft nach Art. 15 DSGVO (im Container; in der Oberflaeche unter "Datenschutz"):
    docker compose exec samonboarding python -m samonboarding.privacy auskunft <sAMAccountName>
Bereinigung sofort ausfuehren:
    docker compose exec samonboarding python -m samonboarding.privacy bereinigen
"""

import json
import logging
import sys
import threading
from datetime import datetime, timedelta, timezone

from . import config, offboard_store, reports

log = logging.getLogger(__name__)
INTERVAL_SECONDS = 24 * 3600


def _cutoff_iso(days, now=None):
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    return cutoff.astimezone(timezone.utc).isoformat(timespec="seconds")


def purge_audit(days, now=None):
    """Entfernt Aenderungen, die aelter als `days` Tage sind. Liefert die Anzahl."""
    return reports.delete_older_than("audit", _cutoff_iso(days, now)) if days > 0 else 0


def purge_log(days, now=None):
    """Entfernt Protokoll-Eintraege, die aelter als `days` Tage sind."""
    return reports.delete_older_than("applog", _cutoff_iso(days, now)) if days > 0 else 0


def purge_offboarding(days, now=None):
    """Entfernt Wiederherstellungs-Eintraege, die aelter als `days` Tage sind."""
    return offboard_store.purge_older_than(_cutoff_iso(days, now)) if days > 0 else 0


def run_retention(now=None):
    """Alle Fristen anwenden; Fehler werden protokolliert, nie geworfen."""
    result = {"audit": 0, "log": 0, "offboarding": 0}
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
    log.info(
        "Aufbewahrungsfristen geprueft: %s Aenderungen, %s Protokoll-Eintraege und %s Wiederherstellungs-Eintraege "
        "entfernt",
        result["audit"],
        result["log"],
        result["offboarding"],
    )
    return result


def start_retention_thread():
    """Bereinigung jetzt und danach taeglich im Hintergrund."""
    stop = threading.Event()

    def loop():
        while True:
            run_retention()
            try:
                from . import tls

                tls.check_expiry()  # Warnung ins Protokoll, wenn das HTTPS-Zertifikat bald ablaeuft
            except Exception as e:
                log.error("Pruefung des HTTPS-Zertifikats fehlgeschlagen: %s", e)
            if stop.wait(INTERVAL_SECONDS):
                return

    threading.Thread(target=loop, name="retention", daemon=True).start()
    return stop


def subject_report(sam):
    """Alles, was die Anwendung selbst ueber ein Konto gespeichert hat (Auskunft nach Art. 15 DSGVO)."""
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
