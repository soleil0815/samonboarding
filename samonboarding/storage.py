"""JSON-Speicher: atomares Schreiben und gesichertes Lesen der Konfigurationsdateien."""

import copy
import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)


file_lock = threading.RLock()


def load_json(filename, default):
    with file_lock:
        if not os.path.exists(filename):
            return copy.deepcopy(default)
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            # Defekte Datei nicht ueberschreiben, sondern sichern.
            backup = f"{filename}.corrupt-{int(time.time())}"
            try:
                os.replace(filename, backup)
                log.error("%s ist kein gueltiges JSON - gesichert als %s", filename, backup)
            except OSError as e:
                log.error("%s ist kein gueltiges JSON und konnte nicht gesichert werden: %s", filename, e)
            return copy.deepcopy(default)
        except OSError as e:
            log.error("%s konnte nicht gelesen werden: %s", filename, e)
            return copy.deepcopy(default)


def save_json(filename, data, invalidate=True):
    with file_lock:
        tmp = f"{filename}.tmp"
        # Nur fuer den Eigentuemer lesbar: die Dateien enthalten z. B. das SMTP-Passwort
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, filename)
        restrict(filename)
    if invalidate:
        from . import listcache

        listcache.invalidate()  # geaenderte Einstellungen (z. B. Quell-OUs) wirken sofort auf die Listen


def restrict(path):
    """Rechte auf 0600 setzen (best effort, z. B. fuer vorhandene Dateien aus aelteren Versionen)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
