"""Kurzer Zwischenspeicher fuer Konto-Listen (nur im Arbeitsspeicher, je Sitzung).

Wechselt man in der Oberflaeche zwischen den Bereichen, muessen die Listen nicht jedes Mal neu vom DC gelesen
werden. Bewusst KEINE Kopie der AD-Daten in einer Datenbank:
  - je Sitzung: jeder sieht nur, was er mit seinen eigenen AD-Rechten sehen darf
  - nur im Arbeitsspeicher und nur kurz (CACHE_SECONDS): nichts landet auf der Festplatte (Datenschutz)
  - jede Aenderung leert den Speicher sofort (invalidate, aufgerufen von audit() und save_json())
  - "Aktualisieren" in der Oberflaeche liest immer frisch (frisch=1)
  - Entscheidungen (geschuetzt? in der freigegebenen OU?) werden vor jeder Aktion weiterhin live geprueft
"""

import copy
import threading
import time

CACHE_SECONDS = 60
MAX_ENTRIES = 500

_lock = threading.Lock()
_store = {}  # (Sitzung, Schluessel) -> (gueltig bis, Generation, Wert)
_generation = 0


def invalidate():
    """Alles verwerfen (nach jeder Aenderung im AD oder an den Einstellungen)."""
    global _generation
    with _lock:
        _generation += 1
        _store.clear()


def cached(user, key, build, fresh=False):
    """Wert aus dem Speicher oder build() aufrufen und merken. Fehler werden nie gespeichert."""
    sid = (user or {}).get("sid") or ""
    now = time.monotonic()
    with _lock:
        hit = _store.get((sid, key))
        gen = _generation
        if hit and not fresh and hit[0] > now and hit[1] == gen:
            return copy.deepcopy(hit[2])
    value = build()
    if isinstance(value, dict) and value.get("error"):
        return value  # Ersatzliste bei DC-Fehler (z. B. AD-Struktur) nicht merken - naechstes Mal neu versuchen
    with _lock:
        for k in [k for k, v in _store.items() if v[0] <= now]:  # Abgelaufenes sofort aus dem Speicher
            del _store[k]
        if gen == _generation and sid:  # zwischendurch geaendert? dann nicht merken
            if len(_store) >= MAX_ENTRIES:
                for k in list(_store)[: MAX_ENTRIES // 2]:
                    _store.pop(k, None)
            _store[(sid, key)] = (now + CACHE_SECONDS, gen, copy.deepcopy(value))
    return value


def forget_session(sid):
    with _lock:
        for k in [k for k in _store if k[0] == sid]:
            del _store[k]
