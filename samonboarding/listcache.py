# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Short-lived cache for account lists (in memory only, per session).

When switching between sections in the UI, the lists do not have to be re-read from the DC every time.
Deliberately NO copy of the AD data in a database:
  - per session: everyone sees only what their own AD permissions allow
  - in memory only and only briefly (CACHE_SECONDS): nothing is written to disk (data protection)
  - every change clears the cache immediately (invalidate, called from audit() and save_json())
  - "Aktualisieren" (refresh) in the UI always reads fresh data (frisch=1)
  - decisions (protected? in the permitted OU?) are still checked live before every action
"""

import copy
import threading
import time

CACHE_SECONDS = 60
MAX_ENTRIES = 500

_lock = threading.Lock()
_store = {}  # (session, key) -> (valid until, generation, value)
_generation = 0


def invalidate():
    """Discard everything (after every change in AD or to the settings)."""
    global _generation
    with _lock:
        _generation += 1
        _store.clear()


def cached(user, key, build, fresh=False):
    """Value from the cache, or call build() and remember it. Errors are never cached."""
    sid = (user or {}).get("sid") or ""
    now = time.monotonic()
    with _lock:
        hit = _store.get((sid, key))
        gen = _generation
        if hit and not fresh and hit[0] > now and hit[1] == gen:
            return copy.deepcopy(hit[2])
    value = build()
    if isinstance(value, dict) and value.get("error"):
        return value  # do not cache a fallback list after a DC error (e.g. AD structure) - try again next time
    with _lock:
        for k in [k for k, v in _store.items() if v[0] <= now]:  # evict expired entries right away
            del _store[k]
        if gen == _generation and sid:  # changed in the meantime? then do not cache
            if len(_store) >= MAX_ENTRIES:
                for k in list(_store)[: MAX_ENTRIES // 2]:
                    _store.pop(k, None)
            _store[(sid, key)] = (now + CACHE_SECONDS, gen, copy.deepcopy(value))
    return value


def forget_session(sid):
    with _lock:
        for k in [k for k in _store if k[0] == sid]:
            del _store[k]
