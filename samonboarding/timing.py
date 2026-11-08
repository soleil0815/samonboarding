# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""How long does a request spend where? (only durations - never names, filters or values)

Every request collects the time of its steps (connect to the DC, searches, role check, protection check).
Slow requests (from SLOW_SECONDS) are logged with their steps, e.g.
  "Langsam: GET /api/offboarding/users 2.9 s (Verbindung 0.1 s, Suche 0.4 s, Schutzpruefung 2.4 s)"
and every API response carries the same numbers in the Server-Timing header (browser developer tools).
"""

import contextvars
import time
from contextlib import contextmanager

SLOW_SECONDS = 1.0

# label -> (header name, log text)
STEPS = {
    "connect": ("ldap-connect", "Verbindung"),
    "search": ("ldap-search", "Suche"),
    "role": ("role", "Rollenpruefung"),
    "protect": ("protect", "Schutzpruefung"),
}

_current = contextvars.ContextVar("samonboarding_timing", default=None)


def start():
    """New collection for this request; returns the token for stop()."""
    return _current.set({})


def stop(token):
    steps = _current.get() or {}
    _current.reset(token)
    return steps


@contextmanager
def timed(label):
    """Adds the duration of the block to `label` (several blocks add up). Outside a request: does nothing."""
    steps = _current.get()
    began = time.perf_counter()
    try:
        yield
    finally:
        if steps is not None:
            steps[label] = steps.get(label, 0.0) + time.perf_counter() - began


def server_timing(steps, total):
    parts = [f"{STEPS[k][0]};dur={v * 1000:.0f}" for k, v in steps.items() if k in STEPS]
    parts.append(f"total;dur={total * 1000:.0f}")
    return ", ".join(parts)


def slow_message(method, path, steps, total):
    detail = ", ".join(f"{STEPS[k][1]} {v:.1f} s" for k, v in steps.items() if k in STEPS)
    return f"Langsam: {method} {path} {total:.1f} s" + (f" ({detail})" if detail else "")
