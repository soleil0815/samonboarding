# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""How long does a request spend where? (only durations - never names, filters or values)

Every request collects the time of its steps (connect to the DC, searches, role check, protection check).
Slow requests (from SLOW_SECONDS) are logged with their steps, e.g.
  "Langsam: GET /api/offboarding/users 2.9 s (Verbindung 0.1 s, Suche 0.4 s, Schutzpruefung 2.4 s)"
and every API response carries the same numbers in the Server-Timing header (browser developer tools).
"""

import contextvars
import threading
import time
from collections import deque
from contextlib import contextmanager

SLOW_SECONDS = 1.0

# label -> (header name, log text)
STEPS = {
    "connect": ("ldap-connect", "Verbindung"),
    "search": ("ldap-search", "Suche"),
    "role": ("role", "Rollenpruefung"),
    "protect": ("protect", "Schutzpruefung"),
}

_current: contextvars.ContextVar[dict[str, float] | None] = contextvars.ContextVar("samonboarding_timing", default=None)


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


# ---------------------------------------------------------------------------------------------------------------------
# Statistics for the diagnostic package: per route (the path pattern, e.g. /api/templates/{tmpl_id} - never the
# values in it) the last durations since the start. Kept in memory only.
KEEP_PER_ROUTE = 200
_stats_lock = threading.Lock()
_stats: dict[str, dict] = {}


def record(route, total, steps):
    with _stats_lock:
        entry = _stats.setdefault(route, {"count": 0, "errors": 0, "totals": deque(maxlen=KEEP_PER_ROUTE), "steps": {}})
        entry["count"] += 1
        entry["totals"].append(total)
        for label, value in steps.items():
            if label in STEPS:
                entry["steps"].setdefault(label, deque(maxlen=KEEP_PER_ROUTE)).append(value)


def record_error(route):
    with _stats_lock:
        entry = _stats.setdefault(route, {"count": 0, "errors": 0, "totals": deque(maxlen=KEEP_PER_ROUTE), "steps": {}})
        entry["errors"] += 1


def _percentile(values, share):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, int(round(share * (len(ordered) - 1))))]


def summary():
    """{route: {count, errors, medianMs, p95Ms, maxMs, steps: {label: medianMs}}}, slowest first."""
    with _stats_lock:
        items = [
            (
                route,
                {
                    "count": e["count"],
                    "errors": e["errors"],
                    "totals": list(e["totals"]),
                    "steps": {k: list(v) for k, v in e["steps"].items()},
                },
            )
            for route, e in _stats.items()
        ]
    out: dict[str, dict] = {}
    for route, e in sorted(items, key=lambda kv: -_percentile(kv[1]["totals"], 0.95)):
        totals = e["totals"]
        out[route] = {
            "count": e["count"],
            "errors": e["errors"],
            "medianMs": round(_percentile(totals, 0.5) * 1000),
            "p95Ms": round(_percentile(totals, 0.95) * 1000),
            "maxMs": round(max(totals, default=0.0) * 1000),
            "stepsMedianMs": {STEPS[k][1]: round(_percentile(v, 0.5) * 1000) for k, v in e["steps"].items()},
        }
    return out


def reset_stats():
    with _stats_lock:
        _stats.clear()
