# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Changes (audit, without passwords): who performed which action and when. Stored in SQLite (reports.py)."""

import logging
from contextlib import contextmanager

from fastapi import HTTPException

from . import listcache, reports

log = logging.getLogger(__name__)


def audit(actor, action, target="", ok=True, **details):
    listcache.invalidate()  # any action may have changed accounts - re-read the lists
    clean = {k: v for k, v in details.items() if v not in (None, "", [])}
    try:
        reports.write_audit(actor, action, target, ok, clean)
    except Exception as e:
        log.error("Audit-Eintrag konnte nicht gespeichert werden (%s): %s %s", e, action, target)


def actor_name(user):
    return (user or {}).get("username", "-")


@contextmanager
def audited(user, action, target="", **details):
    """Records success or failure of an action in the reports."""
    info = dict(details)
    try:
        yield info
    except Exception as e:
        err = e.detail if isinstance(e, HTTPException) else str(e)
        audit(actor_name(user), action, target, ok=False, error=err, **info)
        raise
    else:
        audit(actor_name(user), action, target, ok=True, **info)
