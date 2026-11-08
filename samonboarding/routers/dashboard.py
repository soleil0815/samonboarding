# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Start page: only the numbers, counted by the domain controller itself.

Instead of sending whole account lists to the browser, each question is asked as an LDAP filter, so the DC
returns only the matching accounts (usually a handful) with very few attributes - fast even with thousands
of accounts. Always live (never cached), with the signed-in user's own AD account and only in the OUs
released for the respective area. Nothing is stored or logged; the browser receives only numbers.
"""

import logging
import time

from fastapi import APIRouter, Depends
from ldap3.core.exceptions import LDAPException

from ..config import (
    OFFBOARDING_CONFIG_FILE,
    PWDRESET_CONFIG_FILE,
    USER_FILTER,
    default_offboarding_config,
    default_pwdreset_config,
)
from ..ldap_client import FILETIME_EPOCH_OFFSET, ad_session, ldap_search, row_filetime, row_is_locked
from ..permissions import is_admin
from ..protection import mark_protected
from ..sessions import get_current_user
from ..storage import load_json
from .deletion import load_deletion_config

log = logging.getLogger(__name__)
router = APIRouter()

INACTIVE_DAYS = 90
DISABLED = "(userAccountControl:1.2.840.113556.1.4.803:=2)"  # bit 2 = account disabled


def filetime(seconds):
    """Unix time -> AD FILETIME (100 ns since 1601)."""
    return int((seconds + FILETIME_EPOCH_OFFSET) * 10_000_000)


def inactive_filter(now):
    """Enabled accounts that have never logged on or not for INACTIVE_DAYS (lastLogonTimestamp, approximate)."""
    limit = filetime(now - INACTIVE_DAYS * 86400)
    return f"(&{USER_FILTER}(!{DISABLED})(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<={limit})))"


LOCKED_FILTER = f"(&{USER_FILTER}(lockoutTime>=1))"
DISABLED_FILTER = f"(&{USER_FILTER}{DISABLED})"


def own_sam(user):
    return str(user.get("username") or "").lower().split("\\")[-1].split("@")[0]


def search_ous(conn, ous, flt, attrs):
    """Matches from several OUs, each account once. An OU that cannot be read is skipped (logged)."""
    rows, seen, failed = [], set(), 0
    for ou in ous:
        if not ou:
            continue
        try:
            found = ldap_search(conn, ou, flt, attrs)
        except LDAPException as e:
            log.warning("Startseite: Suche in OU '%s' fehlgeschlagen: %s", ou, e)
            failed += 1
            continue
        for row in found:
            if row.dn.lower() not in seen:
                seen.add(row.dn.lower())
                rows.append(row)
    if failed and failed == len([ou for ou in ous if ou]):
        raise LDAPException("no OU readable")
    return rows


def count_actionable(conn, rows, me, user=None):
    """Without one's own account and without protected accounts (they cannot be offboarded/deleted here)."""
    entries = [
        {"dn": r.dn, "_adminCount": r.text("adminCount") == "1", "row": r}
        for r in rows
        if r.text("sAMAccountName").lower() != me
    ]
    mark_protected(conn, entries, user)
    return [e["row"] for e in entries if not e.get("protected")]


def section(build):
    try:
        return build()
    except LDAPException:
        return {"error": "Liste nicht lesbar"}


@router.get("/api/dashboard")
def get_dashboard(user: dict = Depends(get_current_user)):
    off_ous = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config).get("sourceOus", [])
    pwd_ous = load_json(PWDRESET_CONFIG_FILE, default_pwdreset_config).get("sourceOus", [])
    del_cfg = load_deletion_config() if is_admin(user) else None
    me = own_sam(user)
    result = {"status": "success", "inactiveDays": INACTIVE_DAYS}
    with ad_session(user) as conn:

        def inactive():
            if not off_ous:
                return {"warning": "Keine Quell-OUs für das Offboarding konfiguriert."}
            rows = search_ous(
                conn, off_ous, inactive_filter(time.time()), ["sAMAccountName", "adminCount", "lastLogonTimestamp"]
            )
            rows = count_actionable(conn, rows, me, user)
            return {"count": len(rows), "never": sum(1 for r in rows if row_filetime(r, "lastLogonTimestamp") is None)}

        def locked():
            if not pwd_ous:
                return {"warning": "Keine Quell-OUs für Passwort-Reset konfiguriert."}
            rows = search_ous(conn, pwd_ous, LOCKED_FILTER, ["lockoutTime"])
            return {"count": sum(1 for r in rows if row_is_locked(r))}

        def deletable(cfg):
            if not cfg["enabled"] or not cfg["disabledOu"]:
                return {"warning": "Die Löschfunktion ist nicht aktiviert."}
            rows = search_ous(conn, [cfg["disabledOu"]], DISABLED_FILTER, ["sAMAccountName", "adminCount"])
            return {"count": len(count_actionable(conn, rows, me, user))}

        result["inactive"] = section(inactive)
        result["locked"] = section(locked)
        result["deletion"] = section(lambda: deletable(del_cfg)) if del_cfg is not None else None
    return result
