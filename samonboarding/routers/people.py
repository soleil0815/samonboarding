# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Quick search (Ctrl+K): the DC searches, the browser receives at most a few hits.

Instead of loading complete account lists into the browser, the typed text becomes an LDAP filter
(name, logon name or e-mail contain every typed word). Only the OUs released for user management, leaving
and password reset are searched - with the signed-in user's own AD account, so nobody finds more than the
lists would show. Never cached, nothing stored or logged (the search text is not written anywhere).
"""

import logging

import ldap3
from fastapi import APIRouter, Depends
from ldap3.core.exceptions import LDAPException

from ..config import (
    OFFBOARDING_CONFIG_FILE,
    PWDRESET_CONFIG_FILE,
    USER_FILTER,
    USERMGMT_CONFIG_FILE,
    default_offboarding_config,
    default_pwdreset_config,
    default_usermgmt_config,
)
from ..dn import ldap_escape
from ..ldap_client import Row, ad_session, name_sort_key, row_display_name, row_uac
from ..models import PeopleSearchModel
from ..sessions import get_current_user
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()

MIN_CHARS = 2
MAX_WORDS = 4
MAX_HITS = 10
ATTRS = ["sAMAccountName", "displayName", "cn", "mail", "userAccountControl"]
SEARCHED = ("displayName", "cn", "sAMAccountName", "mail")

# Where a person opens: user management first, then leaving, then password reset
AREAS = (
    ("usermgmt", USERMGMT_CONFIG_FILE, default_usermgmt_config),
    ("offboard", OFFBOARDING_CONFIG_FILE, default_offboarding_config),
    ("pwdreset", PWDRESET_CONFIG_FILE, default_pwdreset_config),
)


def people_filter(query):
    """Every word must appear in one of the searched attributes; None if the query is too short."""
    words = [w for w in str(query or "").split() if w][:MAX_WORDS]
    if not words or len("".join(words)) < MIN_CHARS:
        return None
    parts = []
    for word in words:
        value = ldap_escape(word[:64])
        parts.append("(|" + "".join(f"({attr}=*{value}*)" for attr in SEARCHED) + ")")
    return f"(&{USER_FILTER}{''.join(parts)})"


def search_limited(conn, base, flt, limit):
    """At most `limit` entries; the DC stops early (sizeLimitExceeded is not an error here)."""
    conn.search(base, flt, ldap3.SUBTREE, attributes=ATTRS, size_limit=limit)
    code = (conn.result or {}).get("result")
    if code not in (None, 0, 4):  # 4 = sizeLimitExceeded: enough hits
        raise LDAPException(str((conn.result or {}).get("description")))
    return [Row(e["dn"], e.get("attributes")) for e in (conn.response or []) if e.get("type") == "searchResEntry"]


def rank(person, words):
    name, sam = person["name"].lower(), person["sam"].lower()
    q = " ".join(words).lower()
    if q in (sam, name):
        return 0
    if sam.startswith(q) or name.startswith(q) or any(part.startswith(q) for part in name.split()):
        return 1
    return 2


@router.post("/api/people")
def search_people(data: PeopleSearchModel, user: dict = Depends(get_current_user)):
    """POST so the search text never appears in a URL (proxies, browser history)."""
    q = str(data.q or "")[:200]
    flt = people_filter(q)
    if flt is None:
        return {"status": "success", "people": []}
    found, seen = [], set()
    with ad_session(user) as conn:
        for tab, path, default in AREAS:
            for ou in load_json(path, default).get("sourceOus", []):
                if not ou or len(found) >= MAX_HITS * 3:
                    continue
                try:
                    rows = search_limited(conn, ou, flt, MAX_HITS * 3)
                except LDAPException as e:
                    log.warning("Schnellsuche in OU '%s' fehlgeschlagen: %s", ou, e)
                    continue
                for row in rows:
                    if row.dn.lower() in seen:
                        continue
                    seen.add(row.dn.lower())
                    found.append(
                        {
                            "dn": row.dn,
                            "name": row_display_name(row),
                            "sam": row.text("sAMAccountName"),
                            "mail": row.text("mail"),
                            "disabled": bool(row_uac(row) & 2),
                            "tab": tab,
                        }
                    )
    words = str(q).split()
    found.sort(key=lambda p: (rank(p, words), name_sort_key(p["name"], p["sam"])))
    return {"status": "success", "people": found[:MAX_HITS]}
