# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""AD-Infrastruktur (OUs, Gruppen, Benutzer, Laender) fuer die Auswahllisten der Oberflaeche."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from ldap3.core.exceptions import LDAPException

from .. import listcache
from ..config import CONFIG_FILE, USER_FILTER, default_config
from ..dn import base_dn
from ..ldap_client import ad_session, ldap_search, name_sort_key, row_display_name
from ..sessions import get_current_user
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/ad/infrastructure")
def get_ad_infrastructure(user: dict = Depends(get_current_user), frisch: bool = False):
    """Liste kurz zwischengespeichert (listcache); frisch=1 liest immer neu vom DC."""
    return listcache.cached(user, "infrastructure", lambda: _get_ad_infrastructure(user), frisch)


def _get_ad_infrastructure(user):
    cfg = load_json(CONFIG_FILE, default_config)
    search_base = base_dn(cfg["domain"])
    fallback_countries = ["Deutschland", "Österreich", "Schweiz"]
    try:
        with ad_session(user) as conn:
            ous = [
                {"name": r.text("name"), "dn": r.dn}
                for r in ldap_search(conn, search_base, "(objectClass=organizationalUnit)", ["name"])
            ]
            groups = [
                {"name": r.text("sAMAccountName"), "dn": r.dn}
                for r in ldap_search(conn, search_base, "(objectClass=group)", ["sAMAccountName"])
                if r.text("sAMAccountName")
            ]
            user_rows = ldap_search(conn, search_base, USER_FILTER, ["cn", "displayName", "co"])
        users = sorted(
            ({"name": row_display_name(r), "dn": r.dn} for r in user_rows),
            key=lambda u: name_sort_key(u["name"]),
        )
        countries = sorted({r.text("co") for r in user_rows if r.text("co")}) or fallback_countries
        return {"status": "success", "ous": ous, "groups": groups, "users": users, "countries": countries}
    except HTTPException as he:
        if he.status_code == 401:
            raise
        error = str(he.detail)
    except LDAPException as e:
        error = str(e)
    log.warning("AD-Infrastruktur konnte nicht geladen werden: %s", error)
    return {
        "status": "success",
        "error": error,
        "ous": [{"name": "Users (Default)", "dn": f"CN=Users,{search_base}"}],
        "groups": [{"name": "Domain Users", "dn": f"CN=Domain Users,CN=Users,{search_base}"}],
        "users": [],
        "countries": fallback_countries,
    }
