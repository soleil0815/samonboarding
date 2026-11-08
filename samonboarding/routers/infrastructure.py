# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""AD infrastructure (OUs, groups, users, countries) for the UI selection lists."""

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
def get_ad_infrastructure(
    user: dict = Depends(get_current_user), frisch: bool = False, gruppen: bool = True, benutzer: bool = True
):
    """List briefly cached (listcache); frisch=1 always re-reads from the DC.

    The OUs are small and always included. All groups (gruppen) and all users of the domain (benutzer: manager
    selection and countries in the templates) are the large part - the UI asks for them only on the pages
    that show them; without them the keys are missing from the answer."""
    key = f"infrastructure:{int(gruppen)}{int(benutzer)}"
    return listcache.cached(user, key, lambda: _get_ad_infrastructure(user, gruppen, benutzer), frisch)


def _get_ad_infrastructure(user, with_groups=True, with_users=True):
    cfg = load_json(CONFIG_FILE, default_config)
    search_base = base_dn(cfg["domain"])
    fallback_countries = ["Deutschland", "Österreich", "Schweiz"]
    try:
        with ad_session(user) as conn:
            ous = [
                {"name": r.text("name"), "dn": r.dn}
                for r in ldap_search(conn, search_base, "(objectClass=organizationalUnit)", ["name"])
            ]
            result = {"status": "success", "ous": ous}
            if with_groups:
                result["groups"] = [
                    {"name": r.text("sAMAccountName"), "dn": r.dn}
                    for r in ldap_search(conn, search_base, "(objectClass=group)", ["sAMAccountName"])
                    if r.text("sAMAccountName")
                ]
            if with_users:
                user_rows = ldap_search(conn, search_base, USER_FILTER, ["cn", "displayName", "co"])
                result["users"] = sorted(
                    ({"name": row_display_name(r), "dn": r.dn} for r in user_rows),
                    key=lambda u: name_sort_key(u["name"]),
                )
                result["countries"] = sorted({r.text("co") for r in user_rows if r.text("co")}) or fallback_countries
        return result
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
