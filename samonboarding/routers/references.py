# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Check of the references to OUs and groups in the settings (after renaming/moving in AD).
Administrators only - see samonboarding/references.py."""

from fastapi import APIRouter, Depends

from .. import listcache, references
from ..audit import actor_name, audit
from ..config import CONFIG_FILE, default_config
from ..dn import base_dn
from ..ldap_client import ad_session
from ..permissions import require_admin
from ..sessions import get_current_user
from ..storage import load_json

router = APIRouter()


def _base():
    return base_dn(load_json(CONFIG_FILE, default_config)["domain"])


@router.get("/api/references")
def get_references(user: dict = Depends(get_current_user), frisch: bool = False):
    require_admin(user, "Nur Administratoren dürfen die Verweise prüfen.")

    def build():
        with ad_session(user) as conn:
            return {"problems": references.check(conn, _base())}

    return listcache.cached(user, "references", build, frisch)


@router.post("/api/references/repair")
def repair_references(user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Verweise anpassen.")
    with ad_session(user) as conn:
        fixed = references.repair(conn, _base())
    if fixed:
        changes = [f"{f['dn']} -> {f['newDn'] or 'bestätigt'}" for f in fixed]
        audit(actor_name(user), "config-references", changes=changes)
    return {"status": "success", "fixed": fixed}
