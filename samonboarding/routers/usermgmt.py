# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Benutzerverwaltung: Benutzerliste, Verschieben und Gruppenmitgliedschaften."""

import logging

import ldap3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from ldap3.core.exceptions import LDAPException

from .. import listcache
from ..audit import audited
from ..config import (
    CONFIG_FILE,
    SMTP_CONFIG_FILE,
    USERMGMT_CONFIG_FILE,
    default_config,
    default_smtp_config,
    default_usermgmt_config,
)
from ..dn import base_dn, dn_in_any, dn_norm, parent_dn, rdn_label, split_dn
from ..errors import AdError
from ..ldap_client import (
    ad_session,
    collect_users,
    ensure,
    get_object,
    ldap_error_text,
    ldap_search,
    member_change_ok,
    row_display_name,
    row_uac,
)
from ..mailer import render_mail, send_notification_email
from ..models import MoveUserActionModel, UpdateUserGroupsModel
from ..permissions import (
    is_admin,
    reject_special_dn,
    require_not_protected_for_operator,
    require_user_in_ous,
    resolve_account,
)
from ..protection import privileged_group
from ..sessions import get_current_user
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/usermgmt/users")
def get_usermgmt_users(user: dict = Depends(get_current_user), frisch: bool = False):
    """Liste kurz zwischengespeichert (listcache); frisch=1 liest immer neu vom DC."""
    return listcache.cached(user, "usermgmt-users", lambda: _get_usermgmt_users(user), frisch)


def _get_usermgmt_users(user):
    mgmt_cfg = load_json(USERMGMT_CONFIG_FILE, default_usermgmt_config)
    source_ous = mgmt_cfg.get("sourceOus", [])
    if not source_ous:
        return {
            "status": "success",
            "users": [],
            "warning": "Keine Quell-OUs für die Benutzer-Verwaltung konfiguriert.",
        }

    def build(row, ou):
        return {
            "dn": row.dn,
            "name": row_display_name(row),
            "sam": row.text("sAMAccountName"),
            "mail": row.text("mail"),
            "disabled": bool(row_uac(row) & 2),
            "currentOu": parent_dn(row.dn),
            "groups": [rdn_label(g) for g in row.list("memberOf")],
        }

    with ad_session(user) as conn:
        users = collect_users(
            conn, source_ous, ["sAMAccountName", "displayName", "cn", "userAccountControl", "mail", "memberOf"], build
        )
    return {"status": "success", "users": users}


@router.post("/api/usermgmt/move")
def move_user_account(data: MoveUserActionModel, user: dict = Depends(get_current_user)):
    mgmt_cfg = load_json(USERMGMT_CONFIG_FILE, default_usermgmt_config)
    with audited(user, "move-user", data.userDn, targetOu=data.targetOu) as info:
        target_ou = next(
            (ou for ou in mgmt_cfg.get("targetOus", []) if ou and dn_norm(ou) == dn_norm(data.targetOu)), None
        )
        if not target_ou:
            raise HTTPException(
                status_code=403, detail="Die gewählte Ziel-OU ist nicht in den erlaubten Ziel-OUs konfiguriert."
            )
        with ad_session(user) as conn:
            entry = resolve_account(
                conn, data.userDn, mgmt_cfg.get("sourceOus", []), "die Benutzer-Verwaltung", ["sAMAccountName"]
            )
            info["sam"] = entry.text("sAMAccountName")  # fuer die Datenschutz-Auskunft
            require_not_protected_for_operator(conn, user, entry.dn, "verschoben")
            ok = conn.modify_dn(entry.dn, split_dn(entry.dn)[0], new_superior=target_ou)
            ensure(conn, ok, "Verschieben")
    return {"status": "success", "message": "Benutzer erfolgreich in die neue OU verschoben!"}


@router.get("/api/usermgmt/user-groups")
def get_user_groups(userDn: str, user: dict = Depends(get_current_user)):
    cfg = load_json(CONFIG_FILE, default_config)
    mgmt_cfg = load_json(USERMGMT_CONFIG_FILE, default_usermgmt_config)
    group_ous = [o for o in mgmt_cfg.get("groupOus", []) if o] or [base_dn(cfg["domain"])]

    with ad_session(user) as conn:
        entry = resolve_account(conn, userDn, mgmt_cfg.get("sourceOus", []), "die Benutzer-Verwaltung", ["memberOf"])
        member_of = entry.list("memberOf")

        available, seen = [], set()
        for group_ou in group_ous:
            try:
                rows = ldap_search(conn, group_ou, "(objectClass=group)", ["sAMAccountName", "cn"])
            except LDAPException as e:
                log.warning("Gruppensuche in '%s' fehlgeschlagen: %s", group_ou, e)
                continue
            for g in rows:
                if g.dn.lower() in seen:
                    continue
                seen.add(g.dn.lower())
                available.append({"dn": g.dn, "name": g.text("sAMAccountName") or g.text("cn") or g.dn})

    return {"status": "success", "userMemberOf": member_of, "availableGroups": available}


MAX_GROUP_CHANGES = 200


@router.post("/api/usermgmt/update-groups")
def update_user_groups(
    data: UpdateUserGroupsModel, background: BackgroundTasks, user: dict = Depends(get_current_user)
):
    cfg = load_json(CONFIG_FILE, default_config)
    mgmt_cfg = load_json(USERMGMT_CONFIG_FILE, default_usermgmt_config)
    if len(data.addGroupDns) + len(data.removeGroupDns) > MAX_GROUP_CHANGES:
        # jede Gruppe kostet mehrere AD-Abfragen - eine riesige Liste wuerde den Server minutenlang blockieren
        raise HTTPException(status_code=400, detail=f"Höchstens {MAX_GROUP_CHANGES} Gruppenänderungen auf einmal.")

    with audited(user, "update-groups", data.userDn) as info:
        require_user_in_ous(data.userDn, mgmt_cfg.get("sourceOus", []), "die Benutzer-Verwaltung")
        group_scope = [o for o in mgmt_cfg.get("groupOus", []) if o] or [base_dn(cfg["domain"])]
        for group_dn in list(data.addGroupDns) + list(data.removeGroupDns):
            if not dn_in_any(reject_special_dn(group_dn), group_scope):
                raise HTTPException(
                    status_code=403,
                    detail=f"Die Gruppe '{rdn_label(group_dn)}' liegt nicht in einer freigegebenen Gruppen-OU.",
                )
        if not data.addGroupDns and not data.removeGroupDns:
            return {"status": "success", "message": "Keine Änderungen vorgenommen."}

        added, removed, failures = [], [], []
        with ad_session(user) as conn:
            entry = resolve_account(
                conn,
                data.userDn,
                mgmt_cfg.get("sourceOus", []),
                "die Benutzer-Verwaltung",
                ["sAMAccountName", "displayName", "cn"],
            )
            user_dn = entry.dn
            require_not_protected_for_operator(conn, user, user_dn, "geändert")
            target_sam = entry.text("sAMAccountName", user_dn)
            target_name = row_display_name(entry) or target_sam

            def checked_group(group_dn):
                """Gruppe beim DC aufloesen und den echten DN pruefen; privilegierte Gruppen nur fuer Admins."""
                group = get_object(conn, group_dn, ["cn"], flt="(objectClass=group)")
                if not group or not dn_in_any(group.dn, group_scope):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Die Gruppe '{rdn_label(group_dn)}' liegt nicht in einer freigegebenen Gruppen-OU.",
                    )
                special = privileged_group(conn, group.dn)
                if special and not is_admin(user):
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            f"Die Gruppe „{special}“ ist privilegiert und darf nur von Administratoren geändert werden."
                        ),
                    )
                return group.dn

            add_dns = [checked_group(g) for g in data.addGroupDns]
            remove_dns = [checked_group(g) for g in data.removeGroupDns]

            for group_dn in add_dns:
                ok = conn.modify(group_dn, {"member": [(ldap3.MODIFY_ADD, [user_dn])]})
                if member_change_ok(conn, ok):
                    added.append(rdn_label(group_dn))
                else:
                    failures.append(f"{rdn_label(group_dn)} (hinzufügen): {ldap_error_text(conn)}")
            for group_dn in remove_dns:
                ok = conn.modify(group_dn, {"member": [(ldap3.MODIFY_DELETE, [user_dn])]})
                if member_change_ok(conn, ok):
                    removed.append(rdn_label(group_dn))
                else:
                    failures.append(f"{rdn_label(group_dn)} (entfernen): {ldap_error_text(conn)}")

        info.update(sam=target_sam, added=added, removed=removed, failed=failures)
        if failures and not added and not removed:
            raise AdError("Gruppenänderung fehlgeschlagen: " + "; ".join(failures))

    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if smtp_cfg.get("notifyUserMgmt", False) and user.get("email"):
        body_text, body_html = render_mail(
            user["username"],
            "Gruppenmitgliedschaften geändert",
            "#d97706",
            f"Für den Mitarbeiter {target_name} ({target_sam}) wurden Gruppenanpassungen vorgenommen.",
            [
                ("Mitarbeiter:", f"{target_name} ({target_sam})", "bold"),
                ("Benutzer-DN:", user_dn, "mono"),
                ("Hinzugefügt:", ", ".join(added) if added else "Keine", "good"),
                ("Entfernt:", ", ".join(removed) if removed else "Keine", "bad"),
            ],
        )
        background.add_task(
            send_notification_email,
            user["email"],
            f"SAMONBOARDING - Gruppenänderungen für {target_name} ({target_sam})",
            body_text,
            body_html,
        )

    message = "Gruppenmitgliedschaften erfolgreich aktualisiert!"
    if failures:
        message = "Gruppenmitgliedschaften teilweise aktualisiert. Fehler: " + "; ".join(failures)
    return {"status": "success", "message": message, "failed": failures}
