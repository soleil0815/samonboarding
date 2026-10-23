"""Passwort-Reset."""

import ldap3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from .. import listcache
from ..audit import audited
from ..config import PWD_HINT, PWDRESET_CONFIG_FILE, SMTP_CONFIG_FILE, default_pwdreset_config, default_smtp_config
from ..ldap_client import (
    ad_session,
    collect_users,
    ensure,
    ldap_error_text,
    row_display_name,
    row_is_locked,
    row_uac,
)
from ..mailer import render_mail, send_notification_email
from ..models import PwdResetActionModel
from ..naming import generate_secure_password
from ..permissions import require_not_protected_for_operator, require_user_in_ous, resolve_account
from ..sessions import get_current_user
from ..storage import load_json

router = APIRouter()


@router.get("/api/pwdreset/users")
def get_pwdreset_users(user: dict = Depends(get_current_user), frisch: bool = False):
    """Liste kurz zwischengespeichert (listcache); frisch=1 liest immer neu vom DC."""
    return listcache.cached(user, "pwdreset-users", lambda: _get_pwdreset_users(user), frisch)


def _get_pwdreset_users(user):
    pwd_cfg = load_json(PWDRESET_CONFIG_FILE, default_pwdreset_config)
    source_ous = pwd_cfg.get("sourceOus", [])
    if not source_ous:
        return {"status": "success", "users": [], "warning": "Keine Quell-OUs für Passwort-Reset konfiguriert."}

    def build(row, ou):
        return {
            "dn": row.dn,
            "name": row_display_name(row),
            "sam": row.text("sAMAccountName"),
            "mail": row.text("mail"),
            "disabled": bool(row_uac(row) & 2),
            "locked": row_is_locked(row),
            "ou": ou,
        }

    with ad_session(user) as conn:
        users = collect_users(
            conn,
            source_ous,
            ["sAMAccountName", "displayName", "cn", "userAccountControl", "mail", "lockoutTime"],
            build,
        )
    return {"status": "success", "users": users}


@router.post("/api/pwdreset/execute")
def execute_pwdreset(data: PwdResetActionModel, background: BackgroundTasks, user: dict = Depends(get_current_user)):
    pwd_cfg = load_json(PWDRESET_CONFIG_FILE, default_pwdreset_config)

    with audited(
        user, "pwdreset", data.userDn, mode=data.mode, forceChange=data.forceChange, unlock=data.unlockAccount
    ) as info:
        require_user_in_ous(data.userDn, pwd_cfg.get("sourceOus", []), "den Passwort-Reset")
        if data.mode not in ("auto", "manual"):
            raise HTTPException(status_code=400, detail="Ungültiger Modus.")
        password = generate_secure_password() if data.mode == "auto" else data.newPassword
        if not password or len(password) < 6:
            raise HTTPException(status_code=400, detail="Das Passwort ist zu kurz oder ungültig.")

        warnings = []
        with ad_session(user) as conn:
            entry = resolve_account(
                conn,
                data.userDn,
                pwd_cfg.get("sourceOus", []),
                "den Passwort-Reset",
                ["sAMAccountName", "userPrincipalName", "displayName", "cn", "mail"],
            )
            user_dn = entry.dn
            require_not_protected_for_operator(conn, user, user_dn, "zurückgesetzt")
            sam_name = entry.text("sAMAccountName")
            upn_name = entry.text("userPrincipalName")
            mail_addr = entry.text("mail")
            display_name = row_display_name(entry) or sam_name
            info["sam"] = sam_name

            raw_pwd = f'"{password}"'.encode("utf-16-le")
            ok = conn.modify(user_dn, {"unicodePwd": [(ldap3.MODIFY_REPLACE, [raw_pwd])]})
            ensure(conn, ok, "Passwort setzen", PWD_HINT)

            if data.forceChange:
                if not conn.modify(user_dn, {"pwdLastSet": [(ldap3.MODIFY_REPLACE, [0])]}):
                    warnings.append(
                        "Änderung beim nächsten Login konnte nicht erzwungen werden: " + ldap_error_text(conn)
                    )
            if data.unlockAccount:
                if not conn.modify(user_dn, {"lockoutTime": [(ldap3.MODIFY_REPLACE, [0])]}):
                    warnings.append("Kontensperre konnte nicht aufgehoben werden: " + ldap_error_text(conn))
        info["warnings"] = warnings

    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if smtp_cfg.get("notifyPwdReset", False) and user.get("email"):
        body_text, body_html = render_mail(
            user["username"],
            "Passwort zurückgesetzt",
            "#0284c7",
            f"Das Kennwort für das Benutzerkonto von {display_name} wurde erfolgreich zurückgesetzt.",
            [
                ("Mitarbeiter:", f"{display_name} ({sam_name})", "bold"),
                ("UPN:", upn_name, "mono"),
                ("Neues Passwort:", password, "pwd"),
                ("Änderung bei Login:", "Ja" if data.forceChange else "Nein", ""),
                ("Sperre aufgehoben:", "Ja" if data.unlockAccount else "Nein", ""),
            ],
        )
        background.add_task(
            send_notification_email,
            user["email"],
            f"SAMONBOARDING - Passwort-Reset für {display_name} ({sam_name})",
            body_text,
            body_html,
        )

    return {
        "status": "success",
        "newPassword": password,
        "sam": sam_name,
        "upn": upn_name,
        "mail": mail_addr,
        "warnings": warnings,
        "message": "Passwort erfolgreich zurückgesetzt!",
    }
