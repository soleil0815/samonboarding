# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Authentication: login, logout, current session and public configuration."""

import logging

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from ldap3.core.exceptions import LDAPBindError

from .. import datastate
from ..audit import audit
from ..config import CONFIG_FILE, SESSION_IDLE_SECONDS, default_config
from ..dn import base_dn
from ..ldap_client import detect_directory, directory_info, ldap_connection
from ..models import LoginModel
from ..permissions import check_user_role
from ..sessions import (
    create_session,
    drop_session,
    get_current_user,
    peek_session,
    throttle_check,
    throttle_clear,
    throttle_fail,
    throttle_key,
    throttle_release,
)
from ..storage import load_json

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/api/public-config")
def get_public_config():
    cfg = load_json(CONFIG_FILE, default_config)
    return {"domain": cfg.get("domain", "firma.local"), "idleMinutes": SESSION_IDLE_SECONDS // 60}


@router.get("/api/host-notices")
def get_host_notices(user: dict = Depends(get_current_user)):
    """Operational notices (administrators only): e.g. an outdated docker-compose.yml."""
    if user.get("role") != "Administrator":
        return {"notices": []}
    notice = datastate.compose_notice()
    return {"notices": [dict(notice, kind="compose")] if notice else []}


@router.get("/api/me")
def get_me(user: dict = Depends(get_current_user)):
    return {
        "status": "success",
        "user": user["username"],
        "role": user["role"],
        "email": user["email"],
        "directory": directory_info(),
        "idleMinutes": SESSION_IDLE_SECONDS // 60,
    }


# AD logon sub-codes (data xxx) -> readable message. Other details go only to the log, not to a browser
# that is not yet logged in.
BIND_REASONS = {
    "52e": "LDAP-Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.",
    "530": "Anmeldung zu dieser Uhrzeit nicht erlaubt.",
    "531": "Anmeldung von diesem Rechner nicht erlaubt.",
    "532": "Das Passwort ist abgelaufen. Bitte zuerst am Windows-Rechner ändern.",
    "533": "Das Konto ist deaktiviert.",
    "701": "Das Konto ist abgelaufen.",
    "773": "Das Passwort muss geändert werden. Bitte zuerst am Windows-Rechner ändern.",
    "775": "Das Konto ist gesperrt.",
}


def bind_error_message(reason):
    text = reason.lower()
    for code, message in BIND_REASONS.items():
        if f"data {code}" in text:
            return message
    if "invalidcredentials" in text.replace(" ", ""):
        return BIND_REASONS["52e"]
    log.warning("LDAP-Anmeldung fehlgeschlagen: %s", reason)
    return "LDAP-Anmeldung fehlgeschlagen. Details stehen im Protokoll."


@router.post("/api/login")
def login(credentials: LoginModel, request: Request, response: Response):
    cfg = load_json(CONFIG_FILE, default_config)
    domain = cfg["domain"]
    typed = credentials.username.strip()
    clean_user = typed.split("\\")[-1].split("@")[0]

    if not clean_user or not credentials.password:
        raise HTTPException(status_code=401, detail="Benutzername und Passwort sind erforderlich.")

    key = throttle_key(request, clean_user)
    attempt = throttle_check(key)

    # Exactly ONE bind attempt per login: every failed attempt counts towards the AD account lockout.
    # Input of "DOMAIN\\user" or "user@suffix" is used unchanged; otherwise user@domain.
    bind_user = typed if ("\\" in typed or "@" in typed) else f"{typed}@{domain}"

    try:
        with ldap_connection(cfg["dc_ip"], bind_user, credentials.password) as conn:
            role, role_err, user_mail, sam = check_user_role(conn, base_dn(domain), clean_user, bind_user)
            detect_directory(conn)
    except LDAPBindError as e:
        throttle_fail(key)
        audit(
            clean_user, "login", ok=False, error="bind fehlgeschlagen", ip=request.client.host if request.client else ""
        )
        raise HTTPException(status_code=401, detail=bind_error_message(str(e))) from None
    except Exception:
        throttle_release(key, attempt)  # e.g. DC unreachable: not a wrong password
        raise

    if not role:
        throttle_release(key, attempt)
        audit(clean_user, "login", ok=False, error="keine Berechtigung")
        raise HTTPException(status_code=403, detail=role_err)

    throttle_clear(key)
    clean_user = sam or clean_user  # the real sAMAccountName (e.g. when logging in via UPN)
    # Only the address from AD (mail attribute): a guessed <name>@<AD domain> may end up in a shared mailbox or
    # with another person - the emails contain initial passwords. Without a mail attribute, no emails are sent.
    email = user_mail or ""
    token = create_session(
        {
            "username": clean_user,
            "bind_user": bind_user,
            "password": credentials.password,
            "domain": domain,
            "role": role,
            "email": email,
        }
    )
    response.set_cookie(
        key="session_id",
        value=token,
        httponly=True,
        samesite="strict",
        secure=True,  # the application runs over HTTPS only; without max_age the cookie ends with the browser session
    )
    audit(clean_user, "login", ok=True, role=role)
    return {
        "status": "success",
        "user": clean_user,
        "role": role,
        "email": email,
        "idleMinutes": SESSION_IDLE_SECONDS // 60,
    }


@router.post("/api/logout")
def logout(response: Response, session_id: str = Cookie(None)):
    if session_id:
        session = peek_session(session_id)
        if session:
            audit(session["username"], "logout")
        drop_session(session_id)
    response.delete_cookie("session_id")
    return {"status": "success"}
