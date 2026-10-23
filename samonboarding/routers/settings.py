"""Einstellungen (nur Administratoren schreiben): SMTP, Offboarding, Passwort-Reset, Benutzerverwaltung."""

import logging

from fastapi import APIRouter, Depends, HTTPException

from ..audit import actor_name, audit
from ..config import (
    EXCHANGE_CONFIG_FILE,
    OFFBOARDING_CONFIG_FILE,
    PWDRESET_CONFIG_FILE,
    SMTP_CONFIG_FILE,
    SMTP_TLS_MODES,
    USERMGMT_CONFIG_FILE,
    VERSION,
    default_offboarding_config,
    default_pwdreset_config,
    default_smtp_config,
    default_usermgmt_config,
)
from ..exchange import ExchangeError, check_connection, clean_config, default_exchange_config
from ..ldap_client import ad_session, detect_mail_system
from ..mailer import render_mail, smtp_send
from ..models import (
    ExchangeConfigModel,
    OffboardingConfigModel,
    PwdResetConfigModel,
    SmtpConfigModel,
    UserMgmtConfigModel,
    clean_ou_list,
)
from ..permissions import require_admin
from ..sessions import get_current_user
from ..storage import file_lock, load_json, save_json

log = logging.getLogger(__name__)
router = APIRouter()
SMTP_PASSWORD_MASK = "••••••••••••"


@router.get("/api/smtp-config")
def get_smtp_config(user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen SMTP-Einstellungen einsehen.")
    cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    safe_cfg = dict(cfg)
    if safe_cfg.get("password"):
        safe_cfg["password"] = SMTP_PASSWORD_MASK
    return safe_cfg


@router.post("/api/smtp-config")
def save_smtp_config(data: SmtpConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen SMTP-Einstellungen bearbeiten.")
    if data.tlsMode not in SMTP_TLS_MODES:
        raise HTTPException(status_code=400, detail="Ungültiger TLS-Modus.")
    if not 1 <= data.port <= 65535:
        raise HTTPException(status_code=400, detail="Ungültiger SMTP-Port.")

    for value in (data.displayName, data.host, data.username, data.fromEmail, data.ccRecipients):
        if any(ord(ch) < 32 for ch in str(value or "")):
            raise HTTPException(status_code=400, detail="Die SMTP-Angaben dürfen keine Zeilenumbrüche enthalten.")

    with file_lock:
        current_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
        pwd = data.password
        if pwd == SMTP_PASSWORD_MASK or not pwd:
            pwd = current_cfg.get("password", "")
            # Das gespeicherte Passwort geht nur an den Server, fuer den es eingegeben wurde. Sonst liesse es sich
            # durch Umstellen auf einen fremden Server (und eine Test-Mail) auslesen.
            changed = data.host.strip().lower() != str(
                current_cfg.get("host", "")
            ).strip().lower() or data.username != current_cfg.get("username", "")
            if pwd and changed:
                raise HTTPException(
                    status_code=400,
                    detail="Server oder Benutzername wurden geändert - bitte das SMTP-Passwort neu eingeben.",
                )

        save_json(
            SMTP_CONFIG_FILE,
            {
                "enabled": data.enabled,
                "displayName": data.displayName,
                "host": data.host.strip(),
                "port": data.port,
                "username": data.username,
                "password": pwd,
                "fromEmail": data.fromEmail.strip(),
                "ccRecipients": data.ccRecipients,
                "tlsMode": data.tlsMode,
                "notifyOffboarding": data.notifyOffboarding,
                "notifyPwdReset": data.notifyPwdReset,
                "notifyUserMgmt": data.notifyUserMgmt,
                "notifyDeletion": data.notifyDeletion,
            },
        )
    audit(actor_name(user), "config-smtp", host=data.host, enabled=data.enabled)
    return {"status": "success"}


@router.get("/api/offboarding-config")
def get_offboarding_config(user: dict = Depends(get_current_user)):
    return load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)


@router.post("/api/offboarding-config")
def save_offboarding_config(data: OffboardingConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Offboarding-Konfigurationen bearbeiten.")
    save_json(OFFBOARDING_CONFIG_FILE, {"sourceOus": clean_ou_list(data.sourceOus), "targetOu": data.targetOu.strip()})
    audit(actor_name(user), "config-offboarding", sourceOus=data.sourceOus, targetOu=data.targetOu)
    return {"status": "success"}


@router.get("/api/exchange-config")
def get_exchange_config(user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren.")
    return clean_config(load_json(EXCHANGE_CONFIG_FILE, default_exchange_config))


@router.post("/api/exchange-config")
def save_exchange_config(data: ExchangeConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen die Exchange-Einstellungen bearbeiten.")
    try:
        cfg = clean_config(data.model_dump() if hasattr(data, "model_dump") else vars(data))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    save_json(EXCHANGE_CONFIG_FILE, cfg)
    audit(
        actor_name(user),
        "config-exchange",
        enabled=cfg["enabled"],
        server=cfg["server"],
        auth=cfg["auth"],
        verifyCert=cfg["verifyCert"],
    )
    return {"status": "success"}


@router.post("/api/exchange-config/test")
def test_exchange_config(data: ExchangeConfigModel, user: dict = Depends(get_current_user)):
    """Verbindungstest mit den eingegebenen (ungespeicherten) Werten und den Zugangsdaten des Administrators."""
    require_admin(user, "Nur Administratoren.")
    try:
        cfg = clean_config(data.model_dump() if hasattr(data, "model_dump") else vars(data))
        if not cfg["server"]:
            raise ValueError("Bitte den Exchange-Server eintragen.")
        message = check_connection(cfg, user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    except ExchangeError as e:
        audit(actor_name(user), "exchange-test", cfg["server"], ok=False, error=str(e))
        raise HTTPException(status_code=502, detail=str(e)) from None
    audit(actor_name(user), "exchange-test", cfg["server"])
    return {"status": "success", "message": message}


@router.get("/api/onboarding-config/detect")
def detect_onboarding_environment(user: dict = Depends(get_current_user)):
    """Hinweis fuer Administratoren: gibt es im AD Spuren von Exchange oder einer Azure/Entra-Synchronisation?"""
    require_admin(user, "Nur Administratoren.")
    try:
        with ad_session(user) as conn:
            return detect_mail_system(conn)
    except Exception as e:  # nur ein Hinweis, darf nie stoeren
        log.info("Erkennung Exchange/Entra nicht moeglich: %s", e)
        return {"exchange": None, "entra": None}


@router.get("/api/pwdreset-config")
def get_pwdreset_config(user: dict = Depends(get_current_user)):
    return load_json(PWDRESET_CONFIG_FILE, default_pwdreset_config)


@router.post("/api/pwdreset-config")
def save_pwdreset_config(data: PwdResetConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Passwort-Reset-Konfigurationen bearbeiten.")
    save_json(PWDRESET_CONFIG_FILE, {"sourceOus": clean_ou_list(data.sourceOus)})
    audit(actor_name(user), "config-pwdreset", sourceOus=data.sourceOus)
    return {"status": "success"}


@router.get("/api/usermgmt-config")
def get_usermgmt_config(user: dict = Depends(get_current_user)):
    return load_json(USERMGMT_CONFIG_FILE, default_usermgmt_config)


@router.post("/api/usermgmt-config")
def save_usermgmt_config(data: UserMgmtConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen die Benutzer-Verwaltungs Konfiguration bearbeiten.")
    save_json(
        USERMGMT_CONFIG_FILE,
        {
            "sourceOus": clean_ou_list(data.sourceOus),
            "targetOus": clean_ou_list(data.targetOus),
            "groupOus": clean_ou_list(data.groupOus),
        },
    )
    audit(
        actor_name(user),
        "config-usermgmt",
        sourceOus=data.sourceOus,
        targetOus=data.targetOus,
        groupOus=data.groupOus,
    )
    return {"status": "success"}


@router.post("/api/smtp-test")
def test_smtp(user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen SMTP-Tests durchführen.")
    cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    recipient = user.get("email")
    if not recipient:
        raise HTTPException(status_code=400, detail="Keine E-Mail-Adresse für den Administrator hinterlegt.")

    body_text, body_html = render_mail(
        actor_name(user),
        "SAMONBOARDING Suite",
        "#0284c7",
        f"Dies ist eine erfolgreiche Test-Mail der SAMONBOARDING Suite v{VERSION}.",
        [("Server:", f"{cfg.get('host')}:{cfg.get('port')} ({cfg.get('tlsMode')})", "mono")],
    )
    try:
        smtp_send(cfg, recipient, "SAMONBOARDING - SMTP Test-Mail", body_text, body_html)
    except Exception as e:
        log.warning("SMTP-Test fehlgeschlagen: %s", e)
        raise HTTPException(status_code=500, detail=f"Test-Mail konnte nicht gesendet werden: {e}")
    return {"status": "success", "message": f"Test-Mail erfolgreich an {recipient} gesendet!"}
