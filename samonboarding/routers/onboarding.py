# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Onboarding: neuen AD-Benutzer anhand eines Templates anlegen."""

import logging
import re

import ldap3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from ..audit import audited
from ..config import (
    CONFIG_FILE,
    EXCHANGE_CONFIG_FILE,
    PWD_HINT,
    TEMPLATES_FILE,
    default_config,
)
from ..dn import base_dn, escape_rdn_value, ldap_escape, rdn_label
from ..errors import AdError
from ..exchange import ExchangeError, clean_config, default_exchange_config, enable_mailbox
from ..fileshare import FsError, create_home_folder, open_backend
from ..ldap_client import (
    ad_session,
    directory_info,
    ensure,
    get_object,
    ldap_error_text,
    ldap_search,
    member_change_ok,
)
from ..mailer import send_onboarding_mail
from ..models import OnboardModel
from ..naming import (
    DEFAULT_NAMING_MACRO,
    apply_macro,
    country_code,
    generate_secure_password,
    normalize_home_drive,
    sanitize_sam,
    valid_mail,
    valid_person_name,
)
from ..protection import read_sids
from ..sessions import get_current_user
from ..storage import load_json
from .templates import template_mail_mode

log = logging.getLogger(__name__)
router = APIRouter()


def unique_sam(conn, search_base, base_sam, domain=""):
    """Liefert einen freien sAMAccountName (max. 20 Zeichen, bei Kollision mit Zaehler ab 2). Frei heisst auch: kein
    anderes Konto hat den daraus gebildeten Anmeldenamen (UPN) <name>@<domain>."""
    sam, counter = base_sam, 1
    while True:
        flt = f"(sAMAccountName={ldap_escape(sam)})"
        if domain:
            flt = f"(|{flt}(userPrincipalName={ldap_escape(f'{sam}@{domain}')}))"
        rows = ldap_search(conn, search_base, flt, ["sAMAccountName"])
        if not rows:
            return sam
        counter += 1
        if counter > 999:
            raise AdError("Es konnte kein freier Benutzername ermittelt werden.")
        suffix = str(counter)
        sam = base_sam[: 20 - len(suffix)] + suffix


def unique_cn(conn, search_base, base_name):
    cn_val, counter = base_name, 1
    while True:
        flt = f"(|(cn={ldap_escape(cn_val)})(displayName={ldap_escape(cn_val)}))"
        if not ldap_search(conn, search_base, flt, ["cn"]):
            return cn_val
        counter += 1
        cn_val = f"{base_name} {counter}"


def read_sid(conn, user_dn):
    """SID des Kontos als Text, sonst None."""
    sids, _ok = read_sids(conn, user_dn, "objectSid")
    return sids[0] if sids else None


def make_backend(user):
    """SMB-Zugriff im Namen des angemeldeten Benutzers (in Tests austauschbar)."""
    return open_backend(user)


def create_home(user, home_dir, sid, warnings):
    """Legt den Basisordner an. Fehler sind nur Warnungen: das Konto existiert bereits und bleibt bestehen."""
    backend = None
    try:
        backend = make_backend(user)
        outcome = create_home_folder(backend, home_dir, sid)
    except FsError as e:
        warnings.append(f"Basisordner {home_dir} konnte nicht angelegt werden: {e.message}")
        return "failed"
    finally:
        if backend:
            backend.close()
    if outcome == "exists":
        warnings.append(f"Basisordner {home_dir} existiert bereits - Berechtigungen wurden nicht verändert.")
    return outcome


def create_mailbox(user, user_dn, warnings):
    """Legt das Exchange-Postfach an (nur fuer Templates mit E-Mail-Modus 'exchange'). Fehler sind nur Warnungen:
    das Konto existiert bereits. Liefert 'created' oder 'failed'."""
    try:
        cfg = clean_config(load_json(EXCHANGE_CONFIG_FILE, default_exchange_config))
    except ValueError:
        cfg = {"enabled": False}
    if not cfg["enabled"]:
        warnings.append(
            "Postfach nicht angelegt: Die Exchange-Anbindung ist nicht eingerichtet "
            "(Menüpunkt Templates, Kasten „Exchange im eigenen Haus“)."
        )
        return "failed"
    try:
        enable_mailbox(cfg, user, user_dn, directory_info().get("host", ""))
    except ExchangeError as e:
        warnings.append(
            f"Postfach konnte nicht angelegt werden: {e} "
            "Das Konto wurde angelegt, das Postfach bitte in Exchange nachholen."
        )
        return "failed"
    return "created"


def read_mail(user, user_dn):
    """Liest die vom Exchange gesetzte Adresse (best effort)."""
    try:
        with ad_session(user) as conn:
            entry = get_object(conn, user_dn, ["mail"])
            return entry.text("mail") if entry else ""
    except Exception as e:
        log.info("Mailadresse nach Postfach-Anlage nicht lesbar: %s", e)
        return ""


def _rollback_new_account(conn, user, user_dn):
    """Loescht ein gerade angelegtes, noch unfertiges Konto. True bei Erfolg."""
    try:
        if conn.delete(user_dn):
            return True
        log.warning("Rollback von %s: %s", user_dn, ldap_error_text(conn))
    except Exception as e:  # Verbindung weg: mit einer neuen Verbindung versuchen
        log.warning("Rollback von %s ueber die bisherige Verbindung nicht moeglich: %s", user_dn, e)
    try:
        with ad_session(user) as fresh:
            return bool(fresh.delete(user_dn))
    except Exception as e:
        log.warning("Rollback von %s auch ueber eine neue Verbindung nicht moeglich: %s", user_dn, e)
        return False


@router.post("/api/onboard")
def execute_onboard(data: OnboardModel, background: BackgroundTasks, user: dict = Depends(get_current_user)):
    first_name, last_name, custom_mail = data.firstName.strip(), data.lastName.strip(), data.customMail.strip()
    if not first_name or not last_name:
        raise HTTPException(status_code=400, detail="Vorname und Nachname sind Pflichtfelder.")
    if not valid_person_name(first_name) or not valid_person_name(last_name):
        raise HTTPException(
            status_code=400, detail="Vor- und Nachname dürfen höchstens 64 Zeichen und keine Steuerzeichen enthalten."
        )
    if custom_mail and not valid_mail(custom_mail):
        raise HTTPException(status_code=400, detail="Die E-Mail-Adresse ist ungültig.")

    cfg = load_json(CONFIG_FILE, default_config)
    tmpls = load_json(TEMPLATES_FILE, [])
    tmpl = next((t for t in tmpls if isinstance(t, dict) and t.get("id") == data.templateId), None)
    if not tmpl:
        raise HTTPException(status_code=400, detail="Template not found.")
    if not tmpl.get("ouDn"):
        raise HTTPException(status_code=400, detail="Das Template hat keine Ziel-OU.")

    mail_mode = template_mail_mode(tmpl)
    if mail_mode in ("exchange", "cloud"):
        custom_mail = ""  # die Adresse entsteht mit dem Postfach (Exchange / Microsoft 365)
    elif mail_mode == "required" and not custom_mail:
        raise HTTPException(status_code=400, detail="Vorname, Nachname und E-Mail-Adresse sind Pflichtfelder.")

    base_sam = sanitize_sam(apply_macro(tmpl.get("naming") or DEFAULT_NAMING_MACRO, first_name, last_name))
    if not base_sam:
        raise HTTPException(status_code=400, detail="Aus dem Namensschema ergibt sich kein gültiger Benutzername.")

    if tmpl.get("pwdMode", "random") == "random":
        password = generate_secure_password()
    else:
        password = tmpl.get("staticPwd") or ""
        if not password:
            raise HTTPException(
                status_code=400, detail="Das Template verwendet ein festes Passwort, aber es ist keines hinterlegt."
            )

    flags = 65536 if tmpl.get("pwdNeverExpires", False) else 0
    warnings = []

    with audited(user, "onboard", f"{first_name} {last_name}", template=tmpl.get("name")) as info:
        with ad_session(user) as conn:
            search_base = base_dn(cfg["domain"])
            sam = unique_sam(conn, search_base, base_sam, cfg["domain"])
            cn_val = unique_cn(conn, search_base, f"{first_name} {last_name}")
            upn = f"{sam}@{cfg['domain']}"
            user_dn = f"CN={escape_rdn_value(cn_val)},{tmpl['ouDn']}"
            info.update(sam=sam, dn=user_dn)

            def clean_val(val):
                if not val or not str(val).strip():
                    return None
                # wie beim Loeschen: %username% ohne Beachtung der Gross-/Kleinschreibung (%USERNAME% aus RSAT)
                return re.sub(r"%username%", lambda _m: sam, str(val), flags=re.IGNORECASE).strip()

            final_display_name = clean_val(tmpl.get("displayName")) or cn_val
            country_val = clean_val(tmpl.get("country"))

            home_dir = clean_val(tmpl.get("homeDirectory"))
            try:
                home_drive = normalize_home_drive(clean_val(tmpl.get("homeDrive"))) or None
            except ValueError:
                home_drive = None
                warnings.append("Das Laufwerk des Basisordners im Template ist ungültig und wurde nicht gesetzt.")
            if home_drive and not (home_dir or "").startswith("\\\\"):
                home_drive = None
                warnings.append("Ein Laufwerk wurde nicht gesetzt, weil der Basisordner kein Netzwerkpfad ist.")

            attributes = {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "sAMAccountName": sam,
                "userPrincipalName": upn,
                "givenName": first_name,
                "sn": last_name,
                "cn": cn_val,
                # Konto zunaechst deaktiviert anlegen; aktiviert wird es erst nach gesetztem Passwort.
                "userAccountControl": 514 | flags,
            }
            if custom_mail:
                attributes["mail"] = custom_mail
            potential_attributes = {
                "initials": clean_val(tmpl.get("initials")),
                "displayName": final_display_name,
                "description": clean_val(tmpl.get("description")),
                "physicalDeliveryOfficeName": clean_val(tmpl.get("office")),
                "telephoneNumber": clean_val(tmpl.get("telephone")),
                "wWWHomePage": clean_val(tmpl.get("website")),
                "streetAddress": clean_val(tmpl.get("street")),
                "postOfficeBox": clean_val(tmpl.get("pobox")),
                "l": clean_val(tmpl.get("city")),
                "st": clean_val(tmpl.get("state")),
                "postalCode": clean_val(tmpl.get("postalCode")),
                "co": country_val,
                "c": country_code(country_val),
                "homePhone": clean_val(tmpl.get("homePhone")),
                "pager": clean_val(tmpl.get("pager")),
                "mobile": clean_val(tmpl.get("mobile")),
                "facsimileTelephoneNumber": clean_val(tmpl.get("fax")),
                "ipPhone": clean_val(tmpl.get("ipPhone")),
                "info": clean_val(tmpl.get("notes")),
                "title": clean_val(tmpl.get("title")),
                "department": clean_val(tmpl.get("department")),
                "company": clean_val(tmpl.get("company")),
                "manager": clean_val(tmpl.get("manager")),
                "profilePath": clean_val(tmpl.get("profilePath")),
                "scriptPath": clean_val(tmpl.get("scriptPath")),
                "homeDirectory": home_dir,
                "homeDrive": home_drive,
            }
            for attr, val in potential_attributes.items():
                if val is not None:
                    attributes[attr] = val

            ensure(conn, conn.add(user_dn, attributes=attributes), "Benutzer anlegen")

            try:
                raw_pwd = f'"{password}"'.encode("utf-16-le")
                ensure(
                    conn,
                    conn.modify(user_dn, {"unicodePwd": [(ldap3.MODIFY_REPLACE, [raw_pwd])]}),
                    "Passwort setzen",
                    PWD_HINT,
                )
                ensure(
                    conn,
                    conn.modify(user_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [512 | flags])]}),
                    "Konto aktivieren",
                )
            except Exception as e:
                # Halbfertiges Konto wieder entfernen, damit ein erneuter Versuch sauber startet - auch bei einem
                # Verbindungsabbruch (dann ueber eine neue Verbindung)
                if not _rollback_new_account(conn, user, user_dn):
                    log.error("Rollback fehlgeschlagen, Konto %s muss manuell entfernt werden", user_dn)
                detail = e.detail if isinstance(e, AdError) else str(e)
                raise AdError(f"Benutzer wurde nicht angelegt. {detail}") from e

            if tmpl.get("forceChange", True):
                if not conn.modify(user_dn, {"pwdLastSet": [(ldap3.MODIFY_REPLACE, [0])]}):
                    warnings.append(
                        "Passwortänderung beim nächsten Login konnte nicht erzwungen werden: " + ldap_error_text(conn)
                    )

            home_sid = None
            if tmpl.get("createHomeFolder") and home_dir:
                home_sid = read_sid(conn, user_dn)
                if not home_sid:
                    warnings.append("Basisordner nicht angelegt: Die SID des neuen Kontos konnte nicht gelesen werden.")

            for group_dn in tmpl.get("groups", []):
                if not group_dn:
                    continue
                ok = conn.modify(group_dn, {"member": [(ldap3.MODIFY_ADD, [user_dn])]})
                if not member_change_ok(conn, ok):
                    warnings.append(
                        f"Gruppe '{rdn_label(group_dn)}' konnte nicht zugewiesen werden: {ldap_error_text(conn)}"
                    )
        if home_sid:
            info["homeFolder"] = create_home(user, home_dir, home_sid, warnings)
        if mail_mode == "exchange":
            mailbox = create_mailbox(user, user_dn, warnings)
            info["mailbox"] = mailbox
        else:
            mailbox = "off"
        if mailbox == "created" and not custom_mail:
            custom_mail = read_mail(user, user_dn)
        info["warnings"] = warnings

    creator_mail = user.get("email")
    if creator_mail:
        background.add_task(
            send_onboarding_mail,
            creator_mail,
            {"fullname": final_display_name, "sam": sam, "upn": upn, "mail": custom_mail, "pwd": password},
        )

    return {
        "status": "success",
        "samAccountName": sam,
        "upn": upn,
        "mail": custom_mail,
        "generatedPassword": password,
        "warnings": warnings,
        "message": "User created successfully!",
    }
