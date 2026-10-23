"""Onboarding-Templates: anlegen, bearbeiten, duplizieren, loeschen."""

from fastapi import APIRouter, Depends, HTTPException

from ..audit import actor_name, audit
from ..config import (
    LEGACY_MAIL_MODES,
    MAIL_MODES,
    ONBOARDING_CONFIG_FILE,
    TEMPLATES_FILE,
    default_onboarding_config,
)
from ..naming import DEFAULT_NAMING_MACRO, normalize_home_drive
from ..permissions import require_admin
from ..sessions import get_current_user
from ..storage import file_lock, load_json, save_json

router = APIRouter()


TEMPLATE_TEXT_FIELDS = [
    "name",
    "naming",
    "ouDn",
    "pwdMode",
    "staticPwd",
    "initials",
    "displayName",
    "description",
    "office",
    "telephone",
    "mail",
    "website",
    "street",
    "pobox",
    "postalCode",
    "city",
    "state",
    "country",
    "homePhone",
    "pager",
    "mobile",
    "fax",
    "ipPhone",
    "notes",
    "title",
    "department",
    "company",
    "manager",
    "profilePath",
    "scriptPath",
    "homeDirectory",
    "homeDrive",
]

# AD begrenzt diese Attribute auf 260 Zeichen
PATH_FIELDS = {"profilePath": "Profilpfad", "scriptPath": "Anmeldeskript", "homeDirectory": "Basisordner"}


def safe_sort_templates(tmpls):
    if not isinstance(tmpls, list):
        return []
    try:
        return sorted(
            tmpls, key=lambda x: str(x.get("name") if isinstance(x, dict) and x.get("name") is not None else "").lower()
        )
    except Exception:
        return tmpls


def template_mail_mode(tmpl):
    """E-Mail-Modus eines Templates. Aeltere Templates ohne Angabe erben den frueher global gespeicherten Wert."""
    mode = tmpl.get("mailMode") if isinstance(tmpl, dict) else None
    if mode in MAIL_MODES:
        return mode
    legacy = load_json(ONBOARDING_CONFIG_FILE, default_onboarding_config)
    return LEGACY_MAIL_MODES.get(legacy.get("mailMode") if isinstance(legacy, dict) else None, "required")


def sanitize_template(raw):
    """Uebernimmt nur bekannte Felder mit den richtigen Typen."""
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="Ungültige Template-Daten.")
    tmpl = {}
    for key in TEMPLATE_TEXT_FIELDS:
        value = raw.get(key)
        text = "" if value is None else str(value)
        tmpl[key] = text if key == "staticPwd" else text.strip()
    if not tmpl["name"]:
        raise HTTPException(status_code=400, detail="Bitte mindestens einen Namen für das Template angeben.")
    if not tmpl["naming"]:
        tmpl["naming"] = DEFAULT_NAMING_MACRO
    for key, label in PATH_FIELDS.items():
        if len(tmpl[key]) > 260:
            raise HTTPException(status_code=400, detail=f"{label}: Maximal 260 Zeichen erlaubt.")
    try:
        tmpl["homeDrive"] = normalize_home_drive(tmpl["homeDrive"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Basisordner: {e}")
    if tmpl["homeDrive"]:
        # Wie in RSAT ("Verbinden von"): Laufwerk nur mit Netzwerkpfad.
        if not tmpl["homeDirectory"].startswith("\\\\"):
            raise HTTPException(
                status_code=400,
                detail="Basisordner: Für ein Laufwerk muss der Pfad ein Netzwerkpfad sein "
                "(\\\\server\\freigabe\\%username%).",
            )
    tmpl["createHomeFolder"] = bool(raw.get("createHomeFolder", False))
    if tmpl["createHomeFolder"] and not tmpl["homeDirectory"].startswith("\\\\"):
        raise HTTPException(
            status_code=400,
            detail="Basisordner: Zum automatischen Anlegen muss der Pfad ein Netzwerkpfad sein "
            "(\\\\server\\freigabe\\%username%).",
        )
    if tmpl["pwdMode"] not in ("random", "static"):
        tmpl["pwdMode"] = "random"
    mail_mode = str(raw.get("mailMode") or "").strip()
    tmpl["mailMode"] = mail_mode if mail_mode in MAIL_MODES else "required"
    tmpl["forceChange"] = bool(raw.get("forceChange", True))
    tmpl["pwdNeverExpires"] = bool(raw.get("pwdNeverExpires", False))
    groups = raw.get("groups")
    tmpl["groups"] = [str(g).strip() for g in groups if str(g).strip()] if isinstance(groups, list) else []
    template_id = raw.get("id")
    tmpl["id"] = template_id if isinstance(template_id, int) and not isinstance(template_id, bool) else None
    return tmpl


def _next_template_id(tmpls):
    ids = [t.get("id") for t in tmpls if isinstance(t, dict) and isinstance(t.get("id"), int)]
    return max(ids, default=0) + 1


@router.get("/api/templates")
def get_templates(user: dict = Depends(get_current_user)):
    tmpls = [
        dict(t, mailMode=template_mail_mode(t))
        for t in safe_sort_templates(load_json(TEMPLATES_FILE, []))
        if isinstance(t, dict)
    ]
    if user.get("role") != "Administrator":
        # Statische Passwoerter sind nur fuer Administratoren sichtbar.
        tmpls = [{k: v for k, v in t.items() if k != "staticPwd"} for t in tmpls]
    return tmpls


@router.post("/api/templates")
def save_template(tmpl: dict, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Templates erstellen oder bearbeiten.")
    clean = sanitize_template(tmpl)

    with file_lock:
        tmpls = load_json(TEMPLATES_FILE, [])
        if not isinstance(tmpls, list):
            tmpls = []
        if clean["id"] is not None:
            if not any(isinstance(t, dict) and t.get("id") == clean["id"] for t in tmpls):
                raise HTTPException(status_code=404, detail="Template nicht gefunden (wurde es bereits gelöscht?).")
            tmpls = [clean if isinstance(t, dict) and t.get("id") == clean["id"] else t for t in tmpls]
        else:
            clean["id"] = _next_template_id(tmpls)
            tmpls.append(clean)
        save_json(TEMPLATES_FILE, tmpls)

    audit(actor_name(user), "template-save", clean["name"], templateId=clean["id"])
    return {"status": "success", "templates": safe_sort_templates(tmpls)}


@router.post("/api/templates/{tmpl_id}/duplicate")
def duplicate_template(tmpl_id: int, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Templates duplizieren.")
    with file_lock:
        tmpls = load_json(TEMPLATES_FILE, [])
        if not isinstance(tmpls, list):
            tmpls = []
        target = next((t for t in tmpls if isinstance(t, dict) and t.get("id") == tmpl_id), None)
        if not target:
            raise HTTPException(status_code=404, detail="Template nicht gefunden.")
        new_tmpl = dict(target)
        new_tmpl["id"] = _next_template_id(tmpls)
        new_tmpl["name"] = f"{target.get('name', 'Template')} (Kopie)"
        tmpls.append(new_tmpl)
        save_json(TEMPLATES_FILE, tmpls)
    audit(actor_name(user), "template-duplicate", str(target.get("name", "")), templateId=new_tmpl["id"])
    return {"status": "success", "templates": safe_sort_templates(tmpls)}


@router.delete("/api/templates/{tmpl_id}")
def delete_template(tmpl_id: int, user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen Templates löschen.")
    with file_lock:
        tmpls = load_json(TEMPLATES_FILE, [])
        if not isinstance(tmpls, list):
            tmpls = []
        remaining = [t for t in tmpls if not (isinstance(t, dict) and t.get("id") == tmpl_id)]
        save_json(TEMPLATES_FILE, remaining)
    audit(actor_name(user), "template-delete", str(tmpl_id))
    return {"status": "success"}
