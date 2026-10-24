"""Offboarding rueckgaengig machen: Konto zurueck in die alte OU, wieder in die alten Gruppen, wieder aktiv.

Grundlage ist der beim Offboarding gespeicherte Zustand (offboard_store). Konto und Gruppen werden ueber ihre feste
Kennung (objectGUID) gesucht, damit sie auch nach Umbenennen oder Verschieben gefunden werden. Wie beim Loeschen gibt
es erst eine Vorschau, dann die Ausfuehrung. Wer offboarden darf, darf auch wiederherstellen (gleiche Quell-OUs).
"""

import logging

import ldap3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from .. import offboard_store
from ..adguid import guid_filter, read_guid
from ..audit import actor_name, audit, audited
from ..config import (
    CONFIG_FILE,
    OFFBOARD_RETENTION_DAYS,
    OFFBOARDING_CONFIG_FILE,
    SMTP_CONFIG_FILE,
    default_config,
    default_offboarding_config,
    default_smtp_config,
)
from ..dn import base_dn, dn_in_any, dn_norm, parent_dn, rdn_label, split_dn
from ..errors import AdError
from ..ldap_client import (
    ad_session,
    ensure,
    get_object,
    ldap_error_text,
    ldap_search,
    member_change_ok,
    row_uac,
)
from ..mailer import render_mail, send_notification_email
from ..models import RestoreModel
from ..permissions import is_admin, reject_special_dn, require_admin, require_not_protected_for_operator
from ..protection import privileged_group
from ..sessions import get_current_user
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()

USER_ATTRS = ["sAMAccountName", "displayName", "cn", "userAccountControl", "memberOf"]
CONTAINER_FILTER = "(|(objectClass=organizationalUnit)(objectClass=container))"


def _record_or_404(record_id):
    rec = offboard_store.get(record_id)
    if rec and rec["state"] == "restoring":
        raise HTTPException(status_code=409, detail="Dieses Konto wird gerade schon wiederhergestellt.")
    if not rec or rec["state"] != "open":
        raise HTTPException(
            status_code=404, detail="Kein offener Eintrag gefunden (bereits wiederhergestellt oder verworfen)."
        )
    return rec


def _search_base():
    return base_dn(load_json(CONFIG_FILE, default_config)["domain"])


def locate_account(conn, rec):
    """Sucht das Konto: zuerst am zuletzt bekannten Ort, dann ueber die GUID, zuletzt ueber den Anmeldenamen."""
    entry = get_object(conn, rec["current_dn"], USER_ATTRS)
    if entry and entry.text("sAMAccountName").lower() == rec["sam"].lower():
        guid = read_guid(conn, entry.dn, "(objectClass=user)")
        if not rec["user_guid"] or not guid or guid == rec["user_guid"]:
            return entry
    # Verschoben oder umbenannt: nur ueber die feste Kennung (GUID). Ein Konto mit demselben Anmeldenamen kann ein
    # anderes, neueres Konto sein - es bekaeme sonst die Gruppen des alten.
    if rec["user_guid"]:
        rows = ldap_search(conn, _search_base(), f"(&(objectClass=user){guid_filter(rec['user_guid'])})", USER_ATTRS)
        if rows:
            return rows[0]
    return None


def locate_group(conn, group):
    """Liefert den aktuellen DN einer gespeicherten Gruppe oder '' (geloescht)."""
    found = get_object(conn, group["dn"], ["cn"], flt="(objectClass=group)")
    if found:
        guid = read_guid(conn, found.dn, "(objectClass=group)")
        if not group.get("guid") or not guid or guid == group["guid"]:
            return found.dn
    if group.get("guid"):
        rows = ldap_search(conn, _search_base(), f"(&(objectClass=group){guid_filter(group['guid'])})", ["cn"])
        if rows:
            return rows[0].dn
    return ""


def build_plan(conn, rec, off_cfg, target_ou=None, admin=True):
    """Was bei der Wiederherstellung passieren wuerde. Veraendert nichts."""
    sources = [o for o in off_cfg.get("sourceOus", []) if o]
    entry = locate_account(conn, rec)
    target = reject_special_dn(target_ou) if target_ou else rec["original_ou"].strip()
    blockers, notes = [], []

    ou_entry = get_object(conn, target, ["ou"], flt=CONTAINER_FILTER) if target else None
    if ou_entry:
        target = ou_entry.dn  # der DN, den der DC liefert, wird geprueft und verwendet
    ou_exists = bool(ou_entry)
    ou_allowed = dn_in_any(target, sources)
    if not entry:
        blockers.append("Das Konto wurde im AD nicht gefunden (gelöscht?). Es kann nicht wiederhergestellt werden.")
    elif (
        not admin
        and not (off_cfg.get("targetOu") and dn_in_any(entry.dn, [off_cfg["targetOu"]]))
        and not dn_in_any(entry.dn, sources)
    ):
        # Operatoren: nur aus der OU der offgeboardeten Konten (oder ein abgebrochener Versuch, der das Konto schon in
        # eine Quell-OU zurueckgebracht hat). Liegt es woanders, hat ein Administrator es dorthin verschoben (z. B. zum
        # Loeschen) - nicht ueberstimmen. Ohne eingestellte Ziel-OU gilt das ebenso.
        blockers.append(
            "Das Konto liegt nicht mehr in der OU der offgeboardeten Konten. Nur Administratoren können es "
            "von dort wiederherstellen."
        )
    if not ou_exists:
        blockers.append(f"Die OU {target} gibt es nicht mehr. Bitte eine andere OU wählen.")
    elif not ou_allowed:
        blockers.append(f"Die OU {target} gehört nicht zu den Quell-OUs des Offboardings. Bitte eine andere OU wählen.")

    groups = []
    current_groups = {dn_norm(g) for g in (entry.list("memberOf") if entry else [])}
    for g in rec["groups"]:
        dn = locate_group(conn, g) if entry else g["dn"]
        status = "missing" if not dn else ("member" if dn_norm(dn) in current_groups else "add")
        groups.append({"name": g.get("name") or rdn_label(g["dn"]), "dn": dn or g["dn"], "status": status})
    missing = [g["name"] for g in groups if g["status"] == "missing"]
    if missing:
        notes.append("Nicht mehr vorhanden, wird übersprungen: " + ", ".join(missing))

    enabled_now = bool(entry) and not (row_uac(entry) & 2)
    if entry and enabled_now:
        notes.append("Das Konto ist bereits wieder aktiv.")
    if entry and not rec["was_enabled"]:
        notes.append("Das Konto war schon vor dem Offboarding deaktiviert und bleibt deaktiviert.")
    return {
        "id": rec["id"],
        "sam": rec["sam"],
        "name": rec["name"],
        "offboardedAt": rec["offboarded_at"],
        "offboardedBy": rec["offboarded_by"],
        "currentDn": entry.dn if entry else rec["current_dn"],
        "originalOu": rec["original_ou"],
        "targetOu": target,
        "move": bool(entry) and dn_norm(parent_dn(entry.dn)) != dn_norm(target),
        "enable": bool(entry) and rec["was_enabled"] and not enabled_now,
        "groups": groups,
        "ouOptions": sources,
        "blockers": blockers,
        "notes": notes,
        "_entry": entry,
    }


def _public(plan):
    return {k: v for k, v in plan.items() if not k.startswith("_")}


@router.get("/api/offboarding/records")
def list_records(user: dict = Depends(get_current_user)):
    out = []
    for rec in offboard_store.list_open():
        out.append(
            {
                "id": rec["id"],
                "sam": rec["sam"],
                "name": rec["name"],
                "originalOu": rec["original_ou"],
                "groupCount": len(rec["groups"]),
                "groups": [g.get("name") or rdn_label(g["dn"]) for g in rec["groups"]],
                "offboardedAt": rec["offboarded_at"],
                "offboardedBy": rec["offboarded_by"],
                "wasEnabled": rec["was_enabled"],
            }
        )
    return {"status": "success", "records": out, "retentionDays": OFFBOARD_RETENTION_DAYS}


@router.get("/api/offboarding/records/{record_id}/preview")
def preview_restore(record_id: int, targetOu: str = "", user: dict = Depends(get_current_user)):
    rec = _record_or_404(record_id)
    off_cfg = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)
    with ad_session(user) as conn:
        return {"status": "success", **_public(build_plan(conn, rec, off_cfg, targetOu or None, is_admin(user)))}


def _mail(background, user, plan, warnings):
    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if not (smtp_cfg.get("notifyOffboarding", False) and user.get("email")):
        return
    body_text, body_html = render_mail(
        user["username"],
        "Konto wiederhergestellt",
        "#059669",
        f"Das Offboarding von {plan['name']} ({plan['sam']}) wurde rückgängig gemacht.",
        [
            ("Mitarbeiter:", f"{plan['name']} ({plan['sam']})", "bold"),
            ("OU:", plan["targetOu"], "mono"),
            ("Gruppen:", ", ".join(g["name"] for g in plan["groups"] if g["status"] != "missing") or "Keine", "mono"),
            *([("Hinweise:", "; ".join(warnings), "bad")] if warnings else []),
        ],
    )
    background.add_task(
        send_notification_email,
        user["email"],
        f"SAMONBOARDING - Konto wiederhergestellt: {plan['name']} ({plan['sam']})",
        body_text,
        body_html,
    )


@router.post("/api/offboarding/records/{record_id}/restore")
def restore_account(
    record_id: int, data: RestoreModel, background: BackgroundTasks, user: dict = Depends(get_current_user)
):
    rec = _record_or_404(record_id)
    if not offboard_store.claim(record_id):
        raise HTTPException(status_code=409, detail="Dieses Konto wird gerade schon wiederhergestellt.")
    off_cfg = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)
    done = False
    try:
        with audited(user, "offboarding-restore", rec["current_dn"], sam=rec["sam"]) as info:
            warnings = []
            with ad_session(user) as conn:
                plan = build_plan(conn, rec, off_cfg, (data.targetOu or "").strip() or None, is_admin(user))
                info["targetOu"] = plan["targetOu"]
                if plan["blockers"]:
                    raise HTTPException(status_code=400, detail=" ".join(plan["blockers"]))
                entry = plan["_entry"]
                dn = entry.dn
                require_not_protected_for_operator(conn, user, dn, "wiederhergestellt")

                # 1. zurueck in die OU (danach gilt der neue DN fuer die Gruppen)
                if plan["move"]:
                    rdn = split_dn(dn)[0]
                    if not conn.modify_dn(dn, rdn, new_superior=plan["targetOu"]):
                        raise AdError("Das Konto konnte nicht verschoben werden: " + ldap_error_text(conn))
                    dn = rdn + "," + plan["targetOu"]
                    try:  # bricht ein spaeterer Schritt ab, findet ein neuer Versuch das Konto am neuen Ort
                        offboard_store.update_current_dn(record_id, dn)
                    except Exception as e:
                        log.warning("Neuer Ort von %s nicht gespeichert: %s", dn, e)

                # 2. Gruppen
                added, failed = [], []
                for g in plan["groups"]:
                    if g["status"] == "missing":
                        continue
                    special = "" if is_admin(user) else privileged_group(conn, g["dn"])
                    if special:
                        failed.append(f"{g['name']} (privilegierte Gruppe - nur Administratoren)")
                        continue
                    ok = conn.modify(g["dn"], {"member": [(ldap3.MODIFY_ADD, [dn])]})
                    if member_change_ok(conn, ok):
                        added.append(g["name"])
                    else:
                        failed.append(f"{g['name']} ({ldap_error_text(conn)})")
                if failed:
                    warnings.append("Nicht wieder zugewiesen: " + "; ".join(failed))
                warnings.extend(plan["notes"])

                # 3. wieder aktivieren (nur wenn das Konto vor dem Offboarding aktiv war)
                if plan["enable"]:
                    fresh = get_object(conn, dn, ["userAccountControl"])
                    uac = row_uac(fresh) if fresh else row_uac(entry)
                    ensure(
                        conn,
                        conn.modify(dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [uac & ~2])]}),
                        "Konto aktivieren",
                    )
            info.update(dn=dn, groupsAdded=added, groupsFailed=failed)
        done = True
    finally:
        if done:
            offboard_store.remove(record_id)
        else:
            offboard_store.release(record_id)

    _mail(background, user, plan, warnings)
    message = f"{plan['name'] or plan['sam']} wurde wiederhergestellt"
    message += " und ist wieder aktiv." if plan["enable"] else "."
    return {"status": "success", "message": message, "dn": dn, "groupsAdded": added, "warnings": warnings}


@router.post("/api/offboarding/records/{record_id}/dismiss")
def dismiss_record(record_id: int, user: dict = Depends(get_current_user)):
    """Eintrag verwerfen (z. B. Konto wurde von Hand zurueckgeholt). Nur Administratoren."""
    require_admin(user, "Nur Administratoren dürfen Einträge verwerfen.")
    rec = _record_or_404(record_id)
    offboard_store.remove(record_id)
    audit(actor_name(user), "offboarding-record-dismiss", rec["current_dn"], sam=rec["sam"])
    return {"status": "success"}
