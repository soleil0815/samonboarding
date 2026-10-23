"""Offboarding: Konto deaktivieren, aus Gruppen entfernen und in die Ziel-OU verschieben."""

import logging

import ldap3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from .. import listcache, offboard_store
from ..adguid import read_guid
from ..audit import actor_name, audited
from ..config import OFFBOARDING_CONFIG_FILE, SMTP_CONFIG_FILE, default_offboarding_config, default_smtp_config
from ..dn import parent_dn, rdn_label, split_dn
from ..errors import AdError
from ..ldap_client import (
    ad_session,
    collect_users,
    ensure,
    ldap_error_text,
    member_change_ok,
    row_display_name,
    row_uac,
)
from ..mailer import render_mail, send_notification_email
from ..models import OffboardActionModel, OffboardBatchModel
from ..permissions import resolve_account
from ..protection import mark_protected, privileged_reason, protected_message
from ..sessions import get_current_user
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/offboarding/users")
def get_offboarding_users(user: dict = Depends(get_current_user), frisch: bool = False):
    """Liste kurz zwischengespeichert (listcache); frisch=1 liest immer neu vom DC."""
    return listcache.cached(user, "offboarding-users", lambda: _get_offboarding_users(user), frisch)


def _get_offboarding_users(user):
    off_cfg = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)
    source_ous = off_cfg.get("sourceOus", [])
    if not source_ous:
        return {"status": "success", "users": [], "warning": "Keine Quell-OUs für das Offboarding konfiguriert."}

    def build(row, ou):
        return {
            "dn": row.dn,
            "name": row_display_name(row),
            "sam": row.text("sAMAccountName"),
            "mail": row.text("mail"),
            "disabled": bool(row_uac(row) & 2),
            "ou": ou,
            "_adminCount": row.text("adminCount") == "1",
        }

    with ad_session(user) as conn:
        users = collect_users(
            conn, source_ous, ["sAMAccountName", "displayName", "cn", "userAccountControl", "mail", "adminCount"], build
        )
        mark_protected(conn, users)
    return {"status": "success", "users": users}


MAX_BATCH = 25


def remember_state(conn, user, entry, sam, name):
    """Speichert OU, Gruppen und Kontostatus vor dem Offboarding. Fehler verhindern das Offboarding nicht."""
    try:
        groups = [
            {"dn": g, "guid": read_guid(conn, g, "(objectClass=group)"), "name": rdn_label(g)}
            for g in entry.list("memberOf")
        ]
        return offboard_store.record(
            user_guid=read_guid(conn, entry.dn, "(objectClass=user)"),
            sam=sam,
            name=name,
            original_dn=entry.dn,
            original_ou=parent_dn(entry.dn),
            was_enabled=not (row_uac(entry) & 2),
            groups=groups,
            actor=actor_name(user),
        )
    except Exception as e:
        log.error("Offboarding-Zustand fuer %s nicht gespeichert (Wiederherstellung nicht moeglich): %s", entry.dn, e)
        return None


def forget_record(record_id):
    try:
        offboard_store.remove(record_id)
    except Exception as e:
        log.warning("Offboarding-Eintrag %s nicht entfernt: %s", record_id, e)


def note_current_dn(record_id, dn):
    try:
        offboard_store.update_current_dn(record_id, dn)
    except Exception as e:
        log.warning("Offboarding-Eintrag %s nicht aktualisiert: %s", record_id, e)


def offboard_account(user, off_cfg, user_dn):
    """Deaktiviert ein Konto, entfernt es aus allen Gruppen und verschiebt es in die Ziel-OU (mit Audit-Eintrag).
    Liefert {'sam', 'name', 'removed', 'failed'}; Fehler kommen als HTTPException/AdError."""
    target_ou = off_cfg.get("targetOu")
    if not target_ou:
        raise HTTPException(status_code=400, detail="Keine Ziel-OU für deaktivierte Benutzer konfiguriert.")

    with audited(user, "offboarding", user_dn, targetOu=target_ou) as info:
        removed_groups, failed_groups = [], []
        with ad_session(user) as conn:
            entry = resolve_account(
                conn,
                user_dn,
                off_cfg.get("sourceOus", []),
                "das Offboarding",
                ["sAMAccountName", "displayName", "cn", "userAccountControl", "memberOf"],
            )
            user_dn = entry.dn  # ab hier nur noch der DN, den der DC geliefert hat

            target_sam = entry.text("sAMAccountName").lower()
            target_name = row_display_name(entry) or target_sam
            info["sam"] = target_sam
            operator_sam = user["username"].lower().split("\\")[-1].split("@")[0]
            if target_sam == operator_sam:
                raise HTTPException(
                    status_code=400, detail="Sicherheitsfehler: Sie können Ihr eigenes Benutzerkonto nicht offboarden!"
                )

            reason = privileged_reason(conn, user_dn)
            if reason:
                info["protected"] = reason
                raise HTTPException(status_code=403, detail=protected_message(reason, "offgeboardet"))

            # Vorher festhalten, wo das Konto war - fuer eine spaetere Wiederherstellung
            record_id = remember_state(conn, user, entry, target_sam, target_name)
            info["restorable"] = bool(record_id)

            new_uac = row_uac(entry) | 2
            try:
                ensure(
                    conn,
                    conn.modify(user_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_uac])]}),
                    "Konto deaktivieren",
                )
            except Exception:
                if record_id:
                    forget_record(record_id)  # es wurde nichts veraendert
                raise

            for group_dn in entry.list("memberOf"):
                ok = conn.modify(group_dn, {"member": [(ldap3.MODIFY_DELETE, [user_dn])]})
                if member_change_ok(conn, ok):
                    removed_groups.append(rdn_label(group_dn))
                else:
                    failed_groups.append(f"{rdn_label(group_dn)} ({ldap_error_text(conn)})")

            if not conn.modify_dn(user_dn, split_dn(user_dn)[0], new_superior=target_ou):
                raise AdError(
                    "Das Konto wurde deaktiviert, konnte aber nicht in die Ziel-OU verschoben werden: "
                    + ldap_error_text(conn)
                )
            if record_id:
                note_current_dn(record_id, split_dn(user_dn)[0] + "," + target_ou)
        info.update(removedGroups=removed_groups, failedGroups=failed_groups)
    return {"sam": target_sam, "name": target_name, "dn": user_dn, "removed": removed_groups, "failed": failed_groups}


def _single_mail(user, off_cfg, result):
    body_text, body_html = render_mail(
        user["username"],
        "Mitarbeiter Offboarding",
        "#e11d48",
        f"Das Konto von {result['name']} ({result['sam']}) wurde erfolgreich deaktiviert und verschoben.",
        [
            ("Mitarbeiter:", f"{result['name']} ({result['sam']})", "bold"),
            ("Benutzer-DN:", result["dn"], "mono"),
            ("Ziel-OU:", off_cfg.get("targetOu", ""), "mono"),
            ("Entfernte Gruppen:", ", ".join(result["removed"]) if result["removed"] else "Keine", "mono"),
        ],
    )
    return (
        f"SAMONBOARDING - Offboarding für {result['name']} ({result['sam']})",
        body_text,
        body_html,
    )


def _batch_mail(user, off_cfg, done, failed):
    lines = [(f"{r['name']} ({r['sam']}):", "offgeboardet", "bold") for r in done]
    lines += [(f"{f['name']}:", f"NICHT offgeboardet - {f['error']}", "mono") for f in failed]
    body_text, body_html = render_mail(
        user["username"],
        "Mitarbeiter Offboarding (mehrere)",
        "#e11d48",
        f"{len(done)} von {len(done) + len(failed)} Konten wurden deaktiviert und in die Ziel-OU verschoben.",
        [*lines, ("Ziel-OU:", off_cfg.get("targetOu", ""), "mono")],
    )
    return f"SAMONBOARDING - Offboarding von {len(done)} Konten", body_text, body_html


def _queue_mail(background, user, subject_text_html):
    subject, body_text, body_html = subject_text_html
    background.add_task(send_notification_email, user["email"], subject, body_text, body_html)


@router.post("/api/offboarding/execute")
def execute_offboarding(data: OffboardActionModel, background: BackgroundTasks, user: dict = Depends(get_current_user)):
    off_cfg = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)
    result = offboard_account(user, off_cfg, data.userDn)

    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if smtp_cfg.get("notifyOffboarding", False) and user.get("email"):
        _queue_mail(background, user, _single_mail(user, off_cfg, result))

    message = "Benutzer erfolgreich deaktiviert, aus Gruppen entfernt und in Ziel-OU verschoben!"
    if result["failed"]:
        message += " Hinweis: Aus folgenden Gruppen konnte der Benutzer nicht entfernt werden: " + "; ".join(
            result["failed"]
        )
    return {"status": "success", "message": message}


@router.post("/api/offboarding/execute-batch")
def execute_offboarding_batch(
    data: OffboardBatchModel, background: BackgroundTasks, user: dict = Depends(get_current_user)
):
    """Mehrere Konten nacheinander offboarden. Ein Fehler (z. B. geschuetztes Konto) stoppt die anderen nicht."""
    dns = list(dict.fromkeys(data.userDns))
    if not dns:
        raise HTTPException(status_code=400, detail="Keine Konten ausgewählt.")
    if len(dns) > MAX_BATCH:
        raise HTTPException(status_code=400, detail=f"Maximal {MAX_BATCH} Konten gleichzeitig.")
    off_cfg = load_json(OFFBOARDING_CONFIG_FILE, default_offboarding_config)
    if not off_cfg.get("targetOu"):
        raise HTTPException(status_code=400, detail="Keine Ziel-OU für deaktivierte Benutzer konfiguriert.")

    done, failed = [], []
    for dn in dns:
        try:
            done.append(offboard_account(user, off_cfg, dn))
        except HTTPException as e:
            failed.append({"dn": dn, "name": rdn_label(dn), "error": str(e.detail)})
        except Exception as e:
            log.warning("Offboarding %s fehlgeschlagen: %s", dn, e)
            failed.append({"dn": dn, "name": rdn_label(dn), "error": str(e)})

    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if done and smtp_cfg.get("notifyOffboarding", False) and user.get("email"):
        _queue_mail(background, user, _batch_mail(user, off_cfg, done, failed))
    return {
        "status": "success" if done else "error",
        "done": [{"dn": r["dn"], "name": r["name"], "sam": r["sam"], "failedGroups": r["failed"]} for r in done],
        "failed": failed,
    }
