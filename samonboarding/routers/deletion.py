"""Loeschfunktion (nur Administratoren), Schritt 1: Einstellungen, Verbindungstest und Simulation.

Alles hier ist rein lesend: Es wird weder im AD noch auf den Dateiservern etwas veraendert.
Der Zugriff auf die Freigaben erfolgt mit den Zugangsdaten des angemeldeten Administrators.
"""

import contextvars
import copy
import hmac
import logging
import secrets
import threading
import time
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from .. import listcache, offboard_store
from ..audit import actor_name, audit, audited
from ..config import (
    CONFIG_FILE,
    DELETION_CONFIG_FILE,
    SMTP_CONFIG_FILE,
    USER_FILTER,
    default_config,
    default_deletion_config,
    default_smtp_config,
)
from ..dn import base_dn, ldap_escape, rdn_label
from ..errors import AdError
from ..fileshare import (
    LOCATION_LABELS,
    FsError,
    build_targets,
    canonical,
    delete_tree,
    expand_username,
    is_strictly_below,
    normalize_unc,
    open_backend,
    parse_unc,
    scan_tree,
    valid_suffix,
)
from ..ldap_client import ad_session, collect_users, ensure, ldap_search, row_display_name, row_uac
from ..mailer import render_mail, send_notification_email
from ..models import (
    DeletionBatchExecuteModel,
    DeletionBatchSimulateModel,
    DeletionConfigModel,
    DeletionExecuteModel,
    DeletionSimulateModel,
)
from ..permissions import RoleCheckError, check_user_role, require_admin, resolve_account
from ..protection import mark_protected, privileged_reason, protected_message
from ..sessions import get_current_user
from ..storage import load_json, save_json

log = logging.getLogger(__name__)
router = APIRouter()

ADMIN_MSG = "Nur Administratoren dürfen die Löschfunktion nutzen."
KINDS = ("profile", "folderRedirection", "home")
# AD-Attribut, aus dem der Pfad eines Speicherorts stammen kann (Ordnerumleitung steht nur in der GPO)
ATTR_OF_KIND = {"profile": "profilePath", "home": "homeDirectory"}


def make_backend(user):
    """SMB-Zugriff im Namen des angemeldeten Administrators (in Tests austauschbar)."""
    try:
        return open_backend(user)
    except FsError as e:
        raise AdError(e.message) from e


class _NoBackend:
    """Platzhalter ohne Dateizugriff: wenn kein Speicherort aktiviert ist, wird nur das AD-Konto geloescht."""

    def close(self):
        pass


def backend_for(user, cfg):
    """Dateizugriff nur oeffnen, wenn ueberhaupt ein Speicherort (Profil, Ordnerumleitung, Basisordner) aktiv ist."""
    if not any(cfg[kind]["enabled"] for kind in KINDS):
        return _NoBackend()
    return make_backend(user)


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
def load_deletion_config():
    """Gespeicherte Konfiguration, fehlende Schluessel werden mit Standardwerten aufgefuellt."""
    stored = load_json(DELETION_CONFIG_FILE, default_deletion_config)
    cfg = copy.deepcopy(default_deletion_config)
    cfg["enabled"] = bool(stored.get("enabled", False))
    cfg["disabledOu"] = str(stored.get("disabledOu", "") or "")
    for kind in KINDS:
        if isinstance(stored.get(kind), dict):
            cfg[kind].update({k: v for k, v in stored[kind].items() if k in cfg[kind]})
    return cfg


def _clean_location(kind, loc):
    label = LOCATION_LABELS[kind]
    roots, seen = [], set()
    for raw in loc.roots:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            root = normalize_unc(raw)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"{label}: Basispfad '{raw}' ungültig. {e}")
        if root.lower() not in seen:
            seen.add(root.lower())
            roots.append(root)
    out = {"enabled": bool(loc.enabled), "roots": roots, "takeOwnership": bool(loc.takeOwnership)}
    if kind in ATTR_OF_KIND:
        out["useAdAttr"] = bool(loc.useAdAttr)
    if kind == "profile":
        suffixes = []
        for raw in loc.suffixes:
            suffix = str(raw).strip().lstrip(".")
            if not suffix:
                continue
            if not valid_suffix(suffix):
                raise HTTPException(
                    status_code=400, detail=f"{label}: Endung '{raw}' ungültig (nur Buchstaben/Ziffern)."
                )
            if suffix.lower() not in [s.lower() for s in suffixes]:
                suffixes.append(suffix)
        out["suffixes"] = suffixes
    if out["enabled"] and not roots:
        raise HTTPException(status_code=400, detail=f"{label}: Bitte mindestens einen Basispfad angeben.")
    if kind == "profile" and out["enabled"] and not out["suffixes"]:
        raise HTTPException(status_code=400, detail=f"{label}: Bitte mindestens eine Endung angeben (z. B. V2).")
    return out


@router.get("/api/deletion-config")
def get_deletion_config(user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    return load_deletion_config()


@router.post("/api/deletion-config")
def save_deletion_config(data: DeletionConfigModel, user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    cfg = {"enabled": bool(data.enabled), "disabledOu": data.disabledOu.strip()}
    for kind in KINDS:
        cfg[kind] = _clean_location(kind, getattr(data, kind))
    if cfg["enabled"]:
        if not cfg["disabledOu"]:
            raise HTTPException(status_code=400, detail="Bitte die OU der deaktivierten Konten angeben.")
    save_json(DELETION_CONFIG_FILE, cfg)
    audit(
        actor_name(user),
        "config-deletion",
        enabled=cfg["enabled"],
        disabledOu=cfg["disabledOu"],
        profile=cfg["profile"],
        folderRedirection=cfg["folderRedirection"],
        home=cfg["home"],
    )
    return {"status": "success"}


def _require_enabled(cfg):
    if not cfg["enabled"] or not cfg["disabledOu"]:
        raise HTTPException(status_code=400, detail="Die Löschfunktion ist nicht aktiviert (Einstellungen prüfen).")


# ---------------------------------------------------------------------------
# Kandidatenliste
# ---------------------------------------------------------------------------
@router.get("/api/deletion/users")
def get_deletion_users(user: dict = Depends(get_current_user), frisch: bool = False):
    """Liste kurz zwischengespeichert (listcache); frisch=1 liest immer neu vom DC."""
    require_admin(user, ADMIN_MSG)
    return listcache.cached(user, "deletion-users", lambda: _get_deletion_users(user), frisch)


def _get_deletion_users(user):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    if not cfg["enabled"] or not cfg["disabledOu"]:
        return {"status": "success", "users": [], "warning": "Die Löschfunktion ist nicht aktiviert."}

    operator_sam = user["username"].lower().split("\\")[-1].split("@")[0]

    def build(row, ou):
        sam = row.text("sAMAccountName")
        return {
            "dn": row.dn,
            "name": row_display_name(row),
            "sam": sam,
            "mail": row.text("mail"),
            "disabled": bool(row_uac(row) & 2),
            "self": sam.lower() == operator_sam,
            "_adminCount": row.text("adminCount") == "1",
        }

    with ad_session(user) as conn:
        users = collect_users(
            conn,
            [cfg["disabledOu"]],
            ["sAMAccountName", "displayName", "cn", "userAccountControl", "mail", "adminCount"],
            build,
        )
        mark_protected(conn, users)
    return {"status": "success", "users": users}


# ---------------------------------------------------------------------------
# Verbindungstest
# ---------------------------------------------------------------------------
def probe_root(backend, kind, root, server_errors):
    row = {"kind": kind, "label": LOCATION_LABELS[kind], "root": root, "ok": False, "message": "", "entries": 0}
    server = parse_unc(root)[0].lower()
    if server in server_errors:
        row["message"] = server_errors[server]
        return row
    try:
        st = backend.stat(root)
        if not st.is_dir:
            row["message"] = "Der Pfad ist kein Ordner."
            return row
        row["entries"] = len(backend.listdir(root))
        row["ok"] = True
        row["message"] = "Erreichbar, Inhalt lesbar."
    except FsError as e:
        if e.kind in ("auth", "unreachable"):
            server_errors[server] = e.message
        row["message"] = {"notfound": "Pfad nicht gefunden."}.get(e.kind, e.message)
    return row


@router.post("/api/deletion/test")
def test_deletion_paths(user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    roots = [(kind, root) for kind in KINDS for root in cfg[kind]["roots"]]
    if not roots:
        raise HTTPException(status_code=400, detail="Es sind keine Basispfade konfiguriert.")
    backend = make_backend(user)
    server_errors = {}
    try:
        results = [probe_root(backend, kind, root, server_errors) for kind, root in roots]
    finally:
        backend.close()
    audit(actor_name(user), "deletion-test", ok=all(r["ok"] for r in results), roots=len(results))
    return {"status": "success", "results": results}


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
def _path_key(path, strip_suffix=False):
    """Vergleichsschluessel eines UNC-Pfads: Server ohne Domaene (fs = fs.firma.local), alles klein, optional ohne
    Profil-Endung (profilePath steht im AD ohne .V6)."""
    server, share, parts = parse_unc(path)
    parts = [p.lower() for p in parts]
    if strip_suffix and parts and "." in parts[-1]:
        parts[-1] = parts[-1].rsplit(".", 1)[0]
    return (server.lower().split(".")[0], share.lower(), tuple(parts))


def _others_using(conn, search_base, attr, target_path, own_dn, kind):
    """Andere Konten, deren AD-Attribut (homeDirectory/profilePath) auf diesen Ordner zeigt - gleich, ob der Ordner
    aus dem AD-Attribut oder aus dem Basispfad stammt. Verglichen wird tolerant (Gross-/Kleinschreibung, Server mit
    oder ohne Domaene, abschliessender Backslash, Profil-Endung)."""
    profile = kind == "profile"
    want = {_path_key(target_path), _path_key(target_path, strip_suffix=profile)}
    # Liegt der Ordner IM Ordner eines anderen Kontos (z. B. \\fs\home$\chef\mueller), gehoert er nicht allein
    # diesem Konto - auch dann nicht loeschen
    server, share, parts = parse_unc(target_path)
    ancestors = {_path_key(canonical(server, share, parts[:i])) for i in range(1, len(parts))}
    last = parts[-1]
    names = {last, *parts[:-1]}
    if profile and "." in last:
        names.add(last.rsplit(".", 1)[0])
    clauses = "".join(
        f"({attr}=*{ldap_escape(chr(92) + n)})({attr}=*{ldap_escape(chr(92) + n + chr(92))})" for n in names
    )
    rows = ldap_search(conn, search_base, f"(&{USER_FILTER}(|{clauses}))", ["sAMAccountName", attr])
    others = []
    for r in rows:
        if r.dn.lower() == own_dn.lower():
            continue
        try:
            other = normalize_unc(expand_username(r.text(attr), r.text("sAMAccountName")))
        except ValueError:
            continue
        if {_path_key(other), _path_key(other, strip_suffix=profile)} & (want | ancestors):
            others.append(r.text("sAMAccountName"))
    return sorted(others)


def plan_targets(conn, cfg, entry, sam, search_base):
    """Alle moeglichen Ordner des Kontos; Ordner, die auch anderen Konten gehoeren, werden ausgeschlossen."""
    targets = []
    for kind in KINDS:
        attr = ATTR_OF_KIND.get(kind)
        raw = entry.text(attr) if attr else ""
        for target in build_targets(kind, cfg[kind], sam, raw):
            if attr and target["path"] and not target["skip"]:
                others = _others_using(conn, search_base, attr, target["path"], entry.dn, kind)
                if others:
                    shown = ", ".join(others[:5]) + (" …" if len(others) > 5 else "")
                    target["skip"] = f"Wird auch von anderen Konten verwendet ({shown}) - würde deren Daten löschen."
            targets.append(target)
    return targets


MAX_OWNERSHIP_CHECKS = 50


def inspect_target(backend, target, server_errors, takeover=False):
    """Prueft einen Ordner lesend. status: found, takeover, missing, denied, error, skipped.

    takeover=True: fehlende Rechte gelten nicht als Hindernis, wenn der Besitz uebernommen werden koennte
    (status 'takeover' bzw. takeoverNeeded > 0). Es wird dabei nichts veraendert.
    """
    res = dict(
        target,
        status="skipped",
        message=target["skip"],
        files=0,
        dirs=0,
        size=0,
        truncated=False,
        warnings=[],
        deletable=False,
        links=0,
        takeoverNeeded=0,
    )
    if target["skip"]:
        return res
    server = parse_unc(target["path"])[0].lower()
    if server in server_errors:
        res.update(status="error", message=server_errors[server])
        return res
    try:
        st = backend.stat(target["path"])
    except FsError as e:
        if e.kind == "notfound":
            res.update(status="missing", message="Nicht vorhanden.")
        elif e.kind == "denied":
            if takeover and backend.can_take_ownership(target["path"], True):
                res.update(
                    status="takeover",
                    message="Kein Zugriff - der Besitz würde übernommen. Inhalt vorab nicht zählbar.",
                    takeoverNeeded=1,
                    deletable=True,
                )
            else:
                res.update(
                    status="denied", message="Kein Zugriff (Berechtigung für den angemeldeten Administrator fehlt)."
                )
        else:
            if e.kind in ("auth", "unreachable"):
                server_errors[server] = e.message
            res.update(status="error", message=e.message)
        return res
    if not st.is_dir:
        res.update(message="Ist kein Ordner - wird übersprungen.")
        return res
    if st.reparse:
        res.update(message="Ist eine Verknüpfung (Junction/Symlink) - wird nicht verfolgt und übersprungen.")
        return res

    scan = scan_tree(backend, target["path"])
    res.update(
        status="found", message="Vorhanden.", files=scan.files, dirs=scan.dirs, size=scan.size, truncated=scan.truncated
    )
    if scan.truncated:
        res["warnings"].append("Der Scan wurde wegen der Größe abgebrochen - die Zahlen sind Mindestwerte.")
    res["links"] = scan.reparse
    if scan.reparse:
        res["warnings"].append(
            f"{scan.reparse} Verknüpfung(en) enthalten - nur die Verknüpfung selbst wird entfernt, "
            "das Ziel bleibt unberührt."
        )
    blocked = list(scan.denied)
    if scan.denied and takeover:
        checked = scan.denied[:MAX_OWNERSHIP_CHECKS]
        blocked = [p for p in checked if not backend.can_take_ownership(p, True)] + scan.denied[MAX_OWNERSHIP_CHECKS:]
        res["takeoverNeeded"] = len(scan.denied) - len(blocked)
        if res["takeoverNeeded"]:
            res["warnings"].append(
                f"{res['takeoverNeeded']} Unterordner ohne Zugriff - der Besitz würde übernommen. "
                "Deren Inhalt ist in den Zahlen nicht enthalten."
            )
    if blocked:
        res["warnings"].append(f"{len(blocked)} Unterordner ohne Zugriff - Löschen wäre unvollständig.")
    if scan.errors:
        res["warnings"].append(f"{len(scan.errors)} Unterordner mit Fehler, z. B. {scan.errors[0]}")
    res["deletable"] = not blocked and not scan.errors
    return res


def _missing_warnings(cfg, results, sam):
    out = []
    for kind in KINDS:
        if cfg[kind]["enabled"] and not any(r["kind"] == kind and r["status"] == "found" for r in results):
            expected = f"{sam}." + "/".join(cfg[kind].get("suffixes", [])) if kind == "profile" else sam
            out.append(f"{LOCATION_LABELS[kind]}: kein Ordner gefunden (erwartet: {expected}).")
    return out


# ---------------------------------------------------------------------------
# Plaene (Simulation -> Loeschen): kurz gueltig, an Sitzung und Konto gebunden, einmal verwendbar
# ---------------------------------------------------------------------------
PLAN_TTL_SECONDS = 600
_plans = {}
_plans_lock = threading.Lock()
_running = set()
_running_lock = threading.Lock()


def store_plan(user, user_dn, sam, paths):
    token = secrets.token_urlsafe(24)
    expires = time.time() + PLAN_TTL_SECONDS
    with _plans_lock:
        for key in [k for k, v in _plans.items() if v["expires"] <= time.time()]:
            del _plans[key]
        for key in [k for k, v in _plans.items() if v["sid"] == user.get("sid") and v["dn"].lower() == user_dn.lower()]:
            del _plans[key]  # je Sitzung und Konto gilt nur der neueste Plan
        _plans[token] = {
            "sid": user.get("sid"),
            "dn": user_dn,
            "sam": sam,
            "paths": list(paths),
            "expires": expires,
        }
    return token, expires


def _prune_plans():
    """Abgelaufene Plaene entfernen (sonst blieben sie bis zur naechsten Simulation im Speicher)."""
    now = time.time()
    for store in (_plans, _batch_plans):
        for key in [k for k, v in store.items() if v["expires"] <= now]:
            del store[key]


def get_plan(user, token, user_dn):
    with _plans_lock:
        _prune_plans()
        plan = _plans.get(token)
    if (
        not plan
        or plan["expires"] <= time.time()
        or plan["sid"] != user.get("sid")
        or plan["dn"].lower() != user_dn.lower()
    ):
        raise HTTPException(
            status_code=400, detail="Der Plan ist abgelaufen oder ungültig - bitte die Simulation wiederholen."
        )
    return plan


def drop_plan(token):
    with _plans_lock:
        _plans.pop(token, None)


def consume_plan(token, store=None):
    """Plan verbrauchen (unter der Sperre). Wer zweit kommt - z. B. eine doppelt abgeschickte Anfrage - bekommt
    einen Fehler statt eines zweiten Loeschlaufs mit demselben Plan."""
    with _plans_lock:
        plan = (store if store is not None else _plans).pop(token, None)
    if plan is None:
        raise HTTPException(
            status_code=409, detail="Dieser Plan wurde bereits verwendet - bitte die Simulation wiederholen."
        )
    return plan


BATCH_MAX = 25
_batch_plans = {}
JOB_KEEP_SECONDS = 3600
_jobs = {}
_jobs_lock = threading.Lock()


def store_batch_plan(user, items):
    token = secrets.token_urlsafe(24)
    expires = time.time() + PLAN_TTL_SECONDS
    with _plans_lock:
        for key in [k for k, v in _batch_plans.items() if v["expires"] <= time.time() or v["sid"] == user.get("sid")]:
            del _batch_plans[key]  # je Sitzung gilt nur der neueste Sammelplan
        _batch_plans[token] = {"sid": user.get("sid"), "items": list(items), "expires": expires}
    return token, expires


def take_batch_plan(user, token):
    """Liefert den Sammelplan, ohne ihn zu verbrauchen."""
    with _plans_lock:
        plan = _batch_plans.get(token)
    if not plan or plan["expires"] <= time.time() or plan["sid"] != user.get("sid"):
        raise HTTPException(
            status_code=400, detail="Der Plan ist abgelaufen oder ungültig - bitte die Simulation wiederholen."
        )
    return plan


def drop_batch_plan(token):
    with _plans_lock:
        _batch_plans.pop(token, None)


# ---------------------------------------------------------------------------
# Passwortbestaetigung: der angemeldete Administrator muss sein Passwort erneut eingeben
# ---------------------------------------------------------------------------
PW_MAX_FAILS = 5
PW_LOCK_SECONDS = 300
_pw_failures = {}
_pw_lock = threading.Lock()


def verify_admin_password(user, password, action="deletion"):
    """Prueft das Passwort gegen das der Sitzung und danach live die Rolle im AD. Nach zu vielen Fehlversuchen kurze
    Sperre (je Sitzung). `action` benennt die Berichtseintraege (z. B. deletion, reports-delete)."""
    sid = user.get("sid")
    now = time.time()
    with _pw_lock:
        for key in [k for k, v in _pw_failures.items() if not v or now - v[-1] >= PW_LOCK_SECONDS]:
            del _pw_failures[key]  # alte Fehlversuche nicht ewig im Speicher halten
        recent = [t for t in _pw_failures.get(sid, []) if now - t < PW_LOCK_SECONDS]
        if len(recent) >= PW_MAX_FAILS:
            raise HTTPException(
                status_code=429,
                detail="Zu viele falsche Passwörter. Diese Aktion ist für diese Sitzung kurz gesperrt (ca. 5 Minuten).",
            )
    if not password:
        raise HTTPException(status_code=400, detail="Bitte das Passwort zur Bestätigung eingeben.")
    expected = str(user.get("password") or "").encode("utf-8")
    if not expected or not hmac.compare_digest(str(password).encode("utf-8"), expected):
        with _pw_lock:
            _pw_failures[sid] = recent + [now]
        audit(actor_name(user), f"{action}-password-fail")
        raise HTTPException(status_code=403, detail="Das Passwort ist falsch.")
    with _pw_lock:
        _pw_failures.pop(sid, None)
    recheck_admin(user, action)


def recheck_admin(user, action="deletion"):
    """Vor endgueltigem Loeschen: Ist die Person laut AD (jetzt, nicht beim Anmelden) noch Administrator und gilt
    ihr Passwort noch? Sonst koennte jemand, der inzwischen aus den Domaenen-Admins entfernt wurde, weiter loeschen."""
    search_base = base_dn(load_json(CONFIG_FILE, default_config)["domain"])
    try:
        with ad_session(user) as conn:  # wirft 401, wenn das Passwort nicht mehr gilt
            role = check_user_role(
                conn, search_base, user.get("username", ""), user.get("bind_user", ""), raise_errors=True
            )[0]
    except RoleCheckError:
        raise HTTPException(
            status_code=503,
            detail="Die Rolle konnte gerade nicht im Active Directory geprüft werden. Bitte erneut versuchen.",
        ) from None
    if role != "Administrator":
        audit(actor_name(user), f"{action}-role-lost", ok=False)
        raise HTTPException(status_code=403, detail="Sie sind laut Active Directory kein Administrator mehr.")


# ---------------------------------------------------------------------------
# Gemeinsame Vorpruefung
# ---------------------------------------------------------------------------
def load_account_and_targets(user, cfg, user_dn):
    """Prueft das Konto (OU, deaktiviert, nicht man selbst) und liefert (Eintrag, sAMAccountName, Zielordner)."""
    search_base = base_dn(load_json(CONFIG_FILE, default_config)["domain"])
    with ad_session(user) as conn:
        entry = resolve_account(
            conn,
            user_dn,
            [cfg["disabledOu"]],
            "das Löschen",
            [
                "sAMAccountName",
                "displayName",
                "cn",
                "mail",
                "userAccountControl",
                "memberOf",
                "homeDirectory",
                "profilePath",
            ],
        )
        user_dn = entry.dn  # nur der DN, den der DC geliefert hat
        sam = entry.text("sAMAccountName")
        operator_sam = user["username"].lower().split("\\")[-1].split("@")[0]
        if sam.lower() == operator_sam:
            raise HTTPException(
                status_code=400, detail="Sicherheitsfehler: Das eigene Konto kann nicht gelöscht werden!"
            )
        reason = privileged_reason(conn, user_dn)
        if reason:
            raise HTTPException(status_code=403, detail=protected_message(reason, "gelöscht"))
        if not row_uac(entry) & 2:
            raise HTTPException(
                status_code=400, detail="Das Konto ist nicht deaktiviert - bitte zuerst das Offboarding durchführen."
            )
        return entry, sam, plan_targets(conn, cfg, entry, sam, search_base)


FOUND = ("found", "takeover")


def _takeover(cfg, target):
    """Ist fuer diesen Speicherort die Besitzuebernahme erlaubt?"""
    return bool(cfg[target["kind"]].get("takeOwnership"))


def _blockers(results):
    """Gruende, warum nicht gelöscht werden darf (Zustand nicht eindeutig oder nicht vollstaendig loeschbar)."""
    out = []
    for r in results:
        if r["status"] in ("denied", "error"):
            out.append(f"{r['label']} {r['path']}: {r['message']}")
        elif r["status"] in FOUND and not r["deletable"]:
            out.append(f"{r['label']} {r['path']}: nicht vollständig löschbar ({'; '.join(r['warnings'])})")
    return out


def inspect_account(user, cfg, user_dn, backend, server_errors):
    """Liest Konto und Zielordner (nur lesend). Liefert ein Dict mit Konto, Ergebnissen und Hindernissen."""
    entry, sam, targets = load_account_and_targets(user, cfg, user_dn)
    results = [inspect_target(backend, t, server_errors, _takeover(cfg, t)) for t in targets]
    found = [r for r in results if r["status"] in FOUND]
    return {"entry": entry, "sam": sam, "results": results, "found": found, "blockers": _blockers(results)}


def simulation_payload(cfg, info):
    """Darstellbare Daten einer Simulation (ohne Plan)."""
    entry, sam, results, found = info["entry"], info["sam"], info["results"], info["found"]
    return {
        "account": {
            "dn": entry.dn,
            "name": row_display_name(entry),
            "sam": sam,
            "mail": entry.text("mail"),
            "groups": sorted(rdn_label(g) for g in entry.list("memberOf")),
            "profilePath": entry.text("profilePath"),
            "homeDirectory": entry.text("homeDirectory"),
        },
        "targets": results,
        "summary": {
            "folders": len(found),
            "files": sum(r["files"] for r in found),
            "size": sum(r["size"] for r in found),
            "allDeletable": all(r["deletable"] for r in found),
            "takeovers": sum(r["takeoverNeeded"] for r in found),
            "links": sum(r["links"] for r in found),
        },
        "warnings": _missing_warnings(cfg, results, sam),
        "blockers": info["blockers"],
    }


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


@router.post("/api/deletion/simulate")
def simulate_deletion(data: DeletionSimulateModel, user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    _require_enabled(cfg)

    with audited(user, "deletion-simulate", data.userDn) as info_log:
        backend = backend_for(user, cfg)
        try:
            info = inspect_account(user, cfg, data.userDn, backend, {})
        finally:
            backend.close()
        info_log["sam"] = info["sam"]
        found = info["found"]
        plan_id, expires = (None, None)
        if not info["blockers"]:
            plan_id, expires = store_plan(user, info["entry"].dn, info["sam"], [r["path"] for r in found])
        info_log.update(found=len(found), files=sum(r["files"] for r in found), size=sum(r["size"] for r in found))

    return {
        "status": "success",
        "simulatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **simulation_payload(cfg, info),
        "planId": plan_id,
        "planExpiresAt": _iso(expires),
    }


@router.post("/api/deletion/simulate-batch")
def simulate_deletion_batch(data: DeletionBatchSimulateModel, user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    _require_enabled(cfg)
    dns, seen = [], set()
    for dn in data.userDns:
        if dn and dn.lower() not in seen:
            seen.add(dn.lower())
            dns.append(dn)
    if not dns:
        raise HTTPException(status_code=400, detail="Bitte mindestens ein Konto auswählen.")
    if len(dns) > BATCH_MAX:
        raise HTTPException(status_code=400, detail=f"Pro Durchlauf sind höchstens {BATCH_MAX} Konten erlaubt.")

    with audited(user, "deletion-simulate-batch", f"{len(dns)} Konten") as info_log:
        items, ready = [], []
        backend = backend_for(user, cfg)
        server_errors = {}
        try:
            for dn in dns:
                item = {"dn": dn, "state": "blocked", "error": ""}
                try:
                    info = inspect_account(user, cfg, dn, backend, server_errors)
                except HTTPException as e:
                    item["error"] = str(e.detail)
                except AdError as e:
                    item["error"] = str(e.detail)
                else:
                    item.update(simulation_payload(cfg, info))
                    item["name"], item["sam"] = item["account"]["name"], info["sam"]
                    if info["blockers"]:
                        item["error"] = "Nicht löschbar, siehe Hindernisse."
                    else:
                        item["state"] = "ready"
                        ready.append(
                            {
                                "dn": info["entry"].dn,
                                "sam": info["sam"],
                                "name": item["name"],
                                "paths": [r["path"] for r in info["found"]],
                            }
                        )
                items.append(item)
        finally:
            backend.close()
        plan_id, expires = (None, None)
        if ready:
            plan_id, expires = store_batch_plan(user, ready)
        info_log.update(requested=len(dns), ready=len(ready), blocked=len(dns) - len(ready))

    return {
        "status": "success",
        "simulatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "items": items,
        "readyCount": len(ready),
        "max": BATCH_MAX,
        "planId": plan_id,
        "planExpiresAt": _iso(expires),
    }


# ---------------------------------------------------------------------------
# Loeschen
# ---------------------------------------------------------------------------
def _verify_unchanged(cfg, plan, fresh):
    """Vergleicht den aktuellen Zustand mit dem simulierten Plan. Liefert Abweichungen (leer = unveraendert)."""
    problems = []
    planned = {p.lower() for p in plan["paths"]}
    seen = set()
    for r in fresh:
        key = r["path"].lower()
        seen.add(key)
        if key in planned:
            if r["status"] in ("denied", "error") or (r["status"] in FOUND and not r["deletable"]):
                problems.append(f"{r['path']}: {r['message']}")
            elif r["status"] not in (*FOUND, "missing"):
                problems.append(f"{r['path']}: {r['message'] or r['status']}")
            elif not any(is_strictly_below(r["path"], root) for root in cfg[r["kind"]]["roots"]):
                problems.append(f"{r['path']}: liegt nicht mehr unter einem freigegebenen Basispfad")
        elif r["status"] in FOUND:
            problems.append(f"{r['path']}: neu hinzugekommen")
    problems.extend(f"{p}: nicht mehr Teil des Ergebnisses" for p in plan["paths"] if p.lower() not in seen)
    return problems


def _notify_enabled(user):
    smtp_cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    return bool(smtp_cfg.get("notifyDeletion", False) and user.get("email"))


def _queue_mail(background, user, name, sam, results, account_deleted, ad_error=None):
    """Legt (falls aktiviert) die Benachrichtigung an den angemeldeten Administrator in die Warteschlange."""
    if not _notify_enabled(user):
        return
    failed = [r for r in results if r["status"] == "failed"]
    if account_deleted:
        title, accent = "Konto gelöscht", "#e11d48"
        outcome = "Konto und Ordner wurden gelöscht." if results else "Das AD-Konto wurde gelöscht (keine Ordner)."
        intro = f"Das Konto von {name} ({sam}) wurde endgültig gelöscht."
    else:
        title, accent = "Löschen unvollständig", "#d97706"
        outcome = (
            "Ordner gelöscht, AD-Konto konnte nicht gelöscht werden."
            if ad_error
            else "Nicht alle Ordner konnten gelöscht werden - das AD-Konto besteht weiter."
        )
        intro = f"Das Löschen des Kontos von {name} ({sam}) wurde nicht vollständig durchgeführt."
    folders = [f"{r['label']}: {r['path']}" for r in results if r["status"] in ("deleted", "failed")]
    rows = [
        ("Mitarbeiter:", f"{name} ({sam})", "bold"),
        ("Ergebnis:", outcome, "bad" if not account_deleted else "good"),
        ("Ordner:", "; ".join(folders) if folders else "Keine vorhanden", "mono"),
        ("Dateien gelöscht:", sum(r["files"] for r in results), "mono"),
        ("Besitzübernahmen:", sum(r["takeovers"] for r in results), "mono"),
    ]
    if failed:
        rows.append(("Fehlerhafte Ordner:", "; ".join(r["path"] for r in failed), "bad"))
    if ad_error:
        rows.append(("AD-Fehler:", str(ad_error), "bad"))
    body_text, body_html = render_mail(user["username"], title, accent, intro, rows)
    args = (user["email"], f"SAMONBOARDING - {title}: {name} ({sam})", body_text, body_html)
    if ad_error:
        # Danach folgt eine Fehlermeldung (AdError) - Hintergrundaufgaben der Antwort liefen dann nie. Gerade diese
        # Mail (Ordner weg, Konto noch da) muss ankommen: eigener Thread, mit der Sprache der Anfrage.
        ctx = contextvars.copy_context()
        threading.Thread(target=ctx.run, args=(send_notification_email, *args), daemon=True).start()
    else:
        background.add_task(send_notification_email, *args)


def _forget_offboarding(sam, dn):
    """Ein geloeschtes Konto kann nicht mehr wiederhergestellt werden: gespeicherten Offboarding-Zustand entfernen."""
    try:
        offboard_store.forget_account(sam=sam, dn=dn)
    except Exception as e:
        log.warning("Offboarding-Eintrag fuer %s nicht entfernt: %s", sam, e)


TREE_DELETE_OID = "1.2.840.113556.1.4.805"


def run_deletion(user, cfg, plan, mail=None, on_locked=None):
    """Loescht ein Konto samt Ordnern gemaess Plan (Neupruefung, erst Ordner, dann AD-Konto, Audit).

    Liefert das Ergebnis (status success/partial). Fehler als HTTPException/AdError. mail(name, sam, results,
    account_deleted, ad_error) wird bei Erfolg und bei teilweisem Ergebnis aufgerufen. on_locked() laeuft, sobald
    die Sperre fuer das Konto gehalten wird (der Aufrufer verbraucht dort den Plan).
    """
    lock_key = plan["dn"].lower()
    with _running_lock:
        if lock_key in _running:
            raise HTTPException(status_code=409, detail="Für dieses Konto läuft bereits ein Löschvorgang.")
        _running.add(lock_key)
    if on_locked:
        on_locked()

    details = {"sam": plan["sam"]}
    ok = False
    try:
        entry, sam, targets = load_account_and_targets(user, cfg, plan["dn"])
        if sam.lower() != plan["sam"].lower():
            raise HTTPException(status_code=409, detail="Das Konto hat sich seit der Simulation geändert.")
        name = row_display_name(entry)

        backend = backend_for(user, cfg)
        try:
            server_errors = {}
            fresh = [inspect_target(backend, t, server_errors, _takeover(cfg, t)) for t in targets]
            problems = _verify_unchanged(cfg, plan, fresh)
            if problems:
                details["error"] = "Zustand hat sich geändert"
                details["problems"] = problems[:10]
                raise HTTPException(
                    status_code=409,
                    detail="Seit der Simulation hat sich etwas geändert, es wurde nichts gelöscht. "
                    "Bitte die Simulation wiederholen. Abweichungen: " + " | ".join(problems[:5]),
                )

            planned = {p.lower() for p in plan["paths"]}
            results = []
            for r in fresh:
                if r["path"].lower() not in planned:
                    continue
                row = {
                    "kind": r["kind"],
                    "label": r["label"],
                    "path": r["path"],
                    "files": 0,
                    "dirs": 0,
                    "links": 0,
                    "takeovers": 0,
                    "takeoverPaths": [],
                    "errors": [],
                    "errorCount": 0,
                }
                if r["status"] == "missing":
                    row["status"] = "missing"
                else:
                    outcome = delete_tree(backend, r["path"], takeover=_takeover(cfg, r))
                    row.update(
                        files=outcome.files,
                        dirs=outcome.dirs,
                        links=outcome.links,
                        takeovers=outcome.takeover_count,
                        takeoverPaths=outcome.takeovers,
                        errors=outcome.errors,
                        errorCount=outcome.error_count,
                    )
                    row["status"] = "failed" if outcome.error_count else "deleted"
                results.append(row)
        finally:
            backend.close()

        failed = [r for r in results if r["status"] == "failed"]
        details["folders"] = [
            {
                "path": r["path"],
                "status": r["status"],
                "files": r["files"],
                "dirs": r["dirs"],
                "links": r["links"],
                "takeovers": r["takeovers"],
                "takeoverPaths": r["takeoverPaths"][:5],
                "errors": r["errorCount"],
            }
            for r in results
        ]
        if failed:
            details["error"] = f"{len(failed)} Ordner nicht vollständig gelöscht - AD-Konto bleibt bestehen"
            if mail:
                mail(name, sam, results, False, None)
            return {
                "status": "partial",
                "accountDeleted": False,
                "name": name,
                "sam": sam,
                "results": results,
                "message": "Nicht alle Ordner konnten gelöscht werden. Das AD-Konto wurde NICHT gelöscht. "
                "Ursachen beheben und die Simulation wiederholen.",
            }

        with ad_session(user) as conn:
            try:
                deleted = conn.delete(entry.dn)
                if not deleted and (conn.result or {}).get("result") == 66:
                    # notAllowedOnNonLeaf: das Konto hat Unterobjekte (z. B. ActiveSync-Geraete von Exchange) -
                    # mit dem Tree-Delete-Control werden sie zusammen mit dem Konto entfernt
                    deleted = conn.delete(entry.dn, controls=[(TREE_DELETE_OID, True, None)])
                ensure(conn, deleted, "AD-Konto löschen")
            except HTTPException as e:
                details["error"] = f"Ordner gelöscht, aber AD-Konto nicht: {e.detail}"
                if mail:
                    mail(name, sam, results, False, e.detail)
                raise AdError(f"Die Ordner wurden gelöscht, das AD-Konto aber nicht: {e.detail}") from e
        ok = True
        _forget_offboarding(sam, entry.dn)
        if mail:
            mail(name, sam, results, True, None)
        return {
            "status": "success",
            "accountDeleted": True,
            "name": name,
            "sam": sam,
            "results": results,
            "message": f"Konto {sam} und {len(results)} Ordner wurden gelöscht."
            if results
            else f"Konto {sam} wurde gelöscht.",
        }
    except HTTPException as e:
        details.setdefault("error", str(e.detail))
        raise
    except Exception as e:
        details.setdefault("error", str(e))
        raise
    finally:
        with _running_lock:
            _running.discard(lock_key)
        audit(actor_name(user), "deletion-execute", plan["dn"], ok=ok, **details)


@router.post("/api/deletion/execute")
def execute_deletion(data: DeletionExecuteModel, background: BackgroundTasks, user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    _require_enabled(cfg)
    plan = get_plan(user, data.planId, data.userDn)
    if data.confirmSam.strip().lower() != plan["sam"].lower():
        raise HTTPException(status_code=400, detail="Die Bestätigung stimmt nicht mit dem Benutzernamen überein.")
    verify_admin_password(user, data.password)  # erst danach wird der einmalige Plan verbraucht
    consume_plan(data.planId)

    def mail(name, sam, results, account_deleted, ad_error):
        _queue_mail(background, user, name, sam, results, account_deleted, ad_error)

    # Plan ist einmalig - bei jedem Ausgang ist eine neue Simulation noetig
    return run_deletion(user, cfg, plan, mail, on_locked=lambda: drop_plan(data.planId))


# ---------------------------------------------------------------------------
# Sammel-Loeschen als Hintergrundauftrag
# ---------------------------------------------------------------------------
def _batch_mail(user, job):
    """Eine Zusammenfassung je Durchlauf statt einer Mail pro Konto."""
    items = job["items"]
    deleted = [i for i in items if i["status"] == "success"]
    problem = [i for i in items if i["status"] != "success"]
    title = "Sammellöschung abgeschlossen" if not problem else "Sammellöschung mit Problemen"
    intro = f"{len(deleted)} von {len(items)} Konten wurden gelöscht."
    rows = [("Gelöscht:", f"{len(deleted)} von {len(items)}", "good" if not problem else "bold")]
    for i in items:
        folders = sum(1 for r in i.get("results", []) if r["status"] in ("deleted", "failed"))
        files = sum(r["files"] for r in i.get("results", []))
        if i["status"] == "success":
            text, style = f"gelöscht ({folders} Ordner, {files} Dateien)", "good"
        elif i["status"] == "partial":
            text, style = "Ordner unvollständig gelöscht, Konto besteht weiter", "bad"
        else:
            text, style = f"nicht gelöscht: {i['message']}", "bad"
        rows.append((f"{i['sam']}:", text, style))
    body_text, body_html = render_mail(user["username"], title, "#e11d48" if not problem else "#d97706", intro, rows)
    return f"SAMONBOARDING - {title} ({len(deleted)}/{len(items)})", body_text, body_html


def run_batch_job(job_id, user, cfg, items):
    """Arbeitet die Konten nacheinander ab. Jedes Konto durchlaeuft denselben Ablauf wie das Einzellöschen."""
    job = _jobs[job_id]
    try:
        for index, plan in enumerate(items):
            entry = job["items"][index]
            entry["status"] = "running"
            job["current"] = plan["sam"]
            try:
                result = run_deletion(user, cfg, plan)
                entry.update(status=result["status"], message=result["message"], results=result["results"])
            except HTTPException as e:
                entry.update(status="error", message=str(e.detail))
            except AdError as e:
                entry.update(status="error", message=str(e.detail))
            except Exception as e:  # ein Konto darf den Rest nicht verhindern
                log.exception("Sammellöschung: Fehler bei %s", plan["sam"])
                entry.update(status="error", message=f"Unerwarteter Fehler: {e}")
            job["done"] = index + 1
    finally:
        job["current"] = ""
        job["finished"] = True
        job["finishedAt"] = time.time()
        counts = {k: sum(1 for i in job["items"] if i["status"] == k) for k in ("success", "partial", "error")}
        audit(actor_name(user), "deletion-batch", f"{len(items)} Konten", **counts, accounts=[i["sam"] for i in items])
        if _notify_enabled(user):
            subject, text, html = _batch_mail(user, job)
            send_notification_email(user["email"], subject, text, html)


@router.post("/api/deletion/execute-batch")
def execute_deletion_batch(
    data: DeletionBatchExecuteModel, background: BackgroundTasks, user: dict = Depends(get_current_user)
):
    require_admin(user, ADMIN_MSG)
    cfg = load_deletion_config()
    _require_enabled(cfg)
    plan = take_batch_plan(user, data.planId)
    if data.confirmCount != len(plan["items"]):
        raise HTTPException(
            status_code=400,
            detail=f"Die eingegebene Anzahl stimmt nicht. Es würden {len(plan['items'])} Konten gelöscht.",
        )
    verify_admin_password(user, data.password)
    consume_plan(data.planId, _batch_plans)

    job_id = secrets.token_urlsafe(16)
    now = time.time()
    job = {
        "id": job_id,
        "sid": user.get("sid"),
        "total": len(plan["items"]),
        "done": 0,
        "current": "",
        "finished": False,
        "startedAt": now,
        "finishedAt": None,
        "items": [
            {"dn": i["dn"], "sam": i["sam"], "name": i["name"], "status": "pending", "message": "", "results": []}
            for i in plan["items"]
        ],
    }
    with _jobs_lock:
        for key in [k for k, v in _jobs.items() if v["finished"] and now - (v["finishedAt"] or now) > JOB_KEEP_SECONDS]:
            del _jobs[key]
        _jobs[job_id] = job
    background.add_task(run_batch_job, job_id, user, cfg, plan["items"])
    return {"status": "started", "jobId": job_id, "total": job["total"]}


@router.get("/api/deletion/job/{job_id}")
def get_deletion_job(job_id: str, user: dict = Depends(get_current_user)):
    require_admin(user, ADMIN_MSG)
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job or job["sid"] != user.get("sid"):
        raise HTTPException(status_code=404, detail="Auftrag nicht gefunden.")
    return {k: v for k, v in job.items() if k != "sid"}
