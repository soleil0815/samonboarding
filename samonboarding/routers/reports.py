"""Berichte (nur Administratoren): Aenderungen und Protokoll ansehen und manuell loeschen."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from .. import config, reports
from ..audit import actor_name, audit
from ..models import ReportsDeleteModel
from ..permissions import require_admin
from ..sessions import get_current_user
from .deletion import verify_admin_password

router = APIRouter()

KINDS = {"audit": "audit", "log": "applog"}
LABELS = {"audit": "Änderungen", "log": "Protokoll"}


def _admin(user):
    require_admin(user, "Nur Administratoren dürfen die Berichte sehen.")


@router.get("/api/reports/summary")
def reports_summary(user: dict = Depends(get_current_user)):
    _admin(user)
    c = reports.counts()
    return {
        "status": "success",
        "audit": dict(c["audit"], retentionDays=config.AUDIT_RETENTION_DAYS),
        "log": dict(c["applog"], retentionDays=config.LOG_RETENTION_DAYS),
    }


@router.get("/api/reports/audit")
def reports_audit(
    q: str = "", result: str = "all", before: int = 0, limit: int = 100, user: dict = Depends(get_current_user)
):
    _admin(user)
    entries, nxt = reports.query_audit(q.strip()[:200], result, before or None, limit)
    return {"status": "success", "entries": entries, "nextBefore": nxt}


@router.get("/api/reports/log")
def reports_log(
    q: str = "", level: str = "all", before: int = 0, limit: int = 100, user: dict = Depends(get_current_user)
):
    _admin(user)
    entries, nxt = reports.query_log(q.strip()[:200], level, before or None, limit)
    return {"status": "success", "entries": entries, "nextBefore": nxt}


@router.post("/api/reports/delete")
def reports_delete(data: ReportsDeleteModel, user: dict = Depends(get_current_user)):
    _admin(user)
    if data.kind not in KINDS:
        raise HTTPException(status_code=400, detail="Unbekannte Art von Bericht.")
    if data.olderThanDays < 0 or data.olderThanDays > 36500:
        raise HTTPException(status_code=400, detail="Ungültiger Zeitraum.")
    verify_admin_password(user, data.password, action="reports-delete")
    table = KINDS[data.kind]
    if data.olderThanDays:
        cutoff = datetime.now(timezone.utc) - timedelta(days=data.olderThanDays)
        removed = reports.delete_older_than(table, cutoff.isoformat(timespec="seconds"))
    else:
        removed = reports.delete_all(table)
    # Erst nach dem Loeschen eintragen, damit der Nachweis erhalten bleibt
    audit(
        actor_name(user),
        "reports-delete",
        LABELS[data.kind],
        kind=data.kind,
        olderThanDays=data.olderThanDays or "alle",
        removed=removed,
    )
    return {"status": "success", "removed": removed}
