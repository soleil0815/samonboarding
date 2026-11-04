# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Data protection in the UI: show retention periods (public), data access request under Art. 15 GDPR (admins only)."""

from fastapi import APIRouter, Depends, HTTPException

from .. import config, privacy
from ..audit import actor_name, audit
from ..permissions import require_admin
from ..sessions import get_current_user

router = APIRouter()


@router.get("/api/privacy-info")
def privacy_info():
    """Settings only, no personal data - therefore available before login as well."""
    return {
        "auditDays": config.AUDIT_RETENTION_DAYS,
        "logDays": config.LOG_RETENTION_DAYS,
        "offboardDays": config.OFFBOARD_RETENTION_DAYS,
        "sessionIdleMinutes": config.SESSION_IDLE_SECONDS // 60,
    }


@router.get("/api/privacy/report")
def privacy_report(sam: str = "", user: dict = Depends(get_current_user)):
    require_admin(user, "Nur Administratoren dürfen eine Datenschutz-Auskunft erstellen.")
    sam = sam.strip()
    if not sam or len(sam) > 256:
        raise HTTPException(status_code=400, detail="Bitte einen Benutzernamen (sAMAccountName) angeben.")
    report = privacy.subject_report(sam)
    audit(
        actor_name(user),
        "privacy-report",
        sam,
        auditEntries=len(report["auditEntries"]),
        logEntries=len(report["logEntries"]),
        records=len(report["offboardingRecords"]),
    )
    return report
