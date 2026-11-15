# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Diagnostic package (administrators only): preview and download. Anonymous - see diagnose.py."""

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from .. import diagnose
from ..audit import actor_name, audit
from ..models import DiagnoseModel
from ..permissions import require_admin
from ..sessions import get_current_user

router = APIRouter()


def _admin(user):
    require_admin(user, "Nur Administratoren dürfen ein Diagnosepaket erstellen.")


def _browser(body):
    info = getattr(body, "browser", None)
    return info if isinstance(info, dict) and info else None


# plain functions: FastAPI runs them in a worker thread (the connection test waits for the DC)
@router.post("/api/diagnose/preview")
def diagnose_preview(body: DiagnoseModel, user: dict = Depends(get_current_user)):
    """The package as text and JSON - exactly what the download contains (built afresh)."""
    _admin(user)
    data = diagnose.build(user, _browser(body))
    return {"status": "success", "text": diagnose.render_text(data), "data": data, "fileName": diagnose.file_name(data)}


@router.post("/api/diagnose/download")
def diagnose_download(body: DiagnoseModel, user: dict = Depends(get_current_user)):
    _admin(user)
    data = diagnose.build(user, _browser(body))
    content = diagnose.make_zip(data)
    audit(actor_name(user), "diagnose-package", ok=True, format=diagnose.FORMAT)
    return Response(
        content,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{diagnose.file_name(data)}"'},
    )
