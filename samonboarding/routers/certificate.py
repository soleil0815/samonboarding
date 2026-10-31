# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""HTTPS-Zertifikat in der Oberflaeche (nur Administratoren): anzeigen, eigenes hochladen, selbstsigniert erzeugen."""

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException

from .. import config, tls
from ..audit import audited
from ..models import CertSelfSignedModel, CertUploadModel
from ..permissions import require_admin
from ..sessions import get_current_user

router = APIRouter()


def _admin(user):
    require_admin(user, "Nur Administratoren dürfen das Zertifikat verwalten.")


def _decode(value):
    if not value:
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Die Datei konnte nicht übertragen werden.") from None
    if len(data) > tls.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Die Datei ist zu groß (höchstens 1 MB).")
    return data


def _info():
    try:
        info = tls.current_info()
    except Exception:
        raise HTTPException(status_code=500, detail="Das aktuelle Zertifikat ist nicht lesbar.") from None
    info["hostnames"] = config.TLS_HOSTNAMES
    info["warnDays"] = tls.WARN_DAYS
    return info


@router.get("/api/tls/info")
def tls_info(user: dict = Depends(get_current_user)):
    _admin(user)
    return {"status": "success", "certificate": _info()}


@router.post("/api/tls/upload")
def tls_upload(data: CertUploadModel, user: dict = Depends(get_current_user)):
    _admin(user)
    with audited(user, "tls-upload") as info:
        try:
            priv, leaf, chain, warnings = tls.parse_upload(
                pfx=_decode(data.pfx),
                cert=_decode(data.cert),
                key=_decode(data.key),
                chain=_decode(data.chain),
                password=data.password or "",
            )
            live = tls.install(priv, leaf, chain)
        except tls.CertError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Zertifikat konnte nicht gespeichert werden: {e}") from None
        cert = _info()
        info.update(subject=cert["subject"], issuer=cert["issuer"], notAfter=cert["notAfter"], live=live)
    return {"status": "success", "certificate": cert, "warnings": warnings, "live": live}


@router.post("/api/tls/self-signed")
def tls_self_signed(data: CertSelfSignedModel, user: dict = Depends(get_current_user)):
    _admin(user)
    with audited(user, "tls-self-signed") as info:
        try:
            names, live = tls.install_self_signed(data.names)
        except tls.CertError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Zertifikat konnte nicht gespeichert werden: {e}") from None
        info.update(names=names, live=live)
    return {"status": "success", "certificate": _info(), "live": live}
