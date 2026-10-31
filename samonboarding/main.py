# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""SAMONBOARDING - Enterprise Suite: FastAPI-Anwendung zusammenbauen."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from ldap3.core.exceptions import LDAPException
from starlette.middleware.base import BaseHTTPMiddleware

from . import i18n, offboard_store, privacy, reports
from .config import DATA_DIR, HTTPS_PORT, VERSION
from .routers import (
    auth,
    certificate,
    deletion,
    infrastructure,
    manual,
    news,
    offboarding,
    onboarding,
    privacy_info,
    pwdreset,
    restore,
    settings,
    templates,
    ui,
    usermgmt,
)
from .routers import (
    references as references_router,
)
from .routers import (
    reports as reports_router,
)
from .storage import restrict

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def _restrict_data_files():
    """Vorhandene Daten (auch aus aelteren Versionen) nur fuer den Eigentuemer lesbar machen."""
    for path in DATA_DIR.glob("*"):
        if path.is_file() and path.suffix in (".json", ".db", ".log", ".prev", ".pem"):
            restrict(path)
    for path in (DATA_DIR / "tls").glob("*key*"):
        restrict(path)


@asynccontextmanager
async def _lifespan(app):
    """Beim Start: Protokoll in die Datenbank, altes audit.log uebernehmen, Fristen anwenden (taeglich, DSGVO)."""
    reports.install_log_handler()
    _restrict_data_files()
    cert = {"1": "selbstsigniert", "0": "eigenes Zertifikat"}.get(
        os.environ.get("SAMONBOARDING_TLS_SELF_SIGNED", ""), ""
    )
    log.info(
        "SAMONBOARDING %s gestartet - HTTPS auf Port %s%s",
        VERSION,
        HTTPS_PORT,
        f", Zertifikat: {cert}" if cert else "",
    )
    try:
        reports.import_legacy_audit()
    except Exception as e:
        log.error("Altes audit.log konnte nicht uebernommen werden: %s", e)
    try:
        offboard_store.reset_stale_claims()
    except Exception as e:
        log.warning("Wiederherstellungs-Eintraege konnten nicht geprueft werden: %s", e)
    stop = privacy.start_retention_thread()
    try:
        yield
    finally:
        stop.set()
        log.info("SAMONBOARDING wird beendet - alle Sitzungen enden")


# Keine automatische API-Dokumentation (/docs, /redoc, /openapi.json): sie waere ohne Anmeldung erreichbar
app = FastAPI(
    title="SAMONBOARDING - Enterprise Suite",
    lifespan=_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _http_middleware(dispatch):
    """Wie @app.middleware("http"), aber ueber add_middleware - das gibt es in Starlette 0.x und 1.x gleichermassen
    (die Decorator-Form wurde in Starlette 1.0 entfernt). Zuletzt registriert = aeusserste Schicht."""
    app.add_middleware(BaseHTTPMiddleware, dispatch=dispatch)
    return dispatch


# Groesste erlaubte Anfrage (Zertifikats-Upload: bis zu drei Dateien a 1 MB, Base64-kodiert)
MAX_BODY_BYTES = 6 * 1024 * 1024
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def _ldap_exception_handler(request: Request, exc: LDAPException):
    log.error("LDAP-Fehler bei %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "LDAP-Fehler. Details stehen im Protokoll."})


app.add_exception_handler(LDAPException, _ldap_exception_handler)


@_http_middleware
async def _ui_language(request: Request, call_next):
    """Sprache der Oberflaeche (Header X-UI-Lang) fuer diese Anfrage merken - z. B. fuer E-Mails."""
    token = i18n.set_lang(request.headers.get("x-ui-lang", "de"))
    try:
        return await call_next(request)
    finally:
        i18n.reset_lang(token)


CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def _same_origin(request: Request):
    """Schreibende Anfragen nur von der eigenen Seite (zweite Sicherung gegen CSRF neben SameSite=Strict)."""
    origin = request.headers.get("origin") or ""
    if not origin:
        referer = request.headers.get("referer") or ""
        if not referer:
            return True  # z. B. Skripte/Healthcheck ohne Browser - der Browser sendet bei POST immer Origin
        origin = "/".join(referer.split("/")[:3])
    host = (request.headers.get("host") or "").lower()
    return origin.lower() in (f"https://{host}", f"http://{host}")


@_http_middleware
async def _request_guard(request: Request, call_next):
    """Zu grosse Anfragen und schreibende Anfragen von fremden Seiten abweisen."""
    try:
        length = int(request.headers.get("content-length") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Die Anfrage ist zu groß."})
    if request.headers.get("transfer-encoding"):
        # Ohne Laengenangabe liesse sich die Grenze umgehen (der Inhalt wird vor der Pruefung komplett gelesen).
        # Die Oberflaeche sendet immer eine Laenge.
        return JSONResponse(status_code=411, content={"detail": "Die Anfrage braucht eine Längenangabe."})
    # Teil-Downloads (Range) braucht die Oberflaeche nicht. Starlette bis 0.49.0 laesst sich mit praeparierten
    # Range-Angaben bei Dateien (/static) ueberlasten (CVE-2025-62727) - daher wird der Header entfernt.
    if any(k == b"range" for k, _ in request.scope.get("headers", [])):
        request.scope["headers"] = [(k, v) for k, v in request.scope["headers"] if k != b"range"]
    if request.method in UNSAFE_METHODS and not _same_origin(request):
        log.warning("Anfrage von fremder Seite abgewiesen: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=403, content={"detail": "Anfrage von einer fremden Seite abgewiesen."})
    return await call_next(request)


@_http_middleware
async def _https_only(request: Request, call_next):
    """Nur HTTPS. Der Server (python -m samonboarding.serve) hat ohnehin keinen HTTP-Port - das hier ist die
    zweite Sicherung, falls die App doch einmal ohne TLS gestartet wird. ALLOW_HTTP=true nur fuer die Entwicklung."""
    if request.url.scheme != "https" and os.environ.get("ALLOW_HTTP", "").lower() not in ("1", "true", "yes"):
        return JSONResponse(status_code=403, content={"detail": "Nur über HTTPS erreichbar."})
    return await call_next(request)


# Zuletzt registriert = aeusserste Schicht: die Sicherheits-Header stehen auch auf frueh abgewiesenen Antworten
@_http_middleware
async def _security_headers(request: Request, call_next):
    try:
        resp = await call_next(request)
    except Exception:
        # Unerwarteter Fehler: hier beantworten, damit auch diese Antwort die Sicherheits-Header bekommt (sonst
        # antwortet Starlette ausserhalb dieser Schicht). Einzelheiten nur ins Protokoll, nie an den Browser.
        log.exception("Unerwarteter Fehler bei %s %s", request.method, request.url.path)
        resp = JSONResponse(status_code=500, content={"detail": "Interner Fehler. Details stehen im Protokoll."})
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    # Der Browser darf nur vom eigenen Server laden (keine CDNs, keine Google Fonts, kein Tracking)
    resp.headers.setdefault("Content-Security-Policy", CSP)
    if os.environ.get("SAMONBOARDING_TLS_SELF_SIGNED") == "0":
        # Nur mit eigenem (vertrauenswuerdigem) Zertifikat: bei selbstsignierten liesse sich die Warnung sonst nicht
        # mehr wegklicken. Nur fuer einen Tag: wer spaeter zu einem selbstsignierten Zertifikat zurueckwechselt, ist
        # sonst monatelang ausgesperrt (einen HTTP-Port gibt es ohnehin nicht).
        resp.headers.setdefault("Strict-Transport-Security", "max-age=86400")
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    elif request.url.path.startswith("/static/"):
        resp.headers.setdefault("Cache-Control", "public, max-age=86400")
    return resp


for _module in (
    auth,
    settings,
    usermgmt,
    offboarding,
    restore,
    deletion,
    privacy_info,
    reports_router,
    certificate,
    manual,
    news,
    pwdreset,
    infrastructure,
    references_router,
    templates,
    onboarding,
    ui,
):
    app.include_router(_module.router)
ui.mount_static(app)
