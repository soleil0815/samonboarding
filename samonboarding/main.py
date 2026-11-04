# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""SAMONBOARDING - Enterprise Suite: assemble the FastAPI application."""

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
    """Make existing data (including from older versions) readable only by the owner."""
    for path in DATA_DIR.glob("*"):
        if path.is_file() and path.suffix in (".json", ".db", ".log", ".prev", ".pem"):
            restrict(path)
    for path in (DATA_DIR / "tls").glob("*key*"):
        restrict(path)


@asynccontextmanager
async def _lifespan(app):
    """At startup: log to the database, import the old audit.log, apply retention periods (daily, GDPR)."""
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


# No automatic API documentation (/docs, /redoc, /openapi.json): it would be reachable without login
app = FastAPI(
    title="SAMONBOARDING - Enterprise Suite",
    lifespan=_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _http_middleware(dispatch):
    """Like @app.middleware("http"), but via add_middleware - which exists in both Starlette 0.x and 1.x
    (the decorator form was removed in Starlette 1.0). Registered last = outermost layer."""
    app.add_middleware(BaseHTTPMiddleware, dispatch=dispatch)
    return dispatch


# Largest allowed request (certificate upload: up to three files of 1 MB each, Base64-encoded)
MAX_BODY_BYTES = 6 * 1024 * 1024
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def _ldap_exception_handler(request: Request, exc: Exception):  # registered only for LDAPException
    log.error("LDAP-Fehler bei %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "LDAP-Fehler. Details stehen im Protokoll."})


app.add_exception_handler(LDAPException, _ldap_exception_handler)


@_http_middleware
async def _ui_language(request: Request, call_next):
    """Remember the UI language (header X-UI-Lang) for this request - e.g. for emails."""
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
    """Allow write requests only from our own site (second safeguard against CSRF besides SameSite=Strict)."""
    origin = request.headers.get("origin") or ""
    if not origin:
        referer = request.headers.get("referer") or ""
        if not referer:
            return True  # e.g. scripts/healthcheck without a browser - browsers always send Origin on POST
        origin = "/".join(referer.split("/")[:3])
    host = (request.headers.get("host") or "").lower()
    return origin.lower() in (f"https://{host}", f"http://{host}")


@_http_middleware
async def _request_guard(request: Request, call_next):
    """Reject oversized requests and write requests from foreign sites."""
    try:
        length = int(request.headers.get("content-length") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Die Anfrage ist zu groß."})
    if request.headers.get("transfer-encoding"):
        # Without a length the limit could be bypassed (the body is read completely before the check).
        # The UI always sends a length.
        return JSONResponse(status_code=411, content={"detail": "Die Anfrage braucht eine Längenangabe."})
    # The UI does not need partial downloads (Range). Starlette up to 0.49.0 can be overloaded with crafted
    # Range headers on files (/static) (CVE-2025-62727) - hence the header is removed.
    if any(k == b"range" for k, _ in request.scope.get("headers", [])):
        request.scope["headers"] = [(k, v) for k, v in request.scope["headers"] if k != b"range"]
    if request.method in UNSAFE_METHODS and not _same_origin(request):
        log.warning("Anfrage von fremder Seite abgewiesen: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=403, content={"detail": "Anfrage von einer fremden Seite abgewiesen."})
    return await call_next(request)


@_http_middleware
async def _https_only(request: Request, call_next):
    """HTTPS only. The server (python -m samonboarding.serve) has no HTTP port anyway - this is the second
    safeguard in case the app is ever started without TLS. ALLOW_HTTP=true only for development."""
    if request.url.scheme != "https" and os.environ.get("ALLOW_HTTP", "").lower() not in ("1", "true", "yes"):
        return JSONResponse(status_code=403, content={"detail": "Nur über HTTPS erreichbar."})
    return await call_next(request)


# Registered last = outermost layer: the security headers are also set on responses rejected early
@_http_middleware
async def _security_headers(request: Request, call_next):
    try:
        resp = await call_next(request)
    except Exception:
        # Unexpected error: respond here so that this response also gets the security headers (otherwise
        # Starlette responds outside this layer). Details go only to the log, never to the browser.
        log.exception("Unerwarteter Fehler bei %s %s", request.method, request.url.path)
        resp = JSONResponse(status_code=500, content={"detail": "Interner Fehler. Details stehen im Protokoll."})
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    # The browser may load only from our own server (no CDNs, no Google Fonts, no tracking)
    resp.headers.setdefault("Content-Security-Policy", CSP)
    if os.environ.get("SAMONBOARDING_TLS_SELF_SIGNED") == "0":
        # Only with a proper (trusted) certificate: with a self-signed one the warning could otherwise no longer be
        # clicked away. Only for one day: anyone switching back to a self-signed certificate later would otherwise
        # be locked out for months (there is no HTTP port anyway).
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
