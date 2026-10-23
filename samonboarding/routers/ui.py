"""Oberflaeche: HTML-Seite und statische Dateien (lokales Tailwind-CSS, Schriften Manrope/JetBrains Mono, Font Awesome).

Alles wird vom eigenen Server ausgeliefert - es gibt keine Verbindungen zu CDNs oder Google Fonts.
"""

import html
import json
import logging

from fastapi import APIRouter, FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .. import i18n
from ..config import CONFIG_FILE, STATIC_DIR, VERSION, WEB_DIR, default_config
from ..storage import load_json

log = logging.getLogger(__name__)
router = APIRouter()

LOCAL_ASSETS = ("app.css", "vendor/fonts/fonts.css", "vendor/fontawesome/css/all.min.css")


# Ohne Docker-Build fehlen die Dateien. Es wird trotzdem nichts aus dem Internet nachgeladen,
# stattdessen erscheint ein deutlicher Hinweis oben auf der Seite.
MISSING_ASSETS_HINT = """<style>
        body::before { content: "SAMONBOARDING: CSS/Schriften fehlen (static/). Bitte das Docker-Image neu bauen: docker compose up -d --build";
            display: block; padding: 12px 16px; background: #b91c1c; color: #fff; font: 600 14px system-ui, sans-serif; }
    </style>"""


def asset_head():
    """HTML-Kopf-Tags fuer CSS/Schriften - immer lokal aus /static, nie aus dem Internet."""
    links = "\n    ".join(
        f'<link rel="stylesheet" href="/static/{name}?v={VERSION}">'
        for name in ("vendor/fonts/fonts.css", "vendor/fontawesome/css/all.min.css", "app.css")
    )
    if all((STATIC_DIR / name).is_file() for name in LOCAL_ASSETS):
        return links
    log.error("Lokale Assets in %s fehlen - Docker-Image neu bauen (docker compose up -d --build)", STATIC_DIR)
    return links + "\n    " + MISSING_ASSETS_HINT


def mount_static(app: FastAPI):
    """Haengt /static ein (vom Docker-Build erzeugtes CSS, Schriften, Icons), falls vorhanden."""
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


_index_cache = {"mtime": None, "text": ""}


def load_index_html():
    """Liest samonboarding/web/index.html; wird nur neu gelesen, wenn sich die Datei aendert."""
    path = WEB_DIR / "index.html"
    mtime = path.stat().st_mtime_ns
    if _index_cache["mtime"] != mtime:
        _index_cache["text"] = path.read_text(encoding="utf-8")
        _index_cache["mtime"] = mtime
    return _index_cache["text"]


def i18n_json():
    """Woerterbuch fuer die englische Oberflaeche (eingebettet, '</' maskiert)."""
    return json.dumps(i18n.dictionary(), ensure_ascii=False).replace("</", "<\\/")


@router.get("/", response_class=HTMLResponse)
def serve_gui():
    cfg = load_json(CONFIG_FILE, default_config)
    domain = html.escape(str(cfg.get("domain", "yourdomain.local")))
    return (
        load_index_html()
        .replace("__ASSET_HEAD__", asset_head())
        .replace("__APP_VERSION__", VERSION)
        .replace("__APP_DOMAIN__", domain)
        .replace("__I18N__", i18n_json())
    )
