"""Handbuch fuer die Hilfe in der Oberflaeche (Markdown, wird im Browser dargestellt)."""

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from ..config import WEB_DIR
from ..sessions import get_current_user

router = APIRouter()

MANUAL_DIR = WEB_DIR / "manual"
FILES = {"de": "HANDBUCH.md", "en": "MANUAL.en.md"}


@router.get("/api/manual", response_class=PlainTextResponse)
def manual(lang: str = "de", user: dict = Depends(get_current_user)):
    name = FILES.get(lang, FILES["de"])  # nur die zwei festen Dateien, kein Pfad aus der Anfrage
    try:
        text = (MANUAL_DIR / name).read_text(encoding="utf-8")
    except OSError:
        text = "# Handbuch\n\nDas Handbuch fehlt in dieser Installation."
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8", headers={"Cache-Control": "no-store"})
