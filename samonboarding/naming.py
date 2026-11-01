# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Passwoerter, Namensschemata (Makros), Laendercodes und Laufwerksbuchstaben."""

import re
import secrets
import string
import unicodedata

# Zeichen, die man beim Abtippen oder Vorlesen leicht verwechselt (0/O/o, 1/l/I), kommen nicht vor
AMBIGUOUS_CHARS = "0Oo1lI"
PASSWORD_SPECIALS = "!@#$%&*"  # noqa: S105 - erlaubte Sonderzeichen, kein Passwort


def generate_secure_password(length=12):
    alphabet = "".join(c for c in string.ascii_letters + string.digits + PASSWORD_SPECIALS if c not in AMBIGUOUS_CHARS)
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in PASSWORD_SPECIALS for c in pwd)
        ):
            return pwd


def normalize_home_drive(value):
    """'h', 'H' oder 'h:' -> 'H:'. Leer bleibt leer, alles andere wirft ValueError."""
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.fullmatch(r"([A-Za-z]):?", text)
    if not match:
        raise ValueError("Ungültiger Laufwerksbuchstabe (erlaubt: A: bis Z:).")
    return match.group(1).upper() + ":"


def remove_umlauts(text):
    if not text:
        return ""
    text = (
        text.upper()
        .replace("Ä", "AE")
        .replace("Ö", "OE")
        .replace("Ü", "UE")
        .replace("ß", "SS")
        # Buchstaben, die keine Grundform mit Akzent haben (NFKD zerlegt sie nicht): Ø, Æ, Œ, Ł, Đ, Þ
        .replace("Ø", "OE")
        .replace("Æ", "AE")
        .replace("Œ", "OE")
        .replace("Ł", "L")
        .replace("Đ", "D")
        .replace("Þ", "TH")
        .replace("-", "")
        .replace(" ", "")
    )
    # Uebrige Akzente (é, ñ, ...) entfernen, damit der sAMAccountName ASCII bleibt.
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


_MACRO_RE = re.compile(r"%(FIRSTNAME|LASTNAME)(?:\[(\d+)\]%|%(?:\[(\d+)\])?)")


def apply_macro(macro, firstname, lastname):
    names = {"FIRSTNAME": remove_umlauts(firstname), "LASTNAME": remove_umlauts(lastname)}

    def repl(match):
        value = names[match.group(1)]
        count = match.group(2) or match.group(3)
        return value[: int(count)] if count else value

    return _MACRO_RE.sub(repl, macro.upper())


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_person_name(value):
    """Vor-/Nachname: hoechstens 64 Zeichen (AD-Grenze), keine Steuerzeichen (z. B. Zeilenumbrueche)."""
    return bool(value) and len(value) <= 64 and not _CONTROL_RE.search(value)


def valid_mail(value):
    return len(value) <= 256 and bool(_MAIL_RE.match(value))


def sanitize_sam(value):
    """sAMAccountName: nur A-Z, 0-9, '.', '_', '-', maximal 20 Zeichen."""
    # Erst kuerzen, dann Punkte am Rand entfernen - ein Punkt am Ende lehnt das AD ab
    return re.sub(r"[^A-Z0-9._-]", "", value.upper()).strip(".")[:20].rstrip(".")


COUNTRY_CODES = {
    "deutschland": "DE",
    "germany": "DE",
    "österreich": "AT",
    "oesterreich": "AT",
    "austria": "AT",
    "schweiz": "CH",
    "switzerland": "CH",
    "liechtenstein": "LI",
    "luxemburg": "LU",
    "luxembourg": "LU",
    "belgien": "BE",
    "belgium": "BE",
    "niederlande": "NL",
    "netherlands": "NL",
    "frankreich": "FR",
    "france": "FR",
    "italien": "IT",
    "italy": "IT",
    "spanien": "ES",
    "spain": "ES",
    "polen": "PL",
    "poland": "PL",
    "tschechien": "CZ",
    "czechia": "CZ",
    "dänemark": "DK",
    "denmark": "DK",
    "vereinigtes königreich": "GB",
    "united kingdom": "GB",
    "usa": "US",
    "vereinigte staaten": "US",
    "united states": "US",
}


def country_code(name):
    if not name:
        return None
    key = name.strip().lower()
    if key in COUNTRY_CODES:
        return COUNTRY_CODES[key]
    if re.fullmatch(r"[A-Za-z]{2}", name.strip()):
        return name.strip().upper()
    return None


DEFAULT_NAMING_MACRO = "%LASTNAME%%FIRSTNAME%[3]"
