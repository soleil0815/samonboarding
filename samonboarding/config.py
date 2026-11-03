# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Konfiguration: Umgebungsvariablen, Pfade, Standardwerte.

Optionale Umgebungsvariablen (alle mit Defaults, nichts davon ist Pflicht):
  AD_DOMAIN, AD_DC_IP              Verbindung zum Active Directory (Samba/Windows wird automatisch erkannt)
  CUSTOM_OPERATOR_GROUP            sAMAccountName einer zusaetzlichen Operator-Gruppe
  DATA_DIR            Datenverzeichnis (Default: <Projektordner>/data)
  LDAP_CA_FILE        Pfad zu einer CA-PEM-Datei. Gesetzt -> Zertifikat des DC wird geprueft
                      (dann AD_DC_IP als Hostnamen angeben, der zum Zertifikat passt).
  LDAP_ALLOW_PLAIN    true/false (Default false): Fallback auf unverschluesseltes LDAP (389). Passwoerter im Klartext!
  SESSION_IDLE_MINUTES  Abmeldung nach so vielen Minuten ohne Aktivitaet (Default 30).
  SESSION_MAX_HOURS   Hoechstdauer einer Sitzung, auch bei Aktivitaet (Default 12).
  HTTPS_PORT          Port fuer HTTPS (Default 9500). Die Anwendung spricht nur HTTPS.
  TLS_CERT_FILE, TLS_KEY_FILE  eigenes Zertifikat (PEM). Default data/tls/cert.pem und key.pem;
                      fehlen sie, wird ein selbstsigniertes Zertifikat erzeugt.
  TLS_HOSTNAMES       Namen/IPs fuer das selbstsignierte Zertifikat, Komma-getrennt.
  LOGIN_MAX_ATTEMPTS  Fehlversuche je Benutzer/IP bis zur Sperre (Default 5).
  LOGIN_LOCK_MINUTES  Zeitfenster/Sperrdauer in Minuten (Default 5).
  AUDIT_RETENTION_DAYS     Aufbewahrung der Berichte (Aenderungen) in Tagen (Default 365, 0 = unbegrenzt).
  LOG_RETENTION_DAYS       Aufbewahrung des Protokolls in Tagen (Default 90, 0 = unbegrenzt).
  OFFBOARD_RETENTION_DAYS  Aufbewahrung der Wiederherstellungs-Eintraege in Tagen (Default 180, 0 = unbegrenzt)."""

import os
from pathlib import Path


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or not value.strip():  # leer in der .env = Standardwert
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent
WEB_DIR = PACKAGE_DIR / "web"
STATIC_DIR = BASE_DIR / "static"

# Datenverzeichnis: Standard <Projektordner>/data (im Container /app/data), per DATA_DIR ueberschreibbar
DATA_DIR = Path(os.environ.get("DATA_DIR", "").strip() or BASE_DIR / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = str(DATA_DIR / "config.json")
TEMPLATES_FILE = str(DATA_DIR / "templates.json")
SMTP_CONFIG_FILE = str(DATA_DIR / "smtp_config.json")
OFFBOARDING_CONFIG_FILE = str(DATA_DIR / "offboarding_config.json")
PWDRESET_CONFIG_FILE = str(DATA_DIR / "pwdreset_config.json")
ONBOARDING_CONFIG_FILE = str(DATA_DIR / "onboarding_config.json")
EXCHANGE_CONFIG_FILE = str(DATA_DIR / "exchange_config.json")
USERMGMT_CONFIG_FILE = str(DATA_DIR / "usermgmt_config.json")
DELETION_CONFIG_FILE = str(DATA_DIR / "deletion_config.json")
# Alte Textdatei des Audit-Logs (bis 1.22). Wird beim Start in die Datenbank uebernommen und danach entfernt
AUDIT_LOG_FILE = str(DATA_DIR / "audit.log")
# Berichte: Aenderungen (Audit) und Protokoll (Programm-Meldungen) in SQLite
REPORTS_DB_FILE = str(DATA_DIR / "reports.db")
# Merkt sich beim Offboarding OU, Gruppen und Kontostatus, damit ein Konto wiederhergestellt werden kann
OFFBOARD_DB_FILE = str(DATA_DIR / "offboarding.db")

# Aufbewahrungsfristen in Tagen (DSGVO, Speicherbegrenzung). 0 = unbegrenzt
AUDIT_RETENTION_DAYS = max(0, _env_int("AUDIT_RETENTION_DAYS", 365))
LOG_RETENTION_DAYS = max(0, _env_int("LOG_RETENTION_DAYS", 90))
OFFBOARD_RETENTION_DAYS = max(0, _env_int("OFFBOARD_RETENTION_DAYS", 180))

# Leer = keine zusaetzliche Gruppe. Die eingebaute Gruppe Konten-Operatoren wird immer an ihrer SID erkannt - ein
# Gruppenname als Standard waere gefaehrlich (auf deutschen DCs ist "account operators" ein freier Name).
CUSTOM_OPERATOR_GROUP = os.environ.get("CUSTOM_OPERATOR_GROUP", "").strip().lower()

LDAP_CA_FILE = os.environ.get("LDAP_CA_FILE", "").strip()

LDAP_ALLOW_PLAIN = _env_bool("LDAP_ALLOW_PLAIN", False)

# Sitzungen enden bei Abmeldung, nach dieser Zeit ohne Aktivitaet oder beim Neustart (liegen nur im Arbeitsspeicher)
SESSION_IDLE_SECONDS = max(1, _env_int("SESSION_IDLE_MINUTES", 30)) * 60
# Hoechstdauer einer Sitzung, auch bei durchgehender Aktivitaet (danach neu anmelden, Rolle wird neu geprueft)
SESSION_MAX_SECONDS = max(1, _env_int("SESSION_MAX_HOURS", 12)) * 3600

# HTTPS (die Anwendung spricht nur HTTPS). Ohne eigene Dateien wird ein selbstsigniertes Zertifikat erzeugt
HTTPS_PORT = _env_int("HTTPS_PORT", 9500)
TLS_DIR = DATA_DIR / "tls"
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "").strip() or str(TLS_DIR / "cert.pem")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "").strip() or str(TLS_DIR / "key.pem")
# Namen/IPs fuer das selbstsignierte Zertifikat (Komma-getrennt), z. B. samonboarding.firma.local,10.0.10.20
TLS_HOSTNAMES = [h.strip() for h in os.environ.get("TLS_HOSTNAMES", "").split(",") if h.strip()]

LOGIN_MAX_ATTEMPTS = max(1, _env_int("LOGIN_MAX_ATTEMPTS", 5))

LOGIN_LOCK_SECONDS = max(1, _env_int("LOGIN_LOCK_MINUTES", 5)) * 60

VERSION = "2.0.2"

default_config = {
    "domain": os.environ.get("AD_DOMAIN", "").strip() or "firma.local",
    "dc_ip": os.environ.get("AD_DC_IP", "").strip() or "10.0.10.5",
    "backend": os.environ.get("AD_BACKEND", "auto"),  # nur noch ein Hinweis: Samba/Windows wird automatisch erkannt
}

default_smtp_config = {
    "enabled": False,
    "displayName": "SAMONBOARDING NOTIFY",
    "host": "mail.firma.local",
    "port": 587,
    "username": "",
    "password": "",
    "fromEmail": "noreply@firma.local",
    "ccRecipients": "",
    "tlsMode": "Auto",
    "notifyOffboarding": False,
    "notifyPwdReset": False,
    "notifyUserMgmt": False,
    "notifyDeletion": False,
}

default_offboarding_config = {"sourceOus": [], "targetOu": ""}

default_pwdreset_config = {"sourceOus": []}

# E-Mail-Adresse beim Onboarding, einstellbar je Template (Feld mailMode):
#   required  Pflichtfeld (Standard: eigener Mailserver ohne Exchange)
#   optional  Feld vorhanden, darf leer bleiben
#   exchange  Exchange im eigenen Haus: Adresse nicht abfragen, Postfach wird automatisch angelegt
#   cloud     Microsoft 365 / Exchange Online: Adresse nicht abfragen (Postfach entsteht ueber die Lizenz)
MAIL_MODES = ("required", "optional", "exchange", "cloud")
# Aelterer Wert (Version 1.15, global gespeichert) wird nur fuer Templates ohne eigenen mailMode herangezogen
default_onboarding_config = {"mailMode": "required"}
LEGACY_MAIL_MODES = {"required": "required", "optional": "optional", "none": "cloud"}

default_usermgmt_config = {"sourceOus": [], "targetOus": [], "groupOus": []}

# Loeschfunktion (nur Administratoren): standardmaessig aus, jeder Speicherort einzeln schaltbar.
#   disabledOu   OU, in der deaktivierte Konten liegen (nur dort darf geloescht werden)
#   roots        freigegebene Basispfade (UNC), z. B. \\\\server\\profile$ - nur darunter wird je etwas angefasst
#   useAdAttr    Pfad aus dem AD-Konto (profilePath / homeDirectory) verwenden, sofern unter einem Basispfad
#   suffixes     Endungen der Roamingprofil-Ordner (Windows haengt .V2 / .V6 an)
default_deletion_config = {
    "enabled": False,
    "disabledOu": "",
    "profile": {"enabled": False, "roots": [], "useAdAttr": True, "suffixes": ["V2"], "takeOwnership": False},
    "folderRedirection": {"enabled": False, "roots": [], "takeOwnership": False},
    "home": {"enabled": False, "roots": [], "useAdAttr": True, "takeOwnership": False},
}

# "Ohne Verschluesselung" nur fuer ein internes Relay, das kein TLS kann - dann wird auch kein Passwort gesendet
SMTP_UNENCRYPTED = "Ohne Verschlüsselung"
SMTP_TLS_MODES = ("Auto", "STARTTLS", "SSL/TLS", SMTP_UNENCRYPTED)

USER_FILTER = "(&(objectClass=user)(!(objectClass=computer)))"

# Hinweistext, kein Passwort
PWD_HINT = (
    " Moegliche Ursachen: Passwort erfuellt die Passwortrichtlinie nicht, "  # noqa: S105
    "die Verbindung ist nicht per TLS (LDAPS) verschluesselt oder es fehlen Rechte."
)
