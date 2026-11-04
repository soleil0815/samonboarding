# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Configuration: environment variables, paths, defaults.

Optional environment variables (all have defaults, none is required):
  AD_DOMAIN, AD_DC_IP              Connection to Active Directory (Samba/Windows is detected automatically)
  CUSTOM_OPERATOR_GROUP            sAMAccountName of an additional operator group
  DATA_DIR            Data directory (default: <project folder>/data)
  LDAP_CA_FILE        Path to a CA PEM file. If set, the DC's certificate is verified
                      (then give AD_DC_IP as a hostname that matches the certificate).
  LDAP_ALLOW_PLAIN    true/false (default false): fall back to unencrypted LDAP (389). Passwords in clear text!
  SESSION_IDLE_MINUTES  Log out after this many minutes without activity (default 30).
  SESSION_MAX_HOURS   Maximum session lifetime, even with activity (default 12).
  HTTPS_PORT          Port for HTTPS (default 9500). The application speaks HTTPS only.
  TLS_CERT_FILE, TLS_KEY_FILE  Own certificate (PEM). Default data/tls/cert.pem and key.pem;
                      if they are missing, a self-signed certificate is generated.
  TLS_HOSTNAMES       Names/IPs for the self-signed certificate, comma-separated.
  LOGIN_MAX_ATTEMPTS  Failed attempts per user/IP before lockout (default 5).
  LOGIN_LOCK_MINUTES  Time window/lockout duration in minutes (default 5).
  AUDIT_RETENTION_DAYS     Retention of the reports (changes) in days (default 365, 0 = unlimited).
  LOG_RETENTION_DAYS       Retention of the log in days (default 90, 0 = unlimited).
  OFFBOARD_RETENTION_DAYS  Retention of the restore entries in days (default 180, 0 = unlimited)."""

import os
from pathlib import Path


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or not value.strip():  # empty in .env = default value
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

# Data directory: default <project folder>/data (/app/data in the container), can be overridden via DATA_DIR
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
# Old text file of the audit log (up to 1.22). Imported into the database at startup and then removed
AUDIT_LOG_FILE = str(DATA_DIR / "audit.log")
# Reports: changes (audit) and log (program messages) in SQLite
REPORTS_DB_FILE = str(DATA_DIR / "reports.db")
# Remembers OU, groups and account status during offboarding so that an account can be restored
OFFBOARD_DB_FILE = str(DATA_DIR / "offboarding.db")

# Retention periods in days (GDPR, storage limitation). 0 = unlimited
AUDIT_RETENTION_DAYS = max(0, _env_int("AUDIT_RETENTION_DAYS", 365))
LOG_RETENTION_DAYS = max(0, _env_int("LOG_RETENTION_DAYS", 90))
OFFBOARD_RETENTION_DAYS = max(0, _env_int("OFFBOARD_RETENTION_DAYS", 180))

# Empty = no additional group. The built-in Account Operators group is always recognized by its SID - a group
# name as default would be dangerous (on German DCs "account operators" is an unused name).
CUSTOM_OPERATOR_GROUP = os.environ.get("CUSTOM_OPERATOR_GROUP", "").strip().lower()

LDAP_CA_FILE = os.environ.get("LDAP_CA_FILE", "").strip()

LDAP_ALLOW_PLAIN = _env_bool("LDAP_ALLOW_PLAIN", False)

# Sessions end on logout, after this time without activity, or on restart (they are kept in memory only)
SESSION_IDLE_SECONDS = max(1, _env_int("SESSION_IDLE_MINUTES", 30)) * 60
# Maximum session lifetime, even with continuous activity (then log in again; the role is re-checked)
SESSION_MAX_SECONDS = max(1, _env_int("SESSION_MAX_HOURS", 12)) * 3600

# HTTPS (the application speaks HTTPS only). Without own files, a self-signed certificate is generated
HTTPS_PORT = _env_int("HTTPS_PORT", 9500)
TLS_DIR = DATA_DIR / "tls"
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "").strip() or str(TLS_DIR / "cert.pem")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "").strip() or str(TLS_DIR / "key.pem")
# Names/IPs for the self-signed certificate (comma-separated), e.g. samonboarding.firma.local,10.0.10.20
TLS_HOSTNAMES = [h.strip() for h in os.environ.get("TLS_HOSTNAMES", "").split(",") if h.strip()]

LOGIN_MAX_ATTEMPTS = max(1, _env_int("LOGIN_MAX_ATTEMPTS", 5))

LOGIN_LOCK_SECONDS = max(1, _env_int("LOGIN_LOCK_MINUTES", 5)) * 60

VERSION = "2.0.3"

default_config = {
    "domain": os.environ.get("AD_DOMAIN", "").strip() or "firma.local",
    "dc_ip": os.environ.get("AD_DC_IP", "").strip() or "10.0.10.5",
    "backend": os.environ.get("AD_BACKEND", "auto"),  # only a hint now: Samba/Windows is detected automatically
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

# Email address during onboarding, configurable per template (field mailMode):
#   required  mandatory field (default: own mail server without Exchange)
#   optional  field present, may be left empty
#   exchange  on-premises Exchange: do not ask for the address, the mailbox is created automatically
#   cloud     Microsoft 365 / Exchange Online: do not ask for the address (the mailbox comes with the license)
MAIL_MODES = ("required", "optional", "exchange", "cloud")
# Older value (version 1.15, stored globally) is only used for templates without their own mailMode
default_onboarding_config = {"mailMode": "required"}
LEGACY_MAIL_MODES = {"required": "required", "optional": "optional", "none": "cloud"}

default_usermgmt_config = {"sourceOus": [], "targetOus": [], "groupOus": []}

# Delete function (administrators only): off by default, each storage location can be switched individually.
#   disabledOu   OU containing disabled accounts (deletion is allowed only there)
#   roots        allowed base paths (UNC), e.g. \\\\server\\profile$ - nothing outside them is ever touched
#   useAdAttr    use the path from the AD account (profilePath / homeDirectory), if it is under a base path
#   suffixes     suffixes of the roaming profile folders (Windows appends .V2 / .V6)
default_deletion_config = {
    "enabled": False,
    "disabledOu": "",
    "profile": {"enabled": False, "roots": [], "useAdAttr": True, "suffixes": ["V2"], "takeOwnership": False},
    "folderRedirection": {"enabled": False, "roots": [], "takeOwnership": False},
    "home": {"enabled": False, "roots": [], "useAdAttr": True, "takeOwnership": False},
}

# "Ohne Verschlüsselung" (no encryption) only for an internal relay without TLS - then no password is sent either
SMTP_UNENCRYPTED = "Ohne Verschlüsselung"
SMTP_TLS_MODES = ("Auto", "STARTTLS", "SSL/TLS", SMTP_UNENCRYPTED)

USER_FILTER = "(&(objectClass=user)(!(objectClass=computer)))"

# Hint text, not a password
PWD_HINT = (
    " Moegliche Ursachen: Passwort erfuellt die Passwortrichtlinie nicht, "  # noqa: S105
    "die Verbindung ist nicht per TLS (LDAPS) verschluesselt oder es fehlen Rechte."
)
