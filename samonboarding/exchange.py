# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Create a mailbox on an on-premises Exchange server (Enable-Mailbox via PowerShell remoting).

With on-premises Exchange, a new AD account does not have a mailbox yet. If the administrator has enabled this,
the application connects to the Exchange Management Shell (https://<server>/PowerShell) after creating the account
and runs Enable-Mailbox there. The credentials of the logged-in user are used; that user needs the Exchange role
'Mail Recipients'. The pypsrp package is loaded only when needed. Credentials are never logged.
"""

import logging
import re
from contextlib import contextmanager

log = logging.getLogger(__name__)

AUTH_MODES = ("negotiate", "ntlm", "kerberos", "basic")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
OPERATION_TIMEOUT = 90  # seconds: creating a mailbox can take a while
CONNECT_TIMEOUT = 20

default_exchange_config = {
    "enabled": False,
    "server": "",
    "port": 443,
    "ssl": True,
    "verifyCert": True,
    "auth": "negotiate",
    "database": "",
    "domainController": "",
}


class ExchangeError(Exception):
    """Error with a readable message (never contains credentials)."""


def clean_config(raw):
    """Validates and normalizes the settings. Raises ValueError with a readable message."""
    raw = raw or {}
    cfg = dict(default_exchange_config)
    cfg["enabled"] = bool(raw.get("enabled", False))
    cfg["ssl"] = bool(raw.get("ssl", True))
    cfg["verifyCert"] = bool(raw.get("verifyCert", True))
    cfg["server"] = str(raw.get("server") or "").strip()
    cfg["database"] = str(raw.get("database") or "").strip()
    cfg["domainController"] = str(raw.get("domainController") or "").strip()
    auth = str(raw.get("auth") or "negotiate").strip().lower()
    if auth not in AUTH_MODES:
        raise ValueError("Ungültige Anmeldeart.")
    cfg["auth"] = auth
    if auth == "basic" and not cfg["ssl"]:
        # Basic without HTTPS sends the logged-in admin's password in clear text
        raise ValueError("Die Anmeldeart 'basic' ist nur mit HTTPS erlaubt.")
    try:
        port = int(raw.get("port") or (443 if cfg["ssl"] else 80))
    except (TypeError, ValueError):
        raise ValueError("Ungültiger Port.") from None
    if not 1 <= port <= 65535:
        raise ValueError("Ungültiger Port.")
    cfg["port"] = port
    if cfg["server"] and not HOST_RE.match(cfg["server"]):
        raise ValueError(
            "Der Servername darf nur Buchstaben, Ziffern, Punkt und Bindestrich enthalten (kein https://)."
        )
    if cfg["domainController"] and not HOST_RE.match(cfg["domainController"]):
        raise ValueError("Der Domänencontroller darf nur Buchstaben, Ziffern, Punkt und Bindestrich enthalten.")
    if cfg["enabled"] and not cfg["server"]:
        raise ValueError("Bitte den Exchange-Server eintragen.")
    return cfg


def _short(text, limit=300):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


class _Session:
    """Runs cmdlets in the open Exchange shell."""

    def __init__(self, pool, powershell_cls):
        self._pool, self._ps_cls = pool, powershell_cls

    def run(self, cmdlet, **params):
        """Returns (output objects, error texts)."""
        ps = self._ps_cls(self._pool)
        ps.add_cmdlet(cmdlet)
        for key, value in params.items():
            ps.add_parameter(key, value)
        output = ps.invoke()
        errors = [_short(e) for e in (ps.streams.error if ps.had_errors else [])]
        return output, errors


@contextmanager
def _open_session(cfg, user):
    """Connects to the Exchange Management Shell (replaceable in tests)."""
    try:
        from pypsrp.powershell import PowerShell, RunspacePool
        from pypsrp.wsman import WSMan
    except ImportError:
        raise ExchangeError(
            "Das Python-Paket pypsrp ist nicht installiert. Docker-Image mit der aktuellen requirements.txt neu bauen."
        ) from None
    try:
        wsman = WSMan(
            cfg["server"],
            port=cfg["port"],
            ssl=cfg["ssl"],
            path="/PowerShell",
            auth=cfg["auth"],
            username=user["bind_user"],
            password=user["password"],
            cert_validation=cfg["verifyCert"],
            connection_timeout=CONNECT_TIMEOUT,
            operation_timeout=OPERATION_TIMEOUT,
            read_timeout=OPERATION_TIMEOUT + 15,
        )
        with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
            yield _Session(pool, PowerShell)
    except ExchangeError:
        raise
    except Exception as e:
        raise ExchangeError(_explain(e, cfg)) from None


def _explain(error, cfg):
    text = _short(error)
    low = text.lower()
    if "certificate" in low or "ssl" in low:
        hint = (
            "Zertifikat des Exchange-Servers wird nicht akzeptiert (oder in den Einstellungen die Prüfung abschalten)."
        )
    elif "401" in low or "credentials" in low or "authentication" in low or "unauthorized" in low:
        hint = (
            "Anmeldung abgelehnt. Anmeldeart prüfen (z. B. 'ntlm') und ob das Konto "
            "Zugriff auf die Exchange-Verwaltungsshell hat."
        )
    elif "timed out" in low or "timeout" in low or "connection" in low or "refused" in low or "resolve" in low:
        hint = f"Server {cfg['server']}:{cfg['port']} nicht erreichbar. Name, Port und Firewall prüfen."
    else:
        hint = "Verbindung zu Exchange fehlgeschlagen."
    return f"{hint} Details: {text}"


def check_connection(cfg, user):
    """Checks connection, login and whether the account may use Enable-Mailbox. Returns a message."""
    with _open_session(cfg, user) as session:
        output, errors = session.run("Get-Command", Name="Enable-Mailbox")
        if errors:
            raise ExchangeError("Verbindung steht, aber Abfrage schlug fehl: " + errors[0])
        if not output:
            raise ExchangeError(
                "Verbindung steht, aber das Konto darf Enable-Mailbox nicht verwenden "
                "(in Exchange fehlt die Rolle 'Mail Recipients')."
            )
    return "Verbindung zu Exchange steht, Enable-Mailbox ist für dieses Konto verfügbar."


def enable_mailbox(cfg, user, user_dn, domain_controller=""):
    """Creates a mailbox for the AD account. Raises ExchangeError with a readable message."""
    params = {"Identity": user_dn}
    if cfg.get("database"):
        params["Database"] = cfg["database"]
    dc = cfg.get("domainController") or domain_controller
    if dc:
        params["DomainController"] = dc  # same DC as for account creation: no waiting for replication
    with _open_session(cfg, user) as session:
        _output, errors = session.run("Enable-Mailbox", **params)
    if errors:
        raise ExchangeError(errors[0])
    log.info("Exchange-Postfach angelegt: %s (Server %s)", user_dn, cfg.get("server", ""))
