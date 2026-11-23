# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Kerberos for the encrypted LDAP connection on port 389 (see ldap_seal).

Kerberos is preferred over NTLM: the DC proves its identity, the encryption is AES, and it also works in domains in
which NTLM is switched off. It needs:
- the DC's DNS name in AD_DC_IP (the ticket is issued for ldap/<that name>). With an IP address there is no
  Kerberos: the name must come from the configuration - a name read from the network (RootDSE) could be chosen by an
  attacker, who would then get a ticket for a service whose key they hold.
- the KDC on the DC (port 88, TCP) and a clock within 5 minutes of the DC.
- the MIT Kerberos libraries and the Python packages gssapi and krb5 (in the image).

The configuration (krb5.conf) is written by the program itself from AD_DOMAIN and AD_DC_IP - no DNS lookups, no file
on the host. Only AES is allowed. The ticket of a sign-in is fetched into its own in-memory credential cache
(new_ticket) and destroyed as soon as the encrypted connection is set up (destroy_ticket) - never written to disk
and not kept in the process.
"""

import atexit
import contextlib
import ipaddress
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass

from . import config

log = logging.getLogger(__name__)

_lock = threading.Lock()
_written = {"key": None, "path": ""}

# MIT error codes (krb5 base -1765328384 + KDC error number) that mean: this account or password is not accepted.
# Then NTLM must not be tried as well - the same wrong password would count twice towards the account lockout.
_BASE = -1765328384
CREDENTIAL_ERRORS = {
    _BASE + 6: "unbekanntes Konto",  # KDC_ERR_C_PRINCIPAL_UNKNOWN
    _BASE + 18: "Konto gesperrt oder deaktiviert",  # KDC_ERR_CLIENT_REVOKED
    _BASE + 23: "Passwort abgelaufen",  # KDC_ERR_KEY_EXPIRED
    _BASE + 24: "Passwort falsch",  # KDC_ERR_PREAUTH_FAILED
}


def available():
    """Are the Kerberos libraries there (always in the image; maybe not in a development environment)?"""
    try:
        import gssapi  # noqa: F401
        import krb5  # noqa: F401
    except Exception:
        return False
    return config.LDAP_KERBEROS


def is_dns_name(host):
    host = str(host or "").strip()
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host))


def realm_of(domain):
    return str(domain or "").strip().upper()


def principal(bind_user, domain):
    """'anna@firma.local' or 'FIRMA\\anna' -> 'anna@FIRMA.LOCAL' (the realm is case-sensitive). A UPN with another
    suffix stays as it is (Kerberos may then fail - NTLM follows)."""
    user = str(bind_user or "")
    realm = realm_of(domain)
    if "\\" in user:
        return user.split("\\", 1)[1] + "@" + realm
    if "@" in user:
        name, suffix = user.rsplit("@", 1)
        return f"{name}@{realm}" if suffix.lower() == str(domain or "").lower() else user
    return f"{user}@{realm}"


_SAFE = re.compile(r"[A-Za-z0-9.-]+")


def config_text(domain, kdc):
    if not _SAFE.fullmatch(str(domain or "")) or not _SAFE.fullmatch(str(kdc or "")):
        raise ValueError("Ungültiger Domänen- oder DC-Name für Kerberos")
    realm = realm_of(domain)
    dom = str(domain).strip().lower()
    return (
        "# Written by SAMONBOARDING (kerberos.py) from AD_DOMAIN and AD_DC_IP - do not edit\n"
        "[libdefaults]\n"
        f"    default_realm = {realm}\n"
        "    dns_lookup_kdc = false\n"
        "    dns_lookup_realm = false\n"
        "    rdns = false\n"
        "    dns_canonicalize_hostname = false\n"
        "    udp_preference_limit = 0\n"
        "    forwardable = false\n"
        "    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_ccache_name = MEMORY:samonboarding\n"
        "[realms]\n"
        f"    {realm} = {{\n"
        f"        kdc = {kdc}\n"
        "    }\n"
        "[domain_realm]\n"
        f"    .{dom} = {realm}\n"
        f"    {dom} = {realm}\n"
    )


def ensure_config(domain, kdc):
    """Write krb5.conf (once per domain/KDC) and point KRB5_CONFIG to it. Returns the path."""
    key = (realm_of(domain), str(kdc))
    with _lock:
        if _written["key"] == key and os.path.exists(_written["path"]):
            return _written["path"]
        fd, path = tempfile.mkstemp(prefix="samonboarding-krb5-", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(config_text(domain, kdc))
        old = _written["path"]
        os.environ["KRB5_CONFIG"] = path
        _written.update(key=key, path=path)
        if old and old != path:
            with contextlib.suppress(OSError):
                os.unlink(old)
        return path


def credential_error(error):
    """Reason text if a Kerberos error means 'wrong password / locked / expired / unknown account', else ''."""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        for arg in getattr(error, "args", ()) or ():
            if isinstance(arg, int) and arg in CREDENTIAL_ERRORS:
                return CREDENTIAL_ERRORS[arg]
        match = re.search(r"(-17653\d{5})", str(error))
        if match and int(match.group(1)) in CREDENTIAL_ERRORS:
            return CREDENTIAL_ERRORS[int(match.group(1))]
        error = getattr(error, "base_error", None) or error.__cause__ or error.__context__
    return ""


def remove_config():
    """At exit: the generated krb5.conf is not left behind in /tmp."""
    path = _written.get("path")
    if path:
        with contextlib.suppress(OSError):
            os.unlink(path)


atexit.register(remove_config)


@dataclass
class Ticket:
    context: object
    ccache: object
    name: str  # "MEMORY:<unique>" for pyspnego (KerberosCCache)


def new_ticket(principal_name, password):
    """Kerberos ticket (TGT) for one sign-in, in its own in-memory credential cache. Raises the krb5 error (wrong
    password: see credential_error)."""
    import krb5

    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, principal_name.encode("utf-8"))
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_forwardable(opt, False)
    cred = krb5.get_init_creds_password(ctx, princ, opt, password=password.encode("utf-8"))
    ccache = krb5.cc_new_unique(ctx, b"MEMORY")
    try:
        krb5.cc_initialize(ctx, ccache, cred.client)
        krb5.cc_store_cred(ctx, ccache, cred)
    except Exception:
        krb5.cc_destroy(ctx, ccache)
        raise
    return Ticket(ctx, ccache, "MEMORY:" + _text(ccache.name))


def destroy_ticket(ticket):
    """Remove the credential cache with the user's tickets (the encrypted connection keeps only its session key)."""
    if ticket is None:
        return
    import krb5

    try:
        krb5.cc_destroy(ticket.context, ticket.ccache)
    except Exception as e:  # never stop a sign-in because of this - but say so
        log.warning("Kerberos-Ticket nicht geloescht: %s", type(e).__name__)


def _text(value):
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)
