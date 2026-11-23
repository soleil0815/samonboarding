# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""LDAP access: connection, search, error checking and entry objects with convenient attribute access."""

import logging
import ssl
import time
import unicodedata
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from typing import Any

import ldap3
from fastapi import HTTPException
from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError, LDAPException, LDAPOperationResult

from . import timing
from .config import CONFIG_FILE, LDAP_ALLOW_PLAIN, LDAP_CA_FILE, LDAP_SASL_ENCRYPTION, USER_FILTER, default_config
from .errors import AdError, DcUnreachable
from .sessions import drop_session
from .storage import load_json

log = logging.getLogger(__name__)


def _first(value) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


class Row:
    """LDAP entry with case-insensitive attribute access."""

    __slots__ = ("dn", "_attrs")

    def __init__(self, dn, attrs):
        self.dn = dn
        self._attrs = {str(k).lower(): v for k, v in (attrs or {}).items()}

    def get(self, name):
        return self._attrs.get(name.lower())

    def text(self, name, default=""):
        value = _first(self.get(name))
        return default if value is None or value == "" else str(value)

    def list(self, name):
        value = self.get(name)
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
        return [str(value)]


FILETIME_NEVER = (0, 0x7FFFFFFFFFFFFFFF)  # AD: 0 = never, max = "no value" (e.g. accountExpires)
FILETIME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 (FILETIME) and 1970-01-01


def row_filetime(row, name):
    """AD time value (FILETIME, 100 ns since 1601) as ISO 8601 in UTC, or None for "never"/missing/invalid."""
    try:
        value = int(_first(row.get(name)))
    except (TypeError, ValueError):
        return None
    if value in FILETIME_NEVER or value < 0:
        return None
    seconds = value / 10_000_000 - FILETIME_EPOCH_OFFSET
    if not 0 < seconds < 253402300800:  # 1970 .. 9999
        return None
    return datetime.fromtimestamp(seconds, tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def row_uac(row):
    try:
        return int(_first(row.get("userAccountControl")))
    except (TypeError, ValueError):
        return 512


def row_is_locked(row):
    value = _first(row.get("lockoutTime"))
    if value in (None, "", 0, "0"):
        return False
    if isinstance(value, datetime):
        return value.year > 1601
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def row_display_name(row):
    return row.text("displayName") or row.text("cn") or row.text("sAMAccountName")


def _fold(text):
    """Lowercased, umlauts/accents folded to their base letters (Ä = A, ß = ss)."""
    decomposed = unicodedata.normalize("NFKD", str(text or "").casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def name_sort_key(name, tiebreak=""):
    """Sort key for alphabetical lists: case and umlauts are ignored."""
    return (_fold(name), _fold(tiebreak))


def _certificate_rejected(error):
    """Did the DC present a certificate on 636 that fails verification (LDAP_CA_FILE)?

    ldap3 wraps the SSL error in LDAPSocketOpenError (an LDAPCommunicationError); it can only be recognized by its
    text. In that case we must never fall back to unencrypted LDAP (389) - otherwise an attacker with a forged
    certificate could force the login into clear text.
    """
    if isinstance(error, ssl.SSLCertVerificationError):
        return True
    text = str(error).casefold()
    # ldap3 checks the host name itself and reports a mismatch as "... doesn't match any name in ..."
    return any(k in text for k in ("certificate_verify_failed", "certificate verify failed", "doesn't match"))


def _tls_config():
    if LDAP_CA_FILE:
        return ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=LDAP_CA_FILE)
    return ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)


# How the last connection was made (diagnostic package): ldaps, ldap-sealed-ntlm, ldap-sealed-kerberos, ldap-plain
last_transport = {"kind": "", "dc": ""}


# DCs whose LDAPS just failed (dc -> monotonic time until which 636 is skipped). Without a certificate every request
# would otherwise first wait for the failed TLS handshake and write a warning.
LDAPS_RETRY_SECONDS = 600
_ldaps_missing: dict = {}
# DCs whose LDAPS has worked in this process: a later failure on 636 is an outage (or someone on the network path
# resetting the connection) - then never fall back to 389, where an NTLM exchange could be recorded or relayed
_ldaps_seen: set = set()


def transport_of(conn):
    """ldaps, ldap-sealed-ntlm, ldap-sealed-kerberos or ldap-plain (empty for foreign connection objects)."""
    return str(getattr(conn, "sob_transport", "") or "")


def _connection_attempts():
    """Order of the connection attempts: LDAPS first; without a certificate check (LDAP_CA_FILE) then port 389
    encrypted with NTLM/Kerberos (LDAP_SASL_ENCRYPTION, default on); clear text only with LDAP_ALLOW_PLAIN.

    Code audit 2026-11b: with a CA file the certificate is verified - then there is never any fallback, otherwise an
    attacker on the network path only has to reset the connection on 636 to get a weaker connection on 389."""
    attempts = ["ldaps"]
    if not LDAP_CA_FILE:
        if LDAP_SASL_ENCRYPTION:
            attempts.append("ldap-sealed")
        if LDAP_ALLOW_PLAIN:
            attempts.append("ldap-plain")
    return attempts


def _kerberos_for(dc_ip, bind_user):
    """Kerberos target and principal, or None (no libraries, LDAP_KERBEROS=false, or AD_DC_IP is an IP address -
    the ticket's target name must come from the configuration)."""
    from . import kerberos

    if not kerberos.available() or not kerberos.is_dns_name(dc_ip):
        return None
    domain = load_json(CONFIG_FILE, default_config)["domain"]
    principal = kerberos.principal(bind_user, domain)
    if not principal.endswith("@" + kerberos.realm_of(domain)):
        return None  # a UPN with another suffix: Kerberos is not possible for it here - NTLM, not a downgrade
    kerberos.ensure_config(domain, dc_ip)
    return {"principal": principal, "target": dc_ip}


def _open(dc_ip, bind_user, password, kind):
    port, use_ssl = (636, True) if kind == "ldaps" else (389, False)
    server = ldap3.Server(dc_ip, port=port, use_ssl=use_ssl, tls=_tls_config(), get_info=ldap3.NONE, connect_timeout=5)
    if kind == "ldap-sealed":
        from .ldap_seal import sealed_bind

        conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, receive_timeout=30, auto_referrals=False)
        try:
            conn.open()
            return sealed_bind(conn, bind_user, password, dc_ip, _kerberos_for(dc_ip, bind_user))
        except Exception:
            with suppress(Exception):
                conn.unbind()
            raise
    conn = ldap3.Connection(
        server,
        user=bind_user,
        password=password,
        authentication=ldap3.SIMPLE,
        auto_bind=True,
        receive_timeout=30,  # a hanging DC must not block a worker thread forever
        auto_referrals=False,  # never send requests (or the password) on to another server named in a referral
    )
    setattr(conn, "sob_transport", kind)  # noqa: B010 - own marker on the ldap3 object
    return conn


@contextmanager
def ldap_connection(dc_ip, bind_user, password):
    """Connects via LDAPS, otherwise encrypted LDAP on 389 (see _connection_attempts) and always cleans up.

    The fallback happens only on connection errors - never on a wrong password, so that a typo does not count twice
    towards the account lockout.
    """
    conn = None
    attempts = _connection_attempts()
    if dc_ip in _ldaps_seen:
        attempts = attempts[:1]
    now = time.monotonic()
    if _ldaps_missing.get(dc_ip, 0) > now and len(attempts) > 1:
        # LDAPS of this DC failed a moment ago (no certificate): do not wait for it on every request - try again later
        attempts = attempts[1:]
    ldaps_failed = False
    try:
        for kind in attempts:
            try:
                with timing.timed("connect"):
                    conn = _open(dc_ip, bind_user, password, kind)
                transport = transport_of(conn)
                if last_transport.get("kind") != transport or last_transport.get("dc") != dc_ip:  # log changes only
                    if kind == "ldap-sealed":
                        log.info("LDAPS zu %s nicht verfuegbar - Port 389 verschluesselt (%s)", dc_ip, transport)
                    elif kind == "ldap-plain":
                        log.warning(
                            "Unverschluesselte LDAP-Verbindung zu %s (Port 389) - LDAPS nicht erreichbar", dc_ip
                        )
                last_transport.update(kind=transport, dc=dc_ip)
                if kind == "ldaps":
                    _ldaps_missing.pop(dc_ip, None)
                    _ldaps_seen.add(dc_ip)
                elif ldaps_failed and kind == "ldap-sealed":
                    # the DC answers, only LDAPS is missing (no certificate) - not a DC that was down for a moment
                    _ldaps_missing[dc_ip] = now + LDAPS_RETRY_SECONDS
                break
            except (LDAPCommunicationError, OSError) as e:
                conn = None
                if kind == "ldaps" and _certificate_rejected(e):
                    log.error("Zertifikat des DC %s abgelehnt - kein Rueckfall auf Port 389: %s", dc_ip, e)
                    break
                if kind == "ldaps" and len(attempts) > 1:
                    ldaps_failed = True
                    if last_transport.get("dc") != dc_ip or last_transport.get("kind") == "ldaps":
                        log.warning("LDAPS zu %s nicht verfuegbar: %s", dc_ip, e)
                else:
                    log.warning("LDAP-Verbindung zu %s (%s) fehlgeschlagen: %s", dc_ip, kind, e)
        if conn is None:
            # details (socket errors) are logged above, not in the message to the browser
            raise DcUnreachable(f"Domain Controller {dc_ip} nicht erreichbar. Details stehen im Protokoll.")
        yield conn
    finally:
        if conn is not None:
            with suppress(Exception):
                conn.unbind()


AD_CAPABILITY_OID = "1.2.840.113556.1.4.800"  # LDAP_CAP_ACTIVE_DIRECTORY_OID: reported by both Windows and Samba

_directory = {"type": "unknown", "label": "Active Directory", "version": "", "host": ""}


def detect_directory(conn):
    """Detects from the RootDSE whether a Samba AD or a Windows AD is responding. No setting is needed.

    Samba names itself in the RootDSE (vendorName); Windows has no such entry. If the query fails, it stays
    'Active Directory' (the application's behavior does not depend on it).
    """
    info = {"type": "unknown", "label": "Active Directory", "version": "", "host": ""}
    try:
        if conn.search(
            "",
            "(objectClass=*)",
            ldap3.BASE,
            attributes=["vendorName", "vendorVersion", "dnsHostName", "supportedCapabilities"],
        ):
            attrs = {}
            for entry in conn.response or []:
                if entry.get("type") == "searchResEntry":
                    attrs = {str(k).lower(): v for k, v in (entry.get("attributes") or {}).items()}
                    break

            def text(name):
                value = _first(attrs.get(name.lower()))
                return "" if value is None else str(value)

            vendor = (text("vendorName") + " " + text("vendorVersion")).lower()
            caps = [str(c) for c in (attrs.get("supportedcapabilities") or [])]
            info["host"] = text("dnsHostName")
            if "samba" in vendor:
                info.update(type="samba", label="Samba AD", version=text("vendorVersion"))
            elif AD_CAPABILITY_OID in caps:
                info.update(type="windows", label="Windows Server AD")
    except Exception as e:  # detection must never interfere with the login
        log.debug("Verzeichnisdienst nicht erkennbar: %s", e)
    if info != _directory:  # only on first detection or when something changes
        log.info(
            "Verzeichnisdienst erkannt: %s%s%s",
            info["label"],
            f" {info['version']}" if info["version"] else "",
            f" ({info['host']})" if info["host"] else "",
        )
    _directory.update(info)
    return info


def detect_mail_system(conn):
    """Hints whether Exchange or an Azure/Entra sync is set up in AD (None = cannot be determined).

    Exchange creates the entry 'Microsoft Exchange' in the configuration partition. Microsoft Entra Connect creates a
    service account named MSOL_* (older versions AAD_*). Both are only hints for the setting; the administrator
    makes the decision.
    """
    result: dict[str, bool | None] = {"exchange": None, "entra": None}
    try:
        if not conn.search(
            "", "(objectClass=*)", ldap3.BASE, attributes=["configurationNamingContext", "defaultNamingContext"]
        ):
            return result
        attrs = {}
        for entry in conn.response or []:
            if entry.get("type") == "searchResEntry":
                attrs = {str(k).lower(): v for k, v in (entry.get("attributes") or {}).items()}
                break
        config_nc = _first(attrs.get("configurationnamingcontext"))
        default_nc = _first(attrs.get("defaultnamingcontext"))
    except Exception as e:
        log.debug("RootDSE fuer Mail-Erkennung nicht lesbar: %s", e)
        return result
    if config_nc:
        try:
            found = conn.search(
                f"CN=Microsoft Exchange,CN=Services,{config_nc}", "(objectClass=*)", ldap3.BASE, attributes=["cn"]
            )
            code = (conn.result or {}).get("result")
            result["exchange"] = True if found else (False if code in (32, 34) else None)
        except Exception as e:
            log.debug("Exchange-Erkennung nicht moeglich: %s", e)
    if default_nc:
        try:
            conn.search(
                default_nc,
                "(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*))",
                ldap3.SUBTREE,
                attributes=["sAMAccountName"],
                size_limit=1,
            )
            result["entra"] = any(e.get("type") == "searchResEntry" for e in conn.response or [])
        except Exception as e:
            log.debug("Entra-Erkennung nicht moeglich: %s", e)
    return result


def directory_info():
    """Most recently detected directory service (after the first login)."""
    return dict(_directory)


@contextmanager
def ad_session(user):
    """LDAP connection on behalf of the logged-in user."""
    cfg = load_json(CONFIG_FILE, default_config)
    try:
        with ldap_connection(cfg["dc_ip"], user["bind_user"], user["password"]) as conn:
            yield conn
    except LDAPBindError:
        # Password changed in the meantime / account locked -> session invalid.
        drop_session(user.get("sid"))
        raise HTTPException(status_code=401, detail="Sitzung ungueltig - bitte neu anmelden.") from None


def ldap_search(conn, base, flt, attrs, scope=ldap3.SUBTREE, page_size=500):
    """Paged search (bypasses the AD limit of 1000). Raises an LDAPException on server errors."""
    rows = []
    with timing.timed("search"):
        for entry in conn.extend.standard.paged_search(
            base, flt, search_scope=scope, attributes=attrs, paged_size=page_size, generator=True
        ):
            if entry.get("type") != "searchResEntry":
                continue
            rows.append(Row(entry["dn"], entry.get("attributes")))
    # without raise_exceptions, ldap3 raises no error here - an abort (DC busy, time limit, OU missing,
    # no permissions) would otherwise look like "nothing found" or an incomplete list
    result = getattr(conn, "result", None) or {}
    code = result.get("result") if isinstance(result, dict) else None
    if code not in (None, 0):
        raise LDAPOperationResult(
            result=code, description=result.get("description"), message=result.get("message"), dn=base
        )
    return rows


def get_object(conn, dn, attrs, flt="(objectClass=user)"):
    """Reads exactly one object. None if it does not exist."""
    conn.search(dn, flt, ldap3.BASE, attributes=attrs)
    code = (conn.result or {}).get("result")
    if code in (32, 34):  # noSuchObject, invalidDNSyntax
        return None
    if code not in (0, None):
        raise AdError(f"AD-Abfrage fehlgeschlagen: {ldap_error_text(conn)}")
    for entry in conn.response or []:
        if entry.get("type") == "searchResEntry":
            return Row(entry["dn"], entry.get("attributes"))
    return None


def ldap_error_text(conn):
    result = conn.result or {}
    description = result.get("description") or "unbekannter Fehler"
    message = (result.get("message") or "").strip()
    return f"{description} - {message}" if message else str(description)


def ensure(conn, ok, action, hint=""):
    """Success check for add/modify/delete (by default, ldap3 raises no exception here)."""
    if not ok:
        raise AdError(f"{action} fehlgeschlagen: {ldap_error_text(conn)}.{hint}")


def member_change_ok(conn, ok):
    """True if the membership change succeeded or the target state already applies."""
    if ok:
        return True
    result = conn.result or {}
    code = result.get("result")
    message = (result.get("message") or "").upper()
    if code in (16, 20, 68):  # noSuchAttribute, attributeOrValueExists, entryAlreadyExists
        return True
    return code == 53 and ("0561" in message or "NOT_IN_ALIAS" in message or "0562" in message)


def collect_users(conn, ous, attrs, build):
    users, seen = [], set()
    for ou in ous:
        if not ou:
            continue
        try:
            rows = ldap_search(conn, ou, USER_FILTER, attrs)
        except LDAPException as e:
            log.warning("Suche in OU '%s' fehlgeschlagen: %s", ou, e)
            continue
        for row in rows:
            if row.dn.lower() in seen:
                continue
            seen.add(row.dn.lower())
            users.append(build(row, ou))
    users.sort(key=lambda u: name_sort_key(u.get("name"), u.get("sam")))
    return users
