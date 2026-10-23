"""LDAP-Zugriff: Verbindung, Suche, Fehlerpruefung und Zeilenobjekte mit komfortablem Attributzugriff."""

import logging
import ssl
import unicodedata
from contextlib import contextmanager
from datetime import datetime

import ldap3
from fastapi import HTTPException
from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError, LDAPException, LDAPOperationResult

from .config import CONFIG_FILE, LDAP_ALLOW_PLAIN, LDAP_CA_FILE, USER_FILTER, default_config
from .errors import AdError, DcUnreachable
from .sessions import drop_session
from .storage import load_json

log = logging.getLogger(__name__)


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


class Row:
    """LDAP-Eintrag mit case-insensitivem Attributzugriff."""

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
    """Klein geschrieben, Umlaute/Akzente wie ihre Grundbuchstaben (Ä = A, ß = ss)."""
    decomposed = unicodedata.normalize("NFKD", str(text or "").casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def name_sort_key(name, tiebreak=""):
    """Sortierschluessel fuer alphabetische Listen: Gross-/Kleinschreibung und Umlaute spielen keine Rolle."""
    return (_fold(name), _fold(tiebreak))


def _tls_config():
    if LDAP_CA_FILE:
        return ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=LDAP_CA_FILE)
    return ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)


@contextmanager
def ldap_connection(dc_ip, bind_user, password):
    """Verbindet sich per LDAPS (Fallback optional LDAP) und raeumt die Verbindung immer auf.

    Zum Fallback auf Port 389 kommt es nur bei Verbindungsfehlern - nie bei falschem Passwort,
    damit ein Tippfehler nicht doppelt gegen die Kontosperre zaehlt.
    """
    conn = None
    attempts = [(636, True)]
    if LDAP_ALLOW_PLAIN:
        attempts.append((389, False))
    try:
        for port, use_ssl in attempts:
            try:
                server = ldap3.Server(
                    dc_ip, port=port, use_ssl=use_ssl, tls=_tls_config(), get_info=ldap3.NONE, connect_timeout=5
                )
                conn = ldap3.Connection(
                    server,
                    user=bind_user,
                    password=password,
                    authentication=ldap3.SIMPLE,
                    auto_bind=True,
                    receive_timeout=30,  # ein DC, der haengt, darf keinen Arbeits-Thread fuer immer blockieren
                )
                if not use_ssl:
                    log.warning("Unverschluesselte LDAP-Verbindung zu %s (Port 389) - LDAPS nicht erreichbar", dc_ip)
                break
            except (LDAPCommunicationError, OSError) as e:
                conn = None
                log.warning("LDAP-Verbindung zu %s:%s fehlgeschlagen: %s", dc_ip, port, e)
        if conn is None:
            # Einzelheiten (Socket-Fehler) stehen oben im Protokoll, nicht in der Meldung an den Browser
            raise DcUnreachable(f"Domain Controller {dc_ip} nicht erreichbar. Details stehen im Protokoll.")
        yield conn
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


AD_CAPABILITY_OID = "1.2.840.113556.1.4.800"  # LDAP_CAP_ACTIVE_DIRECTORY_OID: Windows und Samba melden ihn

_directory = {"type": "unknown", "label": "Active Directory", "version": "", "host": ""}


def detect_directory(conn):
    """Erkennt aus dem RootDSE, ob ein Samba-AD oder ein Windows-AD antwortet. Es ist keine Einstellung noetig.

    Samba nennt sich im RootDSE (vendorName); Windows hat diesen Eintrag nicht. Schlaegt die Abfrage fehl, bleibt es
    bei 'Active Directory' (das Verhalten der Anwendung haengt nicht davon ab).
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
    except Exception as e:  # die Erkennung darf nie die Anmeldung stoeren
        log.debug("Verzeichnisdienst nicht erkennbar: %s", e)
    if info != _directory:  # nur bei der ersten Erkennung oder wenn sich etwas aendert
        log.info(
            "Verzeichnisdienst erkannt: %s%s%s",
            info["label"],
            f" {info['version']}" if info["version"] else "",
            f" ({info['host']})" if info["host"] else "",
        )
    _directory.update(info)
    return info


def detect_mail_system(conn):
    """Hinweise, ob im AD Exchange oder eine Azure/Entra-Synchronisation eingerichtet ist (None = nicht feststellbar).

    Exchange legt im Konfigurationsbereich den Eintrag 'Microsoft Exchange' an. Microsoft Entra Connect erzeugt ein
    Dienstkonto namens MSOL_* (aeltere Versionen AAD_*). Beides ist nur ein Hinweis fuer die Einstellung, die
    Entscheidung trifft der Administrator.
    """
    result = {"exchange": None, "entra": None}
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
    """Zuletzt erkannter Verzeichnisdienst (nach der ersten Anmeldung)."""
    return dict(_directory)


@contextmanager
def ad_session(user):
    """LDAP-Verbindung im Namen des angemeldeten Benutzers."""
    cfg = load_json(CONFIG_FILE, default_config)
    try:
        with ldap_connection(cfg["dc_ip"], user["bind_user"], user["password"]) as conn:
            yield conn
    except LDAPBindError:
        # Passwort wurde zwischenzeitlich geaendert / Konto gesperrt -> Sitzung ungueltig.
        drop_session(user.get("sid"))
        raise HTTPException(status_code=401, detail="Sitzung ungueltig - bitte neu anmelden.")


def ldap_search(conn, base, flt, attrs, scope=ldap3.SUBTREE, page_size=500):
    """Paged Search (umgeht das 1000er-Limit von AD). Wirft bei Serverfehlern eine LDAPException."""
    rows = []
    for entry in conn.extend.standard.paged_search(
        base, flt, search_scope=scope, attributes=attrs, paged_size=page_size, generator=True
    ):
        if entry.get("type") != "searchResEntry":
            continue
        rows.append(Row(entry["dn"], entry.get("attributes")))
    # ldap3 wirft hier ohne raise_exceptions keinen Fehler - ein Abbruch (DC beschaeftigt, Zeitlimit, OU fehlt,
    # keine Rechte) saehe sonst aus wie "nichts gefunden" bzw. eine unvollstaendige Liste
    result = getattr(conn, "result", None) or {}
    code = result.get("result") if isinstance(result, dict) else None
    if code not in (None, 0):
        raise LDAPOperationResult(
            result=code, description=result.get("description"), message=result.get("message"), dn=base
        )
    return rows


def get_object(conn, dn, attrs, flt="(objectClass=user)"):
    """Liest genau ein Objekt. None, wenn es nicht existiert."""
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
    """Erfolgspruefung fuer add/modify/delete (ldap3 wirft hier standardmaessig keine Exception)."""
    if not ok:
        raise AdError(f"{action} fehlgeschlagen: {ldap_error_text(conn)}.{hint}")


def member_change_ok(conn, ok):
    """True, wenn die Mitgliedschaftsaenderung gelungen ist oder bereits dem Zielzustand entspricht."""
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
