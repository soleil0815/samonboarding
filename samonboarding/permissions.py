# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Berechtigungen: Rollenpruefung beim Login und serverseitige Pruefung der freigegebenen OUs."""

import logging

import ldap3
from fastapi import HTTPException

from . import acl, protection
from .config import CUSTOM_OPERATOR_GROUP, USER_FILTER
from .dn import dn_in_any, ldap_escape
from .ldap_client import ldap_search

log = logging.getLogger(__name__)


def require_admin(user, message):
    if user.get("role") != "Administrator":
        raise HTTPException(status_code=403, detail=message)


# Rollen werden an den festen SIDs der Gruppen erkannt, nie am Namen: Auf deutschen DCs heissen die Gruppen
# "Administratoren"/"Domänen-Admins"; die englischen Namen waeren dort frei und koennten von jedem, der Gruppen
# anlegen darf, mit einer eigenen Gruppe belegt werden.
ADMIN_SIDS = {"S-1-5-32-544"}  # BUILTIN\Administrators
ADMIN_DOMAIN_RIDS = {512, 519}  # Domain Admins, Enterprise Admins
OPERATOR_SIDS = {"S-1-5-32-548"}  # BUILTIN\Account Operators


def _domain_rid(sid):
    if not sid.startswith("S-1-5-21-"):
        return None
    rid = sid.rsplit("-", 1)[-1]
    return int(rid) if rid.isdigit() else None


def _group_sids(row):
    out = set()
    values = row.get("objectSid")
    for value in values if isinstance(values, (list, tuple)) else [values]:
        if value is None:
            continue
        try:
            out.add(acl.sid_from_ldap(value))
        except (acl.AclError, ValueError, TypeError):
            continue
    return out


def _domain_of(search_base):
    """'DC=firma,DC=local' -> 'firma.local'."""
    return ".".join(p.split("=", 1)[1] for p in str(search_base).split(",") if p.strip().lower().startswith("dc="))


def _configuration_nc(conn, search_base):
    """Konfigurationsbereich laut RootDSE. In einer Unterdomaene liegt er unter der Gesamtstruktur-Wurzel, nicht
    unter der eigenen Domaene; ohne Antwort wird die Annahme fuer eine einzelne Domaene verwendet."""
    try:
        if conn.search("", "(objectClass=*)", ldap3.BASE, attributes=["configurationNamingContext"]):
            for entry in conn.response or []:
                value = (entry.get("attributes") or {}).get("configurationNamingContext")
                if isinstance(value, (list, tuple)):
                    value = value[0] if value else ""
                if value:
                    return str(value)
    except Exception as e:
        log.debug("RootDSE nicht lesbar, Konfigurationsbereich wird angenommen: %s", type(e).__name__)
    return f"CN=Configuration,{search_base}"


def _own_names(conn, search_base):
    """(Namen, unter denen sich ein Konto DIESER Domaene anmelden kann, NetBIOS-Name bekannt?)."""
    dns = _domain_of(search_base).lower()
    names = {dns, dns.split(".")[0]} - {""}
    netbios = set()
    try:
        rows = ldap_search(
            conn,
            f"CN=Partitions,{_configuration_nc(conn, search_base)}",
            f"(&(objectClass=crossRef)(nCName={ldap_escape(search_base)}))",
            ["nETBIOSName"],
        )
        netbios = {r.text("nETBIOSName").lower() for r in rows if r.text("nETBIOSName")}
    except Exception as e:  # Konfigurationsbereich nicht lesbar: dann bleibt es beim DNS-Namen
        log.debug("NetBIOS-Name nicht lesbar: %s", type(e).__name__)
    return names | netbios, bool(netbios)


def _whoami(conn):
    """(Domaene, Kontoname) laut DC ('u:DOMAIN\\name'); (None, None), wenn der DC das nicht beantwortet."""
    try:
        who = conn.extend.standard.who_am_i() or ""
    except Exception:
        return None, None
    if isinstance(who, (bytes, bytearray)):
        who = bytes(who).decode("utf-8", "replace")
    who = str(who)
    if who.startswith("u:"):
        who = who[2:]
    if "\\" not in who:
        return None, None
    dom, name = who.split("\\", 1)
    return dom.strip().lower(), name.strip().lower()


def _find_self(conn, search_base, username, bind_user):
    """Sucht das Konto, mit dem tatsaechlich angemeldet wurde (UPN exakt, sonst sAMAccountName).

    Der sAMAccountName wird nur verwendet, wenn die Anmeldung zu dieser Domaene gehoert - sonst koennte
    'administrator@fremde-domaene' oder 'FREMD\\administrator' (Vertrauensstellung) als lokaler Administrator gelten.
    """
    flt_user = "(&(objectClass=user)(!(objectClass=computer))"
    own, netbios_known = _own_names(conn, search_base)
    candidates = []
    sam_allowed = True
    if "@" in bind_user:
        candidates.append(f"{flt_user}(userPrincipalName={ldap_escape(bind_user)}))")
        sam_allowed = bind_user.rsplit("@", 1)[1].strip().lower() in own
    elif "\\" in bind_user:
        sam_allowed = bind_user.split("\\", 1)[0].strip().lower() in own
    if sam_allowed:
        candidates.append(f"{flt_user}(sAMAccountName={ldap_escape(username)}))")
    for flt in candidates:
        rows = ldap_search(conn, search_base, flt, ["sAMAccountName", "mail"])
        if len(rows) > 1:
            log.warning("Anmeldung: %s ist nicht eindeutig (%s Treffer)", username, len(rows))
            return None
        if len(rows) == 1:
            dom, name = _whoami(conn)
            foreign = netbios_known and dom not in own  # ohne bekannten NetBIOS-Namen nur den Kontonamen pruefen
            if name and (name != rows[0].text("sAMAccountName").lower() or foreign):
                log.warning("Anmeldung: DC meldet '%s\\%s', gefunden wurde '%s' - abgelehnt", dom, name, rows[0].dn)
                return None
            return rows[0]
    if not sam_allowed:
        log.warning("Anmeldung mit '%s' gehoert nicht zu dieser Domaene - abgelehnt", bind_user)
    return None


class RoleCheckError(Exception):
    """Die Rolle konnte aus technischen Gruenden nicht bestimmt werden (DC beschaeftigt, Zeitlimit ...)."""


def check_user_role(conn, search_base, username, bind_user="", raise_errors=False):
    """Liefert (Rolle, Fehlermeldung, Mail, sAMAccountName) fuer das angemeldete Konto.

    raise_errors=True: technische Fehler als RoleCheckError melden statt als "keine Rolle" - damit ein kurzer
    DC-Aussetzer nicht wie ein Entzug der Administratorrechte aussieht."""
    try:
        me = _find_self(conn, search_base, username, bind_user or username)
        if me is None:
            return None, "Benutzer wurde im Active Directory nicht gefunden.", "", ""
        user_mail = me.text("mail")
        sam = me.text("sAMAccountName") or username

        # 1. tokenGroups: alle Gruppen inkl. verschachtelter und primaerer Gruppe, als SID
        sids, _ok = protection.read_sids(conn, me.dn, "tokenGroups")
        sids = set(sids)
        # 2. verschachtelte Gruppensuche: liefert Namen (fuer CUSTOM_OPERATOR_GROUP) und zusaetzlich die SIDs
        groups = ldap_search(
            conn,
            search_base,
            f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={ldap_escape(me.dn)}))",
            ["sAMAccountName", "objectSid"],
        )
        group_names = set()
        for g in groups:
            group_names.add(g.text("sAMAccountName").lower())
            sids |= _group_sids(g)

        is_admin = bool(sids & ADMIN_SIDS) or any(_domain_rid(s) in ADMIN_DOMAIN_RIDS for s in sids)
        is_operator = bool(sids & OPERATOR_SIDS) or bool(CUSTOM_OPERATOR_GROUP and CUSTOM_OPERATOR_GROUP in group_names)

        if is_admin:
            return "Administrator", None, user_mail, sam
        if is_operator:
            return "Account Operator", None, user_mail, sam
        if CUSTOM_OPERATOR_GROUP:
            denied = (
                "Zugriff verweigert: Sie müssen Mitglied der Domänen-Admins, der Administratoren, "
                f"der Konten-Operatoren oder der Gruppe '{CUSTOM_OPERATOR_GROUP}' sein."
            )
        else:
            denied = (
                "Zugriff verweigert: Sie müssen Mitglied der Domänen-Admins, der Administratoren "
                "oder der Konten-Operatoren sein."
            )
        return None, denied, "", sam
    except Exception as e:
        log.warning("Rollenpruefung fehlgeschlagen: %s", e)
        if raise_errors:
            raise RoleCheckError(str(e)) from e
        return None, "Die Berechtigungen konnten nicht geprüft werden. Details stehen im Protokoll.", "", ""


def is_admin(user):
    return (user or {}).get("role") == "Administrator"


def reject_special_dn(dn):
    """AD und Samba akzeptieren auch <GUID=...>/<SID=...> als DN. Solche Formen umgehen eine Pruefung am Text des DN
    und werden deshalb abgelehnt (die Oberflaeche sendet immer normale DNs)."""
    text = str(dn or "").strip()
    if not text or text.startswith("<") or "\x00" in text:
        raise HTTPException(status_code=400, detail="Ungültiger DN.")
    return text


def require_user_in_ous(user_dn, ous, what):
    """Serverseitige Pruefung: Das Ziel-Konto muss in einer konfigurierten Quell-OU liegen."""
    reject_special_dn(user_dn)
    ous = [o for o in ous if o]
    if not ous:
        raise HTTPException(status_code=403, detail=f"Keine Quell-OUs für {what} konfiguriert.")
    if not dn_in_any(user_dn, ous):
        raise HTTPException(
            status_code=403, detail="Das Konto liegt nicht in einer für diese Funktion freigegebenen Quell-OU."
        )


def resolve_account(conn, user_dn, ous, what, attrs):
    """Liest das Konto beim DC und prueft die Quell-OU am DN, den der DC zurueckliefert (nicht nur am uebergebenen
    Text). Weitere Aktionen sollen entry.dn verwenden."""
    from .ldap_client import get_object

    require_user_in_ous(user_dn, ous, what)
    entry = get_object(conn, user_dn, attrs, USER_FILTER)  # nur Benutzer - keine Computer- oder Dienstkonten (gMSA)
    if not entry:
        raise HTTPException(status_code=404, detail="Benutzer im AD nicht gefunden.")
    require_user_in_ous(entry.dn, ous, what)
    return entry


def require_not_protected_for_operator(conn, user, entry_dn, action):
    """Geschuetzte Konten (Domaenen-Admins & Co.) duerfen nur Administratoren bearbeiten."""
    if is_admin(user):
        return ""
    reason = protection.privileged_reason(conn, entry_dn)
    if reason:
        raise HTTPException(status_code=403, detail=protection.protected_message(reason, action))
    return ""
