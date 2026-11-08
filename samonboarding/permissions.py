# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Permissions: role check at login and server-side check of the allowed OUs."""

import logging

import ldap3
from fastapi import HTTPException

from . import acl, protection, timing
from .config import CUSTOM_OPERATOR_GROUP, USER_FILTER
from .dn import dn_in_any, ldap_escape
from .ldap_client import ldap_search

log = logging.getLogger(__name__)


def require_admin(user, message):
    if user.get("role") != "Administrator":
        raise HTTPException(status_code=403, detail=message)


# Roles are recognized by the well-known SIDs of the groups, never by name: on German DCs the groups are called
# "Administratoren"/"Domänen-Admins"; the English names would be unused there and could be taken by anyone
# allowed to create groups.
ADMIN_SIDS = {"S-1-5-32-544"}  # BUILTIN\Administrators
ADMIN_DOMAIN_RIDS = {512, 519}  # Domain Admins, Enterprise Admins
OPERATOR_SIDS = {"S-1-5-32-548"}  # BUILTIN\Account Operators


def _domain_rid(sid):
    if not sid.startswith("S-1-5-21-"):
        return None
    rid = sid.rsplit("-", 1)[-1]
    return int(rid) if rid.isdigit() else None


def _role_from(sids, custom_hit):
    """Administrator, Account Operator or None - recognized by SIDs, never by group names."""
    if sids & ADMIN_SIDS or any(_domain_rid(s) in ADMIN_DOMAIN_RIDS for s in sids):
        return "Administrator"
    if sids & OPERATOR_SIDS or custom_hit:
        return "Account Operator"
    return None


def _custom_group_sids(conn, search_base):
    """SID(s) of the own operator group (CUSTOM_OPERATOR_GROUP), looked up by its name."""
    rows = ldap_search(
        conn, search_base, f"(&(objectClass=group)(sAMAccountName={ldap_escape(CUSTOM_OPERATOR_GROUP)}))", ["objectSid"]
    )
    out = set()
    for row in rows:
        out |= _group_sids(row)
    return out


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
    """Configuration partition according to the RootDSE. In a child domain it is under the forest root, not
    under the domain itself; without an answer, the single-domain assumption is used."""
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
    """(Names under which an account of THIS domain can log in, NetBIOS name known?)."""
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
    except Exception as e:  # configuration partition not readable: keep the DNS name
        log.debug("NetBIOS-Name nicht lesbar: %s", type(e).__name__)
    return names | netbios, bool(netbios)


def _whoami(conn):
    """(domain, account name) according to the DC ('u:DOMAIN\\name'); (None, None) if the DC does not answer."""
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
    """Finds the account that was actually used to log in (exact UPN, otherwise sAMAccountName).

    The sAMAccountName is used only if the login belongs to this domain - otherwise
    'administrator@fremde-domaene' or 'FREMD\\administrator' (trust) could count as the local administrator.
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
            foreign = netbios_known and dom not in own  # without a known NetBIOS name, check only the account name
            if name and (name != rows[0].text("sAMAccountName").lower() or foreign):
                log.warning("Anmeldung: DC meldet '%s\\%s', gefunden wurde '%s' - abgelehnt", dom, name, rows[0].dn)
                return None
            return rows[0]
    if not sam_allowed:
        log.warning("Anmeldung mit '%s' gehoert nicht zu dieser Domaene - abgelehnt", bind_user)
    return None


class RoleCheckError(Exception):
    """The role could not be determined for technical reasons (DC busy, time limit ...)."""


def check_user_role(conn, search_base, username, bind_user="", raise_errors=False):
    """Returns (role, error message, mail, sAMAccountName) for the logged-in account.

    raise_errors=True: report technical errors as RoleCheckError instead of "no role" - so that a brief
    DC outage does not look like a revocation of administrator rights."""
    try:
        me = _find_self(conn, search_base, username, bind_user or username)
        if me is None:
            return None, "Benutzer wurde im Active Directory nicht gefunden.", "", ""
        user_mail = me.text("mail")
        sam = me.text("sAMAccountName") or username

        with timing.timed("role"):
            # 1. tokenGroups: all groups incl. nested and primary group, as SIDs - one cheap read of the own
            #    account. The own operator group (CUSTOM_OPERATOR_GROUP) is looked up once by name (indexed).
            sids, token_ok = protection.read_sids(conn, me.dn, "tokenGroups")
            sids = set(sids)
            custom_hit = bool(CUSTOM_OPERATOR_GROUP and token_ok and _custom_group_sids(conn, search_base) & sids)
            role = _role_from(sids, custom_hit)
            if role is None:
                # 2. Only if tokenGroups does not already decide (unreadable, or no role found): the nested
                #    group search across the domain. It is expensive (especially on Samba), so it is the fallback.
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
                role = _role_from(sids, bool(CUSTOM_OPERATOR_GROUP and CUSTOM_OPERATOR_GROUP in group_names))
        if role:
            return role, None, user_mail, sam
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
    """AD and Samba also accept <GUID=...>/<SID=...> as DN. Such forms bypass a check on the DN text
    and are therefore rejected (the UI always sends normal DNs)."""
    text = str(dn or "").strip()
    if not text or text.startswith("<") or "\x00" in text:
        raise HTTPException(status_code=400, detail="Ungültiger DN.")
    return text


def require_user_in_ous(user_dn, ous, what):
    """Server-side check: the target account must be in a configured source OU."""
    reject_special_dn(user_dn)
    ous = [o for o in ous if o]
    if not ous:
        raise HTTPException(status_code=403, detail=f"Keine Quell-OUs für {what} konfiguriert.")
    if not dn_in_any(user_dn, ous):
        raise HTTPException(
            status_code=403, detail="Das Konto liegt nicht in einer für diese Funktion freigegebenen Quell-OU."
        )


def resolve_account(conn, user_dn, ous, what, attrs):
    """Reads the account from the DC and checks the source OU against the DN returned by the DC (not just the
    text passed in). Further actions should use entry.dn."""
    from .ldap_client import get_object

    require_user_in_ous(user_dn, ous, what)
    entry = get_object(conn, user_dn, attrs, USER_FILTER)  # users only - no computer or service accounts (gMSA)
    if not entry:
        raise HTTPException(status_code=404, detail="Benutzer im AD nicht gefunden.")
    require_user_in_ous(entry.dn, ous, what)
    return entry


def require_not_protected_for_operator(conn, user, entry_dn, action):
    """Only administrators may edit protected accounts (Domain Admins & co.)."""
    if is_admin(user):
        return ""
    reason = protection.privileged_reason(conn, entry_dn)
    if reason:
        raise HTTPException(status_code=403, detail=protection.protected_message(reason, action))
    return ""
