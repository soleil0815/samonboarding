# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Protection of privileged accounts: Domain Admins & co. must not be offboarded or deleted by accident.

What counts is the effective group membership (tokenGroups: includes nested groups and the primary group). The check
recognizes groups by their SID, not by name, and therefore also works with German or renamed groups, and with Samba
just as with Windows.
"""

import logging

import ldap3

from . import acl
from .dn import ldap_escape

log = logging.getLogger(__name__)

# Groups that give the account far-reaching rights (well-known SIDs of the built-in groups)
BUILTIN_GROUPS = {
    "S-1-5-32-544": "Administratoren",
    "S-1-5-32-548": "Konten-Operatoren",
    "S-1-5-32-549": "Server-Operatoren",
    "S-1-5-32-550": "Druck-Operatoren",
    "S-1-5-32-551": "Sicherungs-Operatoren",
}
# Groups with a fixed relative ID (RID) after the domain SID
# Privileged groups of the domain (recognized by RID). Members are protected, and only administrators may add
# anyone to these groups - ONE list for both (520/526/527 also lead to a domain takeover)
DOMAIN_GROUP_RIDS = {
    512: "Domänen-Admins",
    517: "Zertifikatherausgeber",
    518: "Schema-Admins",
    519: "Organisations-Admins",
    520: "Richtlinien-Ersteller-Besitzer",
    526: "Schlüsseladministratoren",
    527: "Organisationsschlüsseladministratoren",
}
# Accounts with a fixed RID
SPECIAL_ACCOUNT_RIDS = {500: "integriertes Administratorkonto", 502: "Kerberos-Dienstkonto (krbtgt)"}


def _lookup(mapping, name):
    for key, value in mapping.items():
        if key.lower() == name.lower():
            return value
    return None


def read_sids(conn, dn, attr, flt="(objectClass=user)"):
    """Reads the SIDs of an attribute (objectSid, tokenGroups) as text. Uses the raw bytes because ldap3 without a
    schema may otherwise interpret binary values as text. Returns (list, read?)."""
    if not conn.search(dn, flt, ldap3.BASE, attributes=[attr]):
        return [], False
    for entry in conn.response or []:
        if entry.get("type") != "searchResEntry":
            continue
        raw = _lookup(entry.get("raw_attributes") or {}, attr)
        values = raw if raw else _lookup(entry.get("attributes") or {}, attr)
        if values is None:
            return [], False
        if not isinstance(values, (list, tuple)):
            values = [values]
        out = []
        for value in values:
            try:
                out.append(acl.sid_from_ldap(value))
            except (acl.AclError, ValueError, TypeError):
                continue
        return out, True
    return [], False


def _sid_list(entry, attr):
    raw = _lookup(entry.get("raw_attributes") or {}, attr)
    values = raw if raw else _lookup(entry.get("attributes") or {}, attr)
    if values is None:
        return [], False
    if not isinstance(values, (list, tuple)):
        values = [values]
    out = []
    for value in values:
        try:
            out.append(acl.sid_from_ldap(value))
        except (acl.AclError, ValueError, TypeError):
            continue
    return out, True


def privileged_reason(conn, user_dn):
    """Reason why the account is protected (empty = not protected). A single LDAP query."""
    if not conn.search(
        user_dn, "(objectClass=user)", ldap3.BASE, attributes=["objectSid", "tokenGroups", "adminCount"]
    ):
        if (getattr(conn, "result", None) or {}).get("result") == 32:  # does not exist - the action fails anyway
            return ""
        # query failed: when in doubt, treat as protected (better to refuse than to modify an admin account)
        log.warning("Schutzpruefung fuer %s nicht moeglich: %s", user_dn, getattr(conn, "result", None))
        return "Schutzprüfung nicht möglich"
    entry = next((e for e in conn.response or [] if e.get("type") == "searchResEntry"), None)
    if entry is None:
        return ""
    own, _ = _sid_list(entry, "objectSid")
    if own and own[0].startswith("S-1-5-21-"):
        rid = own[0].rsplit("-", 1)[-1]
        if rid.isdigit() and int(rid) in SPECIAL_ACCOUNT_RIDS:
            return SPECIAL_ACCOUNT_RIDS[int(rid)]
    groups, _ = _sid_list(entry, "tokenGroups")
    for sid in groups:
        if sid in BUILTIN_GROUPS:
            return f"Mitglied von „{BUILTIN_GROUPS[sid]}“"
        if sid.startswith("S-1-5-21-"):
            rid = sid.rsplit("-", 1)[-1]
            if rid.isdigit() and int(rid) in DOMAIN_GROUP_RIDS:
                return f"Mitglied von „{DOMAIN_GROUP_RIDS[int(rid)]}“"
    if not groups:
        # tokenGroups not readable (otherwise it always contains at least the primary group)
        log.warning("tokenGroups fuer %s nicht lesbar - pruefe adminCount und die verschachtelten Gruppen", user_dn)
        value = _lookup(entry.get("attributes") or {}, "adminCount")
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if str(value) == "1":
            return "als privilegiertes Konto markiert (adminCount)"
        # Samba does not always maintain adminCount: read groups via the nested membership
        return _nested_privileged(conn, user_dn)
    return ""


def _nested_privileged(conn, user_dn):
    """Privileged group via (also nested) membership; when in doubt, 'protected'."""
    base = ",".join(p for p in user_dn.split(",") if p.strip().lower().startswith("dc="))
    try:
        flt = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={ldap_escape(user_dn)}))"
        if not conn.search(base, flt, ldap3.SUBTREE, attributes=["objectSid"]):
            if (getattr(conn, "result", None) or {}).get("result") == 0:
                return ""  # no groups found
            return "Schutzprüfung nicht möglich"
        for entry in conn.response or []:
            if entry.get("type") != "searchResEntry":
                continue
            sids, _ = _sid_list(entry, "objectSid")
            for sid in sids:
                if sid in BUILTIN_GROUPS:
                    return f"Mitglied von „{BUILTIN_GROUPS[sid]}“"
                rid = sid.rsplit("-", 1)[-1]
                if sid.startswith("S-1-5-21-") and rid.isdigit() and int(rid) in DOMAIN_GROUP_RIDS:
                    return f"Mitglied von „{DOMAIN_GROUP_RIDS[int(rid)]}“"
        return ""
    except Exception as e:
        log.warning("Schutzpruefung (Gruppen) fuer %s nicht moeglich: %s", user_dn, e)
        return "Schutzprüfung nicht möglich"


# Groups to which only administrators may add accounts (the same list as for protected accounts)
PRIVILEGED_DOMAIN_GROUP_RIDS = DOMAIN_GROUP_RIDS


def _privileged_name(sid):
    if sid in BUILTIN_GROUPS:
        return BUILTIN_GROUPS[sid]
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid.isdigit() and int(rid) in PRIVILEGED_DOMAIN_GROUP_RIDS:
            return PRIVILEGED_DOMAIN_GROUP_RIDS[int(rid)]
    return ""


def privileged_group(conn, group_dn):
    """Name of the privileged group (recognized by its SID) or empty. A group that is itself a (nested) member of a
    privileged group (e.g. "IT-Admins" in Domain Admins) also counts as privileged - anyone added to it would
    get the same rights."""
    sids, _ok = read_sids(conn, group_dn, "objectSid", "(objectClass=group)")
    for sid in sids:
        name = _privileged_name(sid)
        if name:
            return name
    base = ",".join(p for p in group_dn.split(",") if p.strip().lower().startswith("dc="))
    try:
        flt = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={ldap_escape(group_dn)}))"
        if not conn.search(base, flt, ldap3.SUBTREE, attributes=["objectSid"]):
            if (getattr(conn, "result", None) or {}).get("result") in (0, None):
                return ""  # not in any other group
            return "Gruppenprüfung nicht möglich"
        for entry in conn.response or []:
            if entry.get("type") != "searchResEntry":
                continue
            for sid in _sid_list(entry, "objectSid")[0]:
                name = _privileged_name(sid)
                if name:
                    return f"Mitglied von „{name}“"
    except Exception as e:
        log.warning("Pruefung der uebergeordneten Gruppen von %s nicht moeglich: %s", group_dn, e)
        return "Gruppenprüfung nicht möglich"
    return ""


def protected_message(reason, action):
    return (
        f"Dieses Konto ist geschützt ({reason}) und darf nicht {action} werden. "
        "Soll es trotzdem bearbeitet werden, zuerst die Mitgliedschaft im AD entfernen."
    )


def _search_dns(conn, base, flt, attrs=("cn",)):
    """All results (paged, also beyond 1000) as a list of (dn, entry)."""
    from .ldap_client import ldap_search  # import late (ldap_client uses this module)

    return ldap_search(conn, base, flt, list(attrs))


def privileged_map(conn, base):
    """All protected accounts of the domain with few queries: {dn (lowercase): reason}.

    Instead of querying each account of a list individually (300 accounts = 300 queries), the privileged groups
    are searched once and their members - including nested ones - are read. Only for DISPLAY in lists;
    before every action the account is still checked individually and live (privileged_reason)."""
    dom = read_sids(conn, base, "objectSid", "(objectClass=domain)")[0]
    dom_sid = dom[0] if dom and dom[0].startswith("S-1-5-21-") else ""
    wanted = dict(BUILTIN_GROUPS)
    if dom_sid:
        wanted.update({f"{dom_sid}-{rid}": name for rid, name in DOMAIN_GROUP_RIDS.items()})
    # One search per SID: this way the SID comes from the request, not from the result (without a schema, ldap3
    # returns binary values as text if they happen to be valid UTF-8 - e.g. all S-1-5-32-... of the built-in groups)
    found = {}
    for sid, name in wanted.items():
        for row in _search_dns(conn, base, f"(&(objectClass=group)(objectSid={sid}))"):
            found[row.dn] = name
    if not found:
        raise LookupError("privilegierte Gruppen nicht gefunden")
    out = {}
    da_found = False
    for group_dn, name in found.items():
        members = _search_dns(
            conn, base, f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={ldap_escape(group_dn)}))"
        )
        for row in members:
            out.setdefault(row.dn.lower(), f"Mitglied von „{name}“")
        da_found = da_found or (bool(members) and name == DOMAIN_GROUP_RIDS[512])
    # Plausible? Every domain has at least one Domain Admin. If none comes back, the directory does not support
    # the nested search - then rather check individually than show admins without a lock.
    if not da_found:
        raise LookupError("verschachtelte Gruppensuche liefert keine Domaenen-Admins")
    if dom_sid:
        # primary group (not listed in memberOf) and accounts with a fixed RID
        rids = "".join(f"(primaryGroupID={rid})" for rid in DOMAIN_GROUP_RIDS)
        for row in _search_dns(conn, base, f"(&(objectClass=user)(|{rids}))", ("primaryGroupID",)):
            rid = int(row.text("primaryGroupID") or 0)
            out.setdefault(row.dn.lower(), f"Mitglied von „{DOMAIN_GROUP_RIDS.get(rid, '')}“")
        specials = "".join(f"(objectSid={dom_sid}-{rid})" for rid in SPECIAL_ACCOUNT_RIDS)
        for row in _search_dns(conn, base, f"(&(objectClass=user)(|{specials}))", ("objectSid",)):
            out.setdefault(row.dn.lower(), "geschütztes Systemkonto")
    return out


def mark_protected(conn, users):
    """Adds the field 'protected' (reason) to lists. First with a bulk query (fast); if that fails (e.g. a
    directory without the required search features), each account is checked individually."""
    for entry in users:
        entry.pop("_adminCount", None)
    if not users:
        return users
    base = ",".join(p for p in users[0]["dn"].split(",") if p.strip().lower().startswith("dc="))
    try:
        known = privileged_map(conn, base)
    except Exception as e:
        log.info("Sammelpruefung geschuetzter Konten nicht moeglich (%s) - pruefe einzeln", e)
        known = None
    for entry in users:
        if known is not None:
            entry["protected"] = known.get(entry["dn"].lower(), "")
            continue
        try:
            entry["protected"] = privileged_reason(conn, entry["dn"])
        except Exception as e:  # the list should still appear; actions are re-checked anyway
            log.warning("Schutzpruefung fuer %s fehlgeschlagen: %s", entry.get("dn"), e)
            entry["protected"] = ""
    return users
