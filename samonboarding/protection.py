"""Schutz privilegierter Konten: Domaenen-Admins & Co. duerfen nicht versehentlich offgeboardet oder geloescht werden.

Massgeblich ist die tatsaechliche Gruppenmitgliedschaft (tokenGroups: enthaelt verschachtelte Gruppen und die primaere
Gruppe). Die Pruefung erkennt die Gruppen an ihrer SID, nicht am Namen, und funktioniert deshalb auch mit deutschen
oder umbenannten Gruppen und mit Samba genauso wie mit Windows.
"""

import logging

import ldap3

from . import acl
from .dn import ldap_escape

log = logging.getLogger(__name__)

# Gruppen, die dem Konto weitreichende Rechte geben (feste SIDs der eingebauten Gruppen)
BUILTIN_GROUPS = {
    "S-1-5-32-544": "Administratoren",
    "S-1-5-32-548": "Konten-Operatoren",
    "S-1-5-32-549": "Server-Operatoren",
    "S-1-5-32-550": "Druck-Operatoren",
    "S-1-5-32-551": "Sicherungs-Operatoren",
}
# Gruppen mit festem Relativ-Teil (RID) hinter der Domaenen-SID
DOMAIN_GROUP_RIDS = {512: "Domänen-Admins", 518: "Schema-Admins", 519: "Organisations-Admins"}
# Konten mit festem RID
SPECIAL_ACCOUNT_RIDS = {500: "integriertes Administratorkonto", 502: "Kerberos-Dienstkonto (krbtgt)"}


def _lookup(mapping, name):
    for key, value in mapping.items():
        if key.lower() == name.lower():
            return value
    return None


def read_sids(conn, dn, attr, flt="(objectClass=user)"):
    """Liest SIDs eines Attributs (objectSid, tokenGroups) als Text. Nutzt die Rohbytes, weil ldap3 Binaerwerte
    ohne Schema sonst unter Umstaenden als Text deutet. Liefert (Liste, gelesen?)."""
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
    """Begruendung, warum das Konto geschuetzt ist (leer = nicht geschuetzt). Eine einzige LDAP-Abfrage."""
    if not conn.search(
        user_dn, "(objectClass=user)", ldap3.BASE, attributes=["objectSid", "tokenGroups", "adminCount"]
    ):
        if (getattr(conn, "result", None) or {}).get("result") == 32:  # gibt es nicht - die Aktion scheitert ohnehin
            return ""
        # Abfrage fehlgeschlagen: im Zweifel als geschuetzt behandeln (lieber abweisen als ein Admin-Konto aendern)
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
        # tokenGroups nicht lesbar (enthaelt sonst immer mindestens die primaere Gruppe)
        log.warning("tokenGroups fuer %s nicht lesbar - pruefe adminCount und die verschachtelten Gruppen", user_dn)
        value = _lookup(entry.get("attributes") or {}, "adminCount")
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if str(value) == "1":
            return "als privilegiertes Konto markiert (adminCount)"
        # Samba pflegt adminCount nicht immer: Gruppen ueber die verschachtelte Mitgliedschaft lesen
        return _nested_privileged(conn, user_dn)
    return ""


def _nested_privileged(conn, user_dn):
    """Privilegierte Gruppe ueber die (auch verschachtelte) Mitgliedschaft; im Zweifel 'geschuetzt'."""
    base = ",".join(p for p in user_dn.split(",") if p.strip().lower().startswith("dc="))
    try:
        flt = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={ldap_escape(user_dn)}))"
        if not conn.search(base, flt, ldap3.SUBTREE, attributes=["objectSid"]):
            if (getattr(conn, "result", None) or {}).get("result") == 0:
                return ""  # keine Gruppen gefunden
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


# Gruppen, in die nur Administratoren Konten aufnehmen duerfen (zusaetzlich zu den Gruppen oben)
PRIVILEGED_DOMAIN_GROUP_RIDS = {
    **DOMAIN_GROUP_RIDS,
    517: "Zertifikatherausgeber",
    520: "Richtlinien-Ersteller-Besitzer",
    526: "Schlüsseladministratoren",
    527: "Organisationsschlüsseladministratoren",
}


def _privileged_name(sid):
    if sid in BUILTIN_GROUPS:
        return BUILTIN_GROUPS[sid]
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid.isdigit() and int(rid) in PRIVILEGED_DOMAIN_GROUP_RIDS:
            return PRIVILEGED_DOMAIN_GROUP_RIDS[int(rid)]
    return ""


def privileged_group(conn, group_dn):
    """Name der privilegierten Gruppe (an ihrer SID erkannt) oder leer. Auch eine Gruppe, die selbst (verschachtelt)
    Mitglied einer privilegierten Gruppe ist (z. B. "IT-Admins" in den Domaenen-Admins), gilt als privilegiert -
    wer dort aufgenommen wird, bekaeme dieselben Rechte."""
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
                return ""  # in keiner anderen Gruppe
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
    """Alle Treffer (paged, auch ueber 1000) als Liste von (dn, Eintrag)."""
    from .ldap_client import ldap_search  # spaet importieren (ldap_client nutzt dieses Modul)

    return ldap_search(conn, base, flt, list(attrs))


def privileged_map(conn, base):
    """Alle geschuetzten Konten der Domaene mit wenigen Abfragen: {dn (klein): Begruendung}.

    Statt fuer jedes Konto einer Liste einzeln nachzufragen (300 Konten = 300 Abfragen), werden die privilegierten
    Gruppen einmal gesucht und ihre - auch verschachtelten - Mitglieder gelesen. Nur fuer die ANZEIGE in Listen;
    vor jeder Aktion wird das Konto weiterhin einzeln und live geprueft (privileged_reason)."""
    dom = read_sids(conn, base, "objectSid", "(objectClass=domain)")[0]
    dom_sid = dom[0] if dom and dom[0].startswith("S-1-5-21-") else ""
    wanted = dict(BUILTIN_GROUPS)
    if dom_sid:
        wanted.update({f"{dom_sid}-{rid}": name for rid, name in DOMAIN_GROUP_RIDS.items()})
    # Je SID eine eigene Suche: die SID kommt so aus der Anfrage, nicht aus dem Ergebnis (ohne Schema liefert ldap3
    # Binaerwerte als Text, wenn sie zufaellig gueltiges UTF-8 sind - z. B. alle S-1-5-32-... der eingebauten Gruppen)
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
    # Plausibel? In jeder Domaene gibt es mindestens einen Domaenen-Admin. Kommt keiner zurueck, kann das Verzeichnis
    # die verschachtelte Suche nicht - dann lieber einzeln pruefen als Admins ohne Schloss anzeigen.
    if not da_found:
        raise LookupError("verschachtelte Gruppensuche liefert keine Domaenen-Admins")
    if dom_sid:
        # primaere Gruppe (steht nicht in memberOf) und Konten mit festem RID
        rids = "".join(f"(primaryGroupID={rid})" for rid in DOMAIN_GROUP_RIDS)
        for row in _search_dns(conn, base, f"(&(objectClass=user)(|{rids}))", ("primaryGroupID",)):
            rid = int(row.text("primaryGroupID") or 0)
            out.setdefault(row.dn.lower(), f"Mitglied von „{DOMAIN_GROUP_RIDS.get(rid, '')}“")
        specials = "".join(f"(objectSid={dom_sid}-{rid})" for rid in SPECIAL_ACCOUNT_RIDS)
        for row in _search_dns(conn, base, f"(&(objectClass=user)(|{specials}))", ("objectSid",)):
            out.setdefault(row.dn.lower(), "geschütztes Systemkonto")
    return out


def mark_protected(conn, users):
    """Ergaenzt in Listen das Feld 'protected' (Begruendung). Zuerst mit einer Sammelabfrage (schnell); klappt die
    nicht (z. B. ein Verzeichnis ohne die noetigen Suchfunktionen), wird jedes Konto einzeln geprueft."""
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
        except Exception as e:  # Liste soll trotzdem erscheinen, ausgefuehrt wird ohnehin erneut geprueft
            log.warning("Schutzpruefung fuer %s fehlgeschlagen: %s", entry.get("dn"), e)
            entry["protected"] = ""
    return users
