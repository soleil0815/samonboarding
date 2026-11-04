# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""References to AD objects in the settings: what happens when an OU or group is renamed or moved?

The settings store the DN (as RSAT shows it), e.g. a template's target OU or the offboarding source OUs. If the object
is renamed or moved in AD, the DN points nowhere. The program stays safe (a missing OU yields no accounts, a missing
group is not assigned), but the feature no longer works as intended.

Therefore the program remembers the objectGUID for each reference (data/verweise.json - only DN and GUID, no
personal data). The GUID stays the same across rename and move. The check (administrators only) reports:
  moved     object renamed/moved - new DN found, can be applied with one click
  replaced  a DIFFERENT object now has the old name (deleted and recreated) - please confirm
  missing   object no longer exists - adjust the setting by hand
Roles (administrator/account operator) are bound to SIDs anyway, not to names; restore uses GUIDs.
"""

import logging
import os

from ldap3.core.exceptions import LDAPException

from . import config
from .adguid import guid_filter, read_guid
from .errors import AdError
from .ldap_client import get_object, ldap_search
from .storage import file_lock, load_json, save_json

log = logging.getLogger(__name__)

FILE = os.path.join(str(config.DATA_DIR), "verweise.json")

# Settings file -> (section, {field: label}); a field contains a DN or a list of DNs
SETTINGS = (
    (config.OFFBOARDING_CONFIG_FILE, "Offboarding", {"sourceOus": "Quell-OU", "targetOu": "Ziel-OU"}),
    (config.PWDRESET_CONFIG_FILE, "Passwort-Reset", {"sourceOus": "Quell-OU"}),
    (
        config.USERMGMT_CONFIG_FILE,
        "Benutzerverwaltung",
        {"sourceOus": "Quell-OU", "targetOus": "Ziel-OU", "groupOus": "Gruppen-OU"},
    ),
    (config.DELETION_CONFIG_FILE, "Löschen", {"disabledOu": "OU deaktivierter Konten"}),
)
TEMPLATE_FIELDS = {"ouDn": "Ziel-OU", "groups": "Gruppe"}


def _fields(obj, fields, fn):
    """Call fn(dn, label) for every DN in the fields; replace it with the return value."""
    changed = False
    for field, label in fields.items():
        value = obj.get(field)
        if isinstance(value, str) and value.strip():
            new = fn(value.strip(), label)
            if new != value:
                obj[field], changed = new, True
        elif isinstance(value, list):
            out = [fn(v.strip(), label) if isinstance(v, str) and v.strip() else v for v in value]
            if out != value:
                seen = set()  # after renaming, do not keep the same OU/group twice
                out = [v for v in out if not (isinstance(v, str) and (v.lower() in seen or seen.add(v.lower())))]
                obj[field], changed = out, True
    return changed


def _visit(fn, write=False):
    """Walk all references: fn(dn, where) -> dn. With write=True, changed files are saved."""
    with file_lock:
        for path, area, fields in SETTINGS:
            cfg = load_json(path, {})
            if not isinstance(cfg, dict):
                continue
            if _fields(cfg, fields, lambda dn, label, a=area: fn(dn, {"label": f"{a}: {label}"})) and write:
                save_json(path, cfg)
        tmpls = load_json(config.TEMPLATES_FILE, [])
        changed = False
        for tmpl in tmpls if isinstance(tmpls, list) else []:
            if isinstance(tmpl, dict):
                name = str(tmpl.get("name") or "?")
                changed |= _fields(
                    tmpl,
                    TEMPLATE_FIELDS,
                    lambda dn, label, n=name: fn(dn, {"label": f"Template: {label}", "template": n}),
                )
        if changed and write:
            save_json(config.TEMPLATES_FILE, tmpls)


def collect():
    """{dn_lower: (dn, [where, ...])} - each DN once, with every place it is used.
    where = {"label": "Offboarding: Quell-OU"} or {"label": "Template: Gruppe", "template": "<Name>"}"""
    found = {}

    def note(dn, where):
        found.setdefault(dn.lower(), (dn, []))[1].append(where)
        return dn

    _visit(note)
    return found


def _guid_of(conn, row):
    """GUID from the raw bytes (read_guid) - without a schema, ldap3 could otherwise mangle it as text."""
    return read_guid(conn, row.dn) if row else ""


def _find_by_guid(conn, base, guid):
    try:
        rows = ldap_search(conn, base, guid_filter(guid), ["objectGUID"])
    except (LDAPException, ValueError):
        return None
    return rows[0].dn if rows else None


def check(conn, base):
    """Check all references. Returns the problems; remembers the GUIDs of the objects found."""
    known = load_json(FILE, {})
    known = known if isinstance(known, dict) else {}
    remember, problems = {}, []
    for key, (dn, where) in sorted(collect().items()):
        old_guid = str(known.get(key) or "")
        try:
            row = get_object(conn, dn, ["objectGUID"], "(objectClass=*)")
        except (AdError, LDAPException) as e:  # cannot be checked (e.g. DC busy) - forget nothing
            log.info("Verweis %s nicht pruefbar: %s", dn, e)
            if old_guid:
                remember[key] = old_guid
            continue
        guid = _guid_of(conn, row)
        if row and (not old_guid or not guid or guid == old_guid):
            if guid or old_guid:
                remember[key] = guid or old_guid
            continue
        new_dn = _find_by_guid(conn, base, old_guid) if old_guid else None
        if new_dn and new_dn.lower() != key:
            kind = "moved"
        elif row:
            kind = "replaced"
        else:
            kind = "missing"
        if old_guid:
            remember[key] = old_guid  # stays reported until fixed or confirmed
        problems.append({"kind": kind, "dn": dn, "newDn": new_dn if kind == "moved" else "", "where": where})
    if remember != known:
        save_json(FILE, remember, invalidate=False)  # only the watch list - the account lists stay valid
    return problems


def repair(conn, base):
    """Apply new DNs (moved) to all settings and confirm replaced objects (replaced).
    Re-checks on its own for this - the browser only sends the request, no DNs."""
    problems = check(conn, base)
    moves = {p["dn"].lower(): p["newDn"] for p in problems if p["kind"] == "moved" and p["newDn"]}
    replaced = [p["dn"] for p in problems if p["kind"] == "replaced"]
    if moves:
        _visit(lambda dn, where: moves.get(dn.lower(), dn), write=True)
    known = load_json(FILE, {})
    known = known if isinstance(known, dict) else {}
    for old, new in moves.items():
        guid = known.pop(old, "")
        if guid:
            known[new.lower()] = guid
    for dn in replaced:
        try:
            guid = _guid_of(conn, get_object(conn, dn, ["objectGUID"], "(objectClass=*)"))
        except (AdError, LDAPException):  # DC briefly unavailable: stays reported, the settings are already updated
            guid = ""
        if guid:
            known[dn.lower()] = guid
    save_json(FILE, known)
    return [{"dn": p["dn"], "newDn": p["newDn"], "kind": p["kind"]} for p in problems if p["kind"] != "missing"]
