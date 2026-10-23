"""Verweise auf AD-Objekte in den Einstellungen: was passiert, wenn eine OU oder Gruppe umbenannt oder verschoben wird?

Gespeichert wird in den Einstellungen der DN (so wie ihn RSAT anzeigt), z. B. die Ziel-OU eines Templates oder die
Quell-OUs des Offboardings. Wird das Objekt im AD umbenannt oder verschoben, zeigt der DN ins Leere. Das Programm
bleibt dabei sicher (eine fehlende OU liefert keine Konten, eine fehlende Gruppe wird nicht zugewiesen), aber die
Funktion arbeitet nicht mehr wie gedacht.

Darum merkt sich das Programm zu jedem Verweis die objectGUID (data/verweise.json - nur DN und GUID, keine
Personendaten). Die GUID bleibt bei Umbenennen und Verschieben gleich. Die Pruefung (nur Administratoren) meldet:
  moved     Objekt umbenannt/verschoben - neuer DN gefunden, mit einem Klick uebernehmbar
  replaced  unter dem alten Namen steht ein ANDERES Objekt (geloescht und neu angelegt) - bitte bestaetigen
  missing   Objekt nicht mehr vorhanden - Einstellung von Hand anpassen
Rollen (Administrator/Kontenoperator) haengen ohnehin an SIDs, nicht an Namen; die Wiederherstellung nutzt GUIDs.
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

# Einstellungsdatei -> (Bereich, {Feld: Bezeichnung}); ein Feld enthaelt einen DN oder eine Liste von DNs
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
    """Ruft fn(dn, bezeichnung) fuer jeden DN in den Feldern auf; ersetzt ihn durch den Rueckgabewert."""
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
                seen = set()  # nach dem Umbenennen nicht zweimal dieselbe OU/Gruppe
                out = [v for v in out if not (isinstance(v, str) and (v.lower() in seen or seen.add(v.lower())))]
                obj[field], changed = out, True
    return changed


def _visit(fn, write=False):
    """Alle Verweise durchlaufen: fn(dn, wo) -> dn. Mit write=True werden geaenderte Dateien gespeichert."""
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
    """{dn_klein: (dn, [wo, ...])} - jeder DN einmal, mit allen Stellen, an denen er verwendet wird.
    wo = {"label": "Offboarding: Quell-OU"} bzw. {"label": "Template: Gruppe", "template": "<Name>"}"""
    found = {}

    def note(dn, where):
        found.setdefault(dn.lower(), (dn, []))[1].append(where)
        return dn

    _visit(note)
    return found


def _guid_of(conn, row):
    """GUID aus den Rohbytes (read_guid) - ohne Schema koennte ldap3 sie sonst als Text verfaelschen."""
    return read_guid(conn, row.dn) if row else ""


def _find_by_guid(conn, base, guid):
    try:
        rows = ldap_search(conn, base, guid_filter(guid), ["objectGUID"])
    except (LDAPException, ValueError):
        return None
    return rows[0].dn if rows else None


def check(conn, base):
    """Prueft alle Verweise. Liefert die Probleme; merkt sich die GUIDs der gefundenen Objekte."""
    known = load_json(FILE, {})
    known = known if isinstance(known, dict) else {}
    remember, problems = {}, []
    for key, (dn, where) in sorted(collect().items()):
        old_guid = str(known.get(key) or "")
        try:
            row = get_object(conn, dn, ["objectGUID"], "(objectClass=*)")
        except (AdError, LDAPException) as e:  # nicht pruefbar (z. B. DC beschaeftigt) - nichts vergessen
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
            remember[key] = old_guid  # bleibt gemeldet, bis es behoben oder bestaetigt ist
        problems.append({"kind": kind, "dn": dn, "newDn": new_dn if kind == "moved" else "", "where": where})
    if remember != known:
        save_json(FILE, remember, invalidate=False)  # nur Merkliste - die Kontolisten bleiben gueltig
    return problems


def repair(conn, base):
    """Uebernimmt neue DNs (moved) in alle Einstellungen und bestaetigt ersetzte Objekte (replaced).
    Prueft dafuer selbst neu - der Browser liefert nur den Auftrag, keine DNs."""
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
        except (AdError, LDAPException):  # DC kurz weg: bleibt gemeldet, die Einstellungen sind schon angepasst
            guid = ""
        if guid:
            known[dn.lower()] = guid
    save_json(FILE, known)
    return [{"dn": p["dn"], "newDn": p["newDn"], "kind": p["kind"]} for p in problems if p["kind"] != "missing"]
