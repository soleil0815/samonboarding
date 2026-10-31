# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""objectGUID: die feste Kennung eines AD-Objekts. Sie bleibt gleich, wenn ein Konto oder eine Gruppe umbenannt oder
verschoben wird. Damit findet die Wiederherstellung nach dem Offboarding Objekte auch unter neuem Namen wieder."""

import uuid

import ldap3


def guid_from_ldap(value):
    """objectGUID aus LDAP (16 Bytes, Windows-Reihenfolge) oder als Text -> GUID-Text. Leer, wenn ungueltig."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, (bytes, bytearray)):
        return str(uuid.UUID(bytes_le=bytes(value))) if len(value) == 16 else ""
    text = str(value or "").strip().strip("{}")
    try:
        return str(uuid.UUID(text)) if text else ""
    except ValueError:
        return ""


def guid_filter(guid):
    """LDAP-Filterteil fuer eine GUID, z. B. (objectGUID=\\67\\45...)."""
    raw = uuid.UUID(guid).bytes_le
    return "(objectGUID=" + "".join(f"\\{b:02x}" for b in raw) + ")"


def _lookup(mapping, name):
    for key, value in (mapping or {}).items():
        if str(key).lower() == name.lower():
            return value
    return None


def read_guid(conn, dn, flt="(objectClass=*)"):
    """Liest die objectGUID eines Objekts (Rohbytes bevorzugt). Leer, wenn nicht lesbar."""
    try:
        if not conn.search(dn, flt, ldap3.BASE, attributes=["objectGUID"]):
            return ""
    except Exception:
        return ""
    for entry in conn.response or []:
        if entry.get("type") != "searchResEntry":
            continue
        value = _lookup(entry.get("raw_attributes"), "objectGUID") or _lookup(entry.get("attributes"), "objectGUID")
        return guid_from_ldap(value)
    return ""
