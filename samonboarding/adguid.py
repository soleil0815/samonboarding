# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""objectGUID: the permanent identifier of an AD object. It stays the same when an account or group is renamed or
moved. This lets the restore after offboarding find objects again even under a new name."""

import uuid

import ldap3


def guid_from_ldap(value):
    """objectGUID from LDAP (16 bytes, Windows byte order) or as text -> GUID text. Empty if invalid."""
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
    """LDAP filter part for a GUID, e.g. (objectGUID=\\67\\45...)."""
    raw = uuid.UUID(guid).bytes_le
    return "(objectGUID=" + "".join(f"\\{b:02x}" for b in raw) + ")"


def _lookup(mapping, name):
    for key, value in (mapping or {}).items():
        if str(key).lower() == name.lower():
            return value
    return None


def read_guid(conn, dn, flt="(objectClass=*)"):
    """Reads the objectGUID of an object (raw bytes preferred). Empty if not readable."""
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
