"""Windows-Sicherheitsbeschreibungen (Security Descriptor, binaer): lesen, um einen Eintrag ergaenzen, schreiben.

Das ist nur der kleine Ausschnitt, der gebraucht wird: einen Besitzer setzen und eine Zugriffsberechtigung (ACE)
hinzufuegen. Alles andere in der Berechtigungsliste bleibt unveraendert, auch unbekannte ACE-Typen (Rohbytes).
Ist gar keine Berechtigungsliste vorhanden (NULL-DACL = Zugriff fuer alle), wird nichts veraendert, weil ein
Hinzufuegen den Ordner sonst ploetzlich einschraenken wuerde.
"""

import struct
from dataclasses import dataclass, field

SID_ADMINISTRATORS = "S-1-5-32-544"  # BUILTIN\Administrators

FILE_ALL_ACCESS = 0x001F01FF

ACE_ACCESS_ALLOWED = 0x00
ACE_ACCESS_DENIED = 0x01
ACE_SYSTEM_AUDIT = 0x02
_SIMPLE_ACE_TYPES = (ACE_ACCESS_ALLOWED, ACE_ACCESS_DENIED, ACE_SYSTEM_AUDIT)

ACE_OBJECT_INHERIT = 0x01
ACE_CONTAINER_INHERIT = 0x02
ACE_INHERIT_ONLY = 0x08
ACE_INHERITED = 0x10
INHERIT_FLAGS = ACE_OBJECT_INHERIT | ACE_CONTAINER_INHERIT

SE_DACL_PRESENT = 0x0004
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_DACL_AUTO_INHERITED = 0x0400
SE_DACL_PROTECTED = 0x1000
SE_SELF_RELATIVE = 0x8000
_PRESERVED_CONTROL = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED

SECINFO_OWNER = 0x00000001
SECINFO_GROUP = 0x00000002
SECINFO_DACL = 0x00000004

MAX_ACL_SIZE = 0xFFFF


class AclError(ValueError):
    """Sicherheitsbeschreibung nicht lesbar oder nicht sicher aenderbar."""


# ---------------------------------------------------------------------------
# SID
# ---------------------------------------------------------------------------
def sid_to_bytes(sid):
    parts = str(sid).split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise AclError(f"Ungültige SID: {sid!r}")
    try:
        revision, authority = int(parts[1]), int(parts[2])
        subs = [int(p) for p in parts[3:]]
    except ValueError as e:
        raise AclError(f"Ungültige SID: {sid!r}") from e
    if revision != 1 or not 0 <= authority < 2**48 or len(subs) > 15 or any(not 0 <= s < 2**32 for s in subs):
        raise AclError(f"Ungültige SID: {sid!r}")
    return (
        bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + b"".join(struct.pack("<I", sub) for sub in subs)
    )


def sid_from_bytes(data, offset=0):
    """Liest eine SID aus data ab offset. Liefert (SID-Text, Laenge in Bytes)."""
    if len(data) < offset + 8:
        raise AclError("SID abgeschnitten.")
    revision = data[offset]
    count = data[offset + 1]
    length = 8 + 4 * count
    if revision != 1 or count > 15 or len(data) < offset + length:
        raise AclError("Ungültige SID im Sicherheitsdeskriptor.")
    authority = int.from_bytes(data[offset + 2 : offset + 8], "big")
    subs = struct.unpack_from("<" + "I" * count, data, offset + 8)
    return "S-1-" + "-".join(str(x) for x in (authority, *subs)), length


def sid_from_ldap(raw):
    """objectSid aus LDAP (Bytes) -> SID-Text. Ein bereits lesbarer Text ('S-1-5-21-...') wird durchgereicht."""
    if isinstance(raw, (bytes, bytearray)):
        sid, length = sid_from_bytes(bytes(raw))
        if length != len(raw):
            raise AclError("objectSid hat unerwartete Länge.")
        return sid
    text = str(raw or "").strip()
    sid_to_bytes(text)  # prueft das Format
    return text


# ---------------------------------------------------------------------------
# ACE / ACL / Security Descriptor
# ---------------------------------------------------------------------------
@dataclass
class Ace:
    ace_type: int
    flags: int
    mask: int = 0
    sid: str = ""
    raw: bytes = b""  # gelesene ACEs bleiben als Originalbytes erhalten (byte-genaues Zurueckschreiben)

    def to_bytes(self):
        if self.raw:
            return self.raw
        sid = sid_to_bytes(self.sid)
        size = 8 + len(sid)
        return struct.pack("<BBHI", self.ace_type, self.flags, size, self.mask) + sid


@dataclass
class SecurityDescriptor:
    control: int = SE_SELF_RELATIVE
    owner: str | None = None
    group: str | None = None
    dacl: list = field(default_factory=list)  # None = keine DACL vorhanden (NULL-DACL)
    dacl_revision: int = 2


def parse_sd(data):
    data = bytes(data)
    if len(data) < 20:
        raise AclError("Sicherheitsdeskriptor zu kurz.")
    revision, _sbz, control, off_owner, off_group, _off_sacl, off_dacl = struct.unpack_from("<BBHIIII", data, 0)
    if revision != 1:
        raise AclError("Unbekannte Revision des Sicherheitsdeskriptors.")
    if not control & SE_SELF_RELATIVE:
        raise AclError("Sicherheitsdeskriptor ist nicht im selbstbezogenen Format.")
    sd = SecurityDescriptor(control=control)
    if off_owner:
        sd.owner, _ = sid_from_bytes(data, off_owner)
    if off_group:
        sd.group, _ = sid_from_bytes(data, off_group)
    if control & SE_DACL_PRESENT and off_dacl:
        sd.dacl, sd.dacl_revision = _parse_acl(data, off_dacl)
    else:
        sd.dacl = None
    return sd


def _parse_acl(data, offset):
    if len(data) < offset + 8:
        raise AclError("ACL abgeschnitten.")
    revision, _sbz, size, count, _sbz2 = struct.unpack_from("<BBHHH", data, offset)
    if size < 8 or offset + size > len(data):
        raise AclError("ACL hat ungültige Größe.")
    aces, pos, end = [], offset + 8, offset + size
    for _ in range(count):
        if pos + 4 > end:
            raise AclError("ACE abgeschnitten.")
        ace_type, flags, ace_size = struct.unpack_from("<BBH", data, pos)
        if ace_size < 4 or pos + ace_size > end:
            raise AclError("ACE hat ungültige Größe.")
        raw = data[pos : pos + ace_size]
        if ace_type in _SIMPLE_ACE_TYPES and ace_size >= 16:
            (mask,) = struct.unpack_from("<I", data, pos + 4)
            sid, sid_len = sid_from_bytes(data, pos + 8)
            if 8 + sid_len <= ace_size:
                aces.append(Ace(ace_type, flags, mask, sid, raw))
                pos += ace_size
                continue
        aces.append(Ace(ace_type, flags, raw=raw))
        pos += ace_size
    return aces, revision


def _build_acl(aces, revision=2):
    body = b"".join(a.to_bytes() for a in aces)
    size = 8 + len(body)
    if size > MAX_ACL_SIZE:
        raise AclError("Die Berechtigungsliste würde zu groß.")
    return struct.pack("<BBHHH", revision, 0, size, len(aces), 0) + body


def build_sd(owner=None, group=None, dacl=None, dacl_control=0, dacl_revision=2):
    """Baut einen selbstbezogenen Deskriptor, der nur die gesetzten Teile enthaelt (fuer SET_INFO)."""
    control = SE_SELF_RELATIVE
    chunks, pos = [], 20
    offsets = {"owner": 0, "group": 0, "dacl": 0}
    if owner is not None:
        blob = sid_to_bytes(owner)
        offsets["owner"], pos = pos, pos + len(blob)
        chunks.append(blob)
    if group is not None:
        blob = sid_to_bytes(group)
        offsets["group"], pos = pos, pos + len(blob)
        chunks.append(blob)
    if dacl is not None:
        blob = _build_acl(dacl, dacl_revision)
        control |= SE_DACL_PRESENT | (dacl_control & _PRESERVED_CONTROL)
        offsets["dacl"], pos = pos, pos + len(blob)
        chunks.append(blob)
    header = struct.pack("<BBHIIII", 1, 0, control, offsets["owner"], offsets["group"], 0, offsets["dacl"])
    return header + b"".join(chunks)


def allow_ace(sid, mask=FILE_ALL_ACCESS, is_dir=False):
    flags = INHERIT_FLAGS if is_dir else 0
    return Ace(ACE_ACCESS_ALLOWED, flags, mask, sid)


def with_allow_ace(sd, ace):
    """Liefert (neue ACE-Liste, geaendert?). Fuegt vor dem ersten geerbten Eintrag ein, falls nicht schon enthalten."""
    if sd.dacl is None:
        raise AclError("Der Ordner hat keine Berechtigungsliste (NULL-DACL) - wird nicht verändert.")
    for existing in sd.dacl:
        if (
            existing.ace_type == ACE_ACCESS_ALLOWED
            and existing.sid == ace.sid
            and existing.mask & ace.mask == ace.mask
            and not existing.flags & ACE_INHERIT_ONLY
            and existing.flags & INHERIT_FLAGS == ace.flags & INHERIT_FLAGS
        ):
            return list(sd.dacl), False
    aces = list(sd.dacl)
    index = next((i for i, a in enumerate(aces) if a.flags & ACE_INHERITED), len(aces))
    aces.insert(index, ace)
    return aces, True


def has_allow_ace(sd, sid, mask=FILE_ALL_ACCESS):
    return bool(sd.dacl) and any(
        a.ace_type == ACE_ACCESS_ALLOWED and a.sid == sid and a.mask & mask == mask for a in sd.dacl
    )
