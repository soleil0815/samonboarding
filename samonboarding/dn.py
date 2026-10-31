# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Hilfsfunktionen fuer Distinguished Names (DN) und LDAP-Filter (Escaping, Zerlegen, Vergleichen)."""

import re


def ldap_escape(value):
    """Escaped einen Wert fuer die Verwendung in einem LDAP-Filter (RFC 4515)."""
    return (
        str(value)
        .replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def escape_rdn_value(value):
    """Escaped einen Wert fuer die Verwendung in einem RDN (RFC 4514)."""
    out = re.sub(r'([\\,+"<>;=])', r"\\\1", str(value))
    out = out.replace("\x00", "\\00")
    if out.startswith(("#", " ")):
        out = "\\" + out
    if out.endswith(" ") and not out.endswith("\\ "):
        out = out[:-1] + "\\ "
    return out


def split_dn(dn):
    """Teilt einen DN an unmaskierten Kommas (beruecksichtigt '\\,')."""
    parts, cur, escaped = [], [], False
    for ch in dn or "":
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            cur.append(ch)
            escaped = True
        elif ch == ",":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def dn_norm(dn):
    return ",".join(p.strip().lower() for p in split_dn(dn))


def dn_is_within(dn, base):
    """dn ist base selbst oder liegt darunter. Verglichen werden ganze DN-Bestandteile, nicht Zeichenketten -
    sonst gaelte 'CN=Max\\,OU=Staff,OU=Firma,...' (Komma im Namen) als in 'OU=Staff,OU=Firma,...'."""
    n = [p.strip().lower() for p in split_dn(dn)]
    b = [p.strip().lower() for p in split_dn(base)]
    return bool(b) and len(n) >= len(b) and n[len(n) - len(b) :] == b


def dn_in_any(dn, bases):
    return any(dn_is_within(dn, b) for b in bases if b)


def dn_unescape(value):
    return re.sub(
        r"\\(?:([0-9a-fA-F]{2})|(.))",
        lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2),
        value,
    )


def rdn_label(dn):
    """'CN=Meier\\, Hans,OU=x' -> 'Meier, Hans'"""
    first = split_dn(dn)[0]
    return dn_unescape(first.split("=", 1)[1] if "=" in first else first)


def parent_dn(dn):
    return ",".join(split_dn(dn)[1:])


def base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))
