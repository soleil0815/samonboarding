# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Replaces names in texts by placeholders - for the diagnostic package.

The same value always gets the same placeholder within one package (benutzer-1, ou-2, host-3 ...), so connections
stay visible without revealing the real names. The mapping lives only in memory while the package is built and is
never stored: nobody can turn the placeholders back into names.

Two steps:
1. Known values (domain, DC, configured OUs, groups, servers, user names from the reports ...) are replaced
   wherever they appear - longest first.
2. Patterns catch what is not known: DNs, e-mail addresses, UNC paths, IP addresses, host names,
   DOMAIN\\user, quoted text and user-name-like words (vorname.nachname).
"""

import re

# Kinds of values and the prefix of their placeholders
KINDS = {
    "user": "benutzer",
    "group": "gruppe",
    "ou": "ou",
    "cn": "objekt",
    "host": "host",
    "share": "freigabe",
    "mail": "mail",
    "text": "wert",
    "domain": "domain",
}

# Documentation addresses (RFC 5737) for replaced IP addresses
_IP_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

# Top-level domains for the host-name pattern. File endings (.py, .json, .db, .gz ...) are not among them,
# so paths and module names stay readable.
_TLDS = (
    "local|lan|intern|internal|corp|home|localdomain|ad|domain|example|test|invalid|"
    "com|net|org|de|at|ch|eu|io|info|biz|nl|be|fr|it|es|uk|co|us|li|lu|dk|se|no|fi|pl|cz"
)

# DC values are labels (no spaces); CN/OU values may contain spaces but end at a separator or a quote
_DN_PART = re.compile(r"\b(?:(DC)=([A-Za-z0-9-]+)|(CN|OU|O|L|ST|C)=((?:\\.|[^,;+\"'\\\n()])+))", re.IGNORECASE)
_MAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UNC = re.compile(r"\\\\([A-Za-z0-9._$-]+)((?:\\[^\\\s'\",;:]+)*)")
# not after "Name/" - that is a version (Chrome/142.0.0.0), not an address; "//10.0.0.1" in a URL is still found
_IPV4 = re.compile(
    r"(?<![\d.])(?<![A-Za-z]/)((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])"
)
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")
_HOST = re.compile(r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + _TLDS + r"))\b", re.IGNORECASE)
_DOMAIN_USER = re.compile(r"(?<![\\\w.-])([A-Za-z0-9][A-Za-z0-9-]{0,14})\\([A-Za-z0-9._$-]{1,64})")
_QUOTED = re.compile(r"'([^'\n]{1,200})'|\"([^\"\n]{1,200})\"|„([^“\n]{1,200})“")
# vorname.nachname, v.nachname, nachname_v ... (lower case) - typical sAMAccountNames
_USERLIKE = re.compile(r"(?<![\w./\\-])([a-z][a-z0-9]*(?:[._-][a-z][a-z0-9]*)+)(?![\w/\\-])")
_PLACEHOLDER = re.compile(r"^(?:" + "|".join(KINDS.values()) + r")-\d+$")

# Words of the program and of libraries that look like user names but are not
_SAFE_WORDS = {
    "ldap3",
    "sqlite3",
    "self-signed",
    "start-tls",
    "starttls",
    "ssl-tls",
    "x-forwarded-for",
    "server-timing",
    "no-store",
    "no-cache",
    "same-origin",
    "max-age",
    "utf-8",
    "time-out",
    "e-mail",
    "auto-bind",
}
_SAFE_PREFIXES = (
    "samonboarding",
    "ldap3",
    "fastapi",
    "starlette",
    "uvicorn",
    "pydantic",
    "asyncio",
    "sqlite",
    "ssl",
    "socket",
    "json",
    "http",
    "urllib",
    "concurrent",
    "cryptography",
    "smtplib",
    "email",
    "pypsrp",
    "requests",
    "anyio",
    "builtins",
    "datetime",
    "pathlib",
    "os",
    "re",
    "contextlib",
    "threading",
)
# Fixed program words in quotes (TLS modes, mail modes ...) that stay readable
SAFE_QUOTED = {
    "Ohne Verschlüsselung",
    "Ohne Verschluesselung",
    "Auto",
    "STARTTLS",
    "SSL/TLS",
    "required",
    "optional",
    "exchange",
    "cloud",
    "basic",
    "negotiate",
    "kerberos",
    "ntlm",
    "random",
    "static",
}


class Anonymizer:
    def __init__(self):
        self._maps = {kind: {} for kind in KINDS}
        self._known = {}  # lower-case value -> placeholder
        self._known_re = None

    # ------------------------------------------------------------------ placeholders
    def placeholder(self, kind, value):
        """Same value (case-insensitive) -> same placeholder."""
        key = str(value).strip().lower()
        if not key:
            return ""
        if _PLACEHOLDER.match(key):  # already replaced (a text passes through several patterns)
            return key
        table = self._maps[kind]
        if key not in table:
            table[key] = f"{KINDS[kind]}-{len(table) + 1}"
        return table[key]

    def ip(self, value):
        if value.startswith("127.") or value in ("0.0.0.0", "255.255.255.255"):  # noqa: S104 - only compared
            return value
        table = self._maps.setdefault("ip", {})
        if value not in table:
            n = len(table)
            table[value] = f"{_IP_NETS[(n // 254) % 3]}{n % 254 + 1}"
        return table[value]

    # ------------------------------------------------------------------ known values
    def learn(self, kind, value):
        """Registers a known value (e.g. the domain or a configured OU) - it is replaced wherever it appears."""
        if value is None:
            return
        value = str(value).strip()
        if len(value) < 3 or _PLACEHOLDER.match(value):
            return
        if kind == "dn":
            self._known[value.lower()] = self.dn(value)
            # the names inside the DN on their own too (an OU name in a message without CN=/OU=)
            for m in _DN_PART.finditer(value):
                attr, part = _dn_groups(m)
                if len(part) >= 3 and attr.upper() != "DC":
                    self._known.setdefault(part.lower(), self._dn_value(attr, part))
        elif kind == "ip":
            self._known[value.lower()] = self.ip(value)
        elif kind == "domain":
            self._known[value.lower()] = self.domain(value)
            netbios = value.split(".")[0]
            if len(netbios) >= 3:
                self._known.setdefault(netbios.lower(), self.placeholder("domain", netbios).upper())
        else:
            self._known[value.lower()] = self.placeholder(kind, value)
        self._known_re = None

    def learn_many(self, kind, values):
        for v in values or []:
            self.learn(kind, v)

    def domain(self, value):
        # keep the number of labels: firma.local -> domain-1.example
        return self.placeholder("domain", value) + ".example"

    # ------------------------------------------------------------------ structured values
    def _dn_value(self, attr, value):
        attr = attr.upper()
        if value.lower() in ("domain", "example") or _PLACEHOLDER.match(value.lower()):
            return value
        if attr == "DC":
            return "example" if value.lower() in ("local", "lan", "intern", "com", "de", "net", "org") else "domain"
        if attr == "OU":
            return self.placeholder("ou", value)
        if attr == "CN":
            # built-in containers stay readable (CN=Users, CN=Builtin ...)
            if value in ("Users", "Computers", "Builtin", "System", "Configuration", "Services", "Schema"):
                return value
            return self.placeholder("cn", value)
        return self.placeholder("text", value)

    def dn(self, value):
        """CN=Max Muster,OU=Vertrieb,DC=firma,DC=local -> CN=objekt-1,OU=ou-1,DC=domain,DC=example"""
        return _DN_PART.sub(self._dn_match, str(value))

    def _dn_match(self, m):
        attr, part = _dn_groups(m)
        return f"{attr}={self._dn_value(attr, part)}"

    def host(self, value):
        value = str(value).strip()
        if not value:
            return ""
        if _IPV4.fullmatch(value):
            return self.ip(value)
        return self.placeholder("host", value) + ".example"

    def mail(self, value):
        return self.placeholder("mail", value) + "@example.invalid"

    def unc(self, value):
        return _UNC.sub(self._unc_match, str(value))

    def _unc_match(self, m):
        parts = [p for p in m.group(2).split("\\") if p]
        out = [self.placeholder("host", m.group(1))]
        for i, p in enumerate(parts):
            # %username% and similar macros stay readable
            if p.startswith("%") and p.endswith("%"):
                out.append(p)
            elif i == 0:
                out.append(self.placeholder("share", p) + ("$" if p.endswith("$") else ""))
            else:
                out.append(self.placeholder("text", p))
        return "\\\\" + "\\".join(out)

    # ------------------------------------------------------------------ free text
    def _known_pattern(self):
        if self._known_re is None:
            keys = sorted(self._known, key=len, reverse=True)
            self._known_re = (
                re.compile("|".join(r"(?<![\w-])" + re.escape(k) + r"(?![\w-])" for k in keys), re.IGNORECASE)
                if keys
                else None
            )
        return self._known_re

    def text(self, value):
        """Replaces everything that could name a person, a host or the organisation."""
        if value is None:
            return ""
        s = str(value)
        known = self._known_pattern()
        if known is not None:
            s = known.sub(lambda m: self._known.get(m.group(0).lower(), m.group(0)), s)
        s = _DN_PART.sub(self._dn_match, s)
        s = _MAIL.sub(lambda m: self.mail(m.group(0)), s)
        s = _UNC.sub(self._unc_match, s)
        s = _DOMAIN_USER.sub(self._domain_user, s)
        s = _IPV4.sub(lambda m: self.ip(m.group(1)), s)
        s = _IPV6.sub(lambda m: self.placeholder("host", m.group(0)), s)
        s = _HOST.sub(lambda m: m.group(0) if _is_placeholder_host(m.group(0)) else self.host(m.group(0)), s)
        s = _QUOTED.sub(self._quoted, s)
        s = _USERLIKE.sub(self._userlike, s)
        return s

    def _domain_user(self, m):
        # the domain may already be a placeholder (a known NetBIOS name is replaced first) - the user name after
        # the backslash must still go (code audit 2026-11b); placeholder() keeps values that already are one
        domain = (
            m.group(1) if _PLACEHOLDER.match(m.group(1).lower()) else self.placeholder("domain", m.group(1)).upper()
        )
        return f"{domain}\\{self.placeholder('user', m.group(2))}"

    def _quoted(self, m):
        inner = next(g for g in m.groups() if g is not None)
        if inner in SAFE_QUOTED or _PLACEHOLDER.match(inner) or _looks_anonymous(inner) or _is_program_path(inner):
            return m.group(0)
        q = m.group(0)[0]
        close = "“" if q == "„" else q
        return f"{q}{self.placeholder('text', inner)}{close}"

    def _userlike(self, m):
        word = m.group(1)
        if word in _SAFE_WORDS or _PLACEHOLDER.match(word) or word.endswith(".example") or word.endswith(".invalid"):
            return word
        if word.split(".")[0].split("_")[0] in _SAFE_PREFIXES:
            return word
        return self.placeholder("user", word)

    def value(self, value):
        """Anonymises lists, dicts and texts recursively (numbers and truth values stay)."""
        if isinstance(value, dict):
            return {k: self.value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.value(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value


def _dn_groups(m):
    if m.group(1):
        return m.group(1), m.group(2)
    # trailing spaces belong to the text around the DN, not to the name
    return m.group(3), m.group(4).rstrip()


def _is_placeholder_host(name):
    name = name.lower()
    return name.endswith((".example", ".invalid")) or name in ("example.invalid",)


def _is_program_path(text):
    """File names of the program and of Python (tracebacks) stay readable."""
    return text.startswith(("/app/", "/usr/", "<")) or bool(re.fullmatch(r"[\w./-]+\.py", text))


def _looks_anonymous(text):
    """Already replaced (placeholders only) - e.g. a DN that became CN=objekt-1,OU=ou-2,DC=domain,DC=example."""
    rest = re.sub(
        r"(?:" + "|".join(KINDS.values()) + r")-\d+(?:\.example|@example\.invalid)?", "", text, flags=re.IGNORECASE
    )
    rest = re.sub(r"\b(?:CN|OU|DC|O|L|ST|C)=|\bdomain\b|\bexample\b|[\s,\\$.=%]", "", rest, flags=re.IGNORECASE)
    rest = re.sub(r"(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+", "", rest)
    return rest == ""
