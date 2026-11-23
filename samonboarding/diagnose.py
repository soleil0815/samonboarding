# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Diagnostic package: everything needed to understand a problem - anonymous.

Built in the interface (Einstellungen -> Diagnose, administrators only) or on the server without a sign-in:
    docker compose exec samonboarding python -m samonboarding.diagnose
(the package then lands in data/diagnose/; without a sign-in it has no connection test and - since it runs in a
separate process - no request statistics).

The package is a ZIP with diagnose.txt (to read) and diagnose.json (machine-readable, FORMAT below).
Nothing is sent anywhere. Passwords, tokens and session cookies never get in; names are replaced by placeholders
(anonymize.py), the mapping is not stored.

Kept up to date with the program (tests/test_diagnose.py):
- every module in routers/ is listed in ROUTER_SECTIONS (with the sections that cover it, or a reason),
- every setting (defaults in config.py/exchange.py, template fields) and every environment variable the program
  reads has a rule in CONFIG_RULES / TEMPLATE_RULES / ENV_RULES. A new key without a rule fails the tests -
  it can neither slip into the package unnoticed nor be missing from it.
"""

import io
import json
import os
import platform
import shutil
import sqlite3
import sys
import time
import zipfile
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from . import config, datastate, reports, timing, updatecheck
from .anonymize import Anonymizer
from .routers.news import version_key

FORMAT = 1  # format of diagnose.json; increase when its structure changes
STARTED = time.time()
LOG_ENTRIES = 200  # newest warnings and errors
SLOW_ENTRIES = 50  # newest "Langsam:" lines
MAX_OU_CHECKS = 40

# ---------------------------------------------------------------------------------------------------------------------
# Rules: how a setting appears in the package
#   show    value as it is (truth values, numbers, fixed choices)
#   domain  host  mail  dn  unc  text   value replaced by a placeholder of that kind
#   dns  uncs  hosts                    list, every entry replaced
#   count   only the number of entries (list or comma-separated text)
#   set     only "gesetzt"/"leer" (free text that might name people or places)
#   secret  only "gesetzt"/"leer" - a password or key, never anything else
RULES = ("show", "domain", "host", "mail", "dn", "unc", "text", "dns", "uncs", "hosts", "count", "set", "secret")

_LOCATION = {"enabled": "show", "roots": "uncs", "useAdAttr": "show", "suffixes": "show", "takeOwnership": "show"}

CONFIG_RULES = {
    "config.json": {"domain": "domain", "dc_ip": "host", "backend": "show"},
    "smtp_config.json": {
        "enabled": "show",
        "displayName": "set",
        "host": "host",
        "port": "show",
        "username": "set",
        "password": "secret",
        "fromEmail": "mail",
        "ccRecipients": "count",
        "tlsMode": "show",
        "notifyOffboarding": "show",
        "notifyPwdReset": "show",
        "notifyUserMgmt": "show",
        "notifyDeletion": "show",
    },
    "offboarding_config.json": {"sourceOus": "dns", "targetOu": "dn"},
    "pwdreset_config.json": {"sourceOus": "dns"},
    "onboarding_config.json": {"mailMode": "show"},
    "usermgmt_config.json": {"sourceOus": "dns", "targetOus": "dns", "groupOus": "dns"},
    "deletion_config.json": {
        "enabled": "show",
        "disabledOu": "dn",
        **{f"{loc}.{k}": v for loc in ("profile", "folderRedirection", "home") for k, v in _LOCATION.items()},
    },
    "exchange_config.json": {
        "enabled": "show",
        "server": "host",
        "port": "show",
        "ssl": "show",
        "verifyCert": "show",
        "auth": "show",
        "database": "text",
        "domainController": "host",
    },
}

TEMPLATE_RULES = {
    "id": "show",
    "name": "text",
    "naming": "show",
    "ouDn": "dn",
    "pwdMode": "show",
    "staticPwd": "secret",
    "mailMode": "show",
    "forceChange": "show",
    "pwdNeverExpires": "show",
    "createHomeFolder": "show",
    "homeDrive": "show",
    "profilePath": "unc",
    "homeDirectory": "unc",
    "scriptPath": "set",
    "groups": "dns",
    **{
        k: "set"
        for k in (
            "initials",
            "displayName",
            "description",
            "office",
            "telephone",
            "mail",
            "website",
            "street",
            "pobox",
            "postalCode",
            "city",
            "state",
            "country",
            "homePhone",
            "pager",
            "mobile",
            "fax",
            "ipPhone",
            "notes",
            "title",
            "department",
            "company",
            "manager",
        )
    },
}

ENV_RULES = {
    "AD_DOMAIN": "domain",
    "AD_DC_IP": "host",
    "AD_BACKEND": "show",
    "CUSTOM_OPERATOR_GROUP": "text",
    "DATA_DIR": "set",
    "LDAP_CA_FILE": "set",
    "LDAP_ALLOW_PLAIN": "show",
    "SESSION_IDLE_MINUTES": "show",
    "SESSION_MAX_HOURS": "show",
    "HTTPS_PORT": "show",
    "TLS_CERT_FILE": "set",
    "TLS_KEY_FILE": "set",
    "TLS_HOSTNAMES": "hosts",
    "LOGIN_MAX_ATTEMPTS": "show",
    "LOGIN_LOCK_MINUTES": "show",
    "AUDIT_RETENTION_DAYS": "show",
    "LOG_RETENTION_DAYS": "show",
    "OFFBOARD_RETENTION_DAYS": "show",
    "ALLOW_HTTP": "show",
    "SAMONBOARDING_TLS_SELF_SIGNED": "show",
    "SAMONBOARDING_COMPOSE": "show",
    "SAMONBOARDING_VERSION": "set",  # shown checked as updatePruefung.festeVersion
    "UPDATE_CHECK": "show",
    "UPDATE_CHECK_PROXY": "set",
}

# Which sections of the package cover a module in routers/ (a new module must be added here - test)
ROUTER_SECTIONS = {
    "auth": ["sitzungen", "protokoll", "aenderungen"],
    "dashboard": ["geschwindigkeit", "verbindung"],
    "people": ["geschwindigkeit"],
    "settings": ["einstellungen"],
    "usermgmt": ["einstellungen", "verbindung", "aenderungen"],
    "offboarding": ["einstellungen", "verbindung", "aenderungen", "wiederherstellung"],
    "restore": ["wiederherstellung", "aenderungen"],
    "deletion": ["einstellungen", "verbindung", "aenderungen"],
    "privacy_info": ["aenderungen"],
    "reports": ["protokoll", "aenderungen"],
    "certificate": ["https"],
    "manual": ["programm"],
    "news": ["programm"],
    "pwdreset": ["einstellungen", "verbindung", "aenderungen"],
    "infrastructure": ["verbindung", "geschwindigkeit"],
    "references": ["verbindung"],
    "templates": ["templates"],
    "onboarding": ["templates", "einstellungen", "aenderungen"],
    "ui": ["programm", "datenordner"],
    "diagnose": ["programm"],
}

# Files in the data folder whose names the program sets (others appear as "andere-datei-n")
KNOWN_DATA_FILES = {
    *CONFIG_RULES,
    "templates.json",
    "reports.db",
    "offboarding.db",
    "audit.log",
    datastate.STATE_NAME,
    datastate.PENDING_NAME,
    datastate.BACKUP_DIR_NAME,
    "verweise.json",
    "tls",
    "diagnose",
}

LIBRARIES = ("fastapi", "starlette", "uvicorn", "ldap3", "pydantic", "cryptography", "pyasn1", "pypsrp", "requests")

# ---------------------------------------------------------------------------------------------------------------------


@contextmanager
def _read_db(path):
    """Opens a database read-only (the package never changes or creates anything). None if it does not exist."""
    if not Path(path).exists():
        yield None
        return
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)) as conn:
        conn.row_factory = sqlite3.Row
        yield conn


def _now():
    return datetime.now(timezone.utc)


def _flatten(data, prefix=""):
    out = {}
    for key, value in (data or {}).items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, path + "."))
        else:
            out[path] = value
    return out


def _filled(value):
    return value not in (None, "", [], {})


def apply_rule(rule, value, anon):
    if rule == "show":
        return value
    if rule == "secret" or rule == "set":
        return "gesetzt" if _filled(value) else "leer"
    if rule == "count":
        if isinstance(value, str):
            return len([v for v in value.replace(";", ",").split(",") if v.strip()])
        return len(value) if isinstance(value, (list, tuple, dict)) else (1 if _filled(value) else 0)
    if not _filled(value):
        return value
    if rule == "domain":
        return anon.domain(value)
    if rule == "host":
        return anon.host(value)
    if rule == "mail":
        return anon.mail(value)
    if rule == "dn":
        return anon.dn(value)
    if rule == "unc":
        return anon.unc(value)
    if rule == "text":
        return anon.placeholder("text", value)
    items = value if isinstance(value, list) else [v for v in str(value).split(",") if v.strip()]
    if rule == "dns":
        return [anon.dn(v) for v in items]
    if rule == "uncs":
        return [anon.unc(v) for v in items]
    if rule == "hosts":
        return [anon.host(v.strip()) for v in items]
    raise ValueError(rule)


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "fehlt (Standardwerte)"
    except (OSError, ValueError) as e:
        return None, f"nicht lesbar: {type(e).__name__}"


# ---------------------------------------------------------------------------------------------------------------------
# Known values: everything the program knows by name is replaced wherever it appears (log messages ...)


# Keys in the audit details that hold account or person names (code audit 2026-11b: a log line such as
# "Sammellöschung: Fehler bei aberg" only names the account that the details list under "accounts")
DETAIL_USER_KEYS = ("sam", "accounts", "account", "user", "users", "member", "members", "manager")
DETAIL_NAME_KEYS = ("name", "displayName", "fullname", "givenName", "sn")


def _learn_details(anon, raw):
    try:
        details = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return
    if not isinstance(details, dict):
        return
    for keys, kind in ((DETAIL_USER_KEYS, "user"), (DETAIL_NAME_KEYS, "text")):
        for key in keys:
            value = details.get(key)
            for v in value if isinstance(value, list) else [value]:
                if isinstance(v, str) and v:
                    anon.learn("dn" if "=" in v else kind, v)


def learn_known_values(anon, user=None):
    for name, rules in CONFIG_RULES.items():
        data, _ = _read_json(config.DATA_DIR / name)
        flat = _flatten(data if isinstance(data, dict) else {})
        for key, rule in rules.items():
            value = flat.get(key)
            if not _filled(value):
                continue
            kind = {"domain": "domain", "host": "host", "mail": "mail", "dn": "dn", "dns": "dn", "hosts": "host"}.get(
                rule
            )
            if kind:
                anon.learn_many(kind, value if isinstance(value, list) else [value])
            elif rule in ("uncs", "unc"):
                for v in value if isinstance(value, list) else [value]:
                    anon.learn("text", v)
            elif rule in ("text", "set") and isinstance(value, str):
                anon.learn("text", value)
            if key == "ccRecipients" and isinstance(value, str):
                anon.learn_many("mail", [v.strip() for v in value.replace(";", ",").split(",")])
    templates, _ = _read_json(config.TEMPLATES_FILE)
    for tmpl in templates if isinstance(templates, list) else []:
        if not isinstance(tmpl, dict):
            continue
        anon.learn("dn", tmpl.get("ouDn"))
        anon.learn_many("dn", tmpl.get("groups") or [])
        anon.learn("text", tmpl.get("name"))
        for key, rule in TEMPLATE_RULES.items():
            if rule == "set" and isinstance(tmpl.get(key), str) and len(tmpl[key].strip()) >= 3:
                anon.learn("text", tmpl[key])
    for env, rule in ENV_RULES.items():
        value = os.environ.get(env, "").strip()
        if value and rule in ("domain", "host", "text"):
            anon.learn(rule if rule != "text" else "group", value)
        elif value and rule == "hosts":
            anon.learn_many("host", [v.strip() for v in value.split(",")])
    from .ldap_client import directory_info  # late: ldap_client loads the configuration

    anon.learn("host", directory_info().get("host"))
    if user:
        anon.learn("user", user.get("username"))
    # actors and targets of the reports: user names, DNs and object names that occur in the log
    try:
        with _read_db(config.REPORTS_DB_FILE) as conn:
            rows = conn.execute("SELECT DISTINCT actor, target FROM audit LIMIT 5000").fetchall() if conn else []
            # account names that only the details name (e.g. the accounts of a batch deletion)
            sql = (
                "SELECT DISTINCT details FROM audit WHERE details LIKE ? OR details LIKE ? OR details LIKE ? LIMIT 5000"
            )
            details = conn.execute(sql, ('%"sam"%', '%"accounts"%', '%"name"%')).fetchall() if conn else []
        for r in rows:
            anon.learn("user", r["actor"])
            target = str(r["target"] or "")
            anon.learn("dn" if "=" in target else "user", target)
        for r in details:
            _learn_details(anon, r["details"])
    except Exception:  # noqa: S110 - the package is built without them; the patterns still apply
        pass
    try:
        with _read_db(config.OFFBOARD_DB_FILE) as conn:
            sql = "SELECT sam, name, original_dn, current_dn, offboarded_by FROM offboarded"
            rows = conn.execute(sql).fetchall() if conn else []
        for r in rows:
            anon.learn("user", r["sam"])
            anon.learn("text", r["name"])
            anon.learn("dn", r["original_dn"])
            anon.learn("dn", r["current_dn"])
            anon.learn("user", r["offboarded_by"])
    except Exception:  # noqa: S110
        pass


# ---------------------------------------------------------------------------------------------------------------------
# Sections


def section_programm(anon, ctx):
    libs = {}
    for name in LIBRARIES:
        try:
            libs[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            libs[name] = None
    state = datastate.read_state(config.DATA_DIR) or {}
    compose_have = os.environ.get("SAMONBOARDING_COMPOSE", "")
    return {
        "version": config.VERSION,
        "datenstand": {
            "programm": datastate.DATA_STATE,
            "daten": state.get("datenstand"),
            "version": state.get("version"),
        },
        "compose": {"datei": compose_have or None, "benoetigt": datastate.COMPOSE_REQUIRED},
        "updatePruefung": updatecheck.status(),
        "python": platform.python_version(),
        "system": f"{platform.system()} {platform.release()}",
        "architektur": platform.machine(),
        "bibliotheken": libs,
        "gestartet": datetime.fromtimestamp(STARTED, timezone.utc).isoformat(timespec="seconds"),
        "laufzeitStunden": round((time.time() - STARTED) / 3600, 1),
        "zeitzone": time.strftime("%Z"),
        "quelle": ctx["source"],
    }


def section_umgebung(anon, ctx):
    out = {}
    for name, rule in ENV_RULES.items():
        if name in os.environ:
            out[name] = apply_rule(rule, os.environ[name].strip(), anon)
    return out


def section_einstellungen(anon, ctx):
    out = {}
    for name, rules in CONFIG_RULES.items():
        data, problem = _read_json(config.DATA_DIR / name)
        if data is None:
            out[name] = {"datei": problem}
            continue
        flat = _flatten(data if isinstance(data, dict) else {})
        entry = {}
        for key, value in flat.items():
            rule = rules.get(key)
            entry[key] = apply_rule(rule, value, anon) if rule else "(nicht eingeordnet - Wert ausgelassen)"
        out[name] = entry
    return out


def section_templates(anon, ctx):
    data, problem = _read_json(config.TEMPLATES_FILE)
    if data is None:
        return {"datei": problem, "anzahl": 0}
    templates = []
    for tmpl in data if isinstance(data, list) else []:
        if not isinstance(tmpl, dict):
            continue
        templates.append(
            {
                key: (apply_rule(TEMPLATE_RULES[key], value, anon) if key in TEMPLATE_RULES else "(nicht eingeordnet)")
                for key, value in tmpl.items()
                if _filled(value) or TEMPLATE_RULES.get(key) == "show"
            }
        )
    return {"anzahl": len(templates), "templates": templates}


def section_datenordner(anon, ctx):
    data_dir = config.DATA_DIR
    files = []
    other = 0
    try:
        entries = sorted(data_dir.iterdir(), key=lambda p: p.name)
    except OSError as e:
        return {"fehler": type(e).__name__}
    for path in entries:
        try:
            st = path.stat()
        except OSError:
            continue
        # also the program's own copies such as smtp_config.json.prev or templates.json.kaputt-<time>
        if path.name in KNOWN_DATA_FILES or any(path.name.startswith(k + ".") for k in KNOWN_DATA_FILES):
            name = path.name
        else:
            other += 1
            name = f"andere-datei-{other}"
        files.append(
            {
                "name": name,
                "ordner": path.is_dir(),
                "groesseKB": round(st.st_size / 1024, 1) if path.is_file() else None,
                "geaendert": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                "rechte": oct(st.st_mode & 0o777),
            }
        )
    backups = sorted((data_dir / datastate.BACKUP_DIR_NAME).glob("vor-*.tar.gz")) if data_dir.exists() else []
    usage = shutil.disk_usage(data_dir)
    st = data_dir.stat()
    return {
        "dateien": files,
        "sicherungen": {
            "anzahl": len(backups),
            "neueste": backups[-1].name if backups else None,
            "groesseMB": round(sum(b.stat().st_size for b in backups) / 1_048_576, 1),
        },
        "wechselNichtAbgeschlossen": (data_dir / datastate.PENDING_NAME).exists(),
        "freiGB": round(usage.free / 1_073_741_824, 1),
        "belegtProzent": round(usage.used * 100 / usage.total, 1) if usage.total else None,
        "eigentuemerUid": st.st_uid,
        "rechte": oct(st.st_mode & 0o777),
    }


def section_https(anon, ctx):
    from . import tls

    try:
        info = tls.current_info()
    except Exception as e:
        return {"fehler": f"Zertifikat nicht lesbar: {type(e).__name__}"}
    names = info.get("names") or []
    return {
        "selbstsigniert": info.get("selfSigned"),
        "tageGueltig": info.get("daysLeft"),
        "ablauf": info.get("notAfter"),
        "schluessel": info.get("keyType"),
        "kette": info.get("chainLength"),
        "namen": [anon.host(n) for n in names] if isinstance(names, list) else anon.text(str(names)),
        # the name of an internal CA could name the organisation
        "aussteller": "selbst" if info.get("selfSigned") else anon.placeholder("text", info.get("issuer") or "?"),
    }


def section_verzeichnis(anon, ctx):
    from .ldap_client import directory_info

    info = directory_info()
    return {
        "art": info.get("label"),
        "typ": info.get("type"),
        "version": info.get("version") or None,
        "dc": anon.host(info.get("host")) if info.get("host") else None,
        "ldapsZertifikatGeprueft": bool(config.LDAP_CA_FILE),
        "unverschluesseltErlaubt": config.LDAP_ALLOW_PLAIN,
        "hinweis": None if info.get("type") != "unknown" else "noch nicht erkannt (erst nach einer Anmeldung)",
    }


def _configured_ous():
    """Every OU/DN the settings refer to, with where it is used."""
    found = []
    for name, rules in CONFIG_RULES.items():
        data, _ = _read_json(config.DATA_DIR / name)
        flat = _flatten(data if isinstance(data, dict) else {})
        for key, rule in rules.items():
            if rule in ("dn", "dns") and _filled(flat.get(key)):
                values = flat[key] if isinstance(flat[key], list) else [flat[key]]
                found += [(f"{name}:{key}", v) for v in values]
    templates, _ = _read_json(config.TEMPLATES_FILE)
    for tmpl in templates if isinstance(templates, list) else []:
        if isinstance(tmpl, dict) and tmpl.get("ouDn"):
            found.append(("templates.json:ouDn", tmpl["ouDn"]))
        if isinstance(tmpl, dict):
            found += [("templates.json:groups", g) for g in tmpl.get("groups") or []]
    seen, unique = set(), []
    for where, dn in found:
        if str(dn).lower() not in seen:
            seen.add(str(dn).lower())
            unique.append((where, dn))
    return unique


def section_verbindung(anon, ctx):
    """Short live test with the signed-in user's credentials (there is no service account)."""
    user = ctx.get("user")
    if not user:
        return {"uebersprungen": "ohne Anmeldung (Kommandozeile) - kein Verbindungstest"}
    import ldap3

    from .ldap_client import detect_directory, ldap_connection

    cfg, _ = _read_json(config.CONFIG_FILE)
    cfg = dict(config.default_config, **(cfg if isinstance(cfg, dict) else {}))
    out = {"dc": anon.host(cfg.get("dc_ip"))}
    began = time.perf_counter()
    try:
        with ldap_connection(cfg["dc_ip"], user["bind_user"], user["password"]) as conn:
            out["verbindenMs"] = round((time.perf_counter() - began) * 1000)
            out["verschluesselt"] = bool(getattr(conn.server, "ssl", False))
            out["port"] = getattr(conn.server, "port", None)
            t = time.perf_counter()
            detect_directory(conn)
            out["rootDseMs"] = round((time.perf_counter() - t) * 1000)
            checks = []
            for where, dn in _configured_ous()[:MAX_OU_CHECKS]:
                t = time.perf_counter()
                ok = conn.search(dn, "(objectClass=*)", ldap3.BASE, attributes=["objectClass"])
                code = (conn.result or {}).get("description") if isinstance(conn.result, dict) else None
                checks.append(
                    {
                        "verwendet": where,
                        "dn": anon.dn(dn),
                        "vorhanden": bool(ok),
                        "antwort": None if ok else code,
                        "ms": round((time.perf_counter() - t) * 1000),
                    }
                )
            out["konfigurierteObjekte"] = checks
            out["fehlend"] = sum(1 for c in checks if not c["vorhanden"])
            out["schutzpruefung"] = _time_protection(conn, cfg)
    except Exception as e:
        out["fehler"] = anon.text(f"{type(e).__name__}: {getattr(e, 'detail', e)}")
        out["nachMs"] = round((time.perf_counter() - began) * 1000)
    return out


def _time_protection(conn, cfg):
    """How long the protection check of the lists takes (the slowest query of the start page and the lists)."""
    from . import protection

    base = ",".join(f"DC={p}" for p in str(cfg.get("domain") or "").split(".") if p)
    if not base:
        return {"uebersprungen": "Domäne unbekannt"}
    result: dict = {}
    t = time.perf_counter()
    try:
        result["geschuetzteKonten"] = len(protection.privileged_map(conn, base))
    except Exception as e:
        result.update(fehler=type(e).__name__, hinweis="Listen prüfen dann jedes Konto einzeln")
    result["ms"] = round((time.perf_counter() - t) * 1000)
    return result


def section_sitzungen(anon, ctx):
    from . import sessions

    now = time.time()
    with sessions._session_lock:
        active = [s for s in sessions.active_sessions.values() if s.get("expires", 0) > now]
    roles = {}
    for s in active:
        roles[s.get("role", "?")] = roles.get(s.get("role", "?"), 0) + 1
    return {
        "aktiv": len(active),
        "rollen": roles,
        "angefordertVon": (ctx.get("user") or {}).get("role"),
        "leerlaufMinuten": config.SESSION_IDLE_SECONDS // 60,
        "hoechstdauerStunden": config.SESSION_MAX_SECONDS // 3600,
        "hinweis": None if ctx["source"] == "oberflaeche" else "Kommandozeile: eigener Prozess, keine Sitzungsdaten",
    }


def section_geschwindigkeit(anon, ctx):
    stats = timing.summary()
    return {
        "langsamAbSekunden": timing.SLOW_SECONDS,
        "anfragen": stats,
        "hinweis": None
        if ctx["source"] == "oberflaeche"
        else "Kommandozeile: eigener Prozess - die Zeiten stehen nur im Paket aus der Oberfläche",
    }


def section_protokoll(anon, ctx):
    out: dict = {"eintraege": [], "langsam": []}
    try:
        with _read_db(config.REPORTS_DB_FILE) as conn:
            if conn is None:
                return {"datei": "fehlt"}
            total = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in reports.TABLES}  # noqa: S608
            out["gesamt"] = {"protokoll": total["applog"], "aenderungen": total["audit"]}
            rows = conn.execute(
                "SELECT ts, level, source, message FROM applog WHERE level IN ('WARNING','ERROR','CRITICAL') "
                "ORDER BY id DESC LIMIT ?",
                (LOG_ENTRIES,),
            ).fetchall()
            slow = conn.execute(
                "SELECT ts, message FROM applog WHERE message LIKE 'Langsam:%' ORDER BY id DESC LIMIT ?",
                (SLOW_ENTRIES,),
            ).fetchall()
            levels = conn.execute(
                "SELECT level, COUNT(*) AS n FROM applog WHERE ts_utc >= datetime('now', '-7 days') GROUP BY level"
            ).fetchall()
    except Exception as e:
        out["fehler"] = type(e).__name__
        return out
    out["letzte7Tage"] = {r["level"]: r["n"] for r in levels}
    out["eintraege"] = [
        {"zeit": r["ts"], "stufe": r["level"], "quelle": r["source"], "text": anon.text(r["message"])} for r in rows
    ]
    out["langsam"] = [{"zeit": r["ts"], "text": anon.text(r["message"])} for r in slow]
    return out


def section_aenderungen(anon, ctx):
    """Which actions ran and how often they failed - without who and on whom."""
    try:
        with _read_db(config.REPORTS_DB_FILE) as conn:
            rows = (
                conn.execute(
                    "SELECT action, ok, COUNT(*) AS n FROM audit WHERE ts_utc >= datetime('now', '-30 days') "
                    "GROUP BY action, ok"
                ).fetchall()
                if conn
                else []
            )
    except Exception as e:
        return {"fehler": type(e).__name__}
    actions = {}
    for r in rows:
        entry = actions.setdefault(r["action"], {"ok": 0, "fehler": 0})
        entry["ok" if r["ok"] else "fehler"] += r["n"]
    return {"letzte30Tage": dict(sorted(actions.items()))}


def section_wiederherstellung(anon, ctx):
    try:
        with _read_db(config.OFFBOARD_DB_FILE) as conn:
            rows = conn.execute("SELECT state, COUNT(*) AS n FROM offboarded GROUP BY state").fetchall() if conn else []
    except Exception as e:
        return {"fehler": type(e).__name__}
    return {"eintraege": {r["state"]: r["n"] for r in rows}, "aufbewahrungTage": config.OFFBOARD_RETENTION_DAYS}


def section_browser(anon, ctx):
    info = ctx.get("browser")
    if not isinstance(info, dict):
        return {"uebersprungen": "nur im Paket aus der Oberfläche"}
    allowed = {"userAgent", "sprache", "darstellung", "fenster", "bildschirm", "zeitzone", "seite"}
    return {k: anon.text(str(v))[:300] for k, v in info.items() if k in allowed}


SECTIONS = {
    "programm": section_programm,
    "umgebung": section_umgebung,
    "einstellungen": section_einstellungen,
    "templates": section_templates,
    "datenordner": section_datenordner,
    "https": section_https,
    "verzeichnis": section_verzeichnis,
    "verbindung": section_verbindung,
    "sitzungen": section_sitzungen,
    "geschwindigkeit": section_geschwindigkeit,
    "protokoll": section_protokoll,
    "aenderungen": section_aenderungen,
    "wiederherstellung": section_wiederherstellung,
    "browser": section_browser,
}


def hints(data):
    """Notable points first - so the cause is often visible at a glance."""
    out = []
    p = data.get("programm", {})
    ds = p.get("datenstand", {})
    if ds.get("daten") is not None and ds.get("daten") != ds.get("programm"):
        out.append(f"Datenstand {ds.get('daten')} passt nicht zum Programm ({ds.get('programm')}).")
    compose = p.get("compose", {})
    have = str(compose.get("datei") or "0")
    if not have.isdigit() or int(have) < compose.get("benoetigt", 0):
        out.append("docker-compose.yml ist veraltet (update.sh ausführen).")
    update = p.get("updatePruefung") or {}
    if update.get("eingeschaltet") and update.get("ergebnis") not in (None, "ok"):
        out.append(f"Versionsprüfung bei GitHub nicht möglich ({update['ergebnis']}) – Internet/Proxy prüfen.")
    newest, have = update.get("neuesteVeroeffentlicht"), update.get("installiert")
    if newest and have and version_key(newest) > version_key(have):
        out.append(f"Neuere Version veröffentlicht: {newest} (installiert {have}).")
    d = data.get("datenordner", {})
    if d.get("wechselNichtAbgeschlossen"):
        out.append("Ein Versionswechsel wurde nicht abgeschlossen (Migration abgebrochen).")
    if isinstance(d.get("freiGB"), (int, float)) and d["freiGB"] < 1:
        out.append(f"Wenig Platz im Datenordner: {d['freiGB']} GB frei.")
    h = data.get("https", {})
    if isinstance(h.get("tageGueltig"), int) and h["tageGueltig"] < 30:
        out.append(f"HTTPS-Zertifikat läuft in {h['tageGueltig']} Tagen ab.")
    v = data.get("verzeichnis", {})
    if v.get("unverschluesseltErlaubt"):
        out.append("Unverschlüsseltes LDAP ist erlaubt (LDAP_ALLOW_PLAIN).")
    c = data.get("verbindung", {})
    if c.get("fehler"):
        out.append("Verbindungstest zum DC fehlgeschlagen: " + str(c["fehler"]))
    if c.get("fehlend"):
        out.append(f"{c['fehlend']} eingestellte OU(s)/Gruppe(n) gibt es im AD nicht (mehr).")
    if isinstance(c.get("verbindenMs"), int) and c["verbindenMs"] > 1000:
        out.append(f"Verbindungsaufbau zum DC dauert lange ({c['verbindenMs']} ms).")
    errors = [e for e in data.get("protokoll", {}).get("eintraege", []) if e.get("stufe") in ("ERROR", "CRITICAL")]
    if errors:
        out.append(f"{len(errors)} Fehler im Protokoll (neueste zuerst unter „Protokoll“).")
    protect = c.get("schutzpruefung") or {}
    if isinstance(protect.get("ms"), int) and protect["ms"] >= 3000:
        out.append(f"Die Schutzprüfung (geschützte Konten in den Listen) dauert {protect['ms'] / 1000:.1f} s.")
    for route, s in list(data.get("geschwindigkeit", {}).get("anfragen", {}).items())[:5]:
        if s.get("p95Ms", 0) < 3000:
            continue
        steps = s.get("stepsMedianMs") or {}
        # "Suche" also contains the searches of the role and protection checks: name the specific step if it is slow
        specific = {k: v for k, v in steps.items() if k not in ("Suche", "Verbindung") and v >= 1000}
        slowest = max((specific or steps).items(), key=lambda kv: kv[1], default=None)
        detail = f", davon {slowest[0]} {slowest[1] / 1000:.1f} s" if slowest and slowest[1] >= 1000 else ""
        out.append(f"Langsam: {route} – üblich {s['medianMs'] / 1000:.1f} s, bis {s['p95Ms'] / 1000:.1f} s{detail}.")
    return out


def build(user=None, browser=None, source="oberflaeche"):
    """Builds the anonymous package as a dict."""
    anon = Anonymizer()
    learn_known_values(anon, user)
    ctx = {"user": user, "browser": browser, "source": source}
    data = {"format": FORMAT, "erstellt": _now().isoformat(timespec="seconds")}
    for name, fn in SECTIONS.items():
        try:
            data[name] = fn(anon, ctx)
        except Exception as e:  # one broken section must not cost the whole package
            data[name] = {"fehler": anon.text(f"{type(e).__name__}: {e}")}
    data["auffaelligkeiten"] = hints(data)
    return data


# ---------------------------------------------------------------------------------------------------------------------
# Output


def _lines(value, indent=0):
    pad = "  " * indent
    if isinstance(value, dict):
        for key, v in value.items():
            if isinstance(v, (dict, list)) and v:
                yield f"{pad}{key}:"
                yield from _lines(v, indent + 1)
            else:
                yield f"{pad}{key}: {_scalar(v)}"
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, dict):
                first = True
                for line in _lines(v, indent + 1):
                    yield (pad + "- " + line.lstrip()) if first else line
                    first = False
            else:
                yield f"{pad}- {_scalar(v)}"
    else:
        yield f"{pad}{_scalar(value)}"


def _scalar(v):
    if v is None:
        return "–"
    if v is True:
        return "ja"
    if v is False:
        return "nein"
    if v in ([], {}):
        return "–"
    return str(v)


TITLES = {
    "programm": "Programm",
    "umgebung": "Umgebungsvariablen (.env)",
    "einstellungen": "Einstellungen",
    "templates": "Templates",
    "datenordner": "Datenordner",
    "https": "HTTPS-Zertifikat",
    "verzeichnis": "Verzeichnisdienst",
    "verbindung": "Verbindungstest zum DC",
    "sitzungen": "Sitzungen",
    "geschwindigkeit": "Geschwindigkeit seit dem Start",
    "protokoll": "Protokoll (Warnungen und Fehler, neueste zuerst)",
    "aenderungen": "Aktionen der letzten 30 Tage",
    "wiederherstellung": "Wiederherstellung (Offboarding)",
    "browser": "Browser",
}


def render_text(data):
    out = [
        f"SAMONBOARDING – Diagnosepaket (Format {data['format']})",
        f"Erstellt: {data['erstellt']}",
        "Anonymisiert: Namen sind durch Platzhalter ersetzt (benutzer-1, ou-2, host-3 …).",
        "Kennwörter, Tokens und Sitzungen sind nie enthalten.",
        "",
        "AUFFÄLLIGKEITEN",
    ]
    out += [f"  • {h}" for h in data.get("auffaelligkeiten") or ["keine"]]
    for name, title in TITLES.items():
        out += ["", title.upper(), *(_lines(data.get(name, {}), 1))]
    return "\n".join(out) + "\n"


def file_name(data):
    stamp = data["erstellt"].replace(":", "").replace("-", "")[:15]
    return f"samonboarding-diagnose-{config.VERSION}-{stamp}.zip"


def make_zip(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("diagnose.txt", render_text(data))
        z.writestr("diagnose.json", json.dumps(data, ensure_ascii=False, indent=2, default=str))
    return buf.getvalue()


def _drop_root():
    """docker compose exec runs as root: continue as the owner of the data folder (the program user), so the
    package and everything it touches belong to the program, as always."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        owner = config.DATA_DIR.stat()
        if owner.st_uid != 0:
            os.setgid(owner.st_gid)
            os.setuid(owner.st_uid)


def main(argv=None):
    """Command line: writes the package to data/diagnose/ (without a sign-in, so without a connection test)."""
    _drop_root()
    data = build(source="kommandozeile")
    target = config.DATA_DIR / "diagnose"
    target.mkdir(mode=0o700, exist_ok=True)
    path = target / file_name(data)
    path.write_bytes(make_zip(data))
    os.chmod(path, 0o600)
    print(f"Diagnosepaket geschrieben: data/diagnose/{path.name}")
    for h in data["auffaelligkeiten"]:
        print(f"  • {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
