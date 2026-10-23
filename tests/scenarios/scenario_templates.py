"""Szenario: Template-Felder (Basisordner, Laufwerk, Skript) und Basisordner-Anlage beim Onboarding."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

import types as _t  # noqa: E402
import samonboarding.routers.templates as T  # noqa: E402
import samonboarding.routers.onboarding as O  # noqa: E402
from samonboarding.naming import normalize_home_drive  # noqa: E402

reset()
N = _t.SimpleNamespace
out, adm, _ = login("admin", "Pass1", ip="10.30.0.1")
out, op, _ = login("op", "Pass2", ip="10.30.0.2")

check("normalize_home_drive", [normalize_home_drive(x) for x in ("h", "H:", " z ", "", None)] == ["H:", "H:", "Z:", "", ""])
for bad in ("HH", "1:", "H::", "\\\\x", "C:\\"):
    try:
        normalize_home_drive(bad); check(f"Laufwerk {bad!r} abgelehnt", False)
    except ValueError:
        pass
check("ungueltige Laufwerke abgelehnt", True)

def tmpl(**kw):
    d = {"name": "T1", "ouDn": "OU=Staff," + B, "profilePath": "\\\\fs\\p$\\%username%", "scriptPath": "logon.bat",
         "homeDirectory": "\\\\fs\\home$\\%username%", "homeDrive": "h"}
    d.update(kw)
    return d

c = T.sanitize_template(tmpl())
check("Drive normalisiert + scriptPath uebernommen", c["homeDrive"] == "H:" and c["scriptPath"] == "logon.bat" and c["homeDirectory"].endswith("%username%"))
c = T.sanitize_template(tmpl(homeDrive="", homeDirectory="C:\\Users\\%username%"))
check("Lokaler Pfad ohne Laufwerk erlaubt", c["homeDrive"] == "" and c["homeDirectory"].startswith("C:"))
c = T.sanitize_template(tmpl(homeDrive="", homeDirectory="\\\\fs\\home$\\%username%"))
check("UNC ohne Laufwerk erlaubt", c["homeDrive"] == "")
for name, kw in [("Laufwerk ohne Pfad", dict(homeDirectory="")), ("Laufwerk mit lokalem Pfad", dict(homeDirectory="C:\\x")),
                 ("Laufwerk ungueltig", dict(homeDrive="ZZ")), ("Pfad zu lang", dict(profilePath="\\\\a\\b\\" + "x" * 300)),
                 ("Skript zu lang", dict(scriptPath="x" * 261))]:
    ok, e = raises(lambda kw=kw: T.sanitize_template(tmpl(**kw)), 400)
    check(f"Template abgelehnt: {name}", ok, e.detail if e else "")
ok, _ = raises(lambda: T.save_template(tmpl(), op), 403)
check("Operator darf kein Template speichern", ok)
res = T.save_template(tmpl(), adm)
tid = res["templates"][0]["id"]
saved = T.get_templates(adm)[0]
check("Template gespeichert mit neuen Feldern", saved["scriptPath"] == "logon.bat" and saved["homeDrive"] == "H:")

def onboard(**kw):
    return O.execute_onboard(M["OnboardModel"](firstName="Eva", lastName="Test", templateId=tid, customMail="e@x.de"), BackgroundTasks(), adm)

r = onboard()
dn = [k for k in D if k.startswith("CN=Eva Test")][0]
a = {k.lower(): v[0] for k, v in D[dn].items()}
check("Onboarding: homeDirectory mit %username% ersetzt", a["homedirectory"] == "\\\\fs\\home$\\" + r["samAccountName"], a.get("homedirectory"))
check("Onboarding: homeDrive H:, scriptPath, profilePath", a["homedrive"] == "H:" and a["scriptpath"] == "logon.bat" and a["profilepath"] == "\\\\fs\\p$\\" + r["samAccountName"])
check("Onboarding ohne Warnungen", r["warnings"] == [], r["warnings"])

# Altes/ungueltiges Template in der Datei (vor der Validierung gespeichert)
tm = json.load(open(M["TEMPLATES_FILE"], encoding="utf-8"))
tm[0].update(homeDrive="Q", homeDirectory="C:\\lokal")
json.dump(tm, open(M["TEMPLATES_FILE"], "w", encoding="utf-8"))
r = onboard()
dn2 = [k for k in D if k.startswith("CN=Eva Test 2")][0]
a2 = {k.lower(): v[0] for k, v in D[dn2].items()}
check("Altes Template: Laufwerk ohne UNC wird nicht gesetzt + Warnung", "homedrive" not in a2 and a2["homedirectory"] == "C:\\lokal" and any("Laufwerk" in w for w in r["warnings"]), r["warnings"])
tm[0].update(homeDrive="ZZZ")
json.dump(tm, open(M["TEMPLATES_FILE"], "w", encoding="utf-8"))
r = onboard()
check("Altes Template: kaputtes Laufwerk -> Warnung, Konto trotzdem angelegt", r["status"] == "success" and any("ungültig" in w for w in r["warnings"]))

# ---- Basisordner beim Onboarding anlegen ----
import samonboarding.acl as acl  # noqa: E402
import ldap3  # noqa: E402
from samonboarding.fileshare import FsError  # noqa: E402

c = T.sanitize_template(tmpl())
check("createHomeFolder standardmaessig aus", c["createHomeFolder"] is False)
c = T.sanitize_template(tmpl(createHomeFolder=True))
check("createHomeFolder wird uebernommen", c["createHomeFolder"] is True)
ok, e = raises(lambda: T.sanitize_template(tmpl(createHomeFolder=True, homeDirectory="C:\\x", homeDrive="")), 400)
check("Anlegen nur mit Netzwerkpfad", ok and "Netzwerkpfad" in e.detail, e.detail if e else "")
ok, e = raises(lambda: T.sanitize_template(tmpl(createHomeFolder=True, homeDirectory="", homeDrive="")), 400)
check("Anlegen ohne Pfad abgelehnt", ok)

class HomeFS:
    """Simuliertes Dateisystem fuer das Anlegen: Freigabe und vorhandene Ordner."""
    def __init__(self, existing=("\\\\fs\\home$",), fail_grant=None, always_exists=False):
        self.always_exists = always_exists
        self.dirs = {x.lower() for x in existing}
        self.acl = {}
        self.fail_grant = fail_grant
        self.closed = False
        self.calls = []
    def mkdir(self, path):
        self.calls.append(("mkdir", path))
        parent = path.rpartition("\\")[0].lower()
        if path.lower() in self.dirs or self.always_exists:
            raise FsError("exists", "Existiert bereits.")
        if parent not in self.dirs:
            raise FsError("notfound", "Pfad nicht gefunden.")
        self.dirs.add(path.lower())
    def grant_access(self, path, is_dir, sid, mask=acl.FILE_ALL_ACCESS):
        self.calls.append(("grant", path, sid))
        if self.fail_grant:
            raise FsError("denied", self.fail_grant)
        self.acl[path.lower()] = sid
    def close(self):
        self.closed = True

SID = "S-1-5-21-1-2-3-1105"
orig_add = ldap3.Connection.add
def add_with_sid(self, dn, object_class=None, attributes=None):
    ok = orig_add(self, dn, object_class, attributes)
    if ok:
        D[dn]["objectSid"] = [SID]
    return ok
ldap3.Connection.add = add_with_sid

def save_home_template(**kw):
    res = T.save_template(tmpl(name="Home", createHomeFolder=True, **kw), adm)
    return [t for t in res["templates"] if t["name"] == "Home"][0]["id"]
def onboard_t(template_id, first="Hans"):
    return O.execute_onboard(M["OnboardModel"](firstName=first, lastName="Heim", templateId=template_id, customMail="h@x.de"), BackgroundTasks(), adm)

hid = save_home_template()
fsh = HomeFS()
O.make_backend = lambda user: fsh
r = onboard_t(hid)
home = "\\\\fs\\home$\\" + r["samAccountName"]
check("Ordner angelegt, Konto bekommt Rechte", home.lower() in fsh.dirs and fsh.acl.get(home.lower()) == SID and r["warnings"] == [], (r["warnings"], fsh.calls))
check("Backend wird geschlossen", fsh.closed)

fsh = HomeFS(always_exists=True)
O.make_backend = lambda user: fsh
r = onboard_t(hid, first="Hans2")
check("Vorhandener Ordner wird nicht angefasst", r["status"] == "success" and not fsh.acl and any("existiert bereits" in w for w in r["warnings"]), r["warnings"])

fsh = HomeFS(existing=())
O.make_backend = lambda user: fsh
r = onboard_t(hid, first="Hans3")
check("Freigabe fehlt -> Warnung, Konto angelegt", r["status"] == "success" and any("existiert nicht" in w for w in r["warnings"]) and any(k.startswith("CN=Hans3 Heim") for k in D), r["warnings"])

fsh = HomeFS(fail_grant="Zugriff verweigert.")
O.make_backend = lambda user: fsh
r = onboard_t(hid, first="Hans4")
check("Rechte nicht setzbar -> Warnung mit Pfad", r["status"] == "success" and any("Zugriff verweigert" in w and "\\\\fs\\home$" in w for w in r["warnings"]), r["warnings"])

def broken(user):
    raise FsError("auth", "Anmeldung am Dateiserver fehlgeschlagen.")
O.make_backend = broken
r = onboard_t(hid, first="Hans5")
check("Dateiserver nicht erreichbar -> Warnung, Konto bleibt", r["status"] == "success" and any("Anmeldung" in w for w in r["warnings"]))

# ohne Flag: Dateiserver wird gar nicht angefasst
O.make_backend = lambda user: (_ for _ in ()).throw(AssertionError("darf nicht aufgerufen werden"))
r = onboard()
check("Ohne createHomeFolder kein Dateizugriff", r["status"] == "success")
ldap3.Connection.add = orig_add

# ---- Exchange-Postfach (eigener Server): nur fuer Templates mit E-Mail-Modus 'exchange'
import samonboarding.exchange as X  # noqa: E402
import samonboarding.routers.settings as ST  # noqa: E402
XM = M["ExchangeConfigModel"]
calls = []
def fake_enable(cfg, user, user_dn, domain_controller=""):
    calls.append((user_dn, domain_controller, cfg["server"]))
    D[user_dn]["mail"] = ["gesetzt.von.exchange@x.de"]
O.enable_mailbox = fake_enable
def mk_exchange_tpl(name, mode):
    res = T.save_template(tmpl(name=name, mailMode=mode), adm)
    return [t for t in res["templates"] if t["name"] == name][0]["id"]
tid_ex, tid_cloud, tid_req = mk_exchange_tpl("Mit Exchange", "exchange"), mk_exchange_tpl("Mit 365", "cloud"), mk_exchange_tpl("Mit Mailserver", "required")
def onboard_x(template_id, first="Eva", mail=""):
    return O.execute_onboard(M["OnboardModel"](firstName=first, lastName="Test", templateId=template_id, customMail=mail), BackgroundTasks(), adm)

r = onboard_x(tid_ex, "Erst")
check("Exchange-Anbindung aus: Template 'exchange' -> Warnung, Konto angelegt, kein Aufruf", not calls and r["status"] == "success" and any("nicht eingerichtet" in w for w in r["warnings"]), r["warnings"])
ST.save_exchange_config(XM(enabled=True, server="exch01.test.local"), adm)
r = onboard_x(tid_ex, "Zweit")
check("Template 'exchange': Postfach wird angelegt, gleicher DC uebergeben", len(calls) == 1 and calls[0][2] == "exch01.test.local" and not any("Postfach" in w for w in r["warnings"]), (calls, r["warnings"]))
check("Von Exchange gesetzte Adresse erscheint im Ergebnis", r["mail"] == "gesetzt.von.exchange@x.de", r["mail"])
n = len(calls)
r = onboard_x(tid_cloud, "Dritt")
check("Template 'cloud': kein Exchange-Aufruf trotz aktiver Anbindung, E-Mail nicht Pflicht", len(calls) == n and r["status"] == "success" and r["mail"] == "")
r = onboard_x(tid_req, "Viert", mail="v@x.de")
check("Template 'required': kein Exchange-Aufruf, Adresse wird gesetzt", len(calls) == n and r["mail"] == "v@x.de")
ok, _ = raises(lambda: onboard_x(tid_req, "Fuenft"), 400, "E-Mail")
check("Template 'required' ohne Adresse -> 400", ok)
def failing_enable(cfg, user, user_dn, domain_controller=""):
    raise X.ExchangeError("Server nicht erreichbar.")
O.enable_mailbox = failing_enable
r = onboard_x(tid_ex, "Sechst")
check("Exchange-Fehler -> Warnung, Konto bleibt", r["status"] == "success" and any("Postfach konnte nicht angelegt" in w and "nachholen" in w for w in r["warnings"]), r["warnings"])

print(f"\n{PASS} Pruefungen bestanden")
