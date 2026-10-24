"""Szenario: Kernfunktionen (Anmeldung, Rollen, Onboarding, Offboarding, Gruppen, Einstellungen, Mail, Audit)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

reset()
VER = M["VERSION"]

# ---- 1. Hilfsfunktionen
check("split_dn mit escaped Komma", M["split_dn"]("CN=Meier\\, Hans,OU=A,DC=x") == ["CN=Meier\\, Hans", "OU=A", "DC=x"])
check("rdn_label unescaped", M["rdn_label"]("CN=Meier\\, Hans,OU=A") == "Meier, Hans")
check("escape_rdn_value", M["escape_rdn_value"]('Meier, Hans+"x"') == 'Meier\\, Hans\\+\\"x\\"')
check("ldap_escape", M["ldap_escape"]("a*)(b\\") == "a\\2a\\29\\28b\\5c")
check("dn_is_within", M["dn_is_within"]("CN=a,OU=Staff,DC=t", "ou=staff, dc=t") and not M["dn_is_within"]("CN=a,OU=StaffX,DC=t", "OU=Staff,DC=t"))
am = M["apply_macro"]
check("macro default", am("%LASTNAME%%FIRSTNAME%[3]", "Jürgen", "Müller") == "MUELLERJUE")
check("macro %FIRSTNAME[1]%.%LASTNAME%", am("%FIRSTNAME[1]%.%LASTNAME%", "Anna", "Schmidt") == "A.SCHMIDT")
check("macro beliebige Laenge", am("%FIRSTNAME[7]%", "Alexander", "x") == "ALEXAND")
check("accents entfernt", M["remove_umlauts"]("José Ñandú") == "JOSENANDU")
check("sanitize_sam 20 Zeichen", len(M["sanitize_sam"]("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) == 20 and M["sanitize_sam"]("a b/c") == "ABC")
check("country_code", M["country_code"]("Österreich") == "AT" and M["country_code"]("xx land") is None and M["country_code"]("de") == "DE")
check("Passwort-Generator erfuellt Komplexitaet", all(
    any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p) and len(p) == 12
    for p in (M["generate_secure_password"]() for _ in range(50))))
check("Passwort ohne verwechselbare Zeichen (0 O o 1 l I)", not any(
    c in "0Oo1lI" for c in "".join(M["generate_secure_password"]() for _ in range(300))))

# ---- 2. Login
bad, e = raises(lambda: login("admin", "falsch"), 401)
check("falsches PW -> 401", bad)
check("genau 1 Bind-Versuch", len(STATE["binds"]) == 1, STATE["binds"])
STATE["ports"].clear()
raises(lambda: login("admin", "falsch"), 401)
check("kein Port-389-Fallback bei falschem PW", STATE["ports"] == [636], STATE["ports"])
raises(lambda: login("admin", "falsch"), 401)
ok, e = raises(lambda: login("admin", "Pass1"), 429)
check("Rate-Limit nach 3 Fehlversuchen (429)", ok)
out, adm, resp = login("admin", "Pass1", ip="10.9.9.9")
check("Admin-Login", out["role"] == "Administrator" and adm["bind_user"] == "admin@test.local")
_ck = resp.cookies["session_id"][1]
check("Cookie httponly/strict/secure, endet mit dem Browser", _ck["httponly"] and _ck["samesite"] == "strict" and _ck["secure"] is True and "max_age" not in _ck, _ck)
out, op, _ = login("op", "Pass2")
check("Operator-Login", out["role"] == "Account Operator")
ok, _ = raises(lambda: login("nobody", "Pass3"), 403)
check("Benutzer ohne Gruppe -> 403", ok)
# Rolle nach SID, nicht nach Namen: eine selbst angelegte Gruppe "Domain Admins"/"Administrators" (auf deutschen DCs
# sind diese Namen frei) darf keine Administrator-Rolle geben
add("CN=Fake Admins,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="Administrators", objectSid="S-1-5-21-1-2-3-4711", member=["CN=Nobody,OU=Staff," + B])
add("CN=Fake DA,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="Domain Admins x", objectSid="S-1-5-21-1-2-3-4712", member=["CN=Nobody,OU=Staff," + B])
ok, _ = raises(lambda: login("nobody", "Pass3"), 403)
check("Gruppe mit Admin-Namen, aber fremder SID -> keine Rolle", ok)
del D["CN=Fake Admins,OU=Groups," + B], D["CN=Fake DA,OU=Groups," + B]
# deutsche Gruppennamen werden ueber die SID erkannt
M["_login_failures"].clear()
D["CN=Domain Admins,CN=Users," + B]["sAMAccountName"] = ["Domänen-Admins"]
out, _, _ = login("admin", "Pass1")
check("Domänen-Admins (deutscher Name) -> Administrator", out["role"] == "Administrator", out)
D["CN=Domain Admins,CN=Users," + B]["sAMAccountName"] = ["Domain Admins"]
out, _, _ = login("admin@test.local", "Pass1")
check("Anmeldung per UPN liefert den sAMAccountName", out["user"] == "admin", out)
ok, _ = raises(lambda: login("", "x"), 401)
check("leerer Benutzername -> 401", ok)
ok, _ = raises(lambda: login("admin", ""), 401)
check("leeres Passwort -> 401 (kein anonymer Bind)", ok)
ok, _ = raises(lambda: login("*)(objectClass=*", "x", ip="10.5.5.5"), 401)
check("Filter-Injection im Login wirkungslos", ok)
STATE["dc_down_ssl"] = True
STATE["ports"].clear()
out, _, _ = login("op", "Pass2", ip="10.7.7.7")
check("Fallback auf 389 nur bei Verbindungsfehler", STATE["ports"] == [636, 389])
STATE["dc_down_ssl"] = False
exp = dict(adm)
exp["expires"] = time.time() - 1
M["active_sessions"]["old"] = exp
ok, _ = raises(lambda: M["get_current_user"]("old"), 401)
check("abgelaufene Session -> 401", ok and "old" not in M["active_sessions"])
tok = [k for k, v in M["active_sessions"].items() if v["username"] == "op"][0]
M["logout"](Response(), tok)
check("Logout entfernt Sitzung", tok not in M["active_sessions"])
out, op, _ = login("op", "Pass2")
check("me liefert Sitzungsdaten", M["get_me"](op)["user"] == "op")

# ---- 3. Konfiguration + Listen
CFG = M["OffboardingConfigModel"](sourceOus=["OU=Staff," + B, "OU=Staff," + B], targetOu="OU=Archive," + B)
M["save_offboarding_config"](CFG, adm)
ok, _ = raises(lambda: M["save_offboarding_config"](CFG, op), 403)
check("Config nur Admin", ok)
check("OU-Liste dedupliziert", json.load(open("data/offboarding_config.json"))["sourceOus"] == ["OU=Staff," + B])
M["save_pwdreset_config"](M["PwdResetConfigModel"](sourceOus=["OU=Staff," + B]), adm)
M["save_usermgmt_config"](M["UserMgmtConfigModel"](sourceOus=["OU=Staff," + B], targetOus=["OU=Archive," + B], groupOus=["OU=Groups," + B]), adm)
users = M["get_offboarding_users"](adm)["users"]
check("Offboarding-Liste ohne Computer", {u["sam"] for u in users} == {"admin", "op", "nobody", "MUSTERMANN"}, users)
pu = {u["sam"]: u for u in M["get_pwdreset_users"](adm)["users"]}
check("locked=False bei lockoutTime 0", pu["MUSTERMANN"]["locked"] is False)
D["CN=Mustermann\\, Max,OU=Staff," + B]["lockoutTime"] = ["133000000000000000"]
pu = {u["sam"]: u for u in M["get_pwdreset_users"](adm)["users"]}
check("Aenderung direkt im AD: Liste bis zu 60 s aus dem Zwischenspeicher", pu["MUSTERMANN"]["locked"] is False)
pu = {u["sam"]: u for u in M["get_pwdreset_users"](adm, True)["users"]}
check("locked=True bei lockoutTime>0 (Aktualisieren liest frisch)", pu["MUSTERMANN"]["locked"] is True)
um = {u["sam"]: u for u in M["get_usermgmt_users"](adm)["users"]}
check("Gruppenname mit Komma korrekt", um["MUSTERMANN"]["groups"] == ["Printers"] and um["MUSTERMANN"]["currentOu"] == "OU=Staff," + B, um["MUSTERMANN"])
infra = M["get_ad_infrastructure"](adm)
check("Infrastruktur", len(infra["ous"]) == 3 and "error" not in infra and any(g["name"] == "VPN" for g in infra["groups"]))
sc = M["get_smtp_config"](adm)
check("SMTP-Config lesen (Passwort maskiert)", "password" in sc and sc["password"] in ("", "••••••••••••"))
ok, _ = raises(lambda: M["get_smtp_config"](op), 403)
check("SMTP-Config nur Admin", ok)
SM = M["SmtpConfigModel"]
_smtp = dict(enabled=False, displayName="IT, Abteilung", host="mail.test.local", port=587, username="svc", password="Geheim!", fromEmail="it@test.local", ccRecipients="", tlsMode="Auto", notifyOffboarding=False, notifyPwdReset=False, notifyUserMgmt=False)
M["save_smtp_config"](SM(**_smtp), adm)
M["save_smtp_config"](SM(**dict(_smtp, password="••••••••••••")), adm)
check("SMTP: maskiertes Passwort behaelt das gespeicherte", M["load_json"]("data/smtp_config.json", {})["password"] == "Geheim!")
ok, _ = raises(lambda: M["save_smtp_config"](SM(**dict(_smtp, host="evil.example", password="••••••••••••")), adm), 400, "neu eingeben")
check("SMTP: anderer Server ohne neues Passwort -> 400 (Passwort nicht an fremden Server)", ok and M["load_json"]("data/smtp_config.json", {})["host"] == "mail.test.local")
M["save_smtp_config"](SM(**dict(_smtp, host="mail2.test.local", password="Neu!")), adm)
check("SMTP: anderer Server mit neuem Passwort", M["load_json"]("data/smtp_config.json", {})["password"] == "Neu!")
ok, _ = raises(lambda: M["save_smtp_config"](SM(**dict(_smtp, displayName="IT\r\nBcc: x@evil", password="x")), adm), 400, "Zeilenumbr")
check("SMTP: Zeilenumbruch in Kopfzeilen -> 400", ok)
check("public-config", M["get_public_config"]()["domain"] == "test.local")

# ---- 4. Gruppen
MAX = "CN=Mustermann\\, Max,OU=Staff," + B
bg = BackgroundTasks()
r = M["update_user_groups"](M["UpdateUserGroupsModel"](userDn=MAX, addGroupDns=["CN=VPN,OU=Groups," + B], removeGroupDns=["CN=Printers,OU=Groups," + B]), bg, adm)
check("Gruppen add/remove", MAX in D["CN=VPN,OU=Groups," + B]["member"] and MAX not in D["CN=Printers,OU=Groups," + B]["member"] and not r["failed"])
ok, _ = raises(lambda: M["update_user_groups"](M["UpdateUserGroupsModel"](userDn=MAX, addGroupDns=["CN=Secret,CN=Users," + B], removeGroupDns=[]), bg, adm), 403)
check("Gruppe ausserhalb groupOus -> 403", ok)
ok, _ = raises(lambda: M["update_user_groups"](M["UpdateUserGroupsModel"](userDn="CN=Admin Elsewhere,CN=Users," + B, addGroupDns=[], removeGroupDns=["CN=VPN,OU=Groups," + B]), bg, adm), 403)
check("Benutzer ausserhalb sourceOus -> 403", ok)
STATE["deny"] = {"member"}
ok, e = raises(lambda: M["update_user_groups"](M["UpdateUserGroupsModel"](userDn=MAX, addGroupDns=["CN=Printers,OU=Groups," + B], removeGroupDns=[]), bg, adm), 500, "insufficientAccessRights")
check("Fehlgeschlagene Gruppenaenderung wird NICHT als Erfolg gemeldet", ok)
STATE["deny"] = set()
r = M["update_user_groups"](M["UpdateUserGroupsModel"](userDn=MAX, addGroupDns=["CN=VPN,OU=Groups," + B], removeGroupDns=[]), bg, adm)
check("Bereits Mitglied = ok (idempotent)", not r["failed"])
r = M["get_user_groups"](MAX, adm)
check("user-groups: Mitgliedschaften + verfuegbare Gruppen", r["userMemberOf"] == ["CN=VPN,OU=Groups," + B] and {g["name"] for g in r["availableGroups"]} == {"Printers", "VPN"}, r)

# ---- 5. Move
mv = M["MoveUserActionModel"]
M["move_user_account"](mv(userDn="CN=Nobody,OU=Staff," + B, targetOu="OU=archive," + B), adm)
check("Move in erlaubte OU", "CN=Nobody,OU=Archive," + B in D)
ok, _ = raises(lambda: M["move_user_account"](mv(userDn=MAX, targetOu="OU=Groups," + B), adm), 403)
check("Move in nicht erlaubte OU -> 403", ok)
M["move_user_account"](mv(userDn=MAX, targetOu="OU=Archive," + B), adm)
check("Move mit Komma im CN", "CN=Mustermann\\, Max,OU=Archive," + B in D)
D["CN=Mustermann\\, Max,OU=Staff," + B] = D.pop("CN=Mustermann\\, Max,OU=Archive," + B)
D["CN=Nobody,OU=Staff," + B] = D.pop("CN=Nobody,OU=Archive," + B)

# ---- 6. Passwort-Reset
PR = M["PwdResetActionModel"]
bg = BackgroundTasks()
STATE["pwd_fail"] = True
ok, e = raises(lambda: M["execute_pwdreset"](PR(userDn=MAX, mode="auto", newPassword="", forceChange=True, unlockAccount=True), bg, adm), 500, "Passwort setzen fehlgeschlagen")
check("PW-Reset: AD-Ablehnung wird gemeldet (mit Hinweis)", ok and "Passwortrichtlinie" in e.detail, e and e.detail)
STATE["pwd_fail"] = False
r = M["execute_pwdreset"](PR(userDn=MAX, mode="auto", newPassword="", forceChange=True, unlockAccount=True), bg, adm)
check("PW-Reset ok", r["sam"] == "MUSTERMANN" and len(r["newPassword"]) == 12 and D[MAX]["lockoutTime"] == [0] and D[MAX]["pwdLastSet"] == [0])
ok, _ = raises(lambda: M["execute_pwdreset"](PR(userDn=MAX, mode="manual", newPassword="abc", forceChange=True, unlockAccount=False), bg, adm), 400)
check("zu kurzes PW -> 400", ok)
ok, _ = raises(lambda: M["execute_pwdreset"](PR(userDn="CN=Nope,OU=Staff," + B, mode="auto", newPassword="", forceChange=True, unlockAccount=False), bg, adm), 404)
check("unbekannter Benutzer -> 404", ok)
STATE["deny"] = {"lockoutTime"}
r = M["execute_pwdreset"](PR(userDn=MAX, mode="auto", newPassword="", forceChange=False, unlockAccount=True), bg, adm)
check("Teilfehler (Entsperren) -> warnings, Passwort trotzdem geliefert", r["warnings"] and r["newPassword"])
STATE["deny"] = set()
cfg = M["load_json"]("data/smtp_config.json", M["default_smtp_config"])
cfg["notifyPwdReset"] = True
cfg["enabled"] = True
M["save_json"]("data/smtp_config.json", cfg)
bg = BackgroundTasks()
M["execute_pwdreset"](PR(userDn=MAX, mode="auto", newPassword="", forceChange=True, unlockAccount=False), bg, adm)
check("Mail wird als Background-Task eingeplant", len(bg.tasks) == 1)

# ---- 7. Offboarding
OB = M["OffboardActionModel"]
bg = BackgroundTasks()
ok, _ = raises(lambda: M["execute_offboarding"](OB(userDn="CN=Admin User,OU=Staff," + B), bg, adm), 400, "eigenes")
check("Selbst-Offboarding verhindert", ok)
r = M["execute_offboarding"](OB(userDn=MAX), bg, adm)
mx = "CN=Mustermann\\, Max,OU=Archive," + B
check("Offboarding: deaktiviert, Gruppen leer, verschoben", mx in D and D[mx]["userAccountControl"] == [514] and all(MAX not in e.get("member", []) for e in D.values()), r)
ok, _ = raises(lambda: M["execute_offboarding"](OB(userDn=mx), bg, adm), 403)
check("Offboarding ausserhalb Quell-OU -> 403", ok)

# Geschuetzte Konten (Domaenen-Admins & Co.) lassen sich nicht offboarden
UCLS = ["top", "person", "organizationalPerson", "user"]
def mkuser(cn, sam, groups, admin_count=None):
    attrs = dict(objectClass=UCLS, sAMAccountName=sam, displayName=cn, userAccountControl="512", tokenGroups=groups,
                 objectSid="S-1-5-21-1-2-3-" + str(2000 + len(D)))
    if admin_count:
        attrs["adminCount"] = admin_count
    add(f"CN={cn},OU=Staff," + B, **attrs)
    return f"CN={cn},OU=Staff," + B
DOMAIN_USERS = "S-1-5-21-1-2-3-513"
dom = mkuser("Dom Admin", "domadm", ["S-1-5-21-1-2-3-512", DOMAIN_USERS], "1")
blt = mkuser("Builtin Admin", "bltadm", ["S-1-5-32-544", DOMAIN_USERS])           # adminCount noch nicht gesetzt
ent = mkuser("Org Admin", "entadm", ["S-1-5-21-9-9-9-519", DOMAIN_USERS], "1")  # Organisations-Admin aus anderer Domaene
exa = mkuser("Ex Admin", "exadm", [DOMAIN_USERS], "1")                          # adminCount veraltet, aber keine Mitgliedschaft mehr
nor = mkuser("Normal User", "normal", [DOMAIN_USERS])
lst = {x["sam"]: x for x in M["get_offboarding_users"](adm)["users"]}
check("Liste markiert Domaenen-Admin als geschuetzt", "Domänen-Admins" in lst["domadm"]["protected"] and "Organisations-Admins" in lst["entadm"]["protected"], lst["domadm"])
check("Admin ohne adminCount-Markierung wird in der Liste trotzdem geschuetzt", "Administratoren" in lst["bltadm"]["protected"], lst["bltadm"])
check("Ehemaliger Admin (nur adminCount) und Normalo sind nicht geschuetzt", lst["exadm"]["protected"] == "" and lst["normal"]["protected"] == "")
check("Interne Felder tauchen nicht in der Liste auf", not any(k.startswith("_") for x in lst.values() for k in x))
for dn_, name in ((dom, "Domaenen-Admin"), (blt, "Builtin-Admin ohne adminCount"), (ent, "Organisations-Admin")):
    before = json.dumps(D[dn_], sort_keys=True, default=str)
    ok, e = raises(lambda dn_=dn_: M["execute_offboarding"](OB(userDn=dn_), bg, adm), 403)
    check(f"Offboarding verweigert: {name}", ok and "geschützt" in e.detail and dn_ in D and json.dumps(D[dn_], sort_keys=True, default=str) == before, e.detail if e else "")
ok, _ = raises(lambda: M["execute_offboarding"](OB(userDn=dom), bg, op), 403)
check("Auch fuer Operatoren verweigert", ok and dom in D)
check("Verweigerung steht im Audit-Log", '"ok": false' in M["audit_jsonl"]() and "geschützt" in M["audit_jsonl"]())
M["execute_offboarding"](OB(userDn=exa), bg, adm)
M["execute_offboarding"](OB(userDn=nor), bg, adm)
check("Ehemalige Admins und normale Konten lassen sich offboarden", f"CN=Ex Admin,OU=Archive," + B in D and f"CN=Normal User,OU=Archive," + B in D)

# Mehrfach-Offboarding
OBB = M["OffboardBatchModel"]
b1 = mkuser("Batch Eins", "bat1", [DOMAIN_USERS])
b2 = mkuser("Batch Zwei", "bat2", [DOMAIN_USERS])
bg = BackgroundTasks()
r = M["execute_offboarding_batch"](OBB(userDns=[b1, dom, b2, b1, "CN=Admin User,OU=Staff," + B, blt]), bg, adm)
check("Batch: normale Konten offgeboardet, Duplikat nur einmal", [x["sam"] for x in r["done"]] == ["bat1", "bat2"] and r["status"] == "success", r)
check("Batch: geschuetzte Konten und eigenes Konto einzeln abgelehnt", len(r["failed"]) == 3 and sum("geschützt" in f["error"] for f in r["failed"]) == 2 and any("eigenes" in f["error"] for f in r["failed"]), r["failed"])
check("Batch: Konten liegen in der Ziel-OU, geschuetzte unveraendert", "CN=Batch Eins,OU=Archive," + B in D and "CN=Batch Zwei,OU=Archive," + B in D and dom in D and D[dom]["userAccountControl"] == ["512"], "")
ok, _ = raises(lambda: M["execute_offboarding_batch"](OBB(userDns=[]), bg, adm), 400)
check("Batch: leere Auswahl -> 400", ok)
ok, _ = raises(lambda: M["execute_offboarding_batch"](OBB(userDns=[f"CN=x{i},OU=Staff," + B for i in range(26)]), bg, adm), 400, "25")
check("Batch: mehr als 25 -> 400", ok)
r = M["execute_offboarding_batch"](OBB(userDns=[dom]), bg, op)
check("Batch: nur geschuetzte Konten -> status error, nichts veraendert", r["status"] == "error" and dom in D, r)
n_before = sum(1 for k in D if k.endswith("OU=Archive," + B))
r = M["execute_offboarding_batch"](OBB(userDns=["CN=Batch Eins,OU=Archive," + B]), bg, adm)
check("Batch: Konto ausserhalb der Quell-OU -> einzeln abgelehnt", len(r["failed"]) == 1 and not r["done"] and sum(1 for k in D if k.endswith("OU=Archive," + B)) == n_before, r)

# Exchange-Einstellungen: nur Administratoren, Eingaben werden geprueft
XCM = M["ExchangeConfigModel"]
ok, _ = raises(lambda: M["save_exchange_config"](XCM(enabled=True, server="exch01"), op), 403)
check("Exchange-Einstellung nur fuer Administratoren", ok)
ok, _ = raises(lambda: M["get_exchange_config"](op), 403)
check("Exchange-Einstellung lesen nur fuer Administratoren", ok)
ok, _ = raises(lambda: M["test_exchange_config"](XCM(server="exch01"), op), 403)
check("Exchange-Test nur fuer Administratoren", ok)
for bad, name in ((dict(enabled=True, server=""), "ohne Server"), (dict(server="https://exch01"), "mit https://"), (dict(server="a b"), "mit Leerzeichen"), (dict(server="exch01", auth="x"), "falsche Anmeldeart"), (dict(server="exch01", port=70000), "falscher Port")):
    ok, _ = raises(lambda bad=bad: M["save_exchange_config"](XCM(**bad), adm), 400)
    check(f"Exchange: Eingabe {name} -> 400", ok)
M["save_exchange_config"](XCM(enabled=True, server=" exch01.test.local ", auth="NTLM", database="DB1"), adm)
saved = M["get_exchange_config"](adm)
check("Exchange-Einstellung gespeichert und bereinigt", saved["server"] == "exch01.test.local" and saved["auth"] == "ntlm" and saved["enabled"] and saved["verifyCert"] and saved["database"] == "DB1", saved)
check("Exchange-Audit ohne Passwort", '"config-exchange"' in M["audit_jsonl"]())
M["save_exchange_config"](XCM(enabled=False), adm)

# ---- 8. Templates
tpl = {"name": " Standard ", "naming": "%LASTNAME%%FIRSTNAME%[3]", "ouDn": "OU=Staff," + B, "pwdMode": "static", "staticPwd": "Geheim1!", "forceChange": True,
       "pwdNeverExpires": False, "country": "Österreich", "groups": ["CN=VPN,OU=Groups," + B], "evil": "<x>", "id": None}
r = M["save_template"](dict(tpl), adm)
t1 = r["templates"][0]
check("Template gespeichert, unbekannte Felder verworfen", t1["id"] == 1 and "evil" not in t1 and t1["name"] == "Standard")
check("Operator sieht staticPwd nicht", all("staticPwd" not in t for t in M["get_templates"](op)) and M["get_templates"](adm)[0]["staticPwd"] == "Geheim1!")
ok, _ = raises(lambda: M["save_template"](dict(tpl, id=99), adm), 404)
check("Update unbekannte ID -> 404", ok)
ok, _ = raises(lambda: M["save_template"]({"name": ""}, adm), 400)
check("Template ohne Namen -> 400", ok)
ok, _ = raises(lambda: M["save_template"](dict(tpl), op), 403)
check("Template speichern nur Admin", ok)
M["save_template"](dict(tpl, name="Zweit", pwdMode="random", id=None), adm)
M["save_template"](dict(tpl, name="Standard v2", id=1), adm)
M["duplicate_template"](1, adm)
ids = sorted(t["id"] for t in M["get_templates"](adm))
check("IDs eindeutig", ids == [1, 2, 3], ids)
M["delete_template"](3, adm)
check("Template geloescht", len(M["get_templates"](adm)) == 2)

# ---- 9. Onboarding
OBM = M["OnboardModel"]
bg = BackgroundTasks()
r = M["execute_onboard"](OBM(firstName="Hans", lastName="Meier, Jr.", templateId=1, customMail="h@x.de"), bg, adm)
udn = "CN=Hans Meier\\, Jr.,OU=Staff," + B
check("Onboarding mit Komma im Namen (DN escaped)", udn in D, [k for k in D if "Hans" in k])
check("Onboarding: aktiviert, PW gesetzt, Gruppe, c=AT", D[udn]["userAccountControl"] == [512] and udn in D["CN=VPN,OU=Groups," + B]["member"] and D[udn]["c"] == ["AT"] and r["generatedPassword"] == "Geheim1!", D[udn])
check("Onboarding-Mail eingeplant", len(bg.tasks) == 1)
r2 = M["execute_onboard"](OBM(firstName="Hans", lastName="Meier, Jr.", templateId=1, customMail="h2@x.de"), bg, adm)
check("SAM-Kollision -> Zaehler", r2["samAccountName"].endswith("2"), (r["samAccountName"], r2["samAccountName"]))
check("SAM max. 20 Zeichen", len(r["samAccountName"]) <= 20 and len(r2["samAccountName"]) <= 20)
check("CN-Kollision -> 'Hans Meier, Jr. 2'", "CN=Hans Meier\\, Jr. 2,OU=Staff," + B in D, [k for k in D if "Hans" in k])
before = set(D)
STATE["pwd_fail"] = True
ok, e = raises(lambda: M["execute_onboard"](OBM(firstName="Eva", lastName="Fehler", templateId=1, customMail="e@x.de"), bg, adm), 500, "nicht angelegt")
check("Rollback: halbfertiges Konto wird entfernt", ok and set(D) == before, e and e.detail)
STATE["pwd_fail"] = False
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="", lastName="x", templateId=1, customMail="a@b"), bg, adm), 400)
check("leerer Vorname -> 400", ok)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="Eva\nAdmin", lastName="x", templateId=1, customMail="a@b.de"), bg, adm), 400, "Steuerzeichen")
check("Zeilenumbruch im Namen -> 400", ok)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="Eva", lastName="x" * 65, templateId=1, customMail="a@b.de"), bg, adm), 400)
check("Name laenger als 64 Zeichen -> 400", ok)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="Eva", lastName="Test", templateId=1, customMail="kein mail"), bg, adm), 400, "E-Mail")
check("ungueltige E-Mail -> 400", ok)
check("Pflichtfelder -> 400", ok)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="A", lastName="B", templateId=42, customMail="a@b"), bg, adm), 400)
check("Unbekanntes Template -> 400", ok)

# E-Mail-Modus beim Onboarding: je Template (eigener Mailserver / Exchange im eigenen Haus / Microsoft 365)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="Mia", lastName="Ohnemail", templateId=1), bg, adm), 400, "E-Mail")
check("Standard-Template: E-Mail ist Pflicht", ok and M["get_templates"](op)[0]["mailMode"] == "required")
def mail_tpl(mode, name):
    res = M["save_template"](dict(tpl, name=name, id=None, mailMode=mode), adm)
    return [t for t in res["templates"] if t["name"] == name][0]
check("mailMode wird gespeichert, ungueltiger Wert faellt auf Pflicht", mail_tpl("cloud", "T-Cloud")["mailMode"] == "cloud" and mail_tpl("quatsch", "T-Quatsch")["mailMode"] == "required")
t_opt, t_cloud, t_exch = mail_tpl("optional", "T-Optional"), mail_tpl("cloud", "T-Cloud2"), mail_tpl("exchange", "T-Exchange")
def find_sam(r):
    return [e for e in D.values() if e.get("sAMAccountName") in ([r["samAccountName"]], r["samAccountName"])]
r = M["execute_onboard"](OBM(firstName="Mia", lastName="Ohnemail", templateId=t_opt["id"]), bg, adm)
mia = find_sam(r)
check("Optional: Konto ohne mail-Attribut angelegt", r["status"] == "success" and r["mail"] == "" and mia and "mail" not in mia[0], r)
r = M["execute_onboard"](OBM(firstName="Max", lastName="Mitmail", templateId=t_opt["id"], customMail="m@x.de"), bg, adm)
check("Optional: angegebene E-Mail wird gesetzt", r["mail"] == "m@x.de")
r = M["execute_onboard"](OBM(firstName="Nina", lastName="Cloud", templateId=t_cloud["id"], customMail="ignoriert@x.de"), bg, adm)
nina = find_sam(r)
check("Microsoft 365: E-Mail wird ignoriert und nicht gesetzt", r["mail"] == "" and nina and "mail" not in nina[0], r)
check("Microsoft 365: kein Exchange-Aufruf, keine Warnung zum Postfach", not any("Postfach" in w for w in r["warnings"]), r["warnings"])
# Aeltere Templates ohne mailMode erben den frueher global gespeicherten Wert
legacy = M["load_json"]("data/templates.json", [])
for t in legacy:
    t.pop("mailMode", None)
M["save_json"]("data/templates.json", legacy)
check("Altes Template ohne Angabe: Pflicht", all(t["mailMode"] == "required" for t in M["get_templates"](op)))
M["save_json"]("data/onboarding_config.json", {"mailMode": "none"})
check("Altes Template erbt frueher gespeicherten globalen Wert", all(t["mailMode"] == "cloud" for t in M["get_templates"](op)))
import os as _os
_os.remove("data/onboarding_config.json")
M["save_json"]("data/templates.json", [t for t in legacy if t["name"] in ("Standard",)] or legacy[:1])

D["CN=VPN,OU=Groups," + B]["member"].clear()
STATE["deny"] = {"member"}
r = M["execute_onboard"](OBM(firstName="Zoe", lastName="Gruppe", templateId=1, customMail="z@x.de"), bg, adm)
check("Gruppen-Fehler beim Onboarding -> warnings statt stiller Erfolg", r["warnings"] and "VPN" in r["warnings"][0], r["warnings"])
STATE["deny"] = set()
t = M["load_json"]("data/templates.json", [])
t[0]["pwdMode"] = "static"
t[0]["staticPwd"] = ""
M["save_json"]("data/templates.json", t)
ok, _ = raises(lambda: M["execute_onboard"](OBM(firstName="A", lastName="B", templateId=1, customMail="a@b.de"), bg, adm), 400, "kein")
check("Static-PW-Template ohne PW -> 400 (kein Hardcode-Fallback)", ok)

# ---- 10. JSON-Speicher
open("data/bad.json", "w").write("{kaputt")
check("Defektes JSON -> Default + Datei gesichert", M["load_json"]("data/bad.json", {"x": 1}) == {"x": 1} and any(f.startswith("bad.json.corrupt-") for f in os.listdir("data")))
M["save_json"]("data/ok.json", {"a": "ä"})
check("Atomares Speichern, keine .tmp-Reste", json.load(open("data/ok.json", encoding="utf-8")) == {"a": "ä"} and not os.path.exists("data/ok.json.tmp"))
mut = M["load_json"]("data/none.json", M["default_usermgmt_config"])
mut["sourceOus"].append("x")
check("Default wird nicht mutiert", M["default_usermgmt_config"]["sourceOus"] == [])

# ---- 11. Mail, Oberflaeche, Audit, Header
txt, htm = M["render_mail"]("Op", "T", "#000", "Hi <b>", [("Name:", "<script>alert(1)</script>", "bold")])
check("Mail: HTML wird escaped", "<script>" not in htm and "&lt;script&gt;" in htm and "&lt;b&gt;" in htm)
page = M["serve_gui"]()
check("GUI: Platzhalter ersetzt", "__APP_" not in page and "__ASSET_HEAD__" not in page and f"test.local - SAMONBOARDING v{VER}" in page)
_i18n_block = page.split('<script id="i18n-data" type="application/json">')[1].split("</script>")[0]
check("GUI: Woerterbuch eingebettet, ohne Script-Ende im JSON", "__I18N__" not in page and json.loads(_i18n_block)["exact"]["Konto suchen..."] == "Search account..." and "</" not in _i18n_block)
audit_txt = M["audit_jsonl"]()
check("Audit-Log geschrieben ohne Passwoerter", "Geheim1" not in audit_txt and '"action": "onboard"' in audit_txt)


class _Resp:
    def __init__(self):
        self.headers = {}


async def _next(req):
    return _Resp()


import asyncio  # noqa: E402

mw = [m for m in M["app"].middlewares if m.__name__ == "_security_headers"][0]
r_api = asyncio.run(mw(Request(path="/api/me"), _next))
r_static = asyncio.run(mw(Request(path="/static/app.css"), _next))
check("Security-Header + no-store fuer API", r_api.headers.get("X-Frame-Options") == "DENY" and r_api.headers.get("Cache-Control") == "no-store")
check("Cache-Header fuer /static", r_static.headers.get("Cache-Control") == "public, max-age=86400")
# Sprache der Oberflaeche: gilt nur waehrend der Anfrage
lang_mw = [m for m in M["app"].middlewares if m.__name__ == "_ui_language"][0]
import samonboarding.i18n as I18  # noqa: E402
seen = []


async def _next_lang(req):
    seen.append(I18.current_lang())
    return _Resp()


asyncio.run(lang_mw(Request(path="/api/x", headers={"x-ui-lang": "en"}), _next_lang))
asyncio.run(lang_mw(Request(path="/api/x"), _next_lang))
check("Sprache je Anfrage aus dem Header, danach wieder Deutsch", seen == ["en", "de"] and I18.current_lang() == "de", seen)
# --- Haertung: DN-Sonderformen, geschuetzte Konten und privilegierte Gruppen nur fuer Administratoren
M["_login_failures"].clear()
_, op2, _ = login("op", "Pass2")
_, adm2, _ = login("admin", "Pass1")
PRr = M["PwdResetActionModel"]
ok, _ = raises(lambda: M["execute_pwdreset"](PRr(userDn="<GUID=1234>", mode="auto", newPassword="", forceChange=True, unlockAccount=False), bg, adm2), 400, "DN")
check("DN-Sonderform <GUID=...> wird abgelehnt", ok)
ok, _ = raises(lambda: M["execute_pwdreset"](PRr(userDn=dom, mode="auto", newPassword="", forceChange=True, unlockAccount=False), bg, op2), 403, "geschützt")
check("Operator darf Passwort eines Domaenen-Admins nicht zuruecksetzen", ok)
r = M["execute_pwdreset"](PRr(userDn=dom, mode="auto", newPassword="", forceChange=True, unlockAccount=False), bg, adm2)
check("Administrator darf es", r["status"] == "success")
ok, _ = raises(lambda: M["move_user_account"](M["MoveUserActionModel"](userDn=dom, targetOu="OU=Archive," + B), op2), 403, "geschützt")
check("Operator darf geschuetztes Konto nicht verschieben", ok)
nor = mkuser("Gruppen Test", "gtest", [DOMAIN_USERS])
add("CN=Backup Ops,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="Backup Ops", objectSid="S-1-5-32-551", member=[])
UG = M["UpdateUserGroupsModel"]
ok, _ = raises(lambda: M["update_user_groups"](UG(userDn=nor, addGroupDns=["CN=Backup Ops,OU=Groups," + B], removeGroupDns=[]), bg, op2), 403, "privilegiert")
check("Operator darf niemanden in privilegierte Gruppen aufnehmen", ok and nor not in D["CN=Backup Ops,OU=Groups," + B]["member"])
r = M["update_user_groups"](UG(userDn=nor, addGroupDns=["CN=Backup Ops,OU=Groups," + B], removeGroupDns=[]), bg, adm2)
check("Administrator darf es", nor in D["CN=Backup Ops,OU=Groups," + B]["member"], r)
ok, _ = raises(lambda: M["update_user_groups"](UG(userDn=nor, addGroupDns=["<SID=S-1-5-32-544>"], removeGroupDns=[]), bg, adm2), 400, "DN")
check("Gruppen-DN als <SID=...> wird abgelehnt", ok)
print(f"\n{PASS} Pruefungen bestanden")
