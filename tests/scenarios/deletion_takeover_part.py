# ---- Besitzuebernahme, Verknuepfungen, Benachrichtigung ----
HOME = "\\\\fs1\\home$\\"
def user_fs(sam, extra=None, **kw):
    fsx = mkfs(clean=True, **kw)
    fsx.tree["\\\\fs1\\home$"].append(sam)
    fsx.tree[HOME.lower() + sam] = ["Docs", "secret.txt"]
    fsx.tree[HOME.lower() + sam + "\\docs"] = ["a.txt"]
    fsx.tree[HOME.lower() + sam + "\\docs\\a.txt"] = 5
    fsx.tree[HOME.lower() + sam + "\\secret.txt"] = 7
    return fsx
def add_user(sam, name):
    dn = f"CN={name},OU=Disabled," + B
    add(dn, objectClass=u, sAMAccountName=sam, displayName=name, userAccountControl="514",
        homeDirectory=HOME + sam)
    return dn
def set_cfg(takeover):
    dele.save_deletion_config(cfg_m(
        profile=loc_m(enabled=True, roots=["\\\\fs1\\profiles$"], suffixes=["V2"], takeOwnership=takeover),
        folderRedirection=loc_m(enabled=True, roots=["//fs1/redir$/"], takeOwnership=takeover),
        home=loc_m(enabled=True, roots=["\\\\fs1\\home$"], takeOwnership=takeover)), adm)
def home_row(sim_result):
    return [x for x in sim_result["targets"] if x["kind"] == "home" and x["source"] == "AD-Attribut"][0]

# Einstellung wird gespeichert, Standard ist aus
check("Besitzuebernahme standardmaessig aus", dele.get_deletion_config(adm)["home"]["takeOwnership"] is False)
set_cfg(True)
check("Besitzuebernahme wird gespeichert", all(dele.get_deletion_config(adm)[k]["takeOwnership"] is True for k in ("profile", "folderRedirection", "home")))

# Ohne Erlaubnis: kein Zugriff bleibt ein Hindernis
set_cfg(False)
dn1 = add_user("ttom", "Take Tom")
fs1 = user_fs("ttom", denied={HOME.lower() + "ttom\\docs"})
s = sim(dn1, fsobj=fs1)
check("Ohne takeOwnership: Unterordner ohne Zugriff blockiert", s["planId"] is None and s["blockers"] and not any(c[0] == "can_take" for c in fs1.calls), s["blockers"])

# Mit Erlaubnis: Unterordner ohne Zugriff -> Besitzuebernahme einplanen, Simulation aendert nichts
set_cfg(True)
fs1 = user_fs("ttom", denied={HOME.lower() + "ttom\\docs"}, locked={HOME.lower() + "ttom\\secret.txt"})
s = sim(dn1, fsobj=fs1)
h = home_row(s)
check("Simulation: Besitz noetig wird erkannt", h["status"] == "found" and h["takeoverNeeded"] == 1 and h["deletable"] and s["planId"] and s["summary"]["takeovers"] == 1, h)
check("Simulation uebernimmt noch nichts", not fs1.taken and all(c[0] in ("stat", "listdir", "can_take") for c in fs1.calls))

# Ausfuehren: Besitz wird uebernommen (Ordner Docs, Datei secret.txt), dann alles geloescht, Konto weg
r = X(exm(dn1, s["planId"], "ttom"), adm)
hr = [x for x in r["results"] if x["kind"] == "home"][0]
check("Mit Besitzuebernahme: alles geloescht, Konto weg", r["status"] == "success" and r["accountDeleted"] and dn1 not in D and HOME.lower() + "ttom" not in fs1.tree, r)
check("Besitz fuer genau die gesperrten Eintraege uebernommen", sorted(x.lower() for x in fs1.taken) == sorted([HOME.lower() + "ttom\\docs", HOME.lower() + "ttom\\secret.txt"]) and hr["takeovers"] == 2, fs1.taken)
check("Besitzuebernahme steht im Ergebnis", hr["takeoverPaths"] and hr["status"] == "deleted")

# Wurzelordner ohne Zugriff (stat verweigert) -> Status 'takeover'
dn2 = add_user("tuwe", "Take Uwe")
fs2 = user_fs("tuwe", denied={HOME.lower() + "tuwe"})
s = sim(dn2, fsobj=fs2)
h = home_row(s)
check("Wurzelordner ohne Zugriff -> takeover", h["status"] == "takeover" and h["deletable"] and s["planId"], h)
r = X(exm(dn2, s["planId"], "tuwe"), adm)
check("Wurzelordner: Besitz uebernommen und geloescht", r["status"] == "success" and HOME.lower() + "tuwe" not in fs2.tree and HOME.lower() + "tuwe" in [x.lower() for x in fs2.taken])

# Besitzuebernahme nicht moeglich -> Hindernis, nichts passiert
dn3 = add_user("tvia", "Take Via")
fs3 = user_fs("tvia", denied={HOME.lower() + "tvia\\docs"}, no_takeover={HOME.lower() + "tvia\\docs"})
s = sim(dn3, fsobj=fs3)
check("Besitzuebernahme unmoeglich -> blockiert", s["planId"] is None and s["blockers"], s["blockers"])
fs3b = user_fs("tvia", denied={HOME.lower() + "tvia"}, no_takeover={HOME.lower() + "tvia"})
s = sim(dn3, fsobj=fs3b)
check("Wurzel: Besitzuebernahme unmoeglich -> denied", home_row(s)["status"] == "denied" and s["planId"] is None)

# Ausfuehrung: Besitzuebernahme scheitert mitten im Lauf -> partial, Konto bleibt
dn4 = add_user("twil", "Take Wil")
fs4 = user_fs("twil", locked={HOME.lower() + "twil\\secret.txt"}, no_takeover={HOME.lower() + "twil\\secret.txt"})
set_cfg(True)
s = sim(dn4, fsobj=fs4)
r = X(exm(dn4, s["planId"], "twil"), adm)
check("Besitzuebernahme scheitert beim Loeschen -> partial, Konto bleibt", r["status"] == "partial" and dn4 in D and not r["accountDeleted"] and any("Besitzübernahme" in e for x in r["results"] for e in x["errors"]), r)

# Mit Erlaubnis aus: gesperrte Datei -> partial wie bisher, keine Besitzuebernahme versucht
set_cfg(False)
dn5 = add_user("tzoe", "Take Zoe")
fs5 = user_fs("tzoe", locked={HOME.lower() + "tzoe\\secret.txt"})
s = sim(dn5, fsobj=fs5)
r = X(exm(dn5, s["planId"], "tzoe"), adm)
check("Ohne Erlaubnis keine Besitzuebernahme", r["status"] == "partial" and not fs5.taken and dn5 in D)

# Verknuepfungen: nur die Verknuepfung wird entfernt, das Ziel bleibt
dn6 = add_user("tlin", "Take Lin")
fs6 = user_fs("tlin", reparse={HOME.lower() + "tlin\\docs"})
s = sim(dn6, fsobj=fs6)
check("Verknuepfung: Plan moeglich, links gezaehlt", s["planId"] and s["summary"]["links"] == 1, s["summary"])
r = X(exm(dn6, s["planId"], "tlin"), adm)
hr = [x for x in r["results"] if x["kind"] == "home"][0]
check("Verknuepfung entfernt, Ziel unberuehrt", r["status"] == "success" and hr["links"] == 1 and (HOME.lower() + "tlin\\docs\\a.txt") in fs6.tree
      and not any(c[0] == "listdir" and c[1].lower().endswith("tlin\\docs") for c in fs6.calls[-12:]) and not any(c == ("remove", HOME + "tlin\\docs\\a.txt") for c in fs6.calls), r)

# E-Mail-Benachrichtigung
import json as _json
def smtp(notify):
    cfg = dict(enabled=True, host="x", port=25, username="", password="", fromEmail="a@b.c", ccRecipients="", tlsMode="Auto",
               displayName="N", notifyOffboarding=False, notifyPwdReset=False, notifyUserMgmt=False, notifyDeletion=notify)
    _json.dump(cfg, open(dele.SMTP_CONFIG_FILE, "w"))
adm["email"] = "admin@test.local"
set_cfg(False)
dn7 = add_user("tml1", "Mail Eins")
smtp(False)
s = sim(dn7, fsobj=user_fs("tml1")); r = X(exm(dn7, s["planId"], "tml1"), adm)
check("Mail aus: keine Benachrichtigung", r["status"] == "success" and not BG["last"].tasks)
dn8 = add_user("tml2", "Mail Zwei")
smtp(True)
s = sim(dn8, fsobj=user_fs("tml2")); r = X(exm(dn8, s["planId"], "tml2"), adm)
t = BG["last"].tasks
check("Mail an: genau eine Mail an den Administrator", r["status"] == "success" and len(t) == 1 and t[0][0] is dele.send_notification_email and t[0][1][0] == "admin@test.local", t)
check("Mail-Inhalt: Konto, Ergebnis", "tml2" in t[0][1][1] and "Konto gelöscht" in t[0][1][1] and "tml2" in t[0][1][2] and "endgültig gelöscht" in t[0][1][2], t[0][1][1])
dn9 = add_user("tml3", "Mail Drei")
s = sim(dn9, fsobj=user_fs("tml3", locked={HOME.lower() + "tml3\\secret.txt"})); r = X(exm(dn9, s["planId"], "tml3"), adm)
t = BG["last"].tasks
check("Mail auch bei unvollstaendigem Loeschen", r["status"] == "partial" and len(t) == 1 and "unvollständig" in t[0][1][1].lower() and "NICHT" not in t[0][1][1] and "besteht weiter" in t[0][1][2], t)
adm["email"] = ""
dn10 = add_user("tml4", "Mail Vier")
s = sim(dn10, fsobj=user_fs("tml4")); r = X(exm(dn10, s["planId"], "tml4"), adm)
check("Ohne E-Mail-Adresse des Admins keine Mail", r["status"] == "success" and not BG["last"].tasks)
adm["email"] = "admin@test.local"
set_cfg(False)
