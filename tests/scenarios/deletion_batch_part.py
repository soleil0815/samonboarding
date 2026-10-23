# ---- Passwortbestaetigung und Sammel-Loeschen ----
BM = lambda **kw: N(**kw)
def fresh_admin(ip):
    return login("admin", "Pass1", ip=ip)[1]
def audit_text():
    return M["audit_jsonl"]()
def run_tasks(bg):
    for fn, args, kw in bg.tasks:
        fn(*args, **kw)
    bg.tasks.clear()

# -- Passwort: falsches/leeres Passwort verbraucht den Plan nicht
adm_p = fresh_admin("10.50.0.1")
dnp = add_user("pwu1", "Pass Eins")
s = sim(dnp, fsobj=user_fs("pwu1"), who=adm_p)
ok, e = raises(lambda: dele.execute_deletion(exm(dnp, s["planId"], "pwu1", password=""), BackgroundTasks(), adm_p), 400)
check("Leeres Passwort -> 400", ok and "Passwort" in e.detail)
ok, e = raises(lambda: dele.execute_deletion(exm(dnp, s["planId"], "pwu1", password="falsch"), BackgroundTasks(), adm_p), 403)
check("Falsches Passwort -> 403, nichts geloescht", ok and dnp in D and not writes(FSX["fs"]))
check("Falsches Passwort steht im Audit-Log, das Passwort nicht", "deletion-password-fail" in audit_text() and "falsch" not in audit_text())
r = dele.execute_deletion(exm(dnp, s["planId"], "pwu1"), BackgroundTasks(), adm_p)
check("Plan nach Fehleingabe weiter nutzbar, richtiges Passwort loescht", r["status"] == "success" and dnp not in D)

# -- Passwort: Sperre nach 5 Fehlversuchen (je Sitzung)
adm_l = fresh_admin("10.50.0.2")
dnl = add_user("pwu2", "Pass Zwei")
s = sim(dnl, fsobj=user_fs("pwu2"), who=adm_l)
for _ in range(dele.PW_MAX_FAILS):
    raises(lambda: dele.execute_deletion(exm(dnl, s["planId"], "pwu2", password="x"), BackgroundTasks(), adm_l), 403)
ok, e = raises(lambda: dele.execute_deletion(exm(dnl, s["planId"], "pwu2"), BackgroundTasks(), adm_l), 429)
check("Nach 5 Fehlversuchen gesperrt (auch mit richtigem Passwort)", ok and dnl in D)
adm_n = fresh_admin("10.50.0.3")
s = sim(dnl, fsobj=user_fs("pwu2"), who=adm_n)
r = dele.execute_deletion(exm(dnl, s["planId"], "pwu2"), BackgroundTasks(), adm_n)
check("Sperre gilt nur fuer die Sitzung", r["status"] == "success")

# -- Sammel-Simulation
def multi_fs():
    fsx = mkfs(clean=True)
    for sam in ("bat1", "bat2", "bat3", "bat5"):
        fsx.tree["\\\\fs1\\home$"].append(sam)
        fsx.tree[HOME.lower() + sam] = ["f.txt"]
        fsx.tree[HOME.lower() + sam + "\\f.txt"] = 11
    fsx.denied.add(HOME.lower() + "bat5")
    return fsx
dn1, dn2 = add_user("bat1", "Batch Eins"), add_user("bat2", "Batch Zwei")
dn3 = add_user("bat3", "Batch Drei")
D[dn3]["userAccountControl"] = ["512"]                      # noch aktiv -> gesperrt
dn5 = add_user("bat5", "Batch Fuenf")                        # Ordner ohne Zugriff -> gesperrt (ohne Besitzuebernahme)
set_cfg(False)
adm_b = fresh_admin("10.50.0.4")
FSX["fs"] = multi_fs()
bs = lambda dns, who=adm_b: dele.simulate_deletion_batch(N(userDns=dns), who)
for fn, args in [(dele.simulate_deletion_batch, (N(userDns=[dn1]),)), (dele.execute_deletion_batch, (N(planId="x", confirmCount=1, password="Pass1"), BackgroundTasks()))]:
    ok, _ = raises(lambda fn=fn, args=args: fn(*args, op), 403)
    check(f"Operator -> 403 bei {fn.__name__}", ok)
ok, _ = raises(lambda: bs([]), 400); check("Leere Auswahl -> 400", ok)
ok, e = raises(lambda: bs([dn1] * 0 + [f"CN=x{i},OU=Disabled," + B for i in range(dele.BATCH_MAX + 1)]), 400)
check("Mehr als 25 Konten -> 400", ok and "25" in e.detail)
before = json.dumps(sorted(D.items()), sort_keys=True, default=str)
bsim = bs([dn1, dn2, dn3, dn5, dn1, "CN=Gibtsnicht,OU=Disabled," + B])
name_of = {dn1: "bat1", dn2: "bat2", dn3: "bat3", dn5: "bat5"}
st = {name_of.get(i["dn"], i["dn"]): i["state"] for i in bsim["items"]}
check("Doppelte werden zusammengefasst", len(bsim["items"]) == 5)
check("Zwei bereit, Rest blockiert", bsim["readyCount"] == 2 and st["bat1"] == "ready" and st["bat2"] == "ready" and st["bat3"] == "blocked" and st["bat5"] == "blocked", st)
blocked_err = {name_of.get(i["dn"], i["dn"]): i["error"] for i in bsim["items"] if i["state"] == "blocked"}
check("Blockierte nennen den Grund", "deaktiviert" in blocked_err["bat3"] and blocked_err["bat5"] and all(blocked_err.values()), blocked_err)
check("Sammel-Simulation aendert nichts", json.dumps(sorted(D.items()), sort_keys=True, default=str) == before and not writes(FSX["fs"]))
check("Sammelplan vorhanden", bsim["planId"] and bsim["planExpiresAt"] and FSX["fs"].closed)
none_ready = bs([dn3])
check("Nichts bereit -> kein Plan", none_ready["planId"] is None and none_ready["readyCount"] == 0)
bsim = bs([dn1, dn2, dn3, dn5])

# -- Bestaetigung
ex = lambda plan, count, pw="Pass1", who=adm_b, bg=None: dele.execute_deletion_batch(N(planId=plan, confirmCount=count, password=pw), bg or BackgroundTasks(), who)
ok, e = raises(lambda: ex(bsim["planId"], 3), 400); check("Falsche Anzahl -> 400", ok and "Anzahl" in e.detail)
ok, e = raises(lambda: ex(bsim["planId"], 2, pw="nein"), 403); check("Falsches Passwort -> 403", ok)
ok, e = raises(lambda: ex("unbekannt", 2), 400); check("Unbekannter Plan -> 400", ok)
ok, e = raises(lambda: ex(bsim["planId"], 2, who=fresh_admin("10.50.0.5")), 400); check("Plan an Sitzung gebunden", ok)
check("Nach Fehleingaben noch nichts geloescht", dn1 in D and dn2 in D and not writes(FSX["fs"]))

# -- Ausfuehren als Hintergrundauftrag
sent = []
orig_send = dele.send_notification_email
dele.send_notification_email = lambda *a, **k: sent.append(a)
smtp(True)
bgb = BackgroundTasks()
started = ex(bsim["planId"], 2, bg=bgb)
check("Start liefert Job, Auftrag laeuft noch nicht", started["status"] == "started" and started["total"] == 2 and len(bgb.tasks) == 1)
job = dele.get_deletion_job(started["jobId"], adm_b)
check("Job vor dem Lauf: ausstehend", not job["finished"] and [i["status"] for i in job["items"]] == ["pending", "pending"] and "sid" not in job)
ok, _ = raises(lambda: dele.get_deletion_job(started["jobId"], fresh_admin("10.50.0.6")), 404); check("Job gehoert zur Sitzung", ok)
ok, _ = raises(lambda: dele.get_deletion_job(started["jobId"], op), 403); check("Operator darf keinen Job lesen", ok)
ok, e = raises(lambda: ex(bsim["planId"], 2), 400); check("Plan ist einmalig", ok)
run_tasks(bgb)
job = dele.get_deletion_job(started["jobId"], adm_b)
check("Job fertig, beide Konten geloescht", job["finished"] and job["done"] == 2 and [i["status"] for i in job["items"]] == ["success", "success"], job["items"])
check("Konten und Ordner weg, Rest unberuehrt", dn1 not in D and dn2 not in D and dn3 in D and dn5 in D and HOME.lower() + "bat1" not in FSX["fs"].tree and HOME.lower() + "bat3" in FSX["fs"].tree)
check("Ergebnis je Konto mit Ordnern", job["items"][0]["results"] and job["items"][0]["results"][0]["status"] == "deleted")
at = audit_text()
check("Audit: Eintrag je Konto und Sammeleintrag", at.count('"action": "deletion-execute"') >= 2 and '"action": "deletion-batch"' in at and "bat1" in at and "Pass1" not in at)
check("Genau eine Sammelmail", len(sent) == 1 and "2/2" in sent[0][1] and "bat1" in sent[0][2] and "bat2" in sent[0][2], sent)

# -- Teilweise: gesperrte Datei, Konto in Bearbeitung
for sam, nm in (("bat6", "Batch Sechs"), ("bat7", "Batch Sieben"), ("bat8", "Batch Acht")):
    add_user(sam, nm)
dn6, dn7, dn8 = (f"CN={n},OU=Disabled," + B for n in ("Batch Sechs", "Batch Sieben", "Batch Acht"))
fsx = multi_fs()
for sam in ("bat6", "bat7", "bat8"):
    fsx.tree["\\\\fs1\\home$"].append(sam)
    fsx.tree[HOME.lower() + sam] = ["f.txt"]
    fsx.tree[HOME.lower() + sam + "\\f.txt"] = 3
FSX["fs"] = fsx
bsim = bs([dn6, dn7, dn8])
fsx.locked.add(HOME.lower() + "bat7\\f.txt")                 # erst nach der Simulation gesperrt
dele._running.add(dn8.lower())                              # parallel schon in Arbeit
sent.clear(); bgb = BackgroundTasks()
started = ex(bsim["planId"], 3, bg=bgb); run_tasks(bgb)
dele._running.discard(dn8.lower())
job = dele.get_deletion_job(started["jobId"], adm_b)
sts = {i["sam"]: i["status"] for i in job["items"]}
check("Gemischtes Ergebnis: success / partial / error", sts == {"bat6": "success", "bat7": "partial", "bat8": "error"}, sts)
check("Teilweise: Konto bleibt, Fehler gemeldet; laufendes Konto uebersprungen", dn6 not in D and dn7 in D and dn8 in D and "läuft bereits" in [i for i in job["items"] if i["sam"] == "bat8"][0]["message"])
check("Sammelmail nennt die Probleme", len(sent) == 1 and "Problemen" in sent[0][1] and "besteht weiter" in sent[0][2])
dele.send_notification_email = orig_send
smtp(False)

# -- Geschuetzte Konten (Domaenen-Admin) lassen sich nicht loeschen, auch nicht deaktiviert in der Loesch-OU
dnA = add_user("dadm", "Deleted Admin")
D[dnA]["tokenGroups"] = ["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-513"]
D[dnA]["adminCount"] = ["1"]
set_cfg(False)
adm_g = fresh_admin("10.50.0.9")
FSX["fs"] = user_fs("dadm")
ok, e = raises(lambda: dele.simulate_deletion(N(userDn=dnA), adm_g), 403)
check("Einzel-Simulation: Domaenen-Admin -> 403", ok and "geschützt" in e.detail)
bsim = dele.simulate_deletion_batch(N(userDns=[dnA]), adm_g)
check("Sammel-Simulation: als blockiert markiert, kein Plan", bsim["items"][0]["state"] == "blocked" and "geschützt" in bsim["items"][0]["error"] and bsim["planId"] is None)
lst = {x["sam"]: x for x in dele.get_deletion_users(adm_g)["users"]}
check("Loesch-Liste markiert das Konto als geschuetzt", "Domänen-Admins" in lst["dadm"]["protected"] and lst["bat3"]["protected"] == "" and not any(k.startswith("_") for k in lst["dadm"]))
check("Nichts wurde angefasst", dnA in D and HOME.lower() + "dadm" in FSX["fs"].tree and not writes(FSX["fs"]))

# -- Domaene ohne Profile, Ordnerumleitung und Basisordner: Konto loeschen ganz ohne Speicherort
def no_backend(user):
    raise AssertionError("Dateizugriff darf ohne aktiven Speicherort nicht geoeffnet werden")
dele.save_deletion_config(cfg_m(profile=loc_m(), folderRedirection=loc_m(), home=loc_m()), adm)
check("Konfiguration ohne Speicherort wird akzeptiert", dele.get_deletion_config(adm)["enabled"] and not any(dele.get_deletion_config(adm)[k]["enabled"] for k in ("profile", "folderRedirection", "home")))
dn_n1, dn_n2 = add_user("nof1", "Ohne Ordner Eins"), add_user("nof2", "Ohne Ordner Zwei")
adm_n = fresh_admin("10.50.0.20")
orig_make_backend = dele.make_backend
dele.make_backend = no_backend
sn = dele.simulate_deletion(N(userDn=dn_n1), adm_n)
check("Simulation ohne Speicherort: keine Ordner, kein Hindernis, Plan vorhanden", sn["targets"] == [] and sn["blockers"] == [] and sn["planId"] and sn["summary"]["folders"] == 0 and sn["warnings"] == [], sn)
rn = dele.execute_deletion(exm(dn_n1, sn["planId"], "nof1"), BackgroundTasks(), adm_n)
check("Loeschen ohne Speicherort: nur das AD-Konto wird geloescht", rn["status"] == "success" and rn["accountDeleted"] and dn_n1 not in D and "Ordner" not in rn["message"], rn)
bsn = dele.simulate_deletion_batch(N(userDns=[dn_n2]), adm_n)
check("Sammel-Simulation ohne Speicherort bereit", bsn["readyCount"] == 1 and bsn["items"][0]["state"] == "ready", bsn)
bgn = BackgroundTasks()
started = dele.execute_deletion_batch(N(planId=bsn["planId"], confirmCount=1, password="Pass1"), bgn, adm_n); run_tasks(bgn)
job = dele.get_deletion_job(started["jobId"], adm_n)
check("Sammel-Loeschen ohne Speicherort", job["finished"] and job["items"][0]["status"] == "success" and dn_n2 not in D, job["items"])
ok, _ = raises(lambda: dele.test_deletion_paths(adm_n), 400)
check("Verbindungstest ohne Basispfade: freundliche Ablehnung", ok)
dele.make_backend = orig_make_backend
set_cfg(False)
