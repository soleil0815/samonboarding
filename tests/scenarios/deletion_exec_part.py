# ---- Deletion (step 2) ----
import os
DN_ALT = "CN=Alt\\, Anna,OU=Disabled," + B
BG = {"last": None}
def X(data, user):
    BG["last"] = BackgroundTasks()
    return dele.execute_deletion(data, BG["last"], user)
def exm(dn, plan, sam, password="Pass1"): return N(userDn=dn, planId=plan, confirmSam=sam, password=password)
def writes(fsobj): return [c for c in fsobj.calls if c[0] in ("remove", "rmdir")]

for fn, args in [(dele.execute_deletion, (exm("x", "y", "z"),))]:
    ok, _ = raises(lambda: X(*args, op), 403)
    check("Operator darf nicht loeschen (403)", ok)

# plan binding
fs_a = mkfs(clean=True)
s = sim(DN_ALT, fsobj=fs_a)
pid = s["planId"]
check("Plan hat Ablaufzeit", s["planExpiresAt"])
ok, e = raises(lambda: X(exm(DN_ALT, "falsch", "aalt"), adm), 400)
check("Falscher Plan -> 400", ok and "Plan" in e.detail)
out2, adm2, _ = login("admin", "Pass1", ip="10.20.0.9")
ok, _ = raises(lambda: X(exm(DN_ALT, pid, "aalt"), adm2), 400)
check("Plan ist an die Sitzung gebunden", ok)
ok, _ = raises(lambda: X(exm("CN=Zed Zora,OU=Disabled," + B, pid, "aalt"), adm), 400)
check("Plan ist an das Konto gebunden", ok)
ok, e = raises(lambda: X(exm(DN_ALT, pid, "falsch"), adm), 400)
check("Falsche Bestaetigung -> 400, nichts geloescht", ok and "Bestätigung" in e.detail and not writes(fs_a) and DN_ALT in D)
# plan survives typos
FSX["fs"] = fs_a
M_plan = dict(dele._plans[pid])
dele._plans[pid]["expires"] = time.time() - 1
ok, _ = raises(lambda: X(exm(DN_ALT, pid, "aalt"), adm), 400)
check("Abgelaufener Plan -> 400 und aus dem Speicher entfernt", ok and not writes(fs_a) and DN_ALT in D and pid not in dele._plans)
dele._plans[pid] = M_plan

# state has changed (new profile folder V6 appeared) -> abort without changes
fs_b = mkfs(clean=True)
s = sim(DN_ALT, fsobj=fs_b)
fs_b.tree["\\\\fs1\\profiles$\\aalt.v6"] = ["x.txt"]
fs_b.tree["\\\\fs1\\profiles$\\aalt.v6\\x.txt"] = 5
ok, e = raises(lambda: X(exm(DN_ALT, s["planId"], "AALT"), adm), 409)
check("Neuer Ordner seit Simulation -> 409, nichts geloescht", ok and not writes(fs_b) and DN_ALT in D and "neu hinzugekommen" in e.detail, e.detail if e else "")
ok, _ = raises(lambda: X(exm(DN_ALT, s["planId"], "aalt"), adm), 400)
check("Plan ist nach Versuch verbraucht", ok)

# access revoked after simulation
fs_c = mkfs(clean=True)
s = sim(DN_ALT, fsobj=fs_c)
fs_c.denied.add("\\\\fs1\\redir$\\aalt")
ok, e = raises(lambda: X(exm(DN_ALT, s["planId"], "aalt"), adm), 409)
check("Zugriff entzogen -> 409, nichts geloescht", ok and not writes(fs_c) and DN_ALT in D)

# AD attribute redirected to a shared folder after simulation: only what was simulated is deleted
fs_d = mkfs(clean=True)
s = sim(DN_ALT, fsobj=fs_d)
D[DN_ALT]["homeDirectory"] = ["\\\\fs1\\home$\\Abteilung"]
r = X(exm(DN_ALT, s["planId"], "aalt"), adm)
check("Umgebogenes Home-Attribut: Abteilungsordner bleibt unberuehrt", r["status"] == "success" and "\\\\fs1\\home$\\abteilung\\shared.txt" in fs_d.tree and not any("abteilung" in c[1].lower() for c in writes(fs_d)))
add("CN=Alt\\, Anna,OU=Disabled," + B, objectClass=u, sAMAccountName="aalt", displayName="Alt, Anna", userAccountControl="514",
    profilePath="\\\\fs1\\profiles$\\%username%", homeDirectory="\\\\fs1\\home$\\aalt")

# successful run
fs_e = mkfs(clean=True)
s = sim(DN_ALT, fsobj=fs_e)
before_other = dict((k, v) for k, v in fs_e.tree.items() if "other.v2" in k or k.endswith("home$\\abteilung") or "abteilung" in k)
r = X(exm(DN_ALT, s["planId"], "aalt"), adm)
check("Erfolg: Konto + 3 Ordner geloescht", r["status"] == "success" and r["accountDeleted"] and len(r["results"]) == 3 and all(x["status"] == "deleted" for x in r["results"]), r)
check("AD-Konto ist weg", DN_ALT not in D)
check("Ordner des Kontos sind weg", not any(k.startswith("\\\\fs1\\profiles$\\aalt.v2") or k.startswith("\\\\fs1\\redir$\\aalt") or k.startswith("\\\\fs1\\home$\\aalt") and "abteilung" not in k for k in fs_e.tree), [k for k in fs_e.tree if "aalt" in k])
check("Basispfade und fremde Ordner unberuehrt", all(fs_e.tree.get(k) == v for k, v in before_other.items()) and "\\\\fs1\\profiles$" in fs_e.tree and "\\\\fs1\\profiles$\\other.v2\\x" in fs_e.tree and "\\\\fs1\\home$" in fs_e.tree and "\\\\fs1\\redir$" in fs_e.tree)
check("Basispfade stehen nicht mehr mit dem Ordner in der Liste", "aalt.V2" not in fs_e.tree["\\\\fs1\\profiles$"] and "other.V2" in fs_e.tree["\\\\fs1\\profiles$"])
dels = writes(fs_e)
check("Nie ein Basispfad/Freigabe geloescht", not any(c[1].lower() in ("\\\\fs1\\profiles$", "\\\\fs1\\redir$", "\\\\fs1\\home$") for c in dels))
check("Reihenfolge: Dateien vor Ordnern, Ordner von innen nach aussen", dels.index(("rmdir", "\\\\fs1\\profiles$\\aalt.V2\\Desktop")) < dels.index(("rmdir", "\\\\fs1\\profiles$\\aalt.V2")) and dels.index(("remove", "\\\\fs1\\profiles$\\aalt.V2\\NTUSER.DAT")) < dels.index(("rmdir", "\\\\fs1\\profiles$\\aalt.V2")))
log = M["audit_jsonl"]()
last = [json.loads(l) for l in log.splitlines() if "deletion-execute" in l][-1]
check("Audit-Eintrag mit Ordnerdetails, ohne Passwort", last["ok"] is True and last["sam"] == "aalt" and len(last["folders"]) == 3 and "Pass1" not in json.dumps(last))
ok, _ = raises(lambda: X(exm(DN_ALT, s["planId"], "aalt"), adm), 400)
check("Zweites Loeschen mit altem Plan -> 400", ok)

# partially failed: file locked -> account stays
add("CN=Alt\\, Anna,OU=Disabled," + B, objectClass=u, sAMAccountName="aalt", displayName="Alt, Anna", userAccountControl="514",
    profilePath="\\\\fs1\\profiles$\\%username%", homeDirectory="\\\\fs1\\home$\\aalt")
fs_f = mkfs(clean=True, locked={"\\\\fs1\\profiles$\\aalt.V2\\NTUSER.DAT"})
s = sim(DN_ALT, fsobj=fs_f)
r = X(exm(DN_ALT, s["planId"], "aalt"), adm)
check("Gesperrte Datei -> partial, Konto bleibt", r["status"] == "partial" and not r["accountDeleted"] and DN_ALT in D, r["message"])
bad = [x for x in r["results"] if x["status"] == "failed"]
check("Nur der Profilordner ist fehlgeschlagen, Rest geloescht", len(bad) == 1 and bad[0]["kind"] == "profile" and bad[0]["errorCount"] >= 1 and {x["status"] for x in r["results"] if x["kind"] != "profile"} == {"deleted"}, r["results"])
check("Fehlerdetail nennt die Datei", any("NTUSER.DAT" in e for e in bad[0]["errors"]))
last = [json.loads(l) for l in M["audit_jsonl"]().splitlines() if "deletion-execute" in l][-1]
check("Audit: partial -> ok false", last["ok"] is False and "AD-Konto bleibt" in last["error"])
# new simulation + run after the fix (only the remainder)
fs_f.locked.clear()
s = sim(DN_ALT, fsobj=fs_f)
check("Nach Teilloeschung: nur noch Profilordner gefunden", [x["kind"] for x in s["targets"] if x["status"] == "found"] == ["profile"])
r = X(exm(DN_ALT, s["planId"], "aalt"), adm)
check("Zweiter Anlauf loescht Rest + Konto", r["status"] == "success" and DN_ALT not in D)

# account without folders: AD account only
add("CN=Leer Lars,OU=Disabled," + B, objectClass=u, sAMAccountName="llar", userAccountControl="514")
add("CN=ExchangeActiveSyncDevices,CN=Leer Lars,OU=Disabled," + B, objectClass=["top", "msExchActiveSyncDevices"])
s = sim("CN=Leer Lars,OU=Disabled," + B, fsobj=mkfs(clean=True))
check("Konto ohne Ordner: Plan ohne Pfade", s["planId"] and s["summary"]["folders"] == 0 and len(s["warnings"]) == 3)
FSX["fs"].calls.clear()
r = X(exm("CN=Leer Lars,OU=Disabled," + B, s["planId"], "llar"), adm)
check("Nur AD-Konto geloescht, keine Schreibzugriffe im FS", r["status"] == "success" and "CN=Leer Lars,OU=Disabled," + B not in D and not writes(FSX["fs"]))
# account with a child object (e.g. Exchange ActiveSync device): deleted with tree delete including the child
check("Unterobjekt-Konten werden mit Tree-Delete geloescht", "CN=ExchangeActiveSyncDevices,CN=Leer Lars,OU=Disabled," + B not in D)

# account was re-enabled after simulation
add("CN=Flip Flo,OU=Disabled," + B, objectClass=u, sAMAccountName="fflo", userAccountControl="514")
s = sim("CN=Flip Flo,OU=Disabled," + B, fsobj=mkfs(clean=True))
D["CN=Flip Flo,OU=Disabled," + B]["userAccountControl"] = ["512"]
ok, e = raises(lambda: X(exm("CN=Flip Flo,OU=Disabled," + B, s["planId"], "fflo"), adm), 400)
check("Zwischenzeitlich aktiviertes Konto -> 400", ok and "Flip Flo" not in "".join(map(str, writes(FSX["fs"]))) and "CN=Flip Flo,OU=Disabled," + B in D)

# parallel lock
add("CN=Par Paul,OU=Disabled," + B, objectClass=u, sAMAccountName="ppau", userAccountControl="514")
s = sim("CN=Par Paul,OU=Disabled," + B, fsobj=mkfs(clean=True))
dele._running.add("cn=par paul,ou=disabled," + B.lower())
ok, _ = raises(lambda: X(exm("CN=Par Paul,OU=Disabled," + B, s["planId"], "ppau"), adm), 409)
dele._running.clear()
check("Parallele Ausfuehrung -> 409", ok)

# deleting the AD account fails (e.g. protection from accidental deletion) after the folders are gone
add("CN=Prot Pia,OU=Disabled," + B, objectClass=u, sAMAccountName="ppia", userAccountControl="514")
fs_g = mkfs(clean=True)
fs_g.tree["\\\\fs1\\redir$"].append("ppia"); fs_g.tree["\\\\fs1\\redir$\\ppia"] = []
s = sim("CN=Prot Pia,OU=Disabled," + B, fsobj=fs_g)
orig_delete = ldap3.Connection.delete
def failing_delete(self, dn):
    self.result = {"result": 50, "description": "insufficientAccessRights", "message": "geschuetzt"}
    return False
ldap3.Connection.delete = failing_delete
ok, e = raises(lambda: X(exm("CN=Prot Pia,OU=Disabled," + B, s["planId"], "ppia"), adm), 500)
ldap3.Connection.delete = orig_delete
check("AD-Loeschen scheitert -> klare Meldung (Ordner waren schon weg)", ok and "Ordner wurden gelöscht" in e.detail and "CN=Prot Pia,OU=Disabled," + B in D, e.detail if e else "")
