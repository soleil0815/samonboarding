"""Szenario: Offboarding merkt sich OU, Gruppen und Status; Wiederherstellen, Vorschau, Fehlerfaelle, Loeschen."""
import os
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

reset()
_, adm, _ = login("admin", "Pass1", ip="10.1.0.1")
_, op, _ = login("op", "Pass2", ip="10.1.0.2")
M["save_offboarding_config"](M["OffboardingConfigModel"](sourceOus=["OU=Staff," + B], targetOu="OU=Archive," + B), adm)
OB, RM = M["OffboardActionModel"], M["RestoreModel"]
U = ["top", "person", "organizationalPerson", "user"]
G_SALES, G_VPN = uuid.uuid4(), uuid.uuid4()
U_ANNA = uuid.uuid4()
add("OU=Sales,OU=Staff," + B, objectClass=["top", "organizationalUnit"], name="Sales")
add("CN=Sales Team,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="Sales Team", objectGUID=G_SALES.bytes_le, member=[])
D["CN=VPN,OU=Groups," + B]["objectGUID"] = [G_VPN.bytes_le]
ANNA = "CN=Anna Berg,OU=Sales,OU=Staff," + B
add(ANNA, objectClass=U, sAMAccountName="aberg", displayName="Anna Berg", userAccountControl="66048", objectGUID=U_ANNA.bytes_le)
D["CN=Sales Team,OU=Groups," + B]["member"].append(ANNA)
D["CN=VPN,OU=Groups," + B]["member"].append(ANNA)
bg = BackgroundTasks()
store = M["offboard_store"] if "offboard_store" in M else __import__("samonboarding.offboard_store", fromlist=["x"])
R = __import__("samonboarding.routers.restore", fromlist=["x"])

# ---- Offboarding speichert den Zustand
M["execute_offboarding"](OB(userDn=ANNA), bg, adm)
ARCH = "CN=Anna Berg,OU=Archive," + B
check("Offboarding wie bisher: deaktiviert, ohne Gruppen, verschoben", ARCH in D and int(D[ARCH]["userAccountControl"][0]) & 2 and ARCH not in D["CN=VPN,OU=Groups," + B]["member"])
recs = R.list_records(op)["records"]
check("Eintrag gespeichert und fuer Operatoren sichtbar", len(recs) == 1 and recs[0]["sam"] == "aberg" and recs[0]["originalOu"] == "OU=Sales,OU=Staff," + B and sorted(recs[0]["groups"]) == ["Sales Team", "VPN"], recs)
raw = store.get(recs[0]["id"])
check("GUIDs von Konto und Gruppen gespeichert", raw["user_guid"] == str(U_ANNA) and {g["guid"] for g in raw["groups"]} == {str(G_SALES), str(G_VPN)} and raw["current_dn"] == ARCH, raw)
check("Kein Passwort gespeichert", "pwd" not in json.dumps(raw).lower() or "Pass" not in json.dumps(raw))
check("Audit vermerkt Wiederherstellbarkeit", '"restorable": true' in M["audit_jsonl"]())
rid = recs[0]["id"]

# ---- Vorschau veraendert nichts und findet umbenannte Gruppen ueber die GUID
D["CN=Vertrieb Team,OU=Groups," + B] = D.pop("CN=Sales Team,OU=Groups," + B)
before = json.dumps(D, sort_keys=True, default=str)
pv = R.preview_restore(rid, "", op)
check("Vorschau ohne Aenderung", json.dumps(D, sort_keys=True, default=str) == before)
check("Vorschau: Ziel-OU, Verschieben, Aktivieren", pv["targetOu"] == "OU=Sales,OU=Staff," + B and pv["move"] and pv["enable"] and pv["blockers"] == [], pv)
gs = {g["name"]: g for g in pv["groups"]}
check("Umbenannte Gruppe ueber GUID gefunden", gs["Sales Team"]["dn"] == "CN=Vertrieb Team,OU=Groups," + B and gs["Sales Team"]["status"] == "add", gs)

# ---- Wiederherstellen
r = R.restore_account(rid, RM(), bg, op)
check("Wiederhergestellt: zurueck in der alten OU", ANNA in D and ARCH not in D and r["dn"] == ANNA, r)
check("Wieder in den Gruppen (auch der umbenannten)", ANNA in D["CN=Vertrieb Team,OU=Groups," + B]["member"] and ANNA in D["CN=VPN,OU=Groups," + B]["member"])
check("Wieder aktiv, andere Flags erhalten (Kennwort laeuft nie ab)", int(D[ANNA]["userAccountControl"][0]) == 66048, D[ANNA]["userAccountControl"])
check("Eintrag danach entfernt", R.list_records(adm)["records"] == [])
ok, _ = raises(lambda: R.restore_account(rid, RM(), bg, adm), 404)
check("Zweites Wiederherstellen -> 404", ok)
check("Audit-Eintrag der Wiederherstellung", '"offboarding-restore"' in M["audit_jsonl"]())

# ---- Gruppe geloescht, OU geloescht -> andere OU waehlen
M["execute_offboarding"](OB(userDn=ANNA), bg, adm)
rid = R.list_records(adm)["records"][0]["id"]
D.pop("CN=VPN,OU=Groups," + B)
D.pop("OU=Sales,OU=Staff," + B)
pv = R.preview_restore(rid, "", adm)
check("Fehlende OU blockiert, fehlende Gruppe nur Hinweis", pv["blockers"] and "gibt es nicht mehr" in pv["blockers"][0] and any("VPN" in n for n in pv["notes"]) and {g["status"] for g in pv["groups"]} == {"missing", "add"}, pv)
ok, e = raises(lambda: R.restore_account(rid, RM(), bg, adm), 400)
check("Ohne gueltige OU kein Wiederherstellen, Eintrag bleibt offen", ok and R.list_records(adm)["records"] and ARCH in D)
ok, e = raises(lambda: R.restore_account(rid, RM(targetOu="CN=Users," + B), bg, adm), 400)
check("OU ausserhalb der Quell-OUs abgelehnt", ok and "Quell-OUs" in e.detail)
r = R.restore_account(rid, RM(targetOu="OU=Staff," + B), bg, adm)
NEW = "CN=Anna Berg,OU=Staff," + B
check("Mit gewaehlter OU wiederhergestellt, Hinweis auf fehlende Gruppe", NEW in D and any("VPN" in w for w in r["warnings"]) and ANNA not in D, r)

# ---- Gruppe kann nicht gesetzt werden (Rechte) -> Warnung, Rest klappt
M["execute_offboarding"](OB(userDn=NEW), bg, adm)
rid = R.list_records(adm)["records"][0]["id"]
STATE["deny"] = {"member"}
r = R.restore_account(rid, RM(), bg, op)
STATE["deny"] = set()
check("Fehlende Rechte fuer Gruppe -> Warnung, Konto trotzdem zurueck und aktiv", NEW in D and int(D[NEW]["userAccountControl"][0]) & 2 == 0 and any("Nicht wieder zugewiesen" in w for w in r["warnings"]), r)

# ---- Konto war vorher schon deaktiviert -> bleibt deaktiviert
D[NEW]["userAccountControl"] = ["514"]
M["execute_offboarding"](OB(userDn=NEW), bg, adm)
rid = R.list_records(adm)["records"][0]["id"]
pv = R.preview_restore(rid, "", adm)
check("Vorher deaktiviertes Konto: kein Aktivieren", pv["enable"] is False and any("bleibt deaktiviert" in n for n in pv["notes"]))
R.restore_account(rid, RM(), bg, adm)
check("Bleibt deaktiviert", int(D[NEW]["userAccountControl"][0]) & 2)
D[NEW]["userAccountControl"] = ["512"]

# ---- Konto inzwischen anders verschoben -> ueber GUID gefunden
M["execute_offboarding"](OB(userDn=NEW), bg, adm)
rid = R.list_records(adm)["records"][0]["id"]
D["CN=Anna Berg,CN=Users," + B] = D.pop(ARCH)
pv = R.preview_restore(rid, "", adm)
check("Verschobenes Konto ueber GUID gefunden", pv["currentDn"] == "CN=Anna Berg,CN=Users," + B and pv["blockers"] == [], pv)

# ---- Konto geloescht -> blockiert; Verwerfen nur Admin
D.pop("CN=Anna Berg,CN=Users," + B)
pv = R.preview_restore(rid, "", adm)
check("Geloeschtes Konto blockiert", any("nicht gefunden" in b for b in pv["blockers"]))
ok, _ = raises(lambda: R.dismiss_record(rid, op), 403)
check("Verwerfen nur fuer Administratoren", ok and R.list_records(adm)["records"])
R.dismiss_record(rid, adm)
check("Verworfen und im Audit", R.list_records(adm)["records"] == [] and '"offboarding-record-dismiss"' in M["audit_jsonl"]())

# ---- Gleichzeitiges Wiederherstellen wird verhindert
BOB = "CN=Bob Bauer,OU=Staff," + B
add(BOB, objectClass=U, sAMAccountName="bbauer", displayName="Bob Bauer", userAccountControl="512")
M["execute_offboarding"](OB(userDn=BOB), bg, adm)
rid = R.list_records(adm)["records"][0]["id"]
store.claim(rid)
ok, e = raises(lambda: R.restore_account(rid, RM(), bg, adm), 409)
check("Laufende Wiederherstellung -> 409", ok)
store.release(rid)

# ---- Mehrfach-Offboarding merkt sich jedes Konto
CARL = "CN=Carl Cord,OU=Staff," + B
add(CARL, objectClass=U, sAMAccountName="ccord", displayName="Carl Cord", userAccountControl="512")
M["execute_offboarding_batch"](M["OffboardBatchModel"](userDns=[CARL]), bg, adm)
check("Batch-Offboarding gespeichert", {x["sam"] for x in R.list_records(adm)["records"]} == {"bbauer", "ccord"})

# ---- Erneutes Offboarding desselben Kontos ersetzt den alten Eintrag
r = R.restore_account(rid, RM(), bg, adm)
M["execute_offboarding"](OB(userDn=BOB), bg, adm)
check("Pro Konto nur ein offener Eintrag", sorted(x["sam"] for x in R.list_records(adm)["records"]) == ["bbauer", "ccord"])

# ---- Loeschen entfernt den Eintrag
store.forget_account(sam="ccord", dn="CN=Carl Cord,OU=Archive," + B)
check("Loeschen entfernt den Eintrag", [x["sam"] for x in R.list_records(adm)["records"]] == ["bbauer"])

# ---- Fehlgeschlagenes Deaktivieren hinterlaesst keinen Eintrag
DAN = "CN=Dan Dorn,OU=Staff," + B
add(DAN, objectClass=U, sAMAccountName="ddorn", displayName="Dan Dorn", userAccountControl="512")
STATE["deny"] = {"userAccountControl"}
raises(lambda: M["execute_offboarding"](OB(userDn=DAN), bg, adm))
STATE["deny"] = set()
check("Nichts geaendert -> kein Eintrag", "ddorn" not in [x["sam"] for x in R.list_records(adm)["records"]] and DAN in D)

# ---- Mail nach Wiederherstellung (wenn Offboarding-Mails an sind)
cfg = dict(M["default_smtp_config"], enabled=True, notifyOffboarding=True)
M["save_json"]("data/smtp_config.json", cfg)
adm["email"] = "admin@test.local"
rid = [x for x in R.list_records(adm)["records"] if x["sam"] == "bbauer"][0]["id"]
bg2 = BackgroundTasks()
R.restore_account(rid, RM(), bg2, adm)
check("Benachrichtigung eingeplant", len(bg2.tasks) == 1 and "wiederhergestellt" in bg2.tasks[0][1][1])

print(f"\n{PASS} Pruefungen bestanden")
