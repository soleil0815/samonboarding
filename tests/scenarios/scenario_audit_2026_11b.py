"""Scenario: code audit 2026-11b - onboarding with privileged template groups, rollback after a lost connection,
protection of the own operator group (CUSTOM_OPERATOR_GROUP)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

import samonboarding.config as C  # noqa: E402
import samonboarding.permissions as P  # noqa: E402

reset()
out, adm, _ = login("admin", "Pass1", ip="10.31.0.1")
out, op, _ = login("op", "Pass2", ip="10.31.0.2")
OBM = M["OnboardModel"]


def template(groups):
    M["save_template"](
        {"name": "Std", "naming": "%LASTNAME%%FIRSTNAME%[3]", "ouDn": "OU=Staff," + B, "pwdMode": "random",
         "forceChange": True, "pwdNeverExpires": False, "groups": groups, "id": None}, adm)
    return M["load_json"](M["TEMPLATES_FILE"], [])[-1]["id"]


def onboard(user, tid, first="Eva", last="Netz"):
    return M["execute_onboard"](OBM(firstName=first, lastName=last, templateId=tid, customMail=f"{first.lower()}@test.local"), BackgroundTasks(), user)


# --- an operator must not create an account in a privileged group via a template ---------------------------------
tid = template(["CN=Domain Admins,CN=Users," + B])
ok, e = raises(lambda: onboard(op, tid), 403, "privilegierte Gruppe")
check("Operator: Template mit Domänen-Admins abgelehnt", ok, getattr(e, "detail", e))
check("Operator: nichts angelegt", not [k for k in D if k.startswith("CN=Eva Netz")])
r = onboard(adm, tid)
check("Administrator darf das Template nutzen", r["status"] == "success")
D.pop("CN=Eva Netz,OU=Staff," + B, None)
D["CN=Domain Admins,CN=Users," + B]["member"] = ["CN=Admin User,OU=Staff," + B]

# --- a lost connection after enabling removes the new account --------------------------------------------------------
tid = template(["CN=VPN,OU=Groups," + B])
orig = FakeConn.modify


def flaky(self, dn, changes):
    if "member" in changes and dn.startswith("CN=VPN"):
        raise LDAPCommunicationError("socket receive error (connection lost)")
    return orig(self, dn, changes)


FakeConn.modify = flaky
try:
    try:
        onboard(adm, tid, "Ole", "Abbruch")
        check("Abbruch wird gemeldet", False)
    except Exception as e:
        check("Abbruch wird gemeldet", "nicht angelegt" in str(getattr(e, "detail", e)), e)
finally:
    FakeConn.modify = orig
check("halbes Konto nach Verbindungsabbruch entfernt", not [k for k in D if k.startswith("CN=Ole Abbruch")])
r = onboard(adm, tid, "Ole", "Abbruch")
check("neuer Versuch gelingt", r["status"] == "success" and "CN=Ole Abbruch,OU=Staff," + B in D)

# --- members of the own operator group are protected, and only admins may add anyone to it ---------------------------
add("CN=Helpdesk,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="helpdesk",
    objectSid="S-1-5-21-1-2-3-4711", member=["CN=Mustermann\\, Max,OU=Staff," + B])
D["CN=Mustermann\\, Max,OU=Staff," + B]["tokenGroups"] = ["S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-4711"]
C.CUSTOM_OPERATOR_GROUP = P.CUSTOM_OPERATOR_GROUP = "helpdesk"
try:
    conn = FakeConn(FakeServer("dc"), user="admin@test.local", password="Pass1")
    reason = M["privileged_reason"](conn, "CN=Mustermann\\, Max,OU=Staff," + B)
    check("Mitglied der eigenen Operatorgruppe ist geschützt", "helpdesk" in reason, repr(reason))
    check("eigene Operatorgruppe gilt als privilegiert",
          "helpdesk" in M["privileged_group"](conn, "CN=Helpdesk,OU=Groups," + B))
    check("normale Gruppe bleibt frei", M["privileged_group"](conn, "CN=VPN,OU=Groups," + B) == "")
    D[B]["objectSid"] = ["S-1-5-21-1-2-3"]
    pmap = M["privileged_map"](conn, B)
    check("Listen: Mitglied der eigenen Operatorgruppe mit Schloss",
          "helpdesk" in pmap.get(("CN=Mustermann\\, Max,OU=Staff," + B).lower(), ""), pmap)
finally:
    C.CUSTOM_OPERATOR_GROUP = P.CUSTOM_OPERATOR_GROUP = ""

# --- restore: an operator stays inside the current source OUs and group OUs ------------------------------------------
import uuid  # noqa: E402

R = __import__("samonboarding.routers.restore", fromlist=["x"])
store = __import__("samonboarding.offboard_store", fromlist=["x"])
OB, RM = M["OffboardActionModel"], M["RestoreModel"]
U = ["top", "person", "organizationalPerson", "user"]
add("OU=Disabled,OU=Staff," + B, objectClass=["top", "organizationalUnit"], name="Disabled")
ok, e = raises(lambda: M["save_offboarding_config"](
    M["OffboardingConfigModel"](sourceOus=["OU=Staff," + B], targetOu="OU=Disabled,OU=Staff," + B), adm), 400)
check("Ziel-OU innerhalb einer Quell-OU wird abgelehnt", ok, getattr(e, "detail", e))
M["save_offboarding_config"](M["OffboardingConfigModel"](sourceOus=["OU=Staff," + B], targetOu="OU=Archive," + B), adm)
M["save_usermgmt_config"](M["UserMgmtConfigModel"](sourceOus=["OU=Staff," + B], targetOus=[], groupOus=["OU=Groups," + B]), adm)
ERIK = "CN=Erik Chef,OU=Staff," + B
add(ERIK, objectClass=U, sAMAccountName="echef", displayName="Erik Chef", userAccountControl="512",
    objectGUID=uuid.uuid4().bytes_le)
D["CN=Secret,CN=Users," + B]["member"].append(ERIK)
D["CN=VPN,OU=Groups," + B]["member"].append(ERIK)
M["execute_offboarding"](OB(userDn=ERIK), BackgroundTasks(), adm)
rid = R.list_records(adm)["records"][0]["id"]
pv = R.preview_restore(rid, "", op)
gs = {g["name"]: g["status"] for g in pv["groups"]}
check("Operator: Gruppe außerhalb der Gruppen-OUs nur für Administratoren", gs == {"Secret": "outside", "VPN": "add"}, gs)
check("Admin: dieselbe Gruppe wird wieder zugewiesen", {g["name"]: g["status"] for g in R.preview_restore(rid, "", adm)["groups"]}["Secret"] == "add")

# a deletion attempt that removed folders but not the account is shown in the preview
store.mark_folders_deleted(sam="echef", dn="CN=Erik Chef,OU=Archive," + B, paths=["\\\\fs01\\home$\\echef"])
notes = " ".join(R.preview_restore(rid, "", adm)["notes"])
check("Vorschau warnt vor schon gelöschten Ordnern", "Löschversuch" in notes and "echef" in notes, notes)

# offboarding the same account again keeps the entry with the real previous OU and groups
again = store.record(user_guid=store.get(rid)["user_guid"], sam="echef", name="Erik Chef",
                     original_dn="CN=Erik Chef,OU=Archive," + B, original_ou="OU=Archive," + B,
                     was_enabled=False, groups=[], actor="admin")
rec = store.get(again)
check("zweites Offboarding behält den ersten Eintrag", again == rid and rec["original_ou"] == "OU=Staff," + B
      and len(rec["groups"]) == 2, rec)

r = R.restore_account(rid, RM(), BackgroundTasks(), op)
check("Operator-Wiederherstellung ohne die fremde Gruppe", ERIK in D and ERIK not in D["CN=Secret,CN=Users," + B]["member"]
      and ERIK in D["CN=VPN,OU=Groups," + B]["member"], r)

# the source OU was removed from the offboarding: operators no longer see or restore the entry
M["execute_offboarding"](OB(userDn=ERIK), BackgroundTasks(), adm)
add("OU=Other," + B, objectClass=["top", "organizationalUnit"], name="Other")
M["save_offboarding_config"](M["OffboardingConfigModel"](sourceOus=["OU=Other," + B], targetOu="OU=Archive," + B), adm)
check("Operator sieht Einträge fremder OUs nicht", R.list_records(op)["records"] == [] and len(R.list_records(adm)["records"]) == 1)
rid = R.list_records(adm)["records"][0]["id"]
ok, e = raises(lambda: R.restore_account(rid, RM(targetOu="OU=Other," + B), BackgroundTasks(), op), 400, "Nur Administratoren")
check("Operator kann es auch nicht direkt wiederherstellen", ok, getattr(e, "detail", e))

print(f"\n{PASS} checks passed")
