"""Scenario: OUs/groups in the settings are renamed, moved, replaced or deleted in AD."""
import json
import os
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

reset()
for dn in ("OU=Staff," + B, "OU=Archive," + B, "CN=VPN,OU=Groups," + B, "CN=Printers,OU=Groups," + B, "CN=Secret,CN=Users," + B):
    D[dn]["objectGUID"] = [uuid.uuid4().bytes_le]
_, adm, _ = login("admin", "Pass1", ip="10.2.0.1")
_, op, _ = login("op", "Pass2", ip="10.2.0.2")
M["save_offboarding_config"](M["OffboardingConfigModel"](sourceOus=["OU=Staff," + B], targetOu="OU=Archive," + B), adm)
tpl = {"name": "Vertrieb", "naming": "%LASTNAME%", "ouDn": "OU=Staff," + B,
       "groups": ["CN=VPN,OU=Groups," + B, "CN=Printers,OU=Groups," + B, "CN=Secret,CN=Users," + B]}
M["save_template"](dict(tpl), adm)
get, repair = M["get_references"], M["repair_references"]

r = get(adm, True)
check("alles gefunden: keine Meldung", r["problems"] == [], r)
with open(os.path.join(tmp, "data", "verweise.json"), encoding="utf-8") as f:
    known = json.load(f)
check("GUIDs gemerkt (nur DN -> GUID)", len(known) == 5 and all(len(v) == 36 for v in known.values()), known)
ok, _ = raises(lambda: get(op, True), 403)
check("Kontenoperator darf nicht pruefen", ok)
ok, _ = raises(lambda: repair(op), 403)
check("Kontenoperator darf nicht anpassen", ok)

# in AD: group renamed, OU renamed, group deleted and recreated, group deleted
D["CN=VPN-Remote,OU=Groups," + B] = D.pop("CN=VPN,OU=Groups," + B)
D["OU=Archiv," + B] = D.pop("OU=Archive," + B)
D["CN=Printers,OU=Groups," + B]["objectGUID"] = [uuid.uuid4().bytes_le]
D.pop("CN=Secret,CN=Users," + B)

r = get(adm)
check("Zwischenspeicher: noch alter Stand", r["problems"] == [], r)
r = get(adm, True)
kinds = {p["dn"]: (p["kind"], p["newDn"]) for p in r["problems"]}
check("umbenannte Gruppe erkannt", kinds.get("CN=VPN,OU=Groups," + B) == ("moved", "CN=VPN-Remote,OU=Groups," + B), kinds)
check("umbenannte OU erkannt", kinds.get("OU=Archive," + B) == ("moved", "OU=Archiv," + B), kinds)
check("neu angelegte Gruppe gleichen Namens erkannt", kinds.get("CN=Printers,OU=Groups," + B) == ("replaced", ""), kinds)
check("geloeschte Gruppe erkannt", kinds.get("CN=Secret,CN=Users," + B) == ("missing", ""), kinds)
check("Fundstelle genannt", any(w == {"label": "Template: Gruppe", "template": "Vertrieb"} for p in r["problems"] for w in p["where"]), r)
check("Fundstelle Einstellung", any(w == {"label": "Offboarding: Ziel-OU"} for p in r["problems"] for w in p["where"]), r)

out = repair(adm)
check("Anpassung meldet 3 Aenderungen", len(out["fixed"]) == 3, out)
tmpl = M["get_templates"](adm)[0]
check("Template: neuer Gruppen-DN", "CN=VPN-Remote,OU=Groups," + B in tmpl["groups"] and "CN=VPN,OU=Groups," + B not in tmpl["groups"], tmpl)
check("Template: geloeschte Gruppe bleibt sichtbar (von Hand entfernen)", "CN=Secret,CN=Users," + B in tmpl["groups"], tmpl)
check("Offboarding: neue Ziel-OU", M["get_offboarding_config"](adm)["targetOu"] == "OU=Archiv," + B)
r = get(adm)
check("danach nur noch die geloeschte Gruppe", [p["kind"] for p in r["problems"]] == ["missing"], r)
check("Anpassung im Protokoll", '"config-references"' in M["audit_jsonl"]())
print(f"\n{PASS} Pruefungen bestanden")
