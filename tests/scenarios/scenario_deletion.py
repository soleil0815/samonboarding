"""Scenario: deleting accounts (configuration, simulation, execution, ownership takeover, links, mail)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
exec(compile(open(os.path.join(HERE, "harness.py"), encoding="utf-8").read(), "harness.py", "exec"))

import types as _t  # noqa: E402
import samonboarding.fileshare as fs  # noqa: E402
import samonboarding.routers.deletion as dele  # noqa: E402
from samonboarding.fileshare import FsEntry, FsError, FsStat  # noqa: E402

reset()
# accounts
u = ["top", "person", "organizationalPerson", "user"]
add("OU=Disabled," + B, objectClass=["top", "organizationalUnit"], name="Disabled")
add("CN=Alt\\, Anna,OU=Disabled," + B, objectClass=u, sAMAccountName="aalt", displayName="Alt, Anna", userAccountControl="514",
    profilePath="\\\\fs1\\profiles$\\%username%", homeDirectory="\\\\fs1\\home$\\aalt")
add("CN=Neu Nils,OU=Disabled," + B, objectClass=u, sAMAccountName="nneu", displayName="Neu Nils", userAccountControl="512")
add("CN=Zed Zora,OU=Disabled," + B, objectClass=u, sAMAccountName="zzed", displayName="Zed Zora", userAccountControl="514",
    homeDirectory="\\\\fs1\\home$\\Abteilung", profilePath="C:\\lokal")
add("CN=Zwo Zeno,OU=Disabled," + B, objectClass=u, sAMAccountName="zzwo", userAccountControl="514", homeDirectory="\\\\fs1\\home$\\Abteilung")
add("CN=Evil Eve,OU=Disabled," + B, objectClass=u, sAMAccountName="eeve", userAccountControl="514",
    homeDirectory="\\\\fs1\\home$\\..\\..\\secret", profilePath="\\\\other\\x$\\eeve")
add("CN=Staffer,OU=Staff," + B, objectClass=u, sAMAccountName="staffer", userAccountControl="514")

# ---- Path functions
P = fs
check("parse_unc normal", P.parse_unc("\\\\FS1\\Profiles$\\a\\b") == ("FS1", "Profiles$", ["a", "b"]))
check("parse_unc Slashes + Endtrenner", P.parse_unc("//fs1/p$/a/") == ("fs1", "p$", ["a"]))
for bad in ["C:\\x", "\\\\fs1", "\\\\fs1\\p$\\..\\x", "\\\\fs1\\p$\\a\\*", "\\\\fs1\\p$\\a:b", "\\\\fs1\\p$\\a.", "\\\\fs1\\p$\\a \\b",
            "\\\\fs1\\p$\\\\a", "\\\\fs 1\\p$", "", "\\\\fs1\\p$\\%x%", "\\\\fs1\\p$\\.", "\\\\fs1\\p$\\a|b"]:
    try:
        P.parse_unc(bad)
        check(f"parse_unc lehnt ab: {bad!r}", False)
    except ValueError:
        pass
check("parse_unc lehnt unzulaessige Pfade ab", True)
check("below: normal", P.is_strictly_below("\\\\FS1\\Profiles$\\aalt.V2", "\\\\fs1\\profiles$"))
check("below: Root selbst nein", not P.is_strictly_below("\\\\fs1\\profiles$", "\\\\fs1\\profiles$"))
check("below: Freigabe-Praefix nein", not P.is_strictly_below("\\\\fs1\\profiles$x\\a", "\\\\fs1\\profiles$"))
check("below: Ordner-Praefix nein", not P.is_strictly_below("\\\\fs1\\p$\\userX\\a", "\\\\fs1\\p$\\user"))
check("below: anderer Server nein", not P.is_strictly_below("\\\\fs2\\p$\\a", "\\\\fs1\\p$"))
check("expand %username%", P.expand_username("\\\\x\\y\\%UserName%", "bob") == "\\\\x\\y\\bob")
try:
    P.expand_username("\\\\x\\%homepath%", "b"); check("fremde Variable", False)
except ValueError:
    check("fremde Variable abgelehnt", True)
check("valid_sam", P.valid_sam("max.m") and not P.valid_sam("..") and not P.valid_sam("a\\b") and not P.valid_sam("a*") and not P.valid_sam(""))

# ---- build_targets
loc = {"enabled": True, "roots": ["\\\\fs1\\profiles$"], "useAdAttr": True, "suffixes": ["V2", "V6"]}
t = P.build_targets("profile", loc, "aalt", "\\\\fs1\\profiles$\\%username%")
check("Profil: nur mit Endung, dedupliziert", [x["path"] for x in t] == ["\\\\fs1\\profiles$\\aalt.V2", "\\\\fs1\\profiles$\\aalt.V6"], t)
check("Profil: Quelle AD-Attribut", t[0]["source"] == "AD-Attribut")
t = P.build_targets("profile", dict(loc, useAdAttr=False), "aalt", "x")
check("Profil ohne AD-Attribut -> Basispfad", {x["source"] for x in t} == {"Basispfad"} and len(t) == 2)
t = P.build_targets("profile", loc, "aalt", "\\\\fs1\\profiles$\\aalt.v2")
check("Profil: Attribut mit Endung bleibt, keine Doppel-Endung", t[0]["path"] == "\\\\fs1\\profiles$\\aalt.v2" and not any(".V2.V2" in x["path"] or ".v2.V" in x["path"] for x in t))
t = P.build_targets("profile", loc, "aalt", "\\\\evil\\x$\\aalt")
check("Attribut ausserhalb der Basispfade -> skip", t[0]["skip"] and "Basispfad" in t[0]["skip"])
t = P.build_targets("home", {"enabled": True, "roots": ["\\\\fs1\\home$"], "useAdAttr": True}, "aalt", "C:\\lokal")
check("Basisordner lokaler Pfad -> skip", t[0]["skip"] and "UNC" in t[0]["skip"])
check("deaktivierter Ort -> keine Ziele", P.build_targets("home", {"enabled": False, "roots": ["\\\\a\\b"]}, "x") == [])
t = P.build_targets("folderRedirection", {"enabled": True, "roots": ["\\\\fs1\\redir$", "\\\\fs2\\redir$"]}, "aalt")
check("Ordnerumleitung: je Basispfad ein Ziel", [x["path"] for x in t] == ["\\\\fs1\\redir$\\aalt", "\\\\fs2\\redir$\\aalt"])
t = P.build_targets("folderRedirection", {"enabled": True, "roots": ["\\\\fs1\\redir$"]}, "..")
check("boeser Benutzername -> kein Pfad", t[0]["skip"] and t[0]["path"] == "")

# ---- Fake file system
class FakeFS:
    def __init__(self, tree, denied=(), down=(), reparse=(), locked=(), no_takeover=()):
        self.no_takeover = {x.lower() for x in no_takeover}
        self.taken = []
        self.locked = {x.lower() for x in locked}
        self.tree = {k.lower(): v for k, v in tree.items()}   # path -> None (file, size) | dict
        self.denied = {d.lower() for d in denied}
        self.down = {d.lower() for d in down}
        self.reparse = {r.lower() for r in reparse}
        self.calls = []
        self.closed = False

    def _node(self, path):
        server = P.parse_unc(path)[0].lower()
        if server in self.down:
            raise FsError("unreachable", "Dateiserver nicht erreichbar (x).")
        if path.lower() in self.denied:
            raise FsError("denied", "Zugriff verweigert.")
        if path.lower() not in self.tree:
            raise FsError("notfound", "nicht gefunden")
        return self.tree[path.lower()]

    def stat(self, path):
        self.calls.append(("stat", path))
        n = self._node(path)
        return FsStat(is_dir=isinstance(n, list), size=0 if isinstance(n, list) else n, reparse=path.lower() in self.reparse)

    def listdir(self, path):
        self.calls.append(("listdir", path))
        n = self._node(path)
        out = []
        for name in n:
            child = path.rstrip("\\") + "\\" + name
            c = self.tree[child.lower()]
            out.append(FsEntry(name, isinstance(c, list), 0 if isinstance(c, list) else c, child.lower() in self.reparse))
        return out

    def _parent(self, path):
        parent, _, name = path.rpartition("\\")
        return parent.lower(), name

    def remove(self, path):
        self.calls.append(("remove", path))
        if path.lower() in self.locked:
            raise FsError("denied", "Zugriff verweigert.")
        n = self._node(path)
        if isinstance(n, list):
            raise FsError("other", "ist ein Ordner")
        parent, name = self._parent(path)
        self.tree[parent] = [x for x in self.tree[parent] if x.lower() != name.lower()]
        del self.tree[path.lower()]

    def rmdir(self, path):
        self.calls.append(("rmdir", path))
        if path.lower() in self.locked:
            raise FsError("denied", "Zugriff verweigert.")
        n = self._node(path)
        if path.lower() in self.reparse:  # link: only the link itself disappears, the target stays
            parent, name = self._parent(path)
            self.tree[parent] = [x for x in self.tree[parent] if x.lower() != name.lower()]
            del self.tree[path.lower()]
            return
        if not isinstance(n, list):
            raise FsError("other", "ist keine Datei")
        if n:
            raise FsError("other", "Das Verzeichnis ist nicht leer.")
        parent, name = self._parent(path)
        self.tree[parent] = [x for x in self.tree[parent] if x.lower() != name.lower()]
        del self.tree[path.lower()]

    def can_take_ownership(self, path, is_dir):
        self.calls.append(("can_take", path))
        return path.lower() not in self.no_takeover

    def take_ownership(self, path, is_dir):
        self.calls.append(("take", path))
        if path.lower() in self.no_takeover:
            raise FsError("denied", "Besitzübernahme fehlgeschlagen: Zugriff verweigert.")
        self.taken.append(path)
        self.denied.discard(path.lower())
        self.locked.discard(path.lower())

    def close(self):
        self.closed = True

def mkfs(clean=False, **kw):
    link = "\\\\fs1\\profiles$\\aalt.V2\\Desktop\\link"
    kw["reparse"] = set(kw.get("reparse", ())) | (set() if clean else {link})
    tree = {
        "\\\\fs1\\profiles$": ["aalt.V2", "other.V2"],
        "\\\\fs1\\profiles$\\aalt.V2": ["NTUSER.DAT", "Desktop"],
        "\\\\fs1\\profiles$\\aalt.V2\\NTUSER.DAT": 1000,
        "\\\\fs1\\profiles$\\aalt.V2\\Desktop": ["a.txt", "link"],
        "\\\\fs1\\profiles$\\aalt.V2\\Desktop\\a.txt": 500,
        "\\\\fs1\\profiles$\\aalt.V2\\Desktop\\link": ["big.iso"],
        "\\\\fs1\\profiles$\\aalt.V2\\Desktop\\link\\big.iso": 9999999,
        "\\\\fs1\\profiles$\\other.V2": ["x"],
        "\\\\fs1\\profiles$\\other.V2\\x": 1,
        "\\\\fs1\\redir$": ["aalt"],
        "\\\\fs1\\redir$\\aalt": ["Documents"],
        "\\\\fs1\\redir$\\aalt\\Documents": ["d.docx"],
        "\\\\fs1\\redir$\\aalt\\Documents\\d.docx": 2000,
        "\\\\fs1\\home$": ["aalt", "Abteilung"],
        "\\\\fs1\\home$\\aalt": ["h.txt"],
        "\\\\fs1\\home$\\aalt\\h.txt": 30,
        "\\\\fs1\\home$\\Abteilung": ["shared.txt"],
        "\\\\fs1\\home$\\Abteilung\\shared.txt": 10,
    }
    if clean:
        tree["\\\\fs1\\profiles$\\aalt.V2\\Desktop"] = ["a.txt"]
        tree = {k: v for k, v in tree.items() if "\\link" not in k}
    return FakeFS(tree, **kw)

FSX = {"fs": None}
dele.make_backend = lambda user: FSX["fs"]

# ---- Configuration
out, adm, _ = login("admin", "Pass1", ip="10.20.0.1")
out, op, _ = login("op", "Pass2", ip="10.20.0.2")
N = _t.SimpleNamespace
def loc_m(**kw):
    d = dict(enabled=False, roots=[], useAdAttr=True, suffixes=[], takeOwnership=False)
    d.update(kw)
    return N(**d)
def cfg_m(**kw):
    d = dict(enabled=True, disabledOu="OU=Disabled," + B,
             profile=loc_m(enabled=True, roots=["\\\\fs1\\profiles$"], suffixes=["V2", ".V6"]),
             folderRedirection=loc_m(enabled=True, roots=["//fs1/redir$/"]),
             home=loc_m(enabled=True, roots=["\\\\fs1\\home$"]))
    d.update(kw)
    return N(**d)

DC = dele.router.routes  # smoke test only
for fn, args in [(dele.get_deletion_config, ()), (dele.save_deletion_config, (cfg_m(),)), (dele.get_deletion_users, ()),
                 (dele.test_deletion_paths, ()), (dele.simulate_deletion, (N(userDn="CN=x"),))]:
    ok, _ = raises(lambda fn=fn, args=args: fn(*args, op), 403)
    check(f"Operator -> 403 bei {fn.__name__}", ok)
check("Operator-Zugriff hat nichts gespeichert", not __import__("os").path.exists(M["DELETION_CONFIG_FILE"]))
check("Standardkonfiguration: aus", dele.get_deletion_config(adm)["enabled"] is False)
ok, _ = raises(lambda: dele.get_deletion_users(adm))
check("Users bei deaktivierter Funktion: leer + Warnung", dele.get_deletion_users(adm)["users"] == [] and dele.get_deletion_users(adm)["warning"])
ok, _ = raises(lambda: dele.simulate_deletion(N(userDn="CN=Alt\\, Anna,OU=Disabled," + B), adm), 400)
check("Simulation bei deaktivierter Funktion -> 400", ok)

for name, bad in [
    ("ohne Deaktiviert-OU", cfg_m(disabledOu="")),
    ("Basispfad ungueltig", cfg_m(profile=loc_m(enabled=True, roots=["\\\\fs1\\p$\\.."], suffixes=["V2"]))),
    ("Ort ohne Basispfad", cfg_m(home=loc_m(enabled=True, roots=[]))),
    ("Profil ohne Endung", cfg_m(profile=loc_m(enabled=True, roots=["\\\\fs1\\p$"], suffixes=[]))),
    ("Endung ungueltig", cfg_m(profile=loc_m(enabled=True, roots=["\\\\fs1\\p$"], suffixes=["V2\\.."]))),
]:
    ok, _ = raises(lambda bad=bad: dele.save_deletion_config(bad, adm), 400)
    check(f"Config abgelehnt: {name}", ok)
check("abgelehnte Configs nicht gespeichert", not __import__("os").path.exists(M["DELETION_CONFIG_FILE"]))
dele.save_deletion_config(cfg_m(), adm)
saved = dele.get_deletion_config(adm)
check("Config gespeichert + normalisiert", saved["profile"]["suffixes"] == ["V2", "V6"] and saved["folderRedirection"]["roots"] == ["\\\\fs1\\redir$"] and saved["enabled"])
check("Config im Audit-Log", "config-deletion" in M["audit_jsonl"]())

# ---- User list
users = dele.get_deletion_users(adm)["users"]
check("Liste nur aus Deaktiviert-OU, alphabetisch", [x["sam"] for x in users] == ["aalt", "eeve", "nneu", "zzed", "zzwo"], [x["sam"] for x in users])
check("Liste markiert aktive Konten", {x["sam"]: x["disabled"] for x in users}["nneu"] is False)
check("Staffer (andere OU) nicht in Liste", "staffer" not in [x["sam"] for x in users])

# ---- Connection test
FSX["fs"] = mkfs()
r = dele.test_deletion_paths(adm)["results"]
check("Verbindungstest: alle Roots ok", len(r) == 3 and all(x["ok"] for x in r) and FSX["fs"].closed, r)
check("Verbindungstest zaehlt Eintraege", [x["entries"] for x in r if x["kind"] == "profile"] == [2])
FSX["fs"] = mkfs(down={"fs1"})
r = dele.test_deletion_paths(adm)["results"]
check("Server offline: alle Roots mit Meldung, nur 1 echter Versuch", not any(x["ok"] for x in r) and sum(1 for c in FSX["fs"].calls if c[0] == "stat") == 1, FSX["fs"].calls)

# ---- Simulation
DN_ALT = "CN=Alt\\, Anna,OU=Disabled," + B
def sim(dn, who=adm, fsobj=None):
    FSX["fs"] = fsobj or mkfs()
    return dele.simulate_deletion(N(userDn=dn), who)
before = json.dumps(sorted(D.items()), sort_keys=True, default=str)
s = sim(DN_ALT)
after = json.dumps(sorted(D.items()), sort_keys=True, default=str)
check("Simulation veraendert das AD nicht", before == after)
check("Simulation nur lesend (kein write/delete im FS-Fake)", all(c[0] in ("stat", "listdir") for c in FSX["fs"]) if False else all(c[0] in ("stat", "listdir") for c in FSX["fs"].calls))
check("Backend wird geschlossen", FSX["fs"].closed)
T = {(x["kind"], x["path"]): x for x in s["targets"]}
prof = T[("profile", "\\\\fs1\\profiles$\\aalt.V2")]
check("Profil .V2 gefunden", prof["status"] == "found" and prof["source"] == "AD-Attribut")
check("Profil: Dateien/Groesse (Junction nicht verfolgt)", prof["files"] == 2 and prof["size"] == 1500 and prof["dirs"] == 1, prof)
check("Profil V6 fehlt", T[("profile", "\\\\fs1\\profiles$\\aalt.V6")]["status"] == "missing")
check("Ordnerumleitung gefunden", T[("folderRedirection", "\\\\fs1\\redir$\\aalt")]["status"] == "found")
check("Basisordner gefunden", T[("home", "\\\\fs1\\home$\\aalt")]["status"] == "found" and T[("home", "\\\\fs1\\home$\\aalt")]["files"] == 1)
check("Zusammenfassung (Junction wird nur selbst entfernt)", s["summary"]["folders"] == 3 and s["summary"]["files"] == 4 and s["summary"]["size"] == 3530 and s["summary"]["allDeletable"] and s["summary"]["links"] == 1, s["summary"])
check("Junction blockiert den Plan nicht, Hinweis erscheint", s["planId"] and not s["blockers"] and any("Verknüpfung" in w for t in s["targets"] for w in t["warnings"]), s["blockers"])
s_clean = sim(DN_ALT, fsobj=mkfs(clean=True))
check("Ohne Junction: allDeletable + Plan", s_clean["summary"]["allDeletable"] and s_clean["planId"] and not s_clean["blockers"] and s_clean["summary"]["files"] == 4)
check("Konto-Infos", s["account"]["sam"] == "aalt" and s["account"]["dn"] == DN_ALT and "profilePath" in s["account"])
check("Fremder Profilordner (other.V2) kommt nicht vor", not any("other" in x["path"] for x in s["targets"]))
check("Warnung wegen fehlendem V6 nur wenn gar nichts gefunden", s["warnings"] == [])
check("Simulation im Audit-Log", "deletion-simulate" in M["audit_jsonl"]())

# warning: no profile
fs0 = mkfs()
for k in [k for k in fs0.tree if "aalt.v2" in k]:
    del fs0.tree[k]
s = sim(DN_ALT, fsobj=fs0)
check("Warnung: kein Profilordner gefunden (erwartet aalt.V2/V6)", any("Roamingprofil" in w and "aalt.V2/V6" in w for w in s["warnings"]), s["warnings"])

# junction at top level, no access, server offline
s = sim(DN_ALT, fsobj=mkfs(reparse={"\\\\fs1\\home$\\aalt"}))
h = [x for x in s["targets"] if x["kind"] == "home"][0]
check("Ordner ist Junction -> uebersprungen", h["status"] == "skipped" and "Verknüpfung" in h["message"])
s = sim(DN_ALT, fsobj=mkfs(denied={"\\\\fs1\\profiles$\\aalt.V2"}))
check("Kein Zugriff gemeldet", [x for x in s["targets"] if x["path"].endswith("aalt.V2")][0]["status"] == "denied")
s = sim(DN_ALT, fsobj=mkfs(denied={"\\\\fs1\\profiles$\\aalt.V2\\Desktop"}))
p2 = [x for x in s["targets"] if x["path"].endswith("aalt.V2")][0]
check("Unterordner ohne Zugriff -> nicht vollstaendig loeschbar", p2["status"] == "found" and not p2["deletable"] and not s["summary"]["allDeletable"] and p2["warnings"])
s = sim(DN_ALT, fsobj=mkfs(down={"fs1"}))
check("Server offline -> Fehlerstatus, nichts loeschbar", all(x["status"] in ("error", "skipped") for x in s["targets"]) and s["summary"]["folders"] == 0)
check("Server offline: nur ein Verbindungsversuch", sum(1 for c in FSX["fs"].calls if c[0] == "stat") == 1)

# boundaries
ok, e = raises(lambda: sim("CN=Neu Nils,OU=Disabled," + B), 400)
check("Aktives Konto -> 400 'nicht deaktiviert'", ok and "nicht deaktiviert" in e.detail)
ok, _ = raises(lambda: sim("CN=Staffer,OU=Staff," + B), 403)
check("Konto ausserhalb der Deaktiviert-OU -> 403", ok)
ok, _ = raises(lambda: sim("CN=Gibt es nicht,OU=Disabled," + B), 404)
check("Unbekanntes Konto -> 404", ok)
ok, _ = raises(lambda: sim("OU=Disabled," + B + ",OU=Fremd"), 403)
check("DN-Trick ausserhalb -> 403", ok)

# own account in the disabled OU
add("CN=Admin Self,OU=Disabled," + B, objectClass=u, sAMAccountName="admin2", userAccountControl="514", pwd="Pass9")
D["CN=Admin Self,OU=Disabled," + B]["member"] = []
D["CN=Domain Admins,CN=Users," + B]["member"].append("CN=Admin Self,OU=Disabled," + B)
D["CN=Admin Self,OU=Disabled," + B]["sAMAccountName"] = ["admin"]  # same name as the logged-in admin
ok, e = raises(lambda: sim("CN=Admin Self,OU=Disabled," + B), 400)
check("Eigenes Konto -> 400", ok and "eigene" in e.detail)

# shared home folder / malicious attribute
s = sim("CN=Zed Zora,OU=Disabled," + B)
hz = [x for x in s["targets"] if x["kind"] == "home" and x["source"] == "AD-Attribut"][0]
check("Fremder/gemeinsamer Ordner im Attribut wird ausgeschlossen", hz["status"] == "skipped" and "passt nicht zum Benutzernamen" in hz["message"] and not hz["deletable"], hz)
pz = [x for x in s["targets"] if x["kind"] == "profile"]
check("Lokaler Profilpfad (C:\\...) wird ausgeschlossen", any(x["skip"] for x in pz) or all(x["source"] == "Basispfad" for x in pz))
s = sim("CN=Evil Eve,OU=Disabled," + B)
ev_t = [x for x in s["targets"] if x["source"] == "AD-Attribut"]
check("Manipulierte Attribute (.. / fremder Server) werden verworfen", ev_t and all(x["status"] == "skipped" for x in ev_t) and not any(c for c in FSX["fs"].calls if "secret" in c[1] or "other" in c[1].lower()), ev_t)
check("Kein deletable bei verworfenen Zielen", not any(x["deletable"] for x in ev_t))

exec(open(os.path.join(HERE, "deletion_exec_part.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "deletion_takeover_part.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "deletion_batch_part.py"), encoding="utf-8").read())
print(f"\n{PASS} Pruefungen bestanden")
