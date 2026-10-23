"""Gemeinsame Testumgebung: simuliertes AD (ldap3-Ersatz), App aus dem Projekt geladen.

Wird von den Szenario-Skripten per exec eingebunden. Benoetigt keine installierten Pakete (fastapi, ldap3, pydantic
werden durch kleine Ersatzmodule in tests/scenarios/stubs ersetzt).
"""
import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.join(HERE, "stubs"))
import ldap3  # noqa: E402
from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError, LDAPOperationResult  # noqa: E402

# ---------------- Fake-Verzeichnis ----------------
B = "DC=test,DC=local"
D = {}


def add(dn, **attrs):
    D[dn] = {k: (v if isinstance(v, list) else [v]) for k, v in attrs.items()}


def reset():
    D.clear()
    add(B, objectClass=["domain"])
    add("OU=Staff," + B, objectClass=["top", "organizationalUnit"], name="Staff")
    add("OU=Archive," + B, objectClass=["top", "organizationalUnit"], name="Archive")
    add("OU=Groups," + B, objectClass=["top", "organizationalUnit"], name="Groups")
    add("CN=Users," + B, objectClass=["container"])
    u = ["top", "person", "organizationalPerson", "user"]
    add("CN=Admin User,OU=Staff," + B, objectClass=u, sAMAccountName="admin", userPrincipalName="admin@test.local", mail="admin@test.local", displayName="Admin User", userAccountControl="512", pwd="Pass1")
    add("CN=Op User,OU=Staff," + B, objectClass=u, sAMAccountName="op", userPrincipalName="op@test.local", displayName="Op User", userAccountControl="512", pwd="Pass2")
    add("CN=Nobody,OU=Staff," + B, objectClass=u, sAMAccountName="nobody", userPrincipalName="nobody@test.local", userAccountControl="512", pwd="Pass3")
    add("CN=Mustermann\\, Max,OU=Staff," + B, objectClass=u, sAMAccountName="MUSTERMANN", displayName="Mustermann, Max", userAccountControl="512", lockoutTime="0")
    add("CN=PC1,OU=Staff," + B, objectClass=u + ["computer"], sAMAccountName="PC1$")
    add("CN=Domain Admins,CN=Users," + B, objectClass=["top", "group"], sAMAccountName="Domain Admins", objectSid="S-1-5-21-1-2-3-512", member=["CN=Admin User,OU=Staff," + B])
    add("CN=Account Operators,CN=Users," + B, objectClass=["top", "group"], sAMAccountName="Account Operators", objectSid="S-1-5-32-548", member=["CN=Op User,OU=Staff," + B])
    add("CN=Printers,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="Printers", member=["CN=Mustermann\\, Max,OU=Staff," + B])
    add("CN=VPN,OU=Groups," + B, objectClass=["top", "group"], sAMAccountName="VPN", member=[])
    add("CN=Secret,CN=Users," + B, objectClass=["top", "group"], sAMAccountName="Secret", member=[])


STATE = {"dc_down_ssl": False, "binds": [], "ports": [], "deny": set(), "pwd_fail": False}


def unesc(v):
    return re.sub(r"\\([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)


def parse(f, i=0):
    assert f[i] == "("
    if f[i + 1] in "&|":
        op, i, kids = f[i + 1], i + 2, []
        while f[i] == "(":
            k, i = parse(f, i)
            kids.append(k)
        return (op, kids), i + 1
    if f[i + 1] == "!":
        k, i = parse(f, i + 2)
        return ("!", [k]), i + 1
    j, depth = i, 0
    while True:
        if f[j] == "(":
            depth += 1
        if f[j] == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return ("item", f[i + 1:j]), j + 1


def vals(dn, attr):
    a = attr.lower()
    if a == "memberof":
        return [g for g, e in D.items() if dn in e.get("member", [])]
    for k, v in D[dn].items():
        if k.lower() == a:
            return v
    return []


def member_chain(dn):
    out, todo = set(), [dn]
    while todo:
        x = todo.pop()
        for g, e in D.items():
            if x in e.get("member", []) and g not in out:
                out.add(g)
                todo.append(g)
    return out


def ev(node, dn):
    op, x = node
    if op == "&":
        return all(ev(k, dn) for k in x)
    if op == "|":
        return any(ev(k, dn) for k in x)
    if op == "!":
        return not ev(x[0], dn)
    attr, _, val = x.partition("=")
    if attr.startswith("member:"):
        return dn in member_chain(unesc(val))
    val = unesc(val)
    if val == "*":  # Praesenzfilter (objectClass=*)
        return bool(vals(dn, attr))
    # Binaerwerte (objectGUID) wie im echten AD als escapte Bytes vergleichen
    return any((v.decode("latin-1") == val) if isinstance(v, bytes) else (str(v).lower() == val.lower()) for v in vals(dn, attr))


def under(dn, base, scope):
    return dn == base if scope == "BASE" else (dn == base or dn.lower().endswith("," + base.lower()))


def view(dn, attrs):
    return {a: vals(dn, a) for a in attrs if vals(dn, a)}


class FakeServer:
    def __init__(self, host, port=389, use_ssl=False, **kw):
        self.port = port
        self.use_ssl = use_ssl


class FakeConn:
    def __init__(self, server, user=None, password=None, authentication=None, auto_bind=False, **kw):
        STATE["ports"].append(server.port)
        if server.use_ssl and STATE["dc_down_ssl"]:
            raise LDAPCommunicationError("socket open error")
        STATE["binds"].append(user)
        sam = user.split("@")[0].split("\\")[-1].lower()
        ok = any(e.get("sAMAccountName", [""])[0].lower() == sam and e.get("pwd", [None])[0] == password for e in D.values())
        if not ok:
            raise LDAPBindError("automatic bind not successful - invalidCredentials")
        self.user = sam
        self.result = {"result": 0}
        self.response = []
        self.extend = types.SimpleNamespace(standard=types.SimpleNamespace(paged_search=self._paged))
        self.unbound = False

    def _paged(self, base, flt, search_scope="SUBTREE", attributes=None, paged_size=100, generator=True):
        if base not in D:
            raise LDAPOperationResult("noSuchObject")
        tree, _ = parse(flt)
        for dn in list(D):
            if under(dn, base, search_scope) and ev(tree, dn):
                yield {"type": "searchResEntry", "dn": dn, "attributes": view(dn, attributes or [])}
        yield {"type": "searchResRef", "uri": ["ldap://x"]}
        self.result = {"result": 0}  # wie ldap3: Ergebnis der letzten Suche

    def search(self, dn, flt, scope, attributes=None):
        if dn not in D:
            self.result = {"result": 32, "description": "noSuchObject"}
            self.response = []
            return False
        tree, _ = parse(flt)
        self.response = [{"type": "searchResEntry", "dn": dn, "attributes": view(dn, attributes or [])}] if ev(tree, dn) else []
        self.result = {"result": 0}
        return bool(self.response)

    def _fail(self, code, desc, msg=""):
        self.result = {"result": code, "description": desc, "message": msg}
        return False

    def add(self, dn, object_class=None, attributes=None):
        if dn in D:
            return self._fail(68, "entryAlreadyExists")
        parts = re.split(r"(?<!\\),", dn, maxsplit=1)
        if len(parts) < 2 or parts[1] not in D:
            return self._fail(32, "noSuchObject")
        D[dn] = {k: (v if isinstance(v, list) else [v]) for k, v in attributes.items()}
        self.result = {"result": 0}
        return True

    def delete(self, dn, controls=None):
        children = [k for k in D if k.lower().endswith("," + dn.lower())]
        if children and not controls:
            return self._fail(66, "notAllowedOnNonLeaf")
        for k in children:
            D.pop(k, None)
        D.pop(dn, None)
        self.result = {"result": 0}
        return True

    def modify(self, dn, changes):
        if dn not in D:
            return self._fail(32, "noSuchObject")
        for attr, [(op, v)] in changes.items():
            if attr in STATE["deny"]:
                return self._fail(50, "insufficientAccessRights")
            if attr == "member":
                m = D[dn].setdefault("member", [])
                if op == "MODIFY_ADD":
                    if v[0] in m:
                        return self._fail(68, "entryAlreadyExists", "0000...ERROR_MEMBER_IN_ALIAS")
                    m.append(v[0])
                else:
                    if v[0] not in m:
                        return self._fail(53, "unwillingToPerform", "00000561: ERROR_MEMBER_NOT_IN_ALIAS")
                    m.remove(v[0])
            elif attr == "unicodePwd":
                if STATE["pwd_fail"]:
                    return self._fail(53, "unwillingToPerform", "0000052D: problem 5003 (WILL_NOT_PERFORM)")
                D[dn]["unicodePwd"] = v
            else:
                D[dn][attr] = v
        self.result = {"result": 0}
        return True

    def modify_dn(self, dn, rdn, new_superior=None):
        if new_superior not in D:
            return self._fail(32, "noSuchObject")
        D[rdn + "," + new_superior] = D.pop(dn)
        self.result = {"result": 0}
        return True

    def unbind(self):
        self.unbound = True


ldap3.Server = FakeServer
ldap3.Connection = FakeConn

# ---------------- App laden ----------------
tmp = tempfile.mkdtemp(prefix="samonboarding-test-")
atexit.register(shutil.rmtree, tmp, True)
os.chdir(tmp)
os.environ["AD_DOMAIN"] = "test.local"
os.environ["LOGIN_MAX_ATTEMPTS"] = "3"
os.environ["LDAP_ALLOW_PLAIN"] = "true"  # Fallback-Logik wird ausdruecklich mitgetestet
os.environ["DATA_DIR"] = tmp + "/data"

sys.path.insert(0, ROOT)
import samonboarding.main  # noqa: E402,F401

M = {}
for name, m in list(sys.modules.items()):
    if name.startswith("samonboarding.") and not hasattr(m, "__path__"):
        for k, v in vars(m).items():
            if not k.startswith("__") and not isinstance(v, types.ModuleType):
                M.setdefault(k, v)

from fastapi import BackgroundTasks, HTTPException, Request, Response  # noqa: E402

PASS = 0


def check(name, cond, extra=""):
    global PASS
    print(("OK   " if cond else "FAIL ") + name + (f"  {extra}" if not cond else ""))
    if not cond:
        raise SystemExit(1)
    PASS += 1


def raises(fn, code=None, contains=None):
    try:
        fn()
    except HTTPException as e:
        return (code is None or e.status_code == code) and (contains is None or contains in str(e.detail)), e
    return False, None


def login(u, p, ip="10.0.0.1"):
    r = Response()
    out = M["login"](M["LoginModel"](username=u, password=p), Request(ip), r)
    return out, M["active_sessions"][r.cookies["session_id"][0]], r


