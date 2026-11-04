"""Sorting of the user lists against the simulated AD (with its own minimal data)."""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, ROOT)
os.environ["DATA_DIR"] = tempfile.mkdtemp(); os.environ["AD_DOMAIN"] = "test.local"
from samonboarding.ldap_client import name_sort_key, collect_users
import samonboarding.ldap_client as lc

names = ["zimmer, Paul", "Ärmel, Anna", "adam, Bert", "Öztürk, Can", "Mueller, Max", "Müller, Max", "Ünal, Ali", "ZED", "Straße, X", "Strasse, Y", "Éclair, Eve", "Bauer"]
print("Sortiert:", sorted(names, key=name_sort_key))
exp = ["adam, Bert", "Ärmel, Anna", "Bauer", "Éclair, Eve", "Mueller, Max", "Müller, Max", "Öztürk, Can", "Straße, X", "Strasse, Y", "Ünal, Ali", "ZED", "zimmer, Paul"]
got = sorted(names, key=name_sort_key)
assert got[:3] == ["adam, Bert", "Ärmel, Anna", "Bauer"] and got[-2:] == ["ZED", "zimmer, Paul"], got
assert got.index("Mueller, Max") < got.index("Müller, Max") < got.index("Öztürk, Can")
assert got.index("Öztürk, Can") < got.index("Ünal, Ali")

# collect_users: several OUs, duplicate DNs, sorting across all OUs
class R:  # minimal Row
    def __init__(s, dn, name, sam): s.dn, s.n, s.s = dn, name, sam
rows = {"OU=A": [R("cn=1,OU=A", "Zeta", "z"), R("cn=2,OU=A", "ärger", "a1")],
        "OU=B": [R("cn=3,OU=B", "Beta", "b"), R("cn=2,OU=A", "ärger", "a1"), R("cn=4,OU=B", "alpha", "al")]}
lc.ldap_search = lambda conn, ou, flt, attrs: rows[ou]
out = collect_users(None, ["OU=A", "OU=B"], [], lambda r, ou: {"name": r.n, "sam": r.s, "dn": r.dn})
print("collect_users:", [u["name"] for u in out])
assert [u["name"] for u in out] == ["alpha", "ärger", "Beta", "Zeta"]
print("Sortier-Tests OK")
