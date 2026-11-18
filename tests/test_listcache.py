"""Cache for the account lists (listcache.py) and bulk lookup of protected accounts (protection.privileged_map)."""

import os
import sys
import unittest
from unittest import mock

import _paths

try:
    import ldap3  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import listcache, protection  # noqa: E402
from samonboarding.ldap_client import Row  # noqa: E402

ADM = {"sid": "sitzung-a"}
OP = {"sid": "sitzung-b"}


class ListCacheTests(unittest.TestCase):
    def setUp(self):
        listcache.invalidate()
        self.calls = 0

    def build(self, value=None):
        def run():
            self.calls += 1
            return {"n": self.calls} if value is None else value

        return run

    def test_second_call_from_cache(self):
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})
        self.assertEqual(self.calls, 1)

    def test_fresh_reads_again(self):
        listcache.cached(ADM, "k", self.build())
        self.assertEqual(listcache.cached(ADM, "k", self.build(), fresh=True), {"n": 2})
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_separate_per_session(self):
        listcache.cached(ADM, "k", self.build())
        self.assertEqual(listcache.cached(OP, "k", self.build()), {"n": 2})

    def test_change_clears_everything(self):
        listcache.cached(ADM, "k", self.build())
        listcache.invalidate()
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_expired(self):
        listcache.cached(ADM, "k", self.build())
        with mock.patch.object(listcache.time, "monotonic", return_value=listcache.time.monotonic() + 61):
            self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_copy_cannot_be_modified(self):
        first = listcache.cached(ADM, "k", self.build([{"dn": "a"}]))
        first.append("x")
        self.assertEqual(listcache.cached(ADM, "k", self.build()), [{"dn": "a"}])

    def test_errors_are_not_cached(self):
        def boom():
            raise RuntimeError("DC weg")

        with self.assertRaises(RuntimeError):
            listcache.cached(ADM, "k", boom)
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})

    def test_changed_while_reading_not_cached(self):
        def build():
            listcache.invalidate()  # e.g. a parallel offboarding
            return "alt"

        listcache.cached(ADM, "k", build)
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})

    def test_logout_forgets_the_session(self):
        listcache.cached(ADM, "k", self.build())
        listcache.forget_session("sitzung-a")
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_error_fallback_list_not_cached(self):
        listcache.cached(ADM, "k", self.build({"error": "DC nicht erreichbar", "ous": []}))
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_expired_entries_are_removed(self):
        listcache.cached(OP, "alt", self.build())
        with mock.patch.object(listcache.time, "monotonic", return_value=listcache.time.monotonic() + 61):
            listcache.cached(ADM, "k", self.build())
        self.assertNotIn(("sitzung-b", "alt"), listcache._store)

    def test_never_cached_without_session(self):
        listcache.cached({}, "k", self.build())
        listcache.cached({}, "k", self.build())
        self.assertEqual(self.calls, 2)


DOM = "S-1-5-21-10-20-30"
BASE = "DC=t,DC=l"
DA = "CN=Domain Admins,CN=Users," + BASE


ADMINS = "CN=Administrators,CN=Builtin," + BASE


class PrivilegedMapTests(unittest.TestCase):
    def run_map(self, groups, primary=(), specials=(), kinds=None):
        """groups: {group DN: [member DNs]}; members that are themselves a key in `groups` are groups."""
        reads = []

        def search(_conn, _base, flt, attrs=("cn",)):
            if flt.startswith("(&(objectClass=group)"):
                # like ldap3 without schema: no (usable) objectSid in the result - the name comes from the query
                known = {f"(objectSid={DOM}-512)": DA, "(objectSid=S-1-5-32-544)": ADMINS}
                return [Row(dn, {"objectSid": ["\x01\x02 kaputt"]}) for f, dn in known.items() if f in flt]
            self.assertNotIn("1.2.840.113556.1.4.1941", flt)  # no "in chain" search across the domain (slow on Samba)
            if "primaryGroupID" in flt:
                return [Row(dn, {"primaryGroupID": [rid]}) for dn, rid in primary]
            return [Row(dn, {}) for dn in specials]

        def members(_conn, dn):
            reads.append(("member", dn))
            return groups.get(dn, [])

        def kind(_conn, dn):
            reads.append(("kind", dn))
            if kinds and dn in kinds:
                return kinds[dn]
            return "group" if dn in groups else "user"

        with (
            mock.patch.object(protection, "read_sids", return_value=([DOM], True)),
            mock.patch.object(protection, "_search_dns", side_effect=search),
            mock.patch.object(protection, "_group_members", side_effect=members),
            mock.patch.object(protection, "_kind", side_effect=kind),
        ):
            out = protection.privileged_map(object(), BASE)
        self.reads = reads
        return out

    def test_members_nested_primary_and_system_accounts(self):
        out = self.run_map(
            {DA: ["CN=Anna," + BASE], ADMINS: ["CN=Bert," + BASE, DA]},
            primary=[("CN=Carl," + BASE, "512")],
            specials=["CN=krbtgt,CN=Users," + BASE],
        )
        self.assertIn("Administratoren", out["cn=bert," + BASE.lower()])
        self.assertIn("Domänen-Admins", out["cn=carl," + BASE.lower()])
        self.assertEqual(out["cn=krbtgt,cn=users," + BASE.lower()], "geschütztes Systemkonto")
        # Anna is in Domain Admins, which is in Administrators: protected either way
        self.assertTrue(out["cn=anna," + BASE.lower()].startswith("Mitglied von"))

    def test_nested_over_several_levels(self):
        it = "CN=IT-Admins,OU=Gruppen," + BASE
        team = "CN=Team-Server,OU=Gruppen," + BASE
        out = self.run_map({DA: ["CN=Anna," + BASE, it], it: [team], team: ["CN=Dora," + BASE]})
        self.assertEqual(out["cn=dora," + BASE.lower()], "Mitglied von „Domänen-Admins“")

    def test_loops_and_shared_groups_are_read_once(self):
        it = "CN=IT-Admins,OU=Gruppen," + BASE
        out = self.run_map({DA: ["CN=Anna," + BASE, it], it: [DA, "CN=Emil," + BASE], ADMINS: [DA, it]})
        self.assertIn("cn=emil," + BASE.lower(), out)
        kinds = [dn for what, dn in self.reads if what == "kind"]
        self.assertEqual(len(kinds), len(set(kinds)), "objectClass of each member read only once")

    def test_contacts_and_foreign_principals_are_ignored(self):
        fsp = "CN=S-1-5-21-9-9-9-1000,CN=ForeignSecurityPrincipals," + BASE
        out = self.run_map({DA: ["CN=Anna," + BASE, fsp]}, kinds={fsp: ""})
        self.assertNotIn(fsp.lower(), out)

    def test_without_domain_admins_check_individually(self):
        # members not readable: better to check individually than to show admins without a lock
        with self.assertRaises(LookupError):
            self.run_map({ADMINS: ["CN=Bert," + BASE]})


class MemberReadTests(unittest.TestCase):
    """The direct reads against a (fake) ldap3 connection."""

    class Conn:
        def __init__(self, objects):
            self.objects, self.response, self.calls = objects, [], []

        def search(self, dn, flt, scope, attributes=None):
            self.calls.append((dn, scope))
            if dn not in self.objects:
                self.response = []
                return False
            self.response = [{"type": "searchResEntry", "dn": dn, "attributes": self.objects[dn]}]
            return True

    def test_reads(self):
        conn = self.Conn(
            {
                DA: {"member": ["CN=Anna," + BASE]},
                "CN=Anna," + BASE: {"objectClass": ["top", "person", "organizationalPerson", "user"]},
                "CN=PC1," + BASE: {"objectClass": ["top", "user", "computer"]},
                "CN=G," + BASE: {"objectClass": ["top", "group"]},
                "CN=Kontakt," + BASE: {"objectClass": ["top", "contact"]},
            }
        )
        self.assertEqual(protection._group_members(conn, DA), ["CN=Anna," + BASE])
        self.assertEqual(protection._kind(conn, "CN=Anna," + BASE), "user")
        self.assertEqual(protection._kind(conn, "CN=PC1," + BASE), "user")
        self.assertEqual(protection._kind(conn, "CN=G," + BASE), "group")
        self.assertEqual(protection._kind(conn, "CN=Kontakt," + BASE), "")
        self.assertEqual(protection._kind(conn, "CN=Weg," + BASE), "")
        self.assertTrue(all(scope == protection.ldap3.BASE for _dn, scope in conn.calls))
        with self.assertRaises(LookupError):
            protection._group_members(conn, "CN=Weg," + BASE)
