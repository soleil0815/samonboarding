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


class PrivilegedMapTests(unittest.TestCase):
    def run_map(self, members, primary=(), specials=()):
        def search(_conn, _base, flt, attrs=("cn",)):
            if flt.startswith("(&(objectClass=group)"):
                # like ldap3 without schema: no (usable) objectSid in the result - the name comes from the query
                admins = "CN=Administrators,CN=Builtin," + BASE
                groups = {f"(objectSid={DOM}-512)": DA, "(objectSid=S-1-5-32-544)": admins}
                return [Row(dn, {"objectSid": ["\x01\x02 kaputt"]}) for f, dn in groups.items() if f in flt]
            if "memberOf:1.2.840.113556.1.4.1941:=" in flt:
                return [Row(dn, {}) for g, dn in members if g in flt]
            if "primaryGroupID" in flt:
                return [Row(dn, {"primaryGroupID": [rid]}) for dn, rid in primary]
            return [Row(dn, {}) for dn in specials]

        with (
            mock.patch.object(protection, "read_sids", return_value=([DOM], True)),
            mock.patch.object(protection, "_search_dns", side_effect=search),
        ):
            return protection.privileged_map(object(), BASE)

    def test_members_nested_primary_and_system_accounts(self):
        out = self.run_map(
            [("Domain Admins", "CN=Anna," + BASE), ("Administrators", "CN=Bert," + BASE)],
            primary=[("CN=Carl," + BASE, "512")],
            specials=["CN=krbtgt,CN=Users," + BASE],
        )
        self.assertIn("Domänen-Admins", out["cn=anna," + BASE.lower()])
        self.assertIn("Administratoren", out["cn=bert," + BASE.lower()])
        self.assertIn("Domänen-Admins", out["cn=carl," + BASE.lower()])
        self.assertEqual(out["cn=krbtgt,cn=users," + BASE.lower()], "geschütztes Systemkonto")

    def test_without_domain_admins_check_individually(self):
        # directory without nested search: better to check individually than to show admins without a lock
        with self.assertRaises(LookupError):
            self.run_map([("Administrators", "CN=Bert," + BASE)])

    def test_mark_protected_falls_back_to_individual_check(self):
        users = [{"dn": "CN=Anna," + BASE}]
        with (
            mock.patch.object(protection, "privileged_map", side_effect=LookupError("x")),
            mock.patch.object(protection, "privileged_reason", return_value="Mitglied von „Domänen-Admins“") as one,
        ):
            protection.mark_protected(object(), users)
        one.assert_called_once()
        self.assertTrue(users[0]["protected"])


if __name__ == "__main__":
    unittest.main()
