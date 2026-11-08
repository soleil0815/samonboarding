"""Faster sign-in and lists without a service account: role from tokenGroups first, protection check once per
session minute, AD structure in parts, durations measured (never names)."""

import contextlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import listcache, permissions, protection, timing  # noqa: E402
from samonboarding.ldap_client import Row  # noqa: E402
from samonboarding.routers import infrastructure  # noqa: E402

ROOT = Path(_paths.ROOT)
DOM = "S-1-5-21-1-2-3"
NESTED = "1.2.840.113556.1.4.1941"


class RoleTests(unittest.TestCase):
    def run_role(self, token_sids, token_ok=True, nested_groups=(), custom="", custom_sid=None):
        searches = []

        def search(conn, base, flt, attrs, *a, **k):
            searches.append(flt)
            if NESTED in flt:
                return [Row(f"CN={n},DC=f", {"sAMAccountName": n, "objectSid": [sid]}) for n, sid in nested_groups]
            if "sAMAccountName=" in flt and "objectClass=group" in flt:
                return [Row("CN=custom,DC=f", {"objectSid": [custom_sid]})] if custom_sid else []
            return []

        me = Row("CN=Ich,DC=f", {"sAMAccountName": "ich", "mail": "ich@firma.local"})
        with (
            mock.patch.object(permissions, "_find_self", lambda *a: me),
            mock.patch.object(protection, "read_sids", lambda conn, dn, attr, *a: (list(token_sids), token_ok)),
            mock.patch.object(permissions, "ldap_search", search),
            mock.patch.object(permissions, "_group_sids", lambda row: set(row.list("objectSid"))),
            mock.patch.object(permissions, "CUSTOM_OPERATOR_GROUP", custom),
        ):
            role = permissions.check_user_role(object(), "DC=f", "ich")[0]
        return role, any(NESTED in f for f in searches)

    def test_admin_from_token_groups_without_domain_search(self):
        self.assertEqual(self.run_role([f"{DOM}-512", f"{DOM}-513"]), ("Administrator", False))
        self.assertEqual(self.run_role(["S-1-5-32-544"]), ("Administrator", False))

    def test_operator_from_token_groups_without_domain_search(self):
        self.assertEqual(self.run_role(["S-1-5-32-548", f"{DOM}-513"]), ("Account Operator", False))

    def test_own_operator_group_by_name_and_sid(self):
        role = self.run_role([f"{DOM}-513", f"{DOM}-1105"], custom="co-admin", custom_sid=f"{DOM}-1105")
        self.assertEqual(role, ("Account Operator", False))

    def test_fallback_when_token_groups_unreadable(self):
        role = self.run_role([], token_ok=False, nested_groups=[("Domain Admins", f"{DOM}-512")])
        self.assertEqual(role, ("Administrator", True))

    def test_fallback_when_no_role_found(self):
        self.assertEqual(self.run_role([f"{DOM}-513"]), (None, True))
        role = self.run_role([f"{DOM}-513"], custom="co-admin", nested_groups=[("CO-ADMIN", f"{DOM}-1105")])
        self.assertEqual(role, ("Account Operator", True))


class ProtectionCacheTests(unittest.TestCase):
    def setUp(self):
        listcache.invalidate()

    def tearDown(self):
        listcache.invalidate()

    def entries(self):
        return [{"dn": "CN=Chef,OU=MA,DC=f,DC=local"}, {"dn": "CN=Anna,OU=MA,DC=f,DC=local"}]

    def test_bulk_query_once_per_session_minute(self):
        calls = []

        def pmap(conn, base):
            calls.append(base)
            return {"cn=chef,ou=ma,dc=f,dc=local": "Mitglied von „Domänen-Admins“"}

        user = {"sid": "s1"}
        with mock.patch.object(protection, "privileged_map", pmap):
            first = protection.mark_protected(object(), self.entries(), user)
            protection.mark_protected(object(), self.entries(), user)
            self.assertEqual(calls, ["DC=f,DC=local"])
            self.assertTrue(first[0]["protected"])
            self.assertEqual(first[1]["protected"], "")
            protection.mark_protected(object(), self.entries(), {"sid": "s2"})  # other session: own query
            self.assertEqual(len(calls), 2)
            listcache.invalidate()  # every change in AD discards it
            protection.mark_protected(object(), self.entries(), user)
            self.assertEqual(len(calls), 3)
            protection.mark_protected(object(), self.entries())  # without session: always live
            self.assertEqual(len(calls), 4)

    def test_errors_are_not_kept(self):
        calls = []

        def pmap(conn, base):
            calls.append(1)
            raise LookupError("no nested search")

        with (
            mock.patch.object(protection, "privileged_map", pmap),
            mock.patch.object(protection, "privileged_reason", lambda conn, dn: ""),
        ):
            protection.mark_protected(object(), self.entries(), {"sid": "s1"})
            protection.mark_protected(object(), self.entries(), {"sid": "s1"})
        self.assertEqual(len(calls), 2)

    def test_all_lists_pass_the_session(self):
        for name in ("offboarding.py", "deletion.py", "dashboard.py"):
            source = (ROOT / "samonboarding" / "routers" / name).read_text(encoding="utf-8")
            self.assertRegex(source, r"mark_protected\(conn, \w+, user\)", name)


class InfrastructureTests(unittest.TestCase):
    def setUp(self):
        listcache.invalidate()

    def run_infra(self, **params):
        searches = []

        def search(conn, base, flt, attrs, *a, **k):
            searches.append(flt)
            if "organizationalUnit" in flt:
                return [Row("OU=MA,DC=firma,DC=local", {"name": "MA"})]
            if "objectClass=group" in flt:
                return [Row("CN=G,DC=firma,DC=local", {"sAMAccountName": "G"})]
            return [Row("CN=Anna,DC=firma,DC=local", {"displayName": "Anna", "co": "Deutschland"})]

        @contextlib.contextmanager
        def session(u):
            yield object()

        with (
            mock.patch.object(infrastructure, "ad_session", session),
            mock.patch.object(infrastructure, "ldap_search", search),
            mock.patch.object(infrastructure, "load_json", lambda *a: {"domain": "firma.local"}),
        ):
            return infrastructure.get_ad_infrastructure(user={"sid": "s1"}, **params), searches

    def test_only_ous_when_nothing_else_is_needed(self):
        out, searches = self.run_infra(gruppen=False, benutzer=False)
        self.assertEqual(set(out), {"status", "ous"})
        self.assertEqual(len(searches), 1)

    def test_groups_and_users_on_request(self):
        out, searches = self.run_infra(gruppen=True, benutzer=True)
        self.assertEqual(set(out), {"status", "ous", "groups", "users", "countries"})
        self.assertEqual(len(searches), 3)
        out, _ = self.run_infra(gruppen=True, benutzer=False)
        self.assertIn("groups", out)
        self.assertNotIn("users", out)

    def test_parts_are_cached_separately(self):
        self.run_infra(gruppen=False, benutzer=False)
        out, searches = self.run_infra(gruppen=True, benutzer=True)
        self.assertIn("users", out)  # not the smaller answer from the cache
        self.assertEqual(len(searches), 3)


class TimingTests(unittest.TestCase):
    def test_steps_add_up_and_only_durations(self):
        token = timing.start()
        with timing.timed("search"):
            pass
        with timing.timed("search"):
            pass
        with timing.timed("protect"):
            pass
        steps = timing.stop(token)
        self.assertEqual(set(steps), {"search", "protect"})
        header = timing.server_timing(steps, 1.234)
        self.assertRegex(header, r"^ldap-search;dur=\d+, protect;dur=\d+, total;dur=1234$")
        msg = timing.slow_message("GET", "/api/offboarding/users", {"protect": 2.4, "search": 0.4}, 2.9)
        self.assertEqual(msg, "Langsam: GET /api/offboarding/users 2.9 s (Schutzpruefung 2.4 s, Suche 0.4 s)")

    def test_outside_a_request_nothing_happens(self):
        with timing.timed("search"):
            pass  # no error, nothing collected

    def test_measured_where_it_matters(self):
        src = {
            n: (ROOT / "samonboarding" / n).read_text(encoding="utf-8")
            for n in ("ldap_client.py", "permissions.py", "protection.py", "main.py")
        }
        self.assertIn('timing.timed("connect")', src["ldap_client.py"])
        self.assertIn('timing.timed("search")', src["ldap_client.py"])
        self.assertIn('timing.timed("role")', src["permissions.py"])
        self.assertIn('timing.timed("protect")', src["protection.py"])
        self.assertIn('resp.headers["Server-Timing"]', src["main.py"])
        self.assertIn("request.url.path", src["main.py"])  # path only, never the query string


if __name__ == "__main__":
    unittest.main()
