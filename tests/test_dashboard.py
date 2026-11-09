"""Start page: the DC counts with search filters, the browser receives only numbers (never lists)."""

import contextlib
import json
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

from ldap3.core.exceptions import LDAPException  # noqa: E402

from samonboarding.ldap_client import Row  # noqa: E402
from samonboarding.routers import dashboard  # noqa: E402

ROOT = Path(_paths.ROOT)
NOW = 1794139200  # 2026-11-08 12:00 UTC
DAY = 86400


def ft(seconds):
    return str(dashboard.filetime(seconds))


class FakeDirectory:
    """Answers per filter kind, records the searches."""

    def __init__(self, inactive=(), locked=(), disabled=(), fail_ous=()):
        self.data = {"inactive": list(inactive), "locked": list(locked), "disabled": list(disabled)}
        self.fail_ous = set(fail_ous)
        self.searches = []

    def search(self, conn, base, flt, attrs):
        self.searches.append((base, flt, tuple(attrs)))
        if base in self.fail_ous:
            raise LDAPException("insufficientAccessRights")
        if "lastLogonTimestamp" in flt:
            kind = "inactive"
        elif "lockoutTime" in flt:
            kind = "locked"
        else:
            kind = "disabled"
        return [r for r in self.data[kind] if r.dn.endswith(base)]


def run(user, directory, off_ous=("OU=MA,DC=f",), pwd_ous=("OU=MA,DC=f",), deletion=None, protected=()):
    def load_json(path, default):
        if path == dashboard.OFFBOARDING_CONFIG_FILE:
            return {"sourceOus": list(off_ous)}
        return {"sourceOus": list(pwd_ous)}

    def mark(conn, entries, user=None):
        for e in entries:
            e.pop("_adminCount", None)
            e["protected"] = "Domänen-Admins" if e["dn"] in protected else ""
        return entries

    @contextlib.contextmanager
    def session(u):
        yield object()

    with (
        mock.patch.object(dashboard, "load_json", load_json),
        mock.patch.object(dashboard, "ad_session", session),
        mock.patch.object(dashboard, "ldap_search", directory.search),
        mock.patch.object(dashboard, "mark_protected", mark),
        mock.patch.object(
            dashboard, "load_deletion_config", lambda: deletion or {"enabled": True, "disabledOu": "OU=Aus,DC=f"}
        ),
        mock.patch.object(dashboard.time, "time", lambda: NOW),
    ):
        return dashboard.get_dashboard(user=user)


ADMIN = {"username": "FIRMA\\it.admin", "role": "Administrator", "sid": "s1"}
OPERATOR = {"username": "op@firma.local", "role": "Account Operator", "sid": "s2"}


def user_row(name, ou="OU=MA,DC=f", **attrs):
    return Row(f"CN={name},{ou}", dict({"sAMAccountName": name}, **attrs))


class FilterTests(unittest.TestCase):
    def test_inactive_filter_is_counted_by_the_dc(self):
        flt = dashboard.inactive_filter(NOW)
        self.assertIn("(!(userAccountControl:1.2.840.113556.1.4.803:=2))", flt)  # only enabled accounts
        self.assertIn("(!(lastLogonTimestamp=*))", flt)  # never logged on
        self.assertIn(f"(lastLogonTimestamp<={ft(NOW - 90 * DAY)})", flt)
        self.assertTrue(flt.startswith("(&(&(objectClass=user)(!(objectClass=computer)))"))

    def test_filetime(self):
        self.assertEqual(dashboard.filetime(0), 116444736000000000)
        self.assertEqual(dashboard.filetime(NOW), (NOW + 11644473600) * 10_000_000)

    def test_other_filters(self):
        self.assertIn("(lockoutTime>=1)", dashboard.LOCKED_FILTER)
        self.assertIn("(userAccountControl:1.2.840.113556.1.4.803:=2)", dashboard.DISABLED_FILTER)


class CountTests(unittest.TestCase):
    def test_counts_for_administrator(self):
        directory = FakeDirectory(
            inactive=[
                user_row("anna", lastLogonTimestamp=ft(NOW - 120 * DAY)),
                user_row("ben"),  # never
                user_row("it.admin"),  # oneself
                user_row("chef", lastLogonTimestamp=ft(NOW - 200 * DAY)),  # protected
            ],
            locked=[user_row("carl", lockoutTime="133000000000000000"), user_row("dora", lockoutTime="0")],
            disabled=[user_row("emil", ou="OU=Aus,DC=f"), user_row("it.admin", ou="OU=Aus,DC=f")],
        )
        out = run(ADMIN, directory, protected={"CN=chef,OU=MA,DC=f"})
        self.assertEqual(out["inactive"], {"count": 2, "never": 1})
        self.assertEqual(out["locked"], {"count": 1})
        self.assertEqual(out["deletion"], {"count": 1})
        # only a few attributes, never names, mails or groups
        for _base, _flt, attrs in directory.searches:
            self.assertNotIn("mail", attrs)
            self.assertNotIn("memberOf", attrs)
            self.assertNotIn("displayName", attrs)

    def test_only_numbers_in_the_answer(self):
        directory = FakeDirectory(inactive=[user_row("anna")])
        text = json.dumps(run(ADMIN, directory))
        self.assertNotIn("anna", text)
        self.assertNotIn("CN=", text)

    def test_operator_gets_no_deletion_count(self):
        directory = FakeDirectory(disabled=[user_row("emil", ou="OU=Aus,DC=f")])
        out = run(OPERATOR, directory)
        self.assertIsNone(out["deletion"])
        self.assertFalse(any(base == "OU=Aus,DC=f" for base, _f, _a in directory.searches))

    def test_not_configured(self):
        out = run(ADMIN, FakeDirectory(), off_ous=(), pwd_ous=(), deletion={"enabled": False, "disabledOu": ""})
        self.assertIn("warning", out["inactive"])
        self.assertIn("warning", out["locked"])
        self.assertIn("warning", out["deletion"])

    def test_several_ous_count_each_account_once(self):
        anna = user_row("anna", ou="OU=Vertrieb,OU=MA,DC=f")
        directory = FakeDirectory(inactive=[anna])
        out = run(ADMIN, directory, off_ous=("OU=MA,DC=f", "OU=Vertrieb,OU=MA,DC=f"))
        self.assertEqual(out["inactive"]["count"], 1)

    def test_unreadable_ou(self):
        directory = FakeDirectory(inactive=[user_row("anna")], fail_ous={"OU=Weg,DC=f"})
        out = run(ADMIN, directory, off_ous=("OU=MA,DC=f", "OU=Weg,DC=f"))
        self.assertEqual(out["inactive"]["count"], 1)  # the readable OU still counts
        out = run(ADMIN, directory, off_ous=("OU=Weg,DC=f",))
        self.assertEqual(out["inactive"], {"error": "Liste nicht lesbar"})  # nothing readable -> no false "0"


class SourceTests(unittest.TestCase):
    def test_never_cached_and_registered(self):
        source = (ROOT / "samonboarding" / "routers" / "dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("listcache", source)
        self.assertIn("Depends(get_current_user)", source)
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(main.count("    dashboard,"), 2)

    def test_interface_uses_the_count_endpoint(self):
        html = _paths.web_source()
        self.assertIn("fetch('/api/dashboard')", html)


if __name__ == "__main__":
    unittest.main()
