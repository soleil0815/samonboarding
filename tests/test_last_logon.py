"""Offboarding list: last logon from lastLogonTimestamp (AD FILETIME), only displayed, never stored."""

import inspect
import json
import unittest
from pathlib import Path

import _paths

from samonboarding.ldap_client import Row, row_filetime
from samonboarding.routers import offboarding

ROOT = Path(_paths.ROOT)


class FiletimeTests(unittest.TestCase):
    def test_conversion(self):
        # 2026-11-08 12:00:00 UTC as FILETIME (100 ns since 1601-01-01)
        value = (1794139200 + 11644473600) * 10_000_000
        self.assertEqual(
            row_filetime(Row("CN=x", {"lastLogonTimestamp": str(value)}), "lastLogonTimestamp"), "2026-11-08T12:00:00Z"
        )
        self.assertEqual(
            row_filetime(Row("CN=x", {"lastLogonTimestamp": [value]}), "lastlogontimestamp"), "2026-11-08T12:00:00Z"
        )

    def test_never_missing_invalid(self):
        for raw in (None, "", "0", "9223372036854775807", "-5", "abc", "1"):
            attrs = {} if raw is None else {"lastLogonTimestamp": raw}
            self.assertIsNone(row_filetime(Row("CN=x", attrs), "lastLogonTimestamp"), raw)


class OffboardingListTests(unittest.TestCase):
    def test_attribute_read_and_returned(self):
        source = inspect.getsource(offboarding._get_offboarding_users)
        self.assertIn('"lastLogonTimestamp"', source)
        self.assertIn('"lastLogon": row_filetime(row, "lastLogonTimestamp")', source)

    def test_not_stored_or_logged(self):
        for module in ("offboard_store.py", "audit.py", "reports.py"):
            self.assertNotIn("lastLogon", (ROOT / "samonboarding" / module).read_text(encoding="utf-8"), module)

    def test_interface_column_and_translation(self):
        html = (ROOT / "samonboarding" / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn("<span>Letzte Anmeldung</span>", html)
        self.assertIn("lastLogonCell(u.lastLogon)", html)
        data = json.loads((ROOT / "samonboarding" / "web" / "i18n.json").read_text(encoding="utf-8"))
        self.assertEqual(data["exact"]["Letzte Anmeldung"], "Last logon")
        self.assertIn(["vor {0} Tagen", "{0} days ago"], data["patterns"])


if __name__ == "__main__":
    unittest.main()
