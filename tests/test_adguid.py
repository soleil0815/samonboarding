"""Read objectGUID and write it as an LDAP filter (restore after offboarding)."""

import os
import sys
import unittest
import uuid

import _paths

try:
    import ldap3  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import adguid  # noqa: E402

KNOWN = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")


class GuidTests(unittest.TestCase):
    def test_bytes_in_windows_order(self):
        self.assertEqual(adguid.guid_from_ldap(KNOWN.bytes_le), str(KNOWN))
        self.assertEqual(adguid.guid_from_ldap([KNOWN.bytes_le]), str(KNOWN))

    def test_text_with_braces(self):
        self.assertEqual(adguid.guid_from_ldap("{00112233-4455-6677-8899-AABBCCDDEEFF}"), str(KNOWN))

    def test_invalid_is_empty(self):
        for value in (b"kurz", "kein-guid", None, [], ""):
            self.assertEqual(adguid.guid_from_ldap(value), "")

    def test_filter_with_escaped_bytes(self):
        # Windows stores the first three blocks reversed
        self.assertEqual(
            adguid.guid_filter(str(KNOWN)),
            "(objectGUID=\\33\\22\\11\\00\\55\\44\\77\\66\\88\\99\\aa\\bb\\cc\\dd\\ee\\ff)",
        )

    def test_read_guid_prefers_raw_data(self):
        class Conn:
            response = [
                {
                    "type": "searchResEntry",
                    "raw_attributes": {"objectGUID": [KNOWN.bytes_le]},
                    "attributes": {"objectGUID": "kaputt"},
                }
            ]

            def search(self, *a, **k):
                return True

        self.assertEqual(adguid.read_guid(Conn(), "CN=x"), str(KNOWN))

    def test_read_guid_error_does_no_harm(self):
        class Conn:
            def search(self, *a, **k):
                raise RuntimeError("boom")

        self.assertEqual(adguid.read_guid(Conn(), "CN=x"), "")


if __name__ == "__main__":
    unittest.main()
