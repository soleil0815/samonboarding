"""Protection of privileged accounts (protection.py) and detection of the directory service (detect_directory)."""

import os
import sys
import unittest

import _paths

try:
    import ldap3  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import acl, ldap_client, protection

DOMAIN = "S-1-5-21-1111-2222-3333"


class FakeConn:
    """Answers base searches from {attribute: values}; real ldap3 entries have attributes AND raw_attributes."""

    def __init__(self, attrs, raw=None, found=True, code=32):
        self.attrs, self.raw, self.found = attrs, raw or {}, found
        self.response = []
        self.result = {"result": 0 if found else code}

    def search(self, _dn, _flt, _scope, attributes=None):
        names = attributes or []
        entry = {
            "type": "searchResEntry",
            "dn": "CN=x",
            "attributes": {k: v for k, v in self.attrs.items() if k in names},
            "raw_attributes": {k: v for k, v in self.raw.items() if k in names},
        }
        self.response = [entry] if self.found else []
        return self.found


def raw_sids(*sids):
    return [acl.sid_to_bytes(s) for s in sids]


class PrivilegedTests(unittest.TestCase):
    def reason(self, groups, own=DOMAIN + "-1105", **extra):
        conn = FakeConn(dict(extra), raw={"tokenGroups": raw_sids(*groups), "objectSid": raw_sids(own)})
        return protection.privileged_reason(conn, "CN=x")

    def test_domain_admins(self):
        self.assertIn("Domänen-Admins", self.reason([DOMAIN + "-513", DOMAIN + "-512"]))

    def test_schema_and_enterprise_admins_also_from_other_domain(self):
        self.assertIn("Schema-Admins", self.reason(["S-1-5-21-9-9-9-518"]))
        self.assertIn("Organisations-Admins", self.reason(["S-1-5-21-9-9-9-519"]))

    def test_key_and_policy_admins_protected(self):
        """The same groups that only admins may add members to also protect their members (e.g. Key Admins)."""
        groups = ((526, "Schlüsseladmin"), (527, "Organisationsschlüssel"), (520, "Richtlinien"), (517, "Zertif"))
        for rid, name in groups:
            self.assertIn(name, self.reason([f"{DOMAIN}-{rid}"]), rid)
        self.assertIs(protection.PRIVILEGED_DOMAIN_GROUP_RIDS, protection.DOMAIN_GROUP_RIDS)

    def test_builtin_groups(self):
        # these SIDs consist only of bytes < 0x80: without raw data ldap3 would misread them as text
        self.assertIn("Administratoren", self.reason(["S-1-5-32-544"]))
        self.assertIn("Konten-Operatoren", self.reason(["S-1-5-32-548"]))
        self.assertIn("Sicherungs-Operatoren", self.reason(["S-1-5-32-551"]))

    def test_normal_accounts_are_not_protected(self):
        self.assertEqual(self.reason([DOMAIN + "-513", DOMAIN + "-1200", "S-1-5-32-545"]), "")

    def test_same_trailing_rid_in_foreign_sid_does_not_count(self):
        self.assertEqual(self.reason(["S-1-5-32-512", "S-1-5-5-512", DOMAIN + "-5120"]), "")

    def test_builtin_accounts(self):
        self.assertIn("Administratorkonto", self.reason([DOMAIN + "-513"], own=DOMAIN + "-500"))
        self.assertIn("krbtgt", self.reason([DOMAIN + "-513"], own=DOMAIN + "-502"))
        self.assertEqual(self.reason([DOMAIN + "-513"], own="S-1-5-32-500"), "")

    def test_former_admin_with_only_stale_marker(self):
        self.assertEqual(self.reason([DOMAIN + "-513"], adminCount=["1"]), "")

    def test_without_readable_groups_admincount_applies(self):
        conn = FakeConn({"adminCount": ["1"]}, raw={"objectSid": raw_sids(DOMAIN + "-1105")})
        self.assertIn("adminCount", protection.privileged_reason(conn, "CN=x"))
        self.assertEqual(
            protection.privileged_reason(FakeConn({}, raw={"objectSid": raw_sids(DOMAIN + "-1105")}), "CN=x"), ""
        )

    def test_text_form_without_raw_data(self):
        conn = FakeConn({"tokenGroups": [DOMAIN + "-512"], "objectSid": [DOMAIN + "-1105"]})
        self.assertIn("Domänen-Admins", protection.privileged_reason(conn, "CN=x"))

    def test_not_found_is_not_protected(self):
        self.assertEqual(protection.privileged_reason(FakeConn({}, found=False), "CN=x"), "")

    def test_failed_query_counts_as_protected(self):
        for code in (1, 50, 51):  # operationsError, insufficientAccessRights, busy
            with self.assertLogs("samonboarding.protection", "WARNING"):
                self.assertTrue(protection.privileged_reason(FakeConn({}, found=False, code=code), "CN=x"))

    def test_mark_protected_checks_every_account(self):
        calls = []
        original = protection.privileged_reason
        protection.privileged_reason = lambda conn, dn: calls.append(dn) or ("X" if dn == "CN=a" else "")
        try:
            users = [{"dn": "CN=a", "_adminCount": False}, {"dn": "CN=b", "_adminCount": False}]
            protection.mark_protected(None, users)
        finally:
            protection.privileged_reason = original
        self.assertEqual(calls, ["CN=a", "CN=b"])
        self.assertEqual([u["protected"] for u in users], ["X", ""])
        self.assertFalse(any("_adminCount" in u for u in users))

    def test_message(self):
        text = protection.protected_message("Mitglied von „Domänen-Admins“", "offgeboardet")
        self.assertIn("geschützt", text)
        self.assertIn("offgeboardet", text)


class DirectoryTests(unittest.TestCase):
    class RootConn:
        def __init__(self, attrs, ok=True, fail=False):
            self.attrs, self.ok, self.fail = attrs, ok, fail
            self.response = [{"type": "searchResEntry", "dn": "", "attributes": attrs}]

        def search(self, *_a, **_k):
            if self.fail:
                raise RuntimeError("boom")
            return self.ok

    def test_samba(self):
        info = ldap_client.detect_directory(
            self.RootConn(
                {
                    "vendorName": ["Samba Team (http://samba.org)"],
                    "vendorVersion": ["4.19.5"],
                    "dnsHostName": ["dc1.x.local"],
                }
            )
        )
        self.assertEqual(
            (info["type"], info["label"], info["version"], info["host"]), ("samba", "Samba AD", "4.19.5", "dc1.x.local")
        )

    def test_windows(self):
        info = ldap_client.detect_directory(
            self.RootConn({"supportedCapabilities": ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670"]})
        )
        self.assertEqual((info["type"], info["label"]), ("windows", "Windows Server AD"))

    def test_unknown_and_errors_do_not_break(self):
        self.assertEqual(ldap_client.detect_directory(self.RootConn({}))["type"], "unknown")
        self.assertEqual(ldap_client.detect_directory(self.RootConn({}, ok=False))["label"], "Active Directory")
        self.assertEqual(ldap_client.detect_directory(self.RootConn({}, fail=True))["type"], "unknown")

    def test_last_detected_is_remembered(self):
        ldap_client.detect_directory(self.RootConn({"vendorName": "Samba Team"}))
        self.assertEqual(ldap_client.directory_info()["type"], "samba")
        ldap_client.detect_directory(self.RootConn({"supportedCapabilities": ["1.2.840.113556.1.4.800"]}))
        self.assertEqual(ldap_client.directory_info()["type"], "windows")


class MailSystemTests(unittest.TestCase):
    class Conn:
        """Answers depending on the search base: RootDSE, Exchange entry, MSOL search."""

        def __init__(self, exchange=True, exchange_code=0, entra=False, root=True):
            self.exchange, self.exchange_code, self.entra, self.root = exchange, exchange_code, entra, root
            self.response, self.result = [], {"result": 0}

        def search(self, base, flt, _scope, attributes=None, **_k):
            self.response, self.result = [], {"result": 0}
            if base == "":
                if not self.root:
                    raise RuntimeError("boom")
                self.response = [
                    {
                        "type": "searchResEntry",
                        "dn": "",
                        "attributes": {
                            "configurationNamingContext": "CN=Configuration,DC=x,DC=local",
                            "defaultNamingContext": "DC=x,DC=local",
                        },
                    }
                ]
                return True
            if base.startswith("CN=Microsoft Exchange"):
                if self.exchange:
                    self.response = [{"type": "searchResEntry", "dn": base, "attributes": {}}]
                    return True
                self.result = {"result": self.exchange_code}
                return False
            if "MSOL_" in flt:
                if self.entra:
                    self.response = [{"type": "searchResEntry", "dn": "CN=MSOL_1", "attributes": {}}]
                return bool(self.entra)
            return False

    def test_both_found(self):
        self.assertEqual(ldap_client.detect_mail_system(self.Conn(entra=True)), {"exchange": True, "entra": True})

    def test_nothing_found(self):
        info = ldap_client.detect_mail_system(self.Conn(exchange=False, exchange_code=32))
        self.assertEqual(info, {"exchange": False, "entra": False})

    def test_no_permission_is_unknown_instead_of_no(self):
        info = ldap_client.detect_mail_system(self.Conn(exchange=False, exchange_code=50))
        self.assertIsNone(info["exchange"])

    def test_errors_do_not_break(self):
        self.assertEqual(ldap_client.detect_mail_system(self.Conn(root=False)), {"exchange": None, "entra": None})


if __name__ == "__main__":
    unittest.main()
