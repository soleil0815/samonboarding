"""Kerberos for the encrypted LDAP connection (2.10.0): configuration, principal, when Kerberos is used, and that a
wrong password is never tried with NTLM as well. With SAMONB_TEST_DC_NAME=<DC DNS name> (and the KDC reachable,
SAMONB_TEST_DOMAIN, SAMONB_TEST_USER, SAMONB_TEST_PASSWORD) also against a real DC - skipped in CI."""

import os
import sys
import unittest
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import kerberos, ldap_client, ldap_seal  # noqa: E402


class HelperTests(unittest.TestCase):
    def test_principal_uses_the_realm_in_capitals(self):
        self.assertEqual(kerberos.principal("anna@firma.local", "firma.local"), "anna@FIRMA.LOCAL")
        self.assertEqual(kerberos.principal("FIRMA\\anna", "firma.local"), "anna@FIRMA.LOCAL")
        self.assertEqual(kerberos.principal("anna", "Firma.Local"), "anna@FIRMA.LOCAL")
        self.assertEqual(kerberos.principal("anna@firma.de", "firma.local"), "anna@firma.de")  # other UPN suffix

    def test_only_a_dns_name_can_be_a_kerberos_target(self):
        self.assertTrue(kerberos.is_dns_name("dc01.firma.local"))
        for value in ("192.0.2.10", "2001:db8::1", "dc01", "", "dc01.firma.local/x"):
            self.assertFalse(kerberos.is_dns_name(value), value)

    def test_configuration_needs_no_dns(self):
        text = kerberos.config_text("firma.local", "dc01.firma.local")
        expected = (
            "default_realm = FIRMA.LOCAL",
            "dns_lookup_kdc = false",
            "rdns = false",
            "dns_canonicalize_hostname = false",
            "kdc = dc01.firma.local",
            ".firma.local = FIRMA.LOCAL",
        )
        for line in expected:
            self.assertIn(line, text)
        self.assertIn("MEMORY:", text)  # tickets never in a file

    def test_configuration_file_is_written_once(self):
        with mock.patch.dict(os.environ):
            path = kerberos.ensure_config("firma.local", "dc01.firma.local")
            self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
            self.assertEqual(os.environ["KRB5_CONFIG"], path)
            self.assertEqual(kerberos.ensure_config("firma.local", "dc01.firma.local"), path)
            with open(path, encoding="utf-8") as f:
                self.assertIn("FIRMA.LOCAL", f.read())

    def test_credential_errors_are_recognised(self):
        class Krb5Error(Exception):
            pass

        wrong = Exception("SpnegoError (1): Preauthentication failed -1765328360, Context: Unable to negotiate")
        self.assertEqual(kerberos.credential_error(wrong), "Passwort falsch")
        locked = Exception("x")
        locked.__cause__ = Krb5Error("Client's credentials have been revoked", -1765328366)
        self.assertEqual(kerberos.credential_error(locked), "Konto gesperrt oder deaktiviert")
        self.assertEqual(kerberos.credential_error(Exception("Server not found in Kerberos database -1765328377")), "")
        self.assertEqual(kerberos.credential_error(Exception("Cannot contact any KDC")), "")


class DecisionTests(unittest.TestCase):
    def _for(self, dc, user="anna@firma.local", available=True):
        with (
            mock.patch.object(kerberos, "available", return_value=available),
            mock.patch.object(kerberos, "ensure_config") as cfg,
            mock.patch.object(ldap_client, "load_json", return_value={"domain": "firma.local"}),
        ):
            return ldap_client._kerberos_for(dc, user), cfg

    def test_dns_name_gives_kerberos_with_the_configured_target(self):
        info, cfg = self._for("dc01.firma.local")
        self.assertEqual(info, {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"})
        cfg.assert_called_once_with("firma.local", "dc01.firma.local")

    def test_no_kerberos_for_an_ip_another_upn_suffix_or_without_libraries(self):
        self.assertIsNone(self._for("192.0.2.10")[0])
        self.assertIsNone(self._for("dc01.firma.local", user="anna@firma.de")[0])
        self.assertIsNone(self._for("dc01.firma.local", available=False)[0])


class StartTests(unittest.TestCase):
    """Kerberos first; NTLM only if Kerberos is not possible - never after a refused password."""

    KRB = {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"}

    def setUp(self):
        ldap_seal._kerberos_seen.clear()
        ldap_seal._kerberos_missing.clear()

    def _start(self, kerberos_error=None):
        used = []

        def context(user, password, hostname, protocol):
            used.append((protocol, user, hostname))
            if protocol == "kerberos" and kerberos_error:
                raise kerberos_error
            return mock.Mock(step=mock.Mock(return_value=b"token"))

        conn = mock.Mock(response=[])
        conn.search.return_value = False
        with mock.patch.object(ldap_seal, "_client_context", side_effect=context):
            result = ldap_seal._start(conn, "anna@firma.local", "x", "dc01.firma.local", self.KRB)
        return result[2], used

    def test_kerberos_first_with_the_configured_name(self):
        kind, used = self._start()
        self.assertEqual(kind, "kerberos")
        self.assertEqual(used, [("kerberos", "anna@FIRMA.LOCAL", "dc01.firma.local")])

    def test_wrong_password_is_never_tried_with_ntlm(self):
        from ldap3.core.exceptions import LDAPBindError

        with self.assertRaises(LDAPBindError):
            self._start(Exception("Preauthentication failed -1765328360"))

    def test_kerberos_not_possible_then_ntlm_and_remembered(self):
        with self.assertLogs("samonboarding", level="INFO"):
            kind, used = self._start(Exception("Cannot contact any KDC for realm"))
        self.assertEqual(kind, "ntlm")
        self.assertEqual([u[0] for u in used], ["kerberos", "ntlm"])
        kind, used = self._start(Exception("Cannot contact any KDC for realm"))
        self.assertEqual([u[0] for u in used], ["ntlm"])  # not tried again on every request

    def test_after_kerberos_worked_no_fallback_to_ntlm(self):
        self._start()
        with self.assertRaises(ldap_seal.SealError):
            self._start(Exception("Cannot contact any KDC for realm"))  # e.g. someone blocking port 88

    def test_only_one_mechanism_is_offered(self):
        try:
            import spnego  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("pyspnego fehlt")
        for protocol in ("kerberos", "ntlm"):
            self.assertEqual(ldap_seal._spnego_class(protocol).available_protocols(), [protocol, "negotiate"])


@unittest.skipUnless(os.environ.get("SAMONB_TEST_DC_NAME") and kerberos.available(), "kein Test-DC mit Kerberos")
class RealKerberosTests(unittest.TestCase):
    def test_kerberos_connection_can_set_a_password(self):
        import ldap3

        dc = os.environ["SAMONB_TEST_DC_NAME"]
        domain = os.environ.get("SAMONB_TEST_DOMAIN", "test.local")
        user = os.environ.get("SAMONB_TEST_USER", f"administrator@{domain}")
        target = os.environ.get("SAMONB_TEST_TARGET", "CN=anna,CN=Users,DC=test,DC=local")
        ldap_seal._kerberos_seen.clear()
        ldap_seal._kerberos_missing.clear()
        with (
            mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldap-sealed"]),
            mock.patch.object(ldap_client, "load_json", return_value={"domain": domain}),
            ldap_client.ldap_connection(dc, user, os.environ.get("SAMONB_TEST_PASSWORD", "")) as conn,
        ):
            self.assertEqual(ldap_client.transport_of(conn), "ldap-sealed-kerberos")
            new = f'"Krb{os.getpid()}Test!x"'
            ok = conn.modify(target, {"unicodePwd": [(ldap3.MODIFY_REPLACE, [new.encode("utf-16-le")])]})
            self.assertTrue(ok, conn.result)
        from ldap3.core.exceptions import LDAPBindError

        with (
            mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldap-sealed"]),
            mock.patch.object(ldap_client, "load_json", return_value={"domain": domain}),
            self.assertRaises(LDAPBindError),
            ldap_client.ldap_connection(dc, user, "falsch"),
        ):
            pass


if __name__ == "__main__":
    unittest.main()
