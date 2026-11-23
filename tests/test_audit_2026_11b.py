"""Code audit 2026-11 (second, full audit at 2.7.0): regression tests for the confirmed findings."""

import os
import sys
import unittest
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

import contextlib  # noqa: E402
import time  # noqa: E402

from fastapi import HTTPException  # noqa: E402

from samonboarding import ldap_client, permissions, sessions  # noqa: E402
from samonboarding.routers import deletion  # noqa: E402

OWN = "CN=Anna,OU=Disabled,DC=firma,DC=local"


def _row(dn, **attrs):
    row = mock.Mock()
    row.dn = dn
    row.text = lambda name: attrs.get(name, "")
    return row


def _search(rows_by_needle):
    """Fake ldap_search: returns the rows whose needle occurs in the filter."""

    def search(conn, base, flt, attrs):
        return [row for needle, rows in rows_by_needle.items() if needle in flt for row in rows]

    return search


class OtherAccountsTests(unittest.TestCase):
    """Deletion must never pick a folder that belongs to another account - for every storage location."""

    ROOT = {"enabled": True, "roots": ["\\\\fs01\\users$"], "useAdAttr": True, "suffixes": []}

    def test_folder_redirection_is_compared_with_other_accounts(self):
        cfg = {"profile": {"enabled": False}, "folderRedirection": dict(self.ROOT), "home": {"enabled": False}}
        entry = _row(OWN)
        other = _row("CN=B,OU=Staff,DC=firma,DC=local", sAMAccountName="bneu", homeDirectory="\\\\fs01\\users$\\anna")
        with mock.patch.object(deletion, "ldap_search", side_effect=_search({"homeDirectory": [other]})):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        self.assertEqual([t for t in targets if t["path"] and not t["skip"]], [])
        self.assertIn("bneu", targets[0]["skip"])

    def test_profile_path_inside_a_home_folder_is_noticed(self):
        cfg = {"profile": {"enabled": False}, "folderRedirection": {"enabled": False}, "home": dict(self.ROOT)}
        entry = _row(OWN)
        other = _row("CN=C,OU=Staff,DC=firma,DC=local", sAMAccountName="cc", profilePath="\\\\fs01\\users$\\anna\\cc")
        with mock.patch.object(deletion, "ldap_search", side_effect=_search({"profilePath": [other]})):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        self.assertEqual([t for t in targets if t["path"] and not t["skip"]], [])

    def test_folder_inside_another_accounts_base_folder_is_kept(self):
        """homeDirectory \\\\fs01\\users$\\chef\\anna: 'chef' uses its base-path folder without any AD attribute."""
        cfg = {"profile": {"enabled": False}, "folderRedirection": {"enabled": False}, "home": dict(self.ROOT)}
        entry = _row(OWN, homeDirectory="\\\\fs01\\users$\\chef\\anna")
        chef = _row("CN=Chef,OU=Staff,DC=firma,DC=local", sAMAccountName="chef")
        with mock.patch.object(deletion, "ldap_search", side_effect=_search({"(sAMAccountName=chef)": [chef]})):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        attr = [t for t in targets if t["source"] == "AD-Attribut"][0]
        self.assertIn("chef", attr["skip"])

    def test_department_folder_without_account_stays_allowed(self):
        cfg = {"profile": {"enabled": False}, "folderRedirection": {"enabled": False}, "home": dict(self.ROOT)}
        entry = _row(OWN, homeDirectory="\\\\fs01\\users$\\abteilung\\anna")
        with mock.patch.object(deletion, "ldap_search", side_effect=_search({})):
            targets = deletion.plan_targets(None, cfg, entry, "anna", "DC=x")
        attr = [t for t in targets if t["source"] == "AD-Attribut"][0]
        self.assertEqual(attr["skip"], "")


class SimulationTests(unittest.TestCase):
    def test_takeover_folder_does_not_count_as_missing(self):
        cfg = {"profile": {"enabled": False}, "folderRedirection": {"enabled": False}, "home": {"enabled": True}}
        results = [{"kind": "home", "status": "takeover"}]
        self.assertEqual(deletion._missing_warnings(cfg, results, "anna"), [])


class LdapFallbackTests(unittest.TestCase):
    """With LDAP_CA_FILE the connection must never fall back to clear text (389)."""

    def _ports(self, error_text, ca_file):
        from ldap3.core.exceptions import LDAPSocketOpenError

        ports = []

        def server(host, port, **kwargs):
            ports.append(port)
            return mock.Mock(port=port)

        def connection(srv, **kwargs):
            if srv.port == 636:
                raise LDAPSocketOpenError("unable to open socket", [(error_text,)])
            return mock.Mock()

        with (
            mock.patch.object(ldap_client, "LDAP_ALLOW_PLAIN", True),
            mock.patch.object(ldap_client, "LDAP_CA_FILE", ca_file),
            mock.patch.object(ldap_client.ldap3, "Tls"),
            mock.patch.object(ldap_client.ldap3, "Server", side_effect=server),
            mock.patch.object(ldap_client.ldap3, "Connection", side_effect=connection),
            self.assertLogs("samonboarding", level="WARNING"),
        ):
            try:
                with ldap_client.ldap_connection("dc01.firma.local", "admin@firma.local", "x"):
                    pass
            except ldap_client.DcUnreachable:
                pass
        return ports

    def test_reset_connection_with_ca_file_stays_encrypted(self):
        self.assertEqual(self._ports("[Errno 104] Connection reset by peer", "/data/ca.pem"), [636])

    def test_hostname_mismatch_counts_as_rejected_certificate(self):
        text = "socket ssl wrapping error: certificate {...} doesn't match any name in ['dc01.firma.local']"
        self.assertTrue(ldap_client._certificate_rejected(Exception(text)))

    def test_without_ca_file_the_emergency_fallback_remains(self):
        self.assertEqual(self._ports("[Errno 111] Connection refused", ""), [636, 389])


class AdminRoleRecheckTests(unittest.TestCase):
    """An admin removed from Domain Admins must lose the admin routes within minutes, not after 12 hours."""

    def _session(self, age):
        token = sessions.create_session({"username": "admin", "bind_user": "admin@firma.local", "password": "x"})
        user = sessions.active_sessions[token]
        user["role"] = "Administrator"
        user["created"] = time.time() - age
        self.addCleanup(sessions.drop_session, token)
        return token, user

    def _check(self, user, role):
        calls = []

        @contextlib.contextmanager
        def ad_session(u):
            calls.append(u["username"])
            yield object()

        with (
            mock.patch.object(ldap_client, "ad_session", ad_session),
            mock.patch.object(permissions, "check_user_role", return_value=(role, "", "", "")),
        ):
            permissions.require_admin(user, "nur Admins")
        return calls

    def test_role_lost_in_ad_ends_the_session(self):
        token, user = self._session(age=permissions.ROLE_RECHECK_SECONDS + 5)
        with self.assertRaises(HTTPException) as ctx:
            self._check(user, "Account Operator")
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertNotIn(token, sessions.active_sessions)

    def test_recent_check_does_not_contact_the_dc(self):
        _, user = self._session(age=10)
        self.assertEqual(self._check(user, "Account Operator"), [])

    def test_unreachable_dc_keeps_pages_without_dc_usable(self):
        token, user = self._session(age=permissions.ROLE_RECHECK_SECONDS + 5)

        @contextlib.contextmanager
        def down(u):
            raise ldap_client.DcUnreachable("Domain Controller nicht erreichbar.")
            yield  # pragma: no cover

        with mock.patch.object(ldap_client, "ad_session", down):
            permissions.require_admin(user, "nur Admins")  # no error, no waiting on every request
        self.assertIn(token, sessions.active_sessions)
        self.assertLess(time.time() - user["roleChecked"], permissions.ROLE_RECHECK_SECONDS)

    def test_role_check_error_is_refused(self):
        _, user = self._session(age=permissions.ROLE_RECHECK_SECONDS + 5)

        @contextlib.contextmanager
        def ad_session(u):
            yield object()

        with (
            mock.patch.object(ldap_client, "ad_session", ad_session),
            mock.patch.object(permissions, "check_user_role", side_effect=permissions.RoleCheckError("x")),
            self.assertRaises(HTTPException) as ctx,
        ):
            permissions.require_admin(user, "nur Admins")
        self.assertEqual(ctx.exception.status_code, 503)

    def test_still_admin_is_rechecked_only_after_the_interval(self):
        _, user = self._session(age=permissions.ROLE_RECHECK_SECONDS + 5)
        self.assertEqual(self._check(user, "Administrator"), ["admin"])
        self.assertEqual(self._check(user, "Administrator"), [])


class ExchangeBasicTests(unittest.TestCase):
    """'basic' sends the admin's own password - never to a server whose certificate is not checked."""

    RAW = {"enabled": True, "server": "ex01.firma.local", "auth": "basic", "ssl": True, "verifyCert": False}

    def test_saving_basic_without_certificate_check_is_refused(self):
        from samonboarding import exchange

        with self.assertRaises(ValueError):
            exchange.clean_config(dict(self.RAW), strict=True)
        self.assertEqual(exchange.clean_config(dict(self.RAW))["auth"], "basic")  # an old file stays readable

    def test_old_settings_file_never_sends_the_password(self):
        from samonboarding import exchange

        cfg = exchange.clean_config(dict(self.RAW))
        with (
            self.assertRaises(exchange.ExchangeError) as ctx,
            exchange._open_session(cfg, {"bind_user": "a", "password": "x"}),
        ):
            pass
        self.assertIn("geprüftem Zertifikat", str(ctx.exception))  # refused before any connection


class AnonymizeTests(unittest.TestCase):
    def test_user_after_known_netbios_name_is_replaced(self):
        from samonboarding.anonymize import Anonymizer

        anon = Anonymizer()
        anon.learn("domain", "firma.local")
        out = anon.text("Anmeldung FIRMA\\kschmidt fehlgeschlagen")
        self.assertNotIn("kschmidt", out)
        self.assertNotIn("FIRMA", out)

    def test_account_names_from_audit_details_are_learned(self):
        from samonboarding import diagnose
        from samonboarding.anonymize import Anonymizer

        anon = Anonymizer()
        diagnose._learn_details(anon, '{"accounts": ["aberg", "kmueller"], "sam": "jdoe", "name": "Jana Doe"}')
        out = anon.text("Sammellöschung: Fehler bei aberg; Eintrag fuer kmueller und jdoe (Jana Doe)")
        for name in ("aberg", "kmueller", "jdoe", "Jana Doe"):
            self.assertNotIn(name, out)
        diagnose._learn_details(anon, "kein json")  # broken details never stop the package


class PasswordConfirmRaceTests(unittest.TestCase):
    """Parallel guesses must each count: the attempt is recorded before the password is compared."""

    def test_attempt_counts_before_the_comparison(self):
        user = {"sid": "race-test", "password": "richtig", "username": "admin"}
        self.addCleanup(deletion._pw_failures.pop, "race-test", None)
        seen = []
        real = deletion.hmac.compare_digest

        def compare(a, b):
            seen.append(len(deletion._pw_failures.get("race-test", [])))
            return real(a, b)

        with (
            mock.patch.object(deletion.hmac, "compare_digest", side_effect=compare),
            mock.patch.object(deletion, "audit"),
        ):
            with self.assertRaises(HTTPException):
                deletion.verify_admin_password(user, "falsch")
        self.assertEqual(seen, [1])
        self.assertEqual(len(deletion._pw_failures["race-test"]), 1)  # counted once, not twice


class SecurityHeaderTests(unittest.TestCase):
    def test_cross_origin_resource_policy(self):
        try:
            from fastapi.applications import FastAPI  # noqa: F401 - real package needed
            from starlette.types import ASGIApp  # noqa: F401
        except ImportError:
            self.skipTest("nur mit den echten Paketen")
        import asyncio

        sys.path.insert(0, _paths.TESTS)
        import smoke_app

        from samonboarding.main import app

        _status, headers, _body = asyncio.run(smoke_app.call(app, "/api/public-config"))
        self.assertEqual(headers.get("cross-origin-resource-policy"), "same-origin")


class OffboardRecordTests(unittest.TestCase):
    """Offboarding an account a second time must not overwrite the entry with its real previous OU and groups."""

    def setUp(self):
        import tempfile

        from samonboarding import config

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "OFFBOARD_DB_FILE", os.path.join(tmp.name, "offboarding.db"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _record(self, dn, ou, groups):
        from samonboarding import offboard_store

        return offboard_store.record(
            user_guid="g-1", sam="anna", name="Anna", original_dn=dn, original_ou=ou, was_enabled=True,
            groups=groups, actor="admin",
        )  # fmt: skip

    def test_second_offboarding_from_the_same_place_keeps_the_entry(self):
        from samonboarding import offboard_store

        first = self._record("CN=Anna,OU=Staff,DC=f", "OU=Staff,DC=f", [{"dn": "CN=VPN,DC=f"}])
        offboard_store.update_current_dn(first, "CN=Anna,OU=Disabled,OU=Staff,DC=f")
        again, created = offboard_store.record_entry(
            user_guid="g-1", sam="anna", name="Anna", original_dn="CN=Anna, OU=Disabled,OU=Staff,DC=f",
            original_ou="OU=Disabled,OU=Staff,DC=f", was_enabled=False, groups=[], actor="admin",
        )  # fmt: skip
        self.assertFalse(created)  # a failed offboarding must not remove the kept entry
        rec = offboard_store.get(again)
        self.assertEqual((again, rec["original_ou"], len(rec["groups"])), (first, "OU=Staff,DC=f", 1))

    def test_account_brought_back_elsewhere_gets_a_new_entry(self):
        from samonboarding import offboard_store

        first = self._record("CN=Anna,OU=Staff,DC=f", "OU=Staff,DC=f", [])
        offboard_store.update_current_dn(first, "CN=Anna,OU=Archive,DC=f")
        again = self._record("CN=Anna,OU=Sales,DC=f", "OU=Sales,DC=f", [])  # moved back by hand, then offboarded
        self.assertNotEqual(again, first)
        self.assertIsNone(offboard_store.get(first))

    def test_partial_deletion_is_remembered(self):
        from samonboarding import offboard_store

        rid = self._record("CN=Anna,OU=Staff,DC=f", "OU=Staff,DC=f", [])
        offboard_store.update_current_dn(rid, "CN=Anna,OU=Archive,DC=f")
        results = [
            {"path": "\\\\fs\\home$\\anna", "status": "failed", "files": 3, "dirs": 0},
            {"path": "\\\\fs\\p$\\anna", "status": "missing", "files": 0, "dirs": 0},
        ]
        deletion._remember_deleted_folders("anna", "CN=Anna,OU=Archive,DC=f", results)
        self.assertEqual(offboard_store.get(rid)["folders_deleted"]["paths"], ["\\\\fs\\home$\\anna"])


class DashboardTests(unittest.TestCase):
    def test_new_accounts_are_not_inactive(self):
        from samonboarding.routers import dashboard

        now = 1_795_000_000
        flt = dashboard.inactive_filter(now)
        self.assertIn(f"(whenCreated<={dashboard.generalized_time(now - 90 * 86400)})", flt)
        self.assertEqual(dashboard.generalized_time(0), "19700101000000.0Z")


class TemplateMacroTests(unittest.TestCase):
    def test_macro_without_placeholder_is_refused(self):
        from samonboarding.routers import templates

        with self.assertRaises(HTTPException) as ctx:
            templates.sanitize_template({"name": "Std", "naming": "vorname.nachname"})
        self.assertEqual(ctx.exception.status_code, 400)
        ok = templates.sanitize_template({"name": "Std", "naming": "%FIRSTNAME%.%LASTNAME%"})
        self.assertEqual(ok["naming"], "%FIRSTNAME%.%LASTNAME%")


if __name__ == "__main__":
    unittest.main()
