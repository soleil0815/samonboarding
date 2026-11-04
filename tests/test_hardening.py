"""Hardening from the security review: folder names on deletion, mail values, file permissions, Exchange, login role."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import exchange, fileshare, i18n, mailer, naming, permissions, storage  # noqa: E402


class FolderNameTests(unittest.TestCase):
    CFG = {"enabled": True, "roots": ["\\\\fs\\home$"], "useAdAttr": True}

    def test_name_matches_the_account(self):
        self.assertTrue(fileshare.name_matches_sam("Mueller", "mueller"))
        self.assertTrue(fileshare.name_matches_sam("mueller.V6", "mueller", ["V2", "V6"]))
        self.assertFalse(fileshare.name_matches_sam("mueller.V6", "mueller"))  # suffix only for profiles
        self.assertFalse(fileshare.name_matches_sam("max.mustermann", "max", ["V6"]))  # another account
        self.assertFalse(fileshare.name_matches_sam("mueller.alt", "mueller", ["V6"]))
        self.assertFalse(fileshare.name_matches_sam("muellerx", "mueller"))
        self.assertFalse(fileshare.name_matches_sam("chef", "mueller"))
        self.assertFalse(fileshare.name_matches_sam("chef", ""))

    def test_foreign_folder_in_attribute_is_skipped(self):
        targets = fileshare.build_targets("home", self.CFG, "mueller", "\\\\fs\\home$\\chef")
        attr = [t for t in targets if t["source"] == "AD-Attribut"][0]
        self.assertIn("passt nicht zum Benutzernamen", attr["skip"])
        other = fileshare.build_targets("home", self.CFG, "max", "\\\\fs\\home$\\max.mustermann")
        self.assertIn("passt nicht", [t for t in other if t["source"] == "AD-Attribut"][0]["skip"])
        profile = dict(self.CFG, roots=["\\\\fs\\prof$"], suffixes=["V6"])
        prof = fileshare.build_targets("profile", profile, "max", "\\\\fs\\prof$\\max.mustermann.V6")
        self.assertTrue(all(t["skip"] for t in prof if t["source"] == "AD-Attribut"))
        own = fileshare.build_targets("home", self.CFG, "mueller", "\\\\fs\\home$\\abteilung\\mueller")
        self.assertEqual([t for t in own if t["source"] == "AD-Attribut"][0]["skip"], "")


class MailValueTests(unittest.TestCase):
    def test_password_and_names_are_never_translated(self):
        token = i18n.set_lang("en")
        try:
            text, html = mailer.render_mail(
                "admin",
                "Passwort zurückgesetzt",
                "#000",
                "Intro",
                [
                    ("Neues Passwort:", "Passwort", "pwd"),
                    ("Mitarbeiter:", "Info", "bold"),
                    ("Änderung bei Login:", "Ja", ""),
                ],
            )
        finally:
            i18n.reset_lang(token)
        self.assertIn("New password: Passwort", text)
        self.assertIn("Info", text)
        self.assertIn("Yes", text)

    def test_sender_name_is_quoted_correctly(self):
        sent = {}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def ehlo(self):
                pass

            def has_extn(self, name):
                return False

            def send_message(self, msg, to_addrs):
                sent["from"] = msg["From"]

            def quit(self):
                pass

        cfg = {
            "displayName": "IT, Abteilung",
            "fromEmail": "it@x.de",
            "host": "h",
            "port": 25,
            "tlsMode": mailer.UNENCRYPTED,
        }
        with mock.patch.object(mailer.smtplib, "SMTP", FakeSMTP):
            mailer.smtp_send(cfg, "a@x.de", "Betreff", "Text")
        self.assertEqual(sent["from"], '"IT, Abteilung" <it@x.de>')


class FilePermissionTests(unittest.TestCase):
    def test_json_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "smtp_config.json")
            storage.save_json(path, {"password": "x"})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class ExchangeTests(unittest.TestCase):
    def test_basic_only_with_https(self):
        with self.assertRaisesRegex(ValueError, "nur mit HTTPS"):
            exchange.clean_config({"enabled": True, "server": "ex1", "auth": "basic", "ssl": False})
        self.assertEqual(exchange.clean_config({"enabled": True, "server": "ex1", "auth": "basic"})["auth"], "basic")


class InputTests(unittest.TestCase):
    def test_names_and_mail(self):
        self.assertTrue(naming.valid_person_name("Müller-Lüdenscheidt"))
        self.assertFalse(naming.valid_person_name("Eva\nAdmin"))
        self.assertFalse(naming.valid_person_name("x" * 65))
        self.assertTrue(naming.valid_mail("a.b@firma.de"))
        self.assertFalse(naming.valid_mail("a@b"))
        self.assertFalse(naming.valid_mail("a b@firma.de"))

    def test_dn_special_forms(self):
        from fastapi import HTTPException

        for dn in ("<GUID=1234>", " <SID=S-1-5-32-544>", ""):
            with self.assertRaises(HTTPException):
                permissions.reject_special_dn(dn)
        self.assertEqual(permissions.reject_special_dn(" CN=x,OU=y "), "CN=x,OU=y")


class RoleTests(unittest.TestCase):
    def test_role_only_via_sid(self):
        self.assertEqual(permissions.ADMIN_SIDS, {"S-1-5-32-544"})
        self.assertEqual(permissions.ADMIN_DOMAIN_RIDS, {512, 519})
        self.assertEqual(permissions._domain_rid("S-1-5-21-1-2-3-512"), 512)
        self.assertIsNone(permissions._domain_rid("S-1-5-32-544"))


class _Row:
    def __init__(self, dn, **attrs):
        self.dn, self.attrs = dn, attrs

    def text(self, name):
        return self.attrs.get(name, "")


class FindSelfTests(unittest.TestCase):
    """A login from a foreign domain must not count as the local account with the same name."""

    BASE = "DC=firma,DC=local"

    def run_find(self, bind_user, whoami=None, netbios="FIRMA"):
        searches = []

        def fake_search(conn, base, flt, attrs):
            searches.append(flt)
            if base.startswith("CN=Partitions"):
                return [_Row("CN=x", nETBIOSName=netbios)] if netbios else []
            if "sAMAccountName=administrator" in flt:
                return [_Row("CN=Administrator,CN=Users," + self.BASE, sAMAccountName="Administrator")]
            return []

        conn = mock.Mock()
        conn.extend.standard.who_am_i.return_value = whoami
        with mock.patch.object(permissions, "ldap_search", side_effect=fake_search):
            return permissions._find_self(conn, self.BASE, "administrator", bind_user), searches

    def test_own_domain(self):
        for bind in ("administrator@firma.local", "FIRMA\\administrator", "firma.local\\administrator"):
            row, _ = self.run_find(bind, whoami="u:FIRMA\\Administrator")
            self.assertIsNotNone(row, bind)

    def test_foreign_domain_is_not_mapped(self):
        for bind in ("administrator@fremd.tld", "FREMD\\administrator"):
            row, searches = self.run_find(bind)
            self.assertIsNone(row, bind)
            self.assertFalse(any("sAMAccountName=" in f for f in searches), bind)

    def test_whoami_contradicts(self):
        row, _ = self.run_find("administrator@firma.local", whoami="u:FREMD\\administrator")
        self.assertIsNone(row)
        row, _ = self.run_find("administrator@firma.local", whoami="u:FIRMA\\jemand")
        self.assertIsNone(row)

    def test_without_whoami_and_without_netbios(self):
        row, _ = self.run_find("administrator@firma.local", whoami=None, netbios="")
        self.assertIsNotNone(row)
        row, _ = self.run_find("administrator@firma.local", whoami="u:SAMDOM\\administrator", netbios="")
        self.assertIsNotNone(row)  # NetBIOS name unknown: only the account name counts (no lockout)


class ReviewFixTests(unittest.TestCase):
    def test_plan_only_once(self):
        from fastapi import HTTPException

        from samonboarding.routers import deletion

        user = {"sid": "s1"}
        token, _ = deletion.store_plan(user, "CN=a,DC=x", "a", [])
        self.assertEqual(deletion.consume_plan(token)["sam"], "a")
        with self.assertRaises(HTTPException) as ctx:
            deletion.consume_plan(token)  # second, concurrent request
        self.assertEqual(ctx.exception.status_code, 409)

    def test_delete_checks_role_live(self):
        from fastapi import HTTPException

        from samonboarding.routers import deletion

        user = {"sid": "s2", "password": "pw", "username": "admin", "bind_user": "admin@x"}

        class Ctx:
            def __enter__(self):
                return object()

            def __exit__(self, *a):
                return False

        with (
            mock.patch.object(deletion, "ad_session", return_value=Ctx()),
            mock.patch.object(deletion, "check_user_role", return_value=("Account Operator", None, "", "admin")),
            mock.patch.object(deletion, "audit"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                deletion.verify_admin_password(user, "pw")
            self.assertEqual(ctx.exception.status_code, 403)
        with (
            mock.patch.object(deletion, "ad_session", return_value=Ctx()),
            mock.patch.object(deletion, "check_user_role", return_value=("Administrator", None, "", "admin")),
        ):
            deletion.verify_admin_password(user, "pw")

    def test_session_has_maximum_lifetime(self):
        from fastapi import HTTPException

        from samonboarding import sessions

        token = sessions.create_session({"username": "x"})
        sessions.active_sessions[token]["created"] -= sessions.SESSION_MAX_SECONDS + 1
        with self.assertRaises(HTTPException):
            sessions.get_current_user(token)
        self.assertIsNone(sessions.peek_session(token))

    def test_data_access_report_whole_word_only(self):
        from samonboarding import reports

        word = reports._mention_re("max")
        for text in ("max", "MAX@firma.local", "\\\\fs\\home$\\max", "max.V6", '"sam": "max"'):
            self.assertTrue(word.search(text), text)
        for text in ("maximilian", "max.mustermann", "a.max", "max-2"):
            self.assertFalse(word.search(text), text)

    def test_smtp_auto_without_starttls_sends_no_password(self):
        import smtplib

        server = mock.Mock()
        server.has_extn.return_value = False
        cfg = {"host": "h", "port": 587, "tlsMode": "Auto", "username": "u", "password": "p", "fromEmail": "a@b.c"}
        with mock.patch.object(smtplib, "SMTP", return_value=server), self.assertRaises(smtplib.SMTPException):
            mailer.smtp_send(cfg, "x@y.z", "s", "t")
        server.login.assert_not_called()
        server.send_message.assert_not_called()


class Review3Tests(unittest.TestCase):
    def test_dc_hiccup_is_not_role_loss(self):
        from fastapi import HTTPException

        from samonboarding.routers import deletion

        class Ctx:
            def __enter__(self):
                return object()

            def __exit__(self, *a):
                return False

        audits = []
        user = {"sid": "s9", "password": "pw", "username": "admin", "bind_user": "admin@x"}
        with (
            mock.patch.object(deletion, "ad_session", return_value=Ctx()),
            mock.patch.object(deletion, "check_user_role", side_effect=permissions.RoleCheckError("busy")),
            mock.patch.object(deletion, "audit", side_effect=lambda *a, **k: audits.append(a)),
        ):
            with self.assertRaises(HTTPException) as ctx:
                deletion.verify_admin_password(user, "pw", action="reports-delete")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(audits, [])  # no false "role-lost" entry
        with mock.patch.object(deletion, "audit", side_effect=lambda *a, **k: audits.append(a)):
            with self.assertRaises(HTTPException):
                deletion.verify_admin_password(dict(user, sid="s10"), "falsch", action="reports-delete")
        self.assertEqual(audits[-1][1], "reports-delete-password-fail")

    def test_netbios_via_rootdse_and_whoami_as_bytes(self):
        conn = mock.Mock()
        conn.search.return_value = True
        conn.response = [{"attributes": {"configurationNamingContext": ["CN=Configuration,DC=firma,DC=de"]}}]
        self.assertEqual(permissions._configuration_nc(conn, "DC=ad,DC=firma,DC=de"), "CN=Configuration,DC=firma,DC=de")
        conn.extend.standard.who_am_i.return_value = b"u:FIRMA\\max"
        self.assertEqual(permissions._whoami(conn), ("firma", "max"))
        conn.extend.standard.who_am_i.return_value = "irgendwas"
        self.assertEqual(permissions._whoami(conn), (None, None))

    def test_data_access_report_finds_dn_entries_and_umlauts(self):
        from samonboarding import config, reports

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(config, "REPORTS_DB_FILE", os.path.join(tmp, "r.db")),
        ):
            dn = "CN=Max Müller,OU=A,DC=x"
            reports.write_audit("admin", "pwdreset", dn, details={"sam": "MÜLLER"})
            reports.write_audit("admin", "move-user", dn, details={"targetOu": "OU=B"})  # only the DN
            reports.write_audit("admin", "pwdreset", "CN=Erika Müller,OU=A,DC=x", details={"sam": "emueller"})
            reports.write_log("WARNING", "x", f"Fehler bei {dn}")
            found = [e["action"] for e in reports.audit_for_account("müller")]
            self.assertEqual(found, ["pwdreset", "move-user"])  # Erika Müller (another person) not included
            self.assertEqual(len(reports.log_for_account("müller")), 1)

    def test_protection_without_tokengroups_via_nested_groups(self):
        from samonboarding import protection

        class Conn:
            def __init__(self):
                self.calls = 0
                self.result = {"result": 0}

            def search(self, base, flt, scope, attributes=None):
                self.calls += 1
                if self.calls == 1:  # the account itself: without tokenGroups and adminCount
                    self.response = [{"type": "searchResEntry", "dn": "CN=x", "attributes": {}, "raw_attributes": {}}]
                else:  # nested groups: Domain Admins
                    self.response = [
                        {
                            "type": "searchResEntry",
                            "dn": "CN=Domain Admins",
                            "attributes": {"objectSid": ["S-1-5-21-1-2-3-512"]},
                            "raw_attributes": {},
                        }
                    ]
                return True

        with self.assertLogs("samonboarding.protection", "WARNING"):
            reason = protection.privileged_reason(Conn(), "CN=x,OU=A,DC=x")
        self.assertIn("Mitglied", reason)

    def test_smtp_auto_without_starttls_sends_nothing(self):
        import smtplib

        server = mock.Mock()
        server.has_extn.return_value = False
        cfg = {"host": "h", "port": 25, "tlsMode": "Auto", "fromEmail": "a@b.c"}
        with mock.patch.object(smtplib, "SMTP", return_value=server):
            with self.assertRaises(smtplib.SMTPException):
                mailer.smtp_send(cfg, "x@y.z", "s", "t")
            server.send_message.assert_not_called()
            # deliberately unencrypted (internal relay): send yes, password never
            mailer.smtp_send(dict(cfg, tlsMode=mailer.UNENCRYPTED), "x@y.z", "s", "t")
            server.send_message.assert_called_once()
            with self.assertRaises(smtplib.SMTPException):
                mailer.smtp_send(dict(cfg, tlsMode=mailer.UNENCRYPTED, username="u", password="p"), "x@y.z", "s", "t")
        server.login.assert_not_called()


class Review4Tests(unittest.TestCase):
    def _row(self, dn, **attrs):
        row = mock.Mock()
        row.dn = dn
        row.text = lambda name: attrs.get(name, "")
        return row

    def test_folder_of_another_account_is_not_deleted(self):
        from samonboarding.routers import deletion

        own = "CN=Alt,OU=Disabled,DC=x"
        rows = [
            self._row(own, sAMAccountName="aalt", homeDirectory="\\\\fs1\\home$\\aalt"),
            # a new employee got the old folder - different server name, trailing separator, upper case
            self._row("CN=Neu,OU=A,DC=x", sAMAccountName="bneu", homeDirectory="\\\\FS1.firma.local\\HOME$\\Aalt\\"),
        ]
        with mock.patch.object(deletion, "ldap_search", return_value=rows) as search:
            others = deletion._others_using(None, "DC=x", "homeDirectory", "\\\\fs1\\home$\\aalt", own, "home")
        self.assertEqual(others, ["bneu"])
        self.assertIn("\\5caalt", search.call_args[0][2])  # backslash escaped in the filter
        prof = [self._row("CN=Neu,OU=A,DC=x", sAMAccountName="bneu", profilePath="\\\\fs1\\profiles$\\aalt")]
        with mock.patch.object(deletion, "ldap_search", return_value=prof):
            self.assertEqual(
                deletion._others_using(None, "DC=x", "profilePath", "\\\\fs1\\profiles$\\aalt.V6", own, "profile"),
                ["bneu"],
            )
        fremd = [self._row("CN=X,OU=A,DC=x", sAMAccountName="x", homeDirectory="\\\\fs1\\home$\\abteilung\\aalt")]
        with mock.patch.object(deletion, "ldap_search", return_value=fremd):
            self.assertEqual(
                deletion._others_using(None, "DC=x", "homeDirectory", "\\\\fs1\\home$\\aalt", own, "home"), []
            )

    def test_ldap_error_is_not_empty(self):
        from ldap3.core.exceptions import LDAPOperationResult

        from samonboarding import ldap_client

        conn = mock.Mock()
        conn.extend.standard.paged_search.return_value = iter([])
        conn.result = {"result": 51, "description": "busy", "message": ""}
        with self.assertRaises(LDAPOperationResult):
            ldap_client.ldap_search(conn, "OU=A,DC=x", "(objectClass=user)", ["cn"])
        conn.result = {"result": 0}
        conn.extend.standard.paged_search.return_value = iter([])
        self.assertEqual(ldap_client.ldap_search(conn, "OU=A,DC=x", "(objectClass=user)", ["cn"]), [])

    def test_ou_check_with_comma_in_name(self):
        from samonboarding.dn import dn_is_within

        self.assertFalse(dn_is_within("CN=Max\\,OU=Staff,OU=Firma,DC=x", "OU=Staff,OU=Firma,DC=x"))
        self.assertTrue(dn_is_within("CN=Max\\,Muster,OU=Staff,OU=Firma,DC=x", "OU=Staff,OU=Firma,DC=x"))

    def test_nested_admin_group_is_privileged(self):
        from samonboarding import protection

        class Conn:
            result = {"result": 0}

            def search(self, base, flt, scope, attributes=None):
                if scope == protection.ldap3.BASE:  # the group itself: ordinary SID
                    self.response = [
                        {
                            "type": "searchResEntry",
                            "attributes": {"objectSid": ["S-1-5-21-1-2-3-1500"]},
                            "raw_attributes": {},
                        }
                    ]
                else:  # parent groups: Domain Admins
                    self.response = [
                        {
                            "type": "searchResEntry",
                            "attributes": {"objectSid": ["S-1-5-21-1-2-3-512"]},
                            "raw_attributes": {},
                        }
                    ]
                return True

        self.assertIn("Domänen-Admins", protection.privileged_group(Conn(), "CN=IT-Admins,OU=G,DC=x"))


class Review5Tests(unittest.TestCase):
    def test_login_error_without_internals(self):
        from samonboarding.routers import auth

        self.assertIn("gesperrt", auth.bind_error_message("invalidCredentials: 80090308: LdapErr: data 775, v4563"))
        self.assertIn("abgelaufen", auth.bind_error_message("... data 532, ..."))
        with self.assertLogs("samonboarding.routers.auth", "WARNING"):
            msg = auth.bind_error_message("socket 10.0.0.5:636 strange internal error")
        self.assertNotIn("10.0.0.5", msg)

    def test_username_without_trailing_dot_and_nordic_letters(self):
        self.assertEqual(
            naming.sanitize_sam(naming.apply_macro("%FIRSTNAME%.%LASTNAME%", "Maximilian-Alexander", "Müller")),
            "MAXIMILIANALEXANDER",
        )
        self.assertEqual(naming.remove_umlauts("Ærø Łukasz"), "AEROELUKASZ")

    def test_username_placeholder_in_upper_case(self):
        src = (Path(_paths.ROOT) / "samonboarding" / "routers" / "onboarding.py").read_text(encoding="utf-8")
        self.assertIn('re.sub(r"%username%", lambda _m: sam, str(val), flags=re.IGNORECASE)', src)


if __name__ == "__main__":
    unittest.main()
