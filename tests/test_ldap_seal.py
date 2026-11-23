"""Encrypted LDAP on port 389 without a certificate (NTLM/Kerberos sign and seal): framing, bind rounds, the order of
the connection attempts. With SAMONB_TEST_DC=<host> (and SAMONB_TEST_USER / SAMONB_TEST_PASSWORD) also against a
real domain controller - CI has none, so that test is skipped there."""

import os
import struct
import sys
import unittest
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import ldap_client, ldap_seal  # noqa: E402


class FakeCtx:
    """Stand-in for a pyspnego context: 'encrypts' by reversing and prefixing a marker."""

    def __init__(self, rounds=2, confidential=True):
        self.complete = False
        self.rounds = rounds
        self.steps = []
        self.confidential = confidential

    def step(self, token=None):
        self.steps.append(token)
        if len(self.steps) >= self.rounds:
            self.complete = True
        return b"token-%d" % len(self.steps)

    @property
    def context_attr(self):
        import spnego

        return spnego.ContextReq.confidentiality if self.confidential else spnego.ContextReq.integrity

    def wrap(self, data, encrypt=True):
        return mock.Mock(data=b"SEAL" + bytes(reversed(data)))

    def unwrap(self, data):
        if not data.startswith(b"SEAL"):
            raise ValueError("bad signature")
        return mock.Mock(data=bytes(reversed(data[4:])))


class RawSocket:
    def __init__(self, incoming=b"", chunk=3):
        self.incoming, self.chunk, self.sent = incoming, chunk, b""

    def recv(self, n):
        out, self.incoming = self.incoming[: min(n, self.chunk)], self.incoming[min(n, self.chunk) :]
        return out

    def sendall(self, data):
        self.sent += data


def frame(ctx, plain):
    wrapped = ctx.wrap(plain).data
    return struct.pack(">I", len(wrapped)) + wrapped


class SealedSocketTests(unittest.TestCase):
    def test_messages_are_sent_encrypted_with_length(self):
        raw, ctx = RawSocket(), FakeCtx()
        ldap_seal.SealedSocket(raw, ctx).sendall(b"\x30\x05hello")
        self.assertEqual(raw.sent, frame(ctx, b"\x30\x05hello"))
        self.assertNotIn(b"hello", raw.sent)  # never in clear text

    def test_frames_split_over_tcp_packets_are_joined(self):
        ctx = FakeCtx()
        raw = RawSocket(frame(ctx, b"first-message") + frame(ctx, b"second"), chunk=3)
        sock = ldap_seal.SealedSocket(raw, ctx)
        got = b""
        while len(got) < len(b"first-messagesecond"):
            got += sock.recv(4)
        self.assertEqual(got, b"first-messagesecond")

    def test_a_message_that_cannot_be_decrypted_is_never_passed_on(self):
        raw = RawSocket(struct.pack(">I", 6) + b"PLAIN!")
        with self.assertRaises(OSError):
            ldap_seal.SealedSocket(raw, FakeCtx()).recv(100)

    def test_absurd_length_is_refused(self):
        raw = RawSocket(struct.pack(">I", ldap_seal.MAX_FRAME + 1))
        with self.assertRaises(OSError):
            ldap_seal.SealedSocket(raw, FakeCtx()).recv(100)

    def test_closed_connection(self):
        with self.assertRaises(OSError):
            ldap_seal.SealedSocket(RawSocket(b"\x00\x00"), FakeCtx()).recv(10)


class BindTests(unittest.TestCase):
    def _bind(self, results, ctx=None):
        ctx = ctx or FakeCtx()
        conn = mock.Mock(response=[], socket=RawSocket())
        conn.search.return_value = False
        sent = []

        def negotiate(c, payload):
            sent.append(payload)
            return results.pop(0)

        with (
            mock.patch.object(ldap_seal, "_client_context", return_value=ctx),
            mock.patch.object(ldap_seal, "_negotiate", side_effect=negotiate),
        ):
            ldap_seal.sealed_bind(conn, "admin@firma.local", "x", "192.0.2.10")
        return conn, sent

    def test_two_rounds_then_everything_is_sealed(self):
        conn, sent = self._bind([{"result": 14, "saslCreds": b"challenge"}, {"result": 0, "saslCreds": b""}])
        self.assertEqual(sent, [b"token-1", b"token-2"])
        self.assertIsInstance(conn.socket, ldap_seal.SealedSocket)
        self.assertTrue(conn.bound)
        self.assertEqual(conn.sob_transport, "ldap-sealed-ntlm")
        self.assertFalse(conn.sasl_in_progress)

    def test_wrong_password_is_a_bind_error_like_a_simple_bind(self):
        from ldap3.core.exceptions import LDAPBindError

        with self.assertRaises(LDAPBindError):
            self._bind([{"result": 14, "saslCreds": b"c"}, {"result": 49, "description": "invalidCredentials"}])

    def test_refused_mechanism_is_a_connection_problem(self):
        with self.assertRaises(ldap_seal.SealError):
            self._bind([{"result": 7, "description": "authMethodNotSupported"}])

    def test_never_continues_without_encryption(self):
        ctx = FakeCtx(confidential=False)
        with self.assertRaises(ldap_seal.SealError):
            self._bind([{"result": 14, "saslCreds": b"c"}, {"result": 0, "saslCreds": b""}], ctx)


class AttemptOrderTests(unittest.TestCase):
    def setUp(self):
        # module state of ldap_client (LDAPS just failed / last connection) must not leak between tests
        ldap_client._ldaps_missing.clear()
        ldap_client.last_transport.update(kind="", dc="")

    def _attempts(self, ca, sasl, plain):
        with (
            mock.patch.object(ldap_client, "LDAP_CA_FILE", ca),
            mock.patch.object(ldap_client, "LDAP_SASL_ENCRYPTION", sasl),
            mock.patch.object(ldap_client, "LDAP_ALLOW_PLAIN", plain),
        ):
            return ldap_client._connection_attempts()

    def test_without_certificate_check_encrypted_389_follows_ldaps(self):
        self.assertEqual(self._attempts("", True, False), ["ldaps", "ldap-sealed"])
        self.assertEqual(self._attempts("", True, True), ["ldaps", "ldap-sealed", "ldap-plain"])
        self.assertEqual(self._attempts("", False, False), ["ldaps"])

    def test_with_ca_file_there_is_never_a_fallback(self):
        self.assertEqual(self._attempts("/data/ca.pem", True, True), ["ldaps"])

    def test_dc_without_certificate_uses_the_encrypted_connection(self):
        from ldap3.core.exceptions import LDAPCommunicationError

        sealed = mock.Mock(sob_transport="ldap-sealed-ntlm")
        calls = []

        def fake_open(dc, user, password, kind):
            calls.append(kind)
            if kind == "ldaps":
                raise LDAPCommunicationError("socket ssl wrapping error: [Errno 104] Connection reset by peer")
            return sealed

        with (
            mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldaps", "ldap-sealed"]),
            mock.patch.object(ldap_client, "_open", side_effect=fake_open),
            self.assertLogs("samonboarding", level="INFO"),
            ldap_client.ldap_connection("192.0.2.10", "admin@firma.local", "x") as conn,
        ):
            self.assertIs(conn, sealed)
        self.assertEqual(calls, ["ldaps", "ldap-sealed"])
        self.assertEqual(ldap_client.last_transport["kind"], "ldap-sealed-ntlm")

    def test_wrong_password_on_the_encrypted_connection_is_not_retried(self):
        from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError

        calls = []

        def fake_open(dc, user, password, kind):
            calls.append(kind)
            if kind == "ldaps":
                raise LDAPCommunicationError("connection reset")
            raise LDAPBindError("automatic bind not successful - invalidCredentials")

        with (
            mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldaps", "ldap-sealed", "ldap-plain"]),
            mock.patch.object(ldap_client, "_open", side_effect=fake_open),
            self.assertLogs("samonboarding", level="WARNING"),
            self.assertRaises(LDAPBindError),
            ldap_client.ldap_connection("192.0.2.10", "admin@firma.local", "x"),
        ):
            pass
        self.assertEqual(calls, ["ldaps", "ldap-sealed"])  # a typo counts once towards the lockout


class LdapsMemoryTests(unittest.TestCase):
    """Without a certificate on the DC not every request waits for the failing LDAPS handshake first."""

    def setUp(self):
        ldap_client._ldaps_missing.clear()
        ldap_client.last_transport.update(kind="", dc="")

    def _connect(self, sealed_ok=True):
        from ldap3.core.exceptions import LDAPCommunicationError

        calls = []

        def fake_open(dc, user, password, kind):
            calls.append(kind)
            if kind == "ldaps" or not sealed_ok:
                raise LDAPCommunicationError("connection reset")
            return mock.Mock(sob_transport="ldap-sealed-ntlm")

        with (
            mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldaps", "ldap-sealed"]),
            mock.patch.object(ldap_client, "_open", side_effect=fake_open),
        ):
            try:
                with ldap_client.ldap_connection("192.0.2.10", "admin@firma.local", "x"):
                    pass
            except ldap_client.DcUnreachable:
                pass
        return calls

    def test_ldaps_is_skipped_for_a_while_once_it_is_missing(self):
        with self.assertLogs("samonboarding", level="INFO") as logs:
            self.assertEqual(self._connect(), ["ldaps", "ldap-sealed"])
            self.assertEqual(self._connect(), ["ldap-sealed"])
            self.assertEqual(self._connect(), ["ldap-sealed"])
        self.assertEqual(len(logs.records), 2)  # one warning, one note - not one per request

    def test_a_dc_that_was_down_is_not_remembered_as_without_ldaps(self):
        with self.assertLogs("samonboarding", level="WARNING"):
            self._connect(sealed_ok=False)
        self.assertEqual(ldap_client._ldaps_missing, {})

    def test_ldaps_is_tried_again_after_the_pause(self):
        with self.assertLogs("samonboarding", level="INFO"):
            self._connect()
        ldap_client._ldaps_missing["192.0.2.10"] = 0  # pause over
        with self.assertNoLogs("samonboarding", level="INFO"):  # nothing new - nothing written again
            self.assertEqual(self._connect(), ["ldaps", "ldap-sealed"])


class DiagnoseTests(unittest.TestCase):
    def test_package_names_the_kind_of_connection(self):
        from samonboarding import diagnose

        sealed = " ".join(diagnose.hints({"verbindung": {"transport": "ldap-sealed-ntlm"}}))
        self.assertIn("NTLM", sealed)
        self.assertIn("Zertifikat", sealed)
        self.assertIn("UNVERSCHLÜSSELT", " ".join(diagnose.hints({"verbindung": {"transport": "ldap-plain"}})))
        self.assertNotIn("NTLM", " ".join(diagnose.hints({"verbindung": {"transport": "ldaps"}})))


@unittest.skipUnless(os.environ.get("SAMONB_TEST_DC"), "kein Test-DC (SAMONB_TEST_DC)")
class RealDcTests(unittest.TestCase):
    """Against a real DC: bind, paged search and setting a password over the encrypted connection."""

    def test_sealed_connection_can_set_a_password(self):
        import ldap3

        dc = os.environ["SAMONB_TEST_DC"]
        user = os.environ.get("SAMONB_TEST_USER", "administrator@test.local")
        password = os.environ.get("SAMONB_TEST_PASSWORD", "")
        target = os.environ.get("SAMONB_TEST_TARGET", "CN=anna,CN=Users,DC=test,DC=local")
        with mock.patch.object(ldap_client, "_connection_attempts", return_value=["ldap-sealed"]):
            with ldap_client.ldap_connection(dc, user, password) as conn:
                self.assertTrue(conn.sob_transport.startswith("ldap-sealed"))
                base = ",".join(p for p in target.split(",") if p.upper().startswith("DC="))
                self.assertGreater(len(ldap_client.ldap_search(conn, base, "(objectClass=*)", ["cn"])), 50)
                new = f'"Seal{os.getpid()}Test!x"'
                ok = conn.modify(target, {"unicodePwd": [(ldap3.MODIFY_REPLACE, [new.encode("utf-16-le")])]})
                self.assertTrue(ok, conn.result)


if __name__ == "__main__":
    unittest.main()
