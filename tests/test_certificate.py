"""Custom HTTPS certificate: formats (PFX, PEM, DER, encrypted), checks, storage, replacement, API."""

import base64
import datetime
import os
import ssl
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

from fastapi import HTTPException  # noqa: E402

from samonboarding import config, tls  # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

ADMIN = {"username": "admin", "role": "Administrator"}
OPERATOR = {"username": "op", "role": "Account Operator"}
NOW = datetime.datetime.now(datetime.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(days=365, san=True, start=-1):
    """Company CA -> intermediate CA -> server certificate (as in a Windows PKI)."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("Firma Root CA"))
        .issuer_name(_name("Firma Root CA"))
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - datetime.timedelta(days=10))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    sub_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub = (
        x509.CertificateBuilder()
        .subject_name(_name("Firma Issuing CA"))
        .issuer_name(root.subject)
        .public_key(sub_key.public_key())
        .serial_number(2)
        .not_valid_before(NOW - datetime.timedelta(days=10))
        .not_valid_after(NOW + datetime.timedelta(days=1800))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("samonboarding.firma.local"))
        .issuer_name(sub.subject)
        .public_key(key.public_key())
        .serial_number(3)
        .not_valid_before(NOW + datetime.timedelta(days=start))
        .not_valid_after(NOW + datetime.timedelta(days=days))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("samonboarding.firma.local")]), critical=False
        )
    return key, builder.sign(sub_key, hashes.SHA256()), sub, root


def pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def key_pem(key, password=None):
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography nicht installiert")
class ParseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.leaf, cls.sub, cls.root = make_pki()

    def test_pfx_with_password_and_chain(self):
        pfx = pkcs12.serialize_key_and_certificates(
            b"web", self.key, self.leaf, [self.root, self.sub], serialization.BestAvailableEncryption(b"Geheim1")
        )
        priv, leaf, chain, warnings = tls.parse_upload(pfx=pfx, password="Geheim1")
        self.assertEqual(leaf, self.leaf)
        self.assertEqual(chain, [self.sub])  # correct order, root omitted
        self.assertEqual(warnings, [])
        with self.assertRaisesRegex(tls.CertError, "Passwort richtig"):
            tls.parse_upload(pfx=pfx, password="falsch")

    def test_pfx_without_key(self):
        pfx = pkcs12.serialize_key_and_certificates(b"x", None, None, [self.leaf], serialization.NoEncryption())
        with self.assertRaisesRegex(tls.CertError, "keinen privaten Schlüssel"):
            tls.parse_upload(pfx=pfx)

    def test_pem_pair_with_chain_in_the_certificate_file(self):
        _, leaf, chain, _ = tls.parse_upload(cert=pem(self.leaf, self.sub), key=key_pem(self.key))
        self.assertEqual((leaf, chain), (self.leaf, [self.sub]))

    def test_der_certificate_and_extra_chain(self):
        der = self.leaf.public_bytes(serialization.Encoding.DER)
        _, leaf, chain, _ = tls.parse_upload(cert=der, key=key_pem(self.key), chain=pem(self.sub, self.root))
        self.assertEqual((leaf, chain), (self.leaf, [self.sub]))

    def test_encrypted_key(self):
        enc = key_pem(self.key, "KeyPw1")
        with self.assertRaisesRegex(tls.CertError, "mit einem Passwort geschützt"):
            tls.parse_upload(cert=pem(self.leaf), key=enc)
        with self.assertRaisesRegex(tls.CertError, "Passwort richtig"):
            tls.parse_upload(cert=pem(self.leaf), key=enc, password="falsch")
        self.assertEqual(tls.parse_upload(cert=pem(self.leaf), key=enc, password="KeyPw1")[1], self.leaf)

    def test_key_in_the_same_file(self):
        self.assertEqual(tls.parse_upload(cert=pem(self.leaf) + key_pem(self.key))[1], self.leaf)

    def test_wrong_key_and_missing_parts(self):
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaisesRegex(tls.CertError, "gehören nicht zusammen"):
            tls.parse_upload(cert=pem(self.leaf), key=key_pem(other))
        with self.assertRaisesRegex(tls.CertError, "Schlüssel fehlt"):
            tls.parse_upload(cert=pem(self.leaf))
        with self.assertRaisesRegex(tls.CertError, "auswählen"):
            tls.parse_upload()
        with self.assertRaisesRegex(tls.CertError, "kein Zertifikat"):
            tls.parse_upload(cert=b"\x00\x01kaputt", key=key_pem(self.key))

    def test_expired_expiring_soon_without_san(self):
        key, leaf, sub, _ = make_pki(days=-1, start=-30)
        with self.assertRaisesRegex(tls.CertError, "abgelaufen"):
            tls.parse_upload(cert=pem(leaf, sub), key=key_pem(key))
        key, leaf, sub, _ = make_pki(days=10, san=False)
        warnings = tls.parse_upload(cert=pem(leaf, sub), key=key_pem(key))[3]
        self.assertTrue(any("bald ab" in w for w in warnings))
        self.assertTrue(any("SAN" in w for w in warnings))

    def test_short_rsa_key(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("x"))
            .issuer_name(_name("x"))
            .public_key(small.public_key())
            .serial_number(9)
            .not_valid_before(NOW)
            .not_valid_after(NOW + datetime.timedelta(days=30))
            .sign(small, hashes.SHA256())
        )
        with self.assertRaisesRegex(tls.CertError, "2048"):
            tls.parse_upload(cert=pem(cert), key=key_pem(small))

    def test_too_large(self):
        with self.assertRaisesRegex(tls.CertError, "zu groß"):
            tls.parse_upload(pfx=b"x" * (tls.MAX_UPLOAD_BYTES + 1))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography nicht installiert")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert = os.path.join(self.tmp.name, "tls", "cert.pem")
        self.key_file = os.path.join(self.tmp.name, "tls", "key.pem")
        self.patches = [
            mock.patch.object(config, "TLS_CERT_FILE", self.cert),
            mock.patch.object(config, "TLS_KEY_FILE", self.key_file),
            mock.patch.object(config, "TLS_HOSTNAMES", []),
            mock.patch.dict(tls._active, {"ctx": None}),
            mock.patch.dict(os.environ, {}),
        ]
        for p in self.patches:
            p.start()
        tls.ensure_certificate()  # self-signed at startup

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_install_backs_up_old_and_swaps_while_running(self):
        base = tls.make_context(self.cert, self.key_file)
        tls.activate(base)
        self.assertEqual(os.environ["SAMONBOARDING_TLS_SELF_SIGNED"], "1")
        old = Path(self.cert).read_bytes()
        key, leaf, sub, _ = make_pki()
        self.assertTrue(tls.install(key, leaf, [sub]))
        self.assertEqual(Path(self.cert + ".prev").read_bytes(), old)
        self.assertEqual(os.stat(self.key_file).st_mode & 0o777, 0o600)
        info = tls.current_info()
        self.assertEqual(
            (info["subject"], info["issuer"], info["chainLength"]), ("samonboarding.firma.local", "Firma Issuing CA", 1)
        )
        self.assertFalse(info["selfSigned"])
        self.assertEqual(os.environ["SAMONBOARDING_TLS_SELF_SIGNED"], "0")  # now with HSTS
        new_ctx = tls._active["ctx"]
        self.assertIsNot(new_ctx, base)
        # SNI callback switches new connections to the new certificate
        obj = mock.MagicMock()
        tls._sni_callback(obj, None, base)
        self.assertIs(obj.context, new_ctx)
        self.assertEqual(new_ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_without_running_server_means_restart(self):
        key, leaf, sub, _ = make_pki()
        self.assertFalse(tls.install(key, leaf, [sub]))
        self.assertEqual(tls.current_info()["subject"], "samonboarding.firma.local")

    def test_back_to_self_signed(self):
        names, live = tls.install_self_signed(["neu.firma.local", "10.0.10.20", "neu.firma.local"])
        self.assertEqual(names, ["neu.firma.local", "10.0.10.20"])
        info = tls.current_info()
        self.assertTrue(info["selfSigned"])
        self.assertEqual(info["names"], ["neu.firma.local", "10.0.10.20"])
        for bad in (["mit leerzeichen"], ["ümlaut.local"], ["a" * 64 + ".local"], ["-x.local"]):
            with self.assertRaises(tls.CertError):
                tls.install_self_signed(bad)
            # the previous certificate stays in service
            self.assertEqual(tls.current_info()["names"], ["neu.firma.local", "10.0.10.20"])
        names, _ = tls.install_self_signed(["*.firma.local"])
        self.assertEqual(names, ["*.firma.local"])

    def test_expiry_warning(self):
        with self.assertLogs("samonboarding.tls", "WARNING") as logs:
            key, leaf, sub, _ = make_pki(days=5)
            tls.install(key, leaf, [sub])
            tls.check_expiry()
        self.assertTrue(any("laeuft in" in m for m in logs.output))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography nicht installiert")
class ApiTests(unittest.TestCase):
    def setUp(self):
        from samonboarding.routers import certificate

        self.api = certificate
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [
            mock.patch.object(config, "TLS_CERT_FILE", os.path.join(self.tmp.name, "cert.pem")),
            mock.patch.object(config, "TLS_KEY_FILE", os.path.join(self.tmp.name, "key.pem")),
            mock.patch.object(config, "REPORTS_DB_FILE", os.path.join(self.tmp.name, "reports.db")),
            mock.patch.dict(tls._active, {"ctx": None}),
            mock.patch.dict(os.environ, {}),
        ]
        for p in self.patches:
            p.start()
        tls.ensure_certificate()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_admins_only(self):
        from samonboarding.models import CertSelfSignedModel, CertUploadModel

        for fn in (
            lambda: self.api.tls_info(OPERATOR),
            lambda: self.api.tls_upload(CertUploadModel(), OPERATOR),
            lambda: self.api.tls_self_signed(CertSelfSignedModel(), OPERATOR),
        ):
            with self.assertRaises(HTTPException) as ctx:
                fn()
            self.assertEqual(ctx.exception.status_code, 403)

    def test_upload_and_errors(self):
        from samonboarding import reports
        from samonboarding.models import CertUploadModel

        key, leaf, sub, root = make_pki()
        pfx = pkcs12.serialize_key_and_certificates(
            b"web", key, leaf, [sub, root], serialization.BestAvailableEncryption(b"pw")
        )
        out = self.api.tls_upload(CertUploadModel(pfx=base64.b64encode(pfx).decode(), password="pw"), ADMIN)
        self.assertEqual(out["certificate"]["subject"], "samonboarding.firma.local")
        self.assertEqual(self.api.tls_info(ADMIN)["certificate"]["issuer"], "Firma Issuing CA")
        entry = reports.query_audit()[0][0]
        self.assertEqual((entry["action"], entry["ok"]), ("tls-upload", True))
        for bad in (CertUploadModel(pfx="kein base64!"), CertUploadModel(pfx=base64.b64encode(pfx).decode())):
            with self.assertRaises(HTTPException) as ctx:
                self.api.tls_upload(bad, ADMIN)
            self.assertEqual(ctx.exception.status_code, 400)
        self.assertFalse(reports.query_audit()[0][0]["ok"])  # failed attempt shows up in the reports


if __name__ == "__main__":
    unittest.main()
