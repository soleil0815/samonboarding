"""Prueft mit den ECHTEN Klassen von smbprotocol, dass Berechtigungs-Anfragen korrekt gebaut und gelesen werden.

Ohne installiertes smbprotocol werden die Tests uebersprungen. Eine echte SMB-Verbindung wird nicht aufgebaut.
"""

import types
import unittest

import _paths  # noqa: F401

from samonboarding import acl
from samonboarding import fileshare as fs

try:
    from smbprotocol.open import SMB2QueryInfoResponse, SMB2SetInfoResponse

    fs._lib()
    HAVE_SMB = True
except Exception:  # Paket fehlt oder nicht importierbar
    HAVE_SMB = False

SD = None


class FakeConnection:
    response = None

    def receive(self, _request):
        return self.response


class FakeFd:
    file_id = b"\x01" * 16

    def __init__(self):
        self.connection = FakeConnection()


class FakeRaw:
    """Ersatz fuer SMBDirectoryIO/SMBFileIO: merkt sich nur, womit geoeffnet werden sollte."""

    opened = []

    def __init__(self, path, **kwargs):
        FakeRaw.opened.append((path, kwargs))
        self.fd = FakeFd()

    def open(self):
        pass

    def close(self):
        pass


class FakeTransaction:
    sent = []

    def __init__(self, raw):
        self.raw = raw
        self.results = None
        self.actions = []

    def __enter__(self):
        return self

    def __iadd__(self, action):
        self.actions.append(action)
        return self

    def __exit__(self, *_exc):
        results = []
        for message, unpack in self.actions:
            FakeTransaction.sent.append((type(message).__name__, message.pack(), message))
            if type(message).__name__ == "SMB2QueryInfoRequest":
                answer = SMB2QueryInfoResponse()
                answer["buffer"] = SD
            else:
                answer = SMB2SetInfoResponse()
            self.raw.fd.connection.response = {"data": types.SimpleNamespace(get_value=lambda a=answer: a.pack())}
            results.append(unpack(message))
        self.results = results


@unittest.skipUnless(HAVE_SMB, "smbprotocol ist nicht installiert")
class SmbRequestTests(unittest.TestCase):
    def setUp(self):
        global SD
        SD = acl.build_sd(
            owner="S-1-5-21-1-2-3-500",
            group="S-1-5-21-1-2-3-513",
            dacl=[acl.allow_ace("S-1-5-18", acl.FILE_ALL_ACCESS, True)],
        )
        FakeRaw.opened.clear()
        FakeTransaction.sent.clear()
        real = fs._lib

        def patched():
            lib = real()
            lib.dir_io = lib.file_io = FakeRaw
            lib.transaction = FakeTransaction
            return lib

        self._real = real
        fs._lib = patched
        self.backend = fs.SmbBackend.__new__(fs.SmbBackend)
        self.backend._smb = None
        self.backend._kw = {"username": "u", "password": "p", "connection_timeout": 5, "connection_cache": {}}

    def tearDown(self):
        fs._lib = self._real

    def test_lesen_baut_korrekte_anfrage_und_liefert_deskriptor(self):
        got = self.backend.get_security("\\\\fs\\share\\dir", True)
        self.assertEqual(bytes(got), SD)
        _name, _packed, message = FakeTransaction.sent[0]
        self.assertEqual(message["info_type"].get_value(), 3)  # SMB2_0_INFO_SECURITY
        self.assertEqual(message["additional_information"].get_value(), 7)  # Besitzer | Gruppe | DACL
        self.assertEqual(message["file_info_class"].get_value(), 0)
        path, kwargs = FakeRaw.opened[0]
        self.assertEqual(kwargs["desired_access"], 0x20000)  # READ_CONTROL
        self.assertEqual(kwargs["share_access"], "rwd")
        self.assertEqual(kwargs["connection_cache"], {})

    def test_schreiben_besitzer_und_dacl(self):
        owner_only = acl.build_sd(owner=acl.SID_ADMINISTRATORS)
        self.backend.set_security("\\\\fs\\share\\dir", True, owner_only, acl.SECINFO_OWNER, lambda a: a.WRITE_OWNER)
        _name, _packed, message = FakeTransaction.sent[-1]
        self.assertEqual(message["info_type"].get_value(), 3)
        self.assertEqual(message["additional_information"].get_value(), acl.SECINFO_OWNER)
        self.assertEqual(bytes(message["buffer"].get_value()), owner_only)
        self.assertEqual(FakeRaw.opened[-1][1]["desired_access"], 0x80000)  # WRITE_OWNER

        self.backend.set_security("\\\\fs\\share\\f.txt", False, owner_only, acl.SECINFO_DACL, lambda a: a.WRITE_DAC)
        self.assertEqual(FakeRaw.opened[-1][1]["desired_access"], 0x40000)  # WRITE_DAC

    def test_zugriff_vergeben_schreibt_nur_bei_aenderung(self):
        sid = "S-1-5-21-1-2-3-1105"
        calls = []
        self.backend.get_security = lambda *_a, **_k: SD
        self.backend.set_security = lambda *a: calls.append(a)
        with self.assertRaises(fs.FsError):  # Rueckpruefung scheitert, weil der Fake-Server nichts speichert
            self.backend.grant_access("\\\\fs\\share\\dir", True, sid)
        self.assertEqual(len(calls), 1)
        written = acl.parse_sd(calls[0][2])
        self.assertTrue(acl.has_allow_ace(written, sid))
        self.assertEqual(calls[0][3], acl.SECINFO_DACL)

    def test_bibliothek_stellt_benoetigte_teile_bereit(self):
        lib = self._real()
        self.assertEqual(int(lib.access.READ_CONTROL), 0x20000)
        self.assertEqual(int(lib.access.WRITE_DAC), 0x40000)
        self.assertEqual(int(lib.access.WRITE_OWNER), 0x80000)
        self.assertEqual(int(lib.info_type.SMB2_0_INFO_SECURITY), 3)


if __name__ == "__main__":
    unittest.main()
