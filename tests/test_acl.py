"""Windows security descriptors (acl.py): pure binary logic, no dependencies."""

import struct
import unittest

import _paths  # noqa: F401

from samonboarding import acl

ADMINS = "S-1-5-32-544"
SYSTEM = "S-1-5-18"
USER = "S-1-5-21-1111-2222-3333-1105"


class SidTests(unittest.TestCase):
    def test_known_sid_bytes(self):
        self.assertEqual(acl.sid_to_bytes(SYSTEM), bytes.fromhex("0101000000000005" + "12000000"))
        self.assertEqual(acl.sid_to_bytes(ADMINS), bytes.fromhex("0102000000000005" + "20000000" + "20020000"))

    def test_roundtrip(self):
        for sid in (SYSTEM, ADMINS, USER):
            raw = acl.sid_to_bytes(sid)
            self.assertEqual(acl.sid_from_bytes(raw), (sid, len(raw)))
            self.assertEqual(acl.sid_from_ldap(raw), sid)

    def test_ldap_text_is_passed_through(self):
        self.assertEqual(acl.sid_from_ldap(USER), USER)

    def test_invalid_sids(self):
        for bad in ("", "S-2-5-18", "S-1-5-x", "X-1-5-18", "S-1", "S-1-5-" + "-".join(["1"] * 16)):
            with self.assertRaises(acl.AclError, msg=bad):
                acl.sid_to_bytes(bad)
        with self.assertRaises(acl.AclError):
            acl.sid_from_bytes(b"\x01\x05\x00")
        with self.assertRaises(acl.AclError):
            acl.sid_from_ldap(acl.sid_to_bytes(USER) + b"\x00")


class DescriptorTests(unittest.TestCase):
    def build(self, aces, **kw):
        return acl.build_sd(owner=kw.get("owner", ADMINS), group=kw.get("group", SYSTEM), dacl=aces)

    def test_ace_bytes(self):
        ace = acl.allow_ace(USER, acl.FILE_ALL_ACCESS, is_dir=True)
        raw = ace.to_bytes()
        sid = acl.sid_to_bytes(USER)
        self.assertEqual(raw[:4], struct.pack("<BBH", 0, acl.INHERIT_FLAGS, 8 + len(sid)))
        self.assertEqual(struct.unpack_from("<I", raw, 4)[0], acl.FILE_ALL_ACCESS)
        self.assertEqual(raw[8:], sid)
        self.assertEqual(acl.allow_ace(USER, is_dir=False).flags, 0)

    def test_roundtrip_and_unknown_aces(self):
        unknown = acl.Ace(0x05, 0, raw=struct.pack("<BBHI", 0x05, 0, 12, 0xFFFF) + b"\x00" * 4)
        sd = acl.parse_sd(self.build([acl.allow_ace(SYSTEM, is_dir=True), unknown, acl.allow_ace(USER)]))
        self.assertEqual((sd.owner, sd.group), (ADMINS, SYSTEM))
        self.assertEqual([a.ace_type for a in sd.dacl], [0, 5, 0])
        self.assertEqual(sd.dacl[1].raw, unknown.raw)  # unknown entries are preserved byte for byte
        again = acl.parse_sd(acl.build_sd(owner=sd.owner, group=sd.group, dacl=sd.dacl))
        self.assertEqual([a.to_bytes() for a in again.dacl], [a.to_bytes() for a in sd.dacl])

    def test_only_set_parts(self):
        sd = acl.parse_sd(acl.build_sd(owner=ADMINS))
        self.assertEqual(sd.owner, ADMINS)
        self.assertIsNone(sd.group)
        self.assertIsNone(sd.dacl)  # no DACL included

    def test_add_before_inherited_entries(self):
        inherited = acl.Ace(acl.ACE_ACCESS_ALLOWED, acl.ACE_INHERITED, acl.FILE_ALL_ACCESS, SYSTEM)
        direct = acl.Ace(acl.ACE_ACCESS_ALLOWED, 0, 0x1200A9, ADMINS)
        sd = acl.SecurityDescriptor(dacl=[direct, inherited])
        aces, changed = acl.with_allow_ace(sd, acl.allow_ace(USER, is_dir=True))
        self.assertTrue(changed)
        self.assertEqual([a.sid for a in aces], [ADMINS, USER, SYSTEM])

    def test_already_present_changes_nothing(self):
        sd = acl.SecurityDescriptor(dacl=[acl.allow_ace(USER, acl.FILE_ALL_ACCESS, True)])
        aces, changed = acl.with_allow_ace(sd, acl.allow_ace(USER, acl.FILE_ALL_ACCESS, True))
        self.assertFalse(changed)
        self.assertEqual(len(aces), 1)

    def test_inherit_only_does_not_count(self):
        only_inherit = acl.Ace(
            acl.ACE_ACCESS_ALLOWED, acl.INHERIT_FLAGS | acl.ACE_INHERIT_ONLY, acl.FILE_ALL_ACCESS, USER
        )
        _aces, changed = acl.with_allow_ace(
            acl.SecurityDescriptor(dacl=[only_inherit]), acl.allow_ace(USER, is_dir=True)
        )
        self.assertTrue(changed)

    def test_null_dacl_is_not_modified(self):
        with self.assertRaises(acl.AclError):
            acl.with_allow_ace(acl.SecurityDescriptor(dacl=None), acl.allow_ace(USER))

    def test_has_allow_ace(self):
        sd = acl.SecurityDescriptor(dacl=[acl.allow_ace(USER, acl.FILE_ALL_ACCESS, True)])
        self.assertTrue(acl.has_allow_ace(sd, USER))
        self.assertFalse(acl.has_allow_ace(sd, SYSTEM))
        self.assertFalse(acl.has_allow_ace(acl.SecurityDescriptor(dacl=None), USER))

    def test_broken_descriptors(self):
        good = self.build([acl.allow_ace(USER)])
        for bad in (b"", good[:10], good[:-3], b"\x02" + good[1:]):
            with self.assertRaises(acl.AclError):
                acl.parse_sd(bad)

    def test_acl_too_large(self):
        many = [acl.allow_ace(USER, mask=i + 1) for i in range(3000)]
        with self.assertRaises(acl.AclError):
            acl.build_sd(dacl=many)


if __name__ == "__main__":
    unittest.main()
