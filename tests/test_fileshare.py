"""Dateiserver-Logik (fileshare.py): Pfadpruefung, Scan, Loeschen, Besitzuebernahme, Fehlerabbildung, Basisordner."""

import errno
import unittest

import _paths  # noqa: F401

from samonboarding import fileshare as fs
from samonboarding.fileshare import FsEntry, FsError


class MemoryShare:
    """Kleines In-Memory-Dateisystem mit den Methoden eines SmbBackend."""

    def __init__(self, tree, reparse=(), denied=(), locked=(), no_takeover=()):
        self.tree = {k.lower(): v for k, v in tree.items()}  # Pfad -> Groesse (Datei) oder Liste (Ordner)
        self.reparse = {x.lower() for x in reparse}
        self.denied = {x.lower() for x in denied}  # Zugriff verweigert, bis der Besitz uebernommen wurde
        self.locked = {x.lower() for x in locked}
        self.no_takeover = {x.lower() for x in no_takeover}
        self.taken = []
        self.calls = []

    def _check(self, path):
        key = path.lower()
        if key in self.denied or key in self.locked:
            raise FsError("denied", "Zugriff verweigert.")
        if key not in self.tree:
            raise FsError("notfound", "Nicht gefunden.")
        return self.tree[key]

    def listdir(self, path):
        self.calls.append(("listdir", path))
        node = self._check(path)
        if not isinstance(node, list):
            raise FsError("other", "Kein Ordner.")
        out = []
        for name in node:
            child = path.rstrip("\\") + "\\" + name
            value = self.tree[child.lower()]
            out.append(
                FsEntry(
                    name,
                    isinstance(value, list),
                    0 if isinstance(value, list) else value,
                    child.lower() in self.reparse,
                )
            )
        return out

    def _unlink(self, path):
        parent, _, name = path.rpartition("\\")
        self.tree[parent.lower()] = [x for x in self.tree[parent.lower()] if x.lower() != name.lower()]
        del self.tree[path.lower()]

    def remove(self, path):
        self.calls.append(("remove", path))
        node = self._check(path)
        if isinstance(node, list):
            raise FsError("other", "Ist ein Ordner.")
        self._unlink(path)

    def rmdir(self, path):
        self.calls.append(("rmdir", path))
        node = self._check(path)
        if path.lower() in self.reparse:
            self._unlink(path)  # nur die Verknuepfung, das Ziel bleibt
            return
        if not isinstance(node, list) or node:
            raise FsError("other", "Ordner ist nicht leer.")
        self._unlink(path)

    def can_take_ownership(self, path, is_dir):
        return path.lower() not in self.no_takeover

    def take_ownership(self, path, is_dir):
        if path.lower() in self.no_takeover:
            raise FsError("denied", "Besitzübernahme fehlgeschlagen: Zugriff verweigert.")
        self.taken.append(path)
        self.denied.discard(path.lower())
        self.locked.discard(path.lower())

    def mkdir(self, path):
        parent = path.rpartition("\\")[0].lower()
        if path.lower() in self.tree:
            raise FsError("exists", "Existiert bereits.")
        if parent not in self.tree:
            raise FsError("notfound", "Pfad nicht gefunden.")
        self.tree[path.lower()] = []
        self.tree[parent].append(path.rpartition("\\")[2])

    def grant_access(self, path, is_dir, sid, mask=None):
        self.calls.append(("grant", path, sid))


ROOT = "\\\\fs\\home$\\anna"


def sample(**kw):
    tree = {
        "\\\\fs\\home$": ["anna"],
        ROOT: ["Docs", "readme.txt"],
        ROOT + "\\Docs": ["a.txt", "Sub"],
        ROOT + "\\Docs\\a.txt": 10,
        ROOT + "\\Docs\\Sub": [],
        ROOT + "\\readme.txt": 5,
    }
    return MemoryShare(tree, **kw)


class PathTests(unittest.TestCase):
    def test_parse_unc(self):
        self.assertEqual(fs.parse_unc("\\\\FS1\\Profiles$\\a\\b"), ("FS1", "Profiles$", ["a", "b"]))
        self.assertEqual(fs.parse_unc("//fs1/p$/a/"), ("fs1", "p$", ["a"]))

    def test_parse_unc_lehnt_gefaehrliches_ab(self):
        bad = [
            "C:\\x",
            "\\\\fs1",
            "\\\\fs1\\p$\\..\\x",
            "\\\\fs1\\p$\\a\\*",
            "\\\\fs1\\p$\\a:b",
            "\\\\fs1\\p$\\a.",
            "\\\\fs1\\p$\\a \\b",
            "\\\\fs1\\p$\\\\a",
            "\\\\fs 1\\p$",
            "",
            "\\\\fs1\\p$\\%x%",
            "\\\\fs1\\p$\\.",
            "\\\\fs1\\p$\\a|b",
        ]
        for path in bad:
            with self.assertRaises(ValueError, msg=path):
                fs.parse_unc(path)

    def test_is_strictly_below(self):
        self.assertTrue(fs.is_strictly_below("\\\\FS1\\Profiles$\\aalt.V2", "\\\\fs1\\profiles$"))
        self.assertFalse(fs.is_strictly_below("\\\\fs1\\profiles$", "\\\\fs1\\profiles$"))
        self.assertFalse(fs.is_strictly_below("\\\\fs1\\profiles$x\\a", "\\\\fs1\\profiles$"))
        self.assertFalse(fs.is_strictly_below("\\\\fs1\\p$\\userX\\a", "\\\\fs1\\p$\\user"))
        self.assertFalse(fs.is_strictly_below("\\\\fs2\\p$\\a", "\\\\fs1\\p$"))

    def test_build_targets_profil_mit_endungen(self):
        loc = {"enabled": True, "roots": ["\\\\fs1\\profiles$"], "useAdAttr": True, "suffixes": ["V2", "V6"]}
        targets = fs.build_targets("profile", loc, "aalt", "\\\\fs1\\profiles$\\%username%")
        self.assertEqual([t["path"] for t in targets], ["\\\\fs1\\profiles$\\aalt.V2", "\\\\fs1\\profiles$\\aalt.V6"])

    def test_build_targets_fremder_pfad_wird_uebersprungen(self):
        loc = {"enabled": True, "roots": ["\\\\fs1\\home$"], "useAdAttr": True}
        target = fs.build_targets("home", loc, "aalt", "\\\\evil\\x$\\aalt")[0]
        self.assertTrue(target["skip"])
        self.assertEqual(fs.build_targets("home", {"enabled": False, "roots": ["\\\\a\\b"]}, "x"), [])

    def test_build_targets_kurzname_mit_tilde(self):
        """ADMINI~1 koennte auf dem Dateiserver der Kurzname von 'Administrator' sein - nie automatisch loeschen."""
        targets = fs.build_targets("home", {"enabled": True, "roots": ["\\\\fs1\\home$"]}, "ADMINI~1")
        self.assertTrue(all(t["skip"] for t in targets))

    def test_build_targets_boeser_benutzername(self):
        target = fs.build_targets("folderRedirection", {"enabled": True, "roots": ["\\\\fs1\\r$"]}, "..")[0]
        self.assertTrue(target["skip"])
        self.assertEqual(target["path"], "")


class ScanTests(unittest.TestCase):
    def test_zaehlt_und_folgt_verknuepfungen_nicht(self):
        share = sample(reparse=[ROOT + "\\Docs\\Sub"])
        result = fs.scan_tree(share, ROOT)
        self.assertEqual((result.files, result.dirs, result.size, result.reparse), (2, 1, 15, 1))

    def test_ohne_zugriff_wird_gemeldet(self):
        share = sample(denied=[ROOT + "\\Docs"])
        result = fs.scan_tree(share, ROOT)
        self.assertEqual(result.denied, [ROOT + "\\Docs"])


class DeleteTests(unittest.TestCase):
    def test_loescht_alles(self):
        share = sample()
        result = fs.delete_tree(share, ROOT)
        self.assertEqual((result.files, result.dirs, result.error_count), (2, 3, 0))
        self.assertNotIn(ROOT.lower(), share.tree)

    def test_verknuepfung_wird_nur_selbst_entfernt(self):
        target = "\\\\fs\\elsewhere\\important.txt"
        share = sample(reparse=[ROOT + "\\Docs\\Sub"])
        share.tree[target.lower()] = 99
        share.tree[ROOT.lower() + "\\docs\\sub"] = ["child"]  # Inhalt "hinter" der Verknuepfung
        share.tree[ROOT.lower() + "\\docs\\sub\\child"] = 7
        result = fs.delete_tree(share, ROOT)
        self.assertEqual((result.links, result.error_count), (1, 0))
        self.assertIn(ROOT.lower() + "\\docs\\sub\\child", share.tree)  # nie hineingegangen
        self.assertIn(target.lower(), share.tree)
        self.assertNotIn(("listdir", ROOT + "\\Docs\\Sub"), share.calls)

    def test_ordner_wird_zwischendurch_zur_verknuepfung(self):
        """Wird ein Unterordner nach dem Auflisten durch eine Junction ersetzt, wird nur sie entfernt (kein Folgen)."""
        share = sample()
        sub = ROOT + "\\Docs\\Sub"

        class Racy(type(share)):
            def stat(self, path):
                self.calls.append(("stat", path))
                return fs.FsStat(is_dir=True, size=0, reparse=path.lower() == sub.lower())

        share.__class__ = Racy
        result = fs.delete_tree(share, ROOT)
        self.assertEqual(result.links, 1)
        self.assertNotIn(("listdir", sub), share.calls)

    def test_ohne_erlaubnis_keine_besitzuebernahme(self):
        share = sample(locked=[ROOT + "\\readme.txt"])
        result = fs.delete_tree(share, ROOT)
        self.assertEqual(result.error_count > 0, True)
        self.assertEqual(share.taken, [])
        self.assertIn(ROOT.lower(), share.tree)  # Ordner bleibt, weil nicht leer

    def test_mit_erlaubnis_wird_besitz_uebernommen(self):
        share = sample(locked=[ROOT + "\\readme.txt"], denied=[ROOT + "\\Docs"])
        result = fs.delete_tree(share, ROOT, takeover=True)
        self.assertEqual(result.error_count, 0)
        self.assertEqual(result.takeover_count, 2)
        self.assertCountEqual(share.taken, [ROOT + "\\readme.txt", ROOT + "\\Docs"])
        self.assertNotIn(ROOT.lower(), share.tree)

    def test_besitzuebernahme_scheitert_wird_gemeldet(self):
        share = sample(locked=[ROOT + "\\readme.txt"], no_takeover=[ROOT + "\\readme.txt"])
        result = fs.delete_tree(share, ROOT, takeover=True)
        self.assertGreaterEqual(result.error_count, 1)
        self.assertTrue(any("Besitzübernahme" in e for e in result.errors))
        self.assertNotIn(ROOT.lower() + "\\docs\\a.txt", share.tree)  # alles andere wurde trotzdem geloescht

    def test_fehlerliste_ist_begrenzt(self):
        names = [f"f{i}.txt" for i in range(fs.MAX_REPORTED_ERRORS + 15)]
        tree = {"\\\\fs\\home$": ["anna"], ROOT: names}
        tree.update({f"{ROOT}\\{n}": 1 for n in names})
        share = MemoryShare(tree, locked=[f"{ROOT}\\{n}" for n in names])
        result = fs.delete_tree(share, ROOT)
        self.assertEqual(result.error_count, len(names) + 1)  # + der nicht leere Ordner
        self.assertEqual(len(result.errors), fs.MAX_REPORTED_ERRORS)

    def test_ungueltige_namen_werden_nicht_angefasst(self):
        share = sample()
        share.listdir = lambda path: [FsEntry("..", True, 0, False), FsEntry("a\\b", False, 1, False)]
        result = fs.delete_tree(share, ROOT)
        self.assertEqual(result.error_count >= 2, True)
        self.assertFalse([c for c in share.calls if c[0] in ("remove", "rmdir") and ".." in c[1]])


class TranslateTests(unittest.TestCase):
    class Err(Exception):
        def __init__(self, ntstatus=None, errno_=None, text=""):
            super().__init__(text)
            self.ntstatus = ntstatus
            self.errno = errno_

    def kind(self, exc):
        return fs._translate(exc).kind

    def test_ntstatus(self):
        cases = {
            0xC0000022: "denied",
            0xC0000061: "denied",
            0xC0000043: "locked",
            0xC0000121: "other",
            0xC0000101: "other",
            0xC0000034: "notfound",
            0xC000003A: "notfound",
            0xC00000CC: "notfound",
            0xC0000035: "exists",
            0xC000006D: "auth",
        }
        for status, kind in cases.items():
            self.assertEqual(self.kind(self.Err(status, errno.EPERM)), kind, hex(status))

    def test_sharing_violation_ist_nicht_zugriff_verweigert(self):
        err = fs._translate(self.Err(0xC0000043, errno.EPERM))
        self.assertEqual(err.kind, "locked")
        self.assertIn("Benutzung", err.message)

    def test_errno_und_netzwerk(self):
        self.assertEqual(self.kind(self.Err(None, errno.EACCES)), "denied")
        self.assertEqual(self.kind(self.Err(None, errno.ENOENT)), "notfound")
        self.assertEqual(self.kind(self.Err(None, errno.EEXIST)), "exists")
        self.assertEqual(self.kind(ConnectionRefusedError("x")), "unreachable")
        self.assertEqual(self.kind(TimeoutError("x")), "unreachable")
        self.assertEqual(self.kind(ValueError("irgendwas")), "other")

    def test_fserror_bleibt_unveraendert(self):
        original = FsError("auth", "x")
        self.assertIs(fs._translate(original), original)


class HomeFolderTests(unittest.TestCase):
    SID = "S-1-5-21-1-2-3-1105"

    def test_legt_ordner_an_und_vergibt_rechte(self):
        share = MemoryShare({"\\\\fs\\home$": []})
        self.assertEqual(fs.create_home_folder(share, "\\\\fs\\home$\\anna", self.SID), "created")
        self.assertIn("\\\\fs\\home$\\anna", share.tree)
        self.assertIn(("grant", "\\\\fs\\home$\\anna", self.SID), share.calls)

    def test_vorhandener_ordner_wird_nicht_angefasst(self):
        share = MemoryShare({"\\\\fs\\home$": ["anna"], "\\\\fs\\home$\\anna": []})
        self.assertEqual(fs.create_home_folder(share, "\\\\fs\\home$\\anna", self.SID), "exists")
        self.assertFalse([c for c in share.calls if c[0] == "grant"])

    def test_fehlender_elternordner_und_freigabe(self):
        share = MemoryShare({"\\\\fs\\home$": []})
        with self.assertRaises(FsError) as ctx:
            fs.create_home_folder(share, "\\\\fs\\home$\\team\\anna", self.SID)
        self.assertEqual(ctx.exception.kind, "notfound")

    def test_freigabe_selbst_und_ungueltige_pfade(self):
        share = MemoryShare({"\\\\fs\\home$": []})
        for bad in ("\\\\fs\\home$", "C:\\Users\\anna", "\\\\fs\\home$\\..\\x"):
            with self.assertRaises(FsError, msg=bad):
                fs.create_home_folder(share, bad, self.SID)


if __name__ == "__main__":
    unittest.main()
