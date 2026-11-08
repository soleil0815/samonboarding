"""Quick search: the DC searches with an escaped filter in the released OUs, at most 10 hits, POST only."""

import contextlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding.routers import people  # noqa: E402

ROOT = Path(_paths.ROOT)


class FakeConn:
    def __init__(self, entries, fail=(), code=0):
        self.entries = entries  # base -> list of (dn, attrs)
        self.fail = set(fail)
        self.code = code
        self.searches = []
        self.result = {}
        self.response = []

    def search(self, base, flt, scope, attributes, size_limit):
        self.searches.append((base, flt, tuple(attributes), size_limit))
        if base in self.fail:
            self.result = {"result": 50, "description": "insufficientAccessRights"}
            self.response = []
            return
        hits = self.entries.get(base, [])
        self.result = {"result": 4 if len(hits) > size_limit else self.code}
        self.response = [{"type": "searchResEntry", "dn": dn, "attributes": a} for dn, a in hits[:size_limit]]


def run(q, conn, ous=None):
    ous = (
        ous
        if ous is not None
        else {
            people.USERMGMT_CONFIG_FILE: ["OU=MA,DC=f"],
            people.OFFBOARDING_CONFIG_FILE: ["OU=MA,DC=f", "OU=Alt,DC=f"],
            people.PWDRESET_CONFIG_FILE: ["OU=Azubi,DC=f"],
        }
    )

    @contextlib.contextmanager
    def session(u):
        yield conn

    with (
        mock.patch.object(people, "ad_session", session),
        mock.patch.object(people, "load_json", lambda path, default: {"sourceOus": ous.get(path, [])}),
    ):
        return people.search_people(people.PeopleSearchModel(q=q), user={"username": "it.admin", "sid": "s"})


def person(name, sam, mail="", uac="512"):
    return {"displayName": name, "sAMAccountName": sam, "mail": mail, "userAccountControl": uac}


class FilterTests(unittest.TestCase):
    def test_too_short(self):
        for q in ("", " ", "a", "  b  "):
            self.assertIsNone(people.people_filter(q), q)

    def test_every_word_must_match(self):
        flt = people.people_filter("Markus Kl")
        self.assertIn("(|(displayName=*Markus*)(cn=*Markus*)(sAMAccountName=*Markus*)(mail=*Markus*))", flt)
        self.assertIn("(|(displayName=*Kl*)(cn=*Kl*)(sAMAccountName=*Kl*)(mail=*Kl*))", flt)
        self.assertTrue(flt.startswith("(&(&(objectClass=user)(!(objectClass=computer)))"))

    def test_input_is_escaped(self):
        flt = people.people_filter("a*)(objectClass=*")
        self.assertNotIn("a*)(objectClass=*", flt)
        self.assertIn("\\2a", flt)
        self.assertIn("\\28", flt)
        self.assertIn("\\29", flt)

    def test_word_and_length_limits(self):
        flt = people.people_filter("a1 b2 c3 d4 e5 f6")
        self.assertEqual(flt.count("(|"), people.MAX_WORDS)
        self.assertNotIn("x" * 65, people.people_filter("x" * 300))


class SearchTests(unittest.TestCase):
    def test_hits_from_released_ous_with_target_page(self):
        conn = FakeConn(
            {
                "OU=MA,DC=f": [
                    ("CN=Markus Klein,OU=MA,DC=f", person("Markus Klein", "M.KLEIN", "m.klein@firma.local"))
                ],
                "OU=Alt,DC=f": [("CN=Kai Klemm,OU=Alt,DC=f", person("Kai Klemm", "K.KLEMM", uac="514"))],
                "OU=Azubi,DC=f": [("CN=Kl Azubi,OU=Azubi,DC=f", person("Klara Azubi", "KL"))],
            }
        )
        out = run("kl", conn)["people"]
        by_sam = {p["sam"]: p for p in out}
        self.assertEqual(by_sam["M.KLEIN"]["tab"], "usermgmt")
        self.assertEqual(by_sam["K.KLEMM"]["tab"], "offboard")
        self.assertTrue(by_sam["K.KLEMM"]["disabled"])
        self.assertEqual(by_sam["KL"]["tab"], "pwdreset")
        self.assertEqual(out[0]["sam"], "KL")  # exact logon name first
        searched = {s[0] for s in conn.searches}
        self.assertEqual(searched, {"OU=MA,DC=f", "OU=Alt,DC=f", "OU=Azubi,DC=f"})  # only released OUs, once each
        for _b, _f, attrs, limit in conn.searches:
            self.assertNotIn("memberOf", attrs)
            self.assertLessEqual(limit, people.MAX_HITS * 3)

    def test_same_account_in_several_areas_once(self):
        hit = ("CN=Anna,OU=MA,DC=f", person("Anna Schmidt", "A.SCHMIDT"))
        conn = FakeConn({"OU=MA,DC=f": [hit], "OU=Alt,DC=f": [hit]})
        out = run("anna", conn)["people"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["tab"], "usermgmt")

    def test_at_most_ten_and_size_limit_is_fine(self):
        many = [(f"CN=U{i},OU=MA,DC=f", person(f"Uwe {i:02d}", f"U{i:02d}")) for i in range(50)]
        out = run("uwe", FakeConn({"OU=MA,DC=f": many}))["people"]
        self.assertEqual(len(out), people.MAX_HITS)

    def test_unreadable_ou_is_skipped(self):
        conn = FakeConn({"OU=MA,DC=f": [("CN=A,OU=MA,DC=f", person("Anna", "A"))]}, fail={"OU=Alt,DC=f"})
        self.assertEqual(len(run("anna", conn)["people"]), 1)

    def test_short_query_asks_nothing(self):
        conn = FakeConn({})
        self.assertEqual(run("a", conn)["people"], [])
        self.assertEqual(conn.searches, [])

    def test_nothing_released(self):
        conn = FakeConn({})
        self.assertEqual(run("anna", conn, ous={})["people"], [])
        self.assertEqual(conn.searches, [])


class SourceTests(unittest.TestCase):
    def test_post_not_cached_not_logged(self):
        source = (ROOT / "samonboarding" / "routers" / "people.py").read_text(encoding="utf-8")
        self.assertIn('@router.post("/api/people")', source)
        self.assertNotIn("listcache", source)
        self.assertNotIn("audit", source)
        self.assertNotIn("log.info", source)
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(main.count("    people,"), 2)


if __name__ == "__main__":
    unittest.main()
