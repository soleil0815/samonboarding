"""Zwischenspeicher der Kontolisten (listcache.py) und Sammelabfrage geschuetzter Konten (protection.privileged_map)."""

import os
import sys
import unittest
from unittest import mock

import _paths

try:
    import ldap3  # noqa: F401
except ImportError:  # ohne installierte Pakete: Ersatzmodule der Szenarien verwenden
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import listcache, protection  # noqa: E402
from samonboarding.ldap_client import Row  # noqa: E402

ADM = {"sid": "sitzung-a"}
OP = {"sid": "sitzung-b"}


class ListCacheTests(unittest.TestCase):
    def setUp(self):
        listcache.invalidate()
        self.calls = 0

    def build(self, value=None):
        def run():
            self.calls += 1
            return {"n": self.calls} if value is None else value

        return run

    def test_zweiter_aufruf_aus_dem_speicher(self):
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})
        self.assertEqual(self.calls, 1)

    def test_frisch_liest_neu(self):
        listcache.cached(ADM, "k", self.build())
        self.assertEqual(listcache.cached(ADM, "k", self.build(), fresh=True), {"n": 2})
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_je_sitzung_getrennt(self):
        listcache.cached(ADM, "k", self.build())
        self.assertEqual(listcache.cached(OP, "k", self.build()), {"n": 2})

    def test_aenderung_leert_alles(self):
        listcache.cached(ADM, "k", self.build())
        listcache.invalidate()
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_abgelaufen(self):
        listcache.cached(ADM, "k", self.build())
        with mock.patch.object(listcache.time, "monotonic", return_value=listcache.time.monotonic() + 61):
            self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_kopie_kann_nicht_veraendert_werden(self):
        first = listcache.cached(ADM, "k", self.build([{"dn": "a"}]))
        first.append("x")
        self.assertEqual(listcache.cached(ADM, "k", self.build()), [{"dn": "a"}])

    def test_fehler_werden_nicht_gemerkt(self):
        def boom():
            raise RuntimeError("DC weg")

        with self.assertRaises(RuntimeError):
            listcache.cached(ADM, "k", boom)
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})

    def test_waehrend_des_lesens_geaendert_nicht_merken(self):
        def build():
            listcache.invalidate()  # z. B. paralleles Offboarding
            return "alt"

        listcache.cached(ADM, "k", build)
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 1})

    def test_abmelden_vergisst_die_sitzung(self):
        listcache.cached(ADM, "k", self.build())
        listcache.forget_session("sitzung-a")
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_fehler_ersatzliste_nicht_gemerkt(self):
        listcache.cached(ADM, "k", self.build({"error": "DC nicht erreichbar", "ous": []}))
        self.assertEqual(listcache.cached(ADM, "k", self.build()), {"n": 2})

    def test_abgelaufenes_wird_entfernt(self):
        listcache.cached(OP, "alt", self.build())
        with mock.patch.object(listcache.time, "monotonic", return_value=listcache.time.monotonic() + 61):
            listcache.cached(ADM, "k", self.build())
        self.assertNotIn(("sitzung-b", "alt"), listcache._store)

    def test_ohne_sitzung_nie_gemerkt(self):
        listcache.cached({}, "k", self.build())
        listcache.cached({}, "k", self.build())
        self.assertEqual(self.calls, 2)


DOM = "S-1-5-21-10-20-30"
BASE = "DC=t,DC=l"
DA = "CN=Domain Admins,CN=Users," + BASE


class PrivilegedMapTests(unittest.TestCase):
    def run_map(self, members, primary=(), specials=()):
        def search(_conn, _base, flt, attrs=("cn",)):
            if flt.startswith("(&(objectClass=group)"):
                # wie ldap3 ohne Schema: kein (brauchbarer) objectSid im Ergebnis - der Name kommt aus der Anfrage
                admins = "CN=Administrators,CN=Builtin," + BASE
                groups = {f"(objectSid={DOM}-512)": DA, "(objectSid=S-1-5-32-544)": admins}
                return [Row(dn, {"objectSid": ["\x01\x02 kaputt"]}) for f, dn in groups.items() if f in flt]
            if "memberOf:1.2.840.113556.1.4.1941:=" in flt:
                return [Row(dn, {}) for g, dn in members if g in flt]
            if "primaryGroupID" in flt:
                return [Row(dn, {"primaryGroupID": [rid]}) for dn, rid in primary]
            return [Row(dn, {}) for dn in specials]

        with (
            mock.patch.object(protection, "read_sids", return_value=([DOM], True)),
            mock.patch.object(protection, "_search_dns", side_effect=search),
        ):
            return protection.privileged_map(object(), BASE)

    def test_mitglieder_verschachtelt_primaer_und_systemkonten(self):
        out = self.run_map(
            [("Domain Admins", "CN=Anna," + BASE), ("Administrators", "CN=Bert," + BASE)],
            primary=[("CN=Carl," + BASE, "512")],
            specials=["CN=krbtgt,CN=Users," + BASE],
        )
        self.assertIn("Domänen-Admins", out["cn=anna," + BASE.lower()])
        self.assertIn("Administratoren", out["cn=bert," + BASE.lower()])
        self.assertIn("Domänen-Admins", out["cn=carl," + BASE.lower()])
        self.assertEqual(out["cn=krbtgt,cn=users," + BASE.lower()], "geschütztes Systemkonto")

    def test_ohne_domaenen_admins_einzeln_pruefen(self):
        # Verzeichnis ohne verschachtelte Suche: lieber einzeln pruefen als Admins ohne Schloss zeigen
        with self.assertRaises(LookupError):
            self.run_map([("Administrators", "CN=Bert," + BASE)])

    def test_mark_protected_faellt_auf_einzelpruefung_zurueck(self):
        users = [{"dn": "CN=Anna," + BASE}]
        with (
            mock.patch.object(protection, "privileged_map", side_effect=LookupError("x")),
            mock.patch.object(protection, "privileged_reason", return_value="Mitglied von „Domänen-Admins“") as one,
        ):
            protection.mark_protected(object(), users)
        one.assert_called_once()
        self.assertTrue(users[0]["protected"])


if __name__ == "__main__":
    unittest.main()
