"""The structure of the whole domain (page "AD-Struktur") is for administrators only. Operators get only what their
pages need: the target OUs released for moving and the groups named in the templates."""

import os
import sys
import tempfile
import unittest
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from fastapi import HTTPException  # noqa: E402

from samonboarding.ldap_client import Row  # noqa: E402
from samonboarding.routers import infrastructure  # noqa: E402
from samonboarding.storage import save_json  # noqa: E402

B = "DC=firma,DC=local"
ADMIN = {"username": "admin", "role": "Administrator", "sid": "s-admin"}
OPERATOR = {"username": "op", "role": "Account Operator", "sid": "s-op"}


class AdStructureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.mgmt = os.path.join(tmp.name, "usermgmt_config.json")
        self.tpl = os.path.join(tmp.name, "templates.json")
        save_json(
            self.mgmt, {"sourceOus": [f"OU=Staff,{B}"], "targetOus": [f"OU=Vertrieb,OU=Staff,{B}"], "groupOus": []}
        )
        save_json(self.tpl, [{"id": 1, "name": "Std", "groups": [f"CN=GG-Vertrieb,OU=Gruppen,{B}"]}])
        self.searches = []

        def search(conn, base, flt, attrs):
            self.searches.append(flt)
            if "organizationalUnit" in flt:
                return [Row(f"OU={n},{B}", {"name": n}) for n in ("Staff", "Geheim", "Vorstand")]
            if "group" in flt:
                return [Row(f"CN={n},OU=Gruppen,{B}", {"sAMAccountName": n}) for n in ("GG-Vertrieb", "GG-Vorstand")]
            return [Row(f"CN=Chef,OU=Vorstand,{B}", {"cn": "Chef", "displayName": "Chef", "co": "Deutschland"})]

        session = mock.MagicMock()
        for patch in (
            mock.patch.object(infrastructure, "USERMGMT_CONFIG_FILE", self.mgmt),
            mock.patch.object(infrastructure, "TEMPLATES_FILE", self.tpl),
            mock.patch.object(infrastructure, "CONFIG_FILE", os.path.join(tmp.name, "config.json")),
            mock.patch.object(infrastructure, "ad_session", return_value=session),
            mock.patch.object(infrastructure, "ldap_search", side_effect=search),
            mock.patch.object(infrastructure.listcache, "cached", side_effect=lambda user, key, fn, fresh: fn()),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def call(self, user, **params):
        params = {"frisch": False, "gruppen": True, "benutzer": True, "struktur": False, **params}
        return infrastructure.get_ad_infrastructure(user=user, **params)

    def test_operator_never_gets_the_whole_domain(self):
        data = self.call(OPERATOR)
        self.assertEqual(data["ous"], [{"name": "Vertrieb", "dn": f"OU=Vertrieb,OU=Staff,{B}"}])
        self.assertEqual([g["dn"] for g in data["groups"]], [f"CN=GG-Vertrieb,OU=Gruppen,{B}"])
        self.assertNotIn("users", data)
        self.assertNotIn("countries", data)
        self.assertEqual(self.searches, [])  # not even asked in the AD

    def test_operator_is_refused_the_page(self):
        with self.assertRaises(HTTPException) as ctx:
            self.call(OPERATOR, struktur=True)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(self.searches, [])

    def test_administrator_still_gets_everything(self):
        data = self.call(ADMIN, struktur=True)
        self.assertEqual(len(data["ous"]), 3)
        self.assertEqual(len(data["groups"]), 2)
        self.assertEqual(data["users"][0]["name"], "Chef")


if __name__ == "__main__":
    unittest.main()
