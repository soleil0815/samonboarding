"""Exchange-Anbindung (exchange.py): Einstellungen pruefen, Aufrufe an pypsrp, Fehlermeldungen. Ohne echten Server."""

import sys
import types
import unittest

import _paths  # noqa: F401

from samonboarding import exchange

USER = {"bind_user": "admin@x.local", "password": "geheim"}
CFG = dict(exchange.default_exchange_config, enabled=True, server="exch01.x.local")


class FakeStreams:
    def __init__(self, errors):
        self.error = errors


class FakePs:
    log = []
    next_errors = []
    next_output = ["x"]

    def __init__(self, pool):
        self.pool, self.cmd, self.params = pool, None, {}
        self.had_errors = False
        self.streams = FakeStreams([])

    def add_cmdlet(self, name):
        self.cmd = name
        return self

    def add_parameter(self, key, value):
        self.params[key] = value
        return self

    def invoke(self):
        FakePs.log.append((self.cmd, dict(self.params)))
        self.had_errors = bool(FakePs.next_errors)
        self.streams = FakeStreams(list(FakePs.next_errors))
        return list(FakePs.next_output)


class FakePool:
    created = []

    def __init__(self, wsman, configuration_name=None):
        self.wsman, self.configuration_name = wsman, configuration_name
        FakePool.created.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeWSMan:
    last = None

    def __init__(self, server, **kw):
        if FakeWSMan.fail:
            raise RuntimeError(FakeWSMan.fail)
        self.server, self.kw = server, kw
        FakeWSMan.last = self

    fail = None


def install_fake():
    ps = types.ModuleType("pypsrp.powershell")
    ps.PowerShell, ps.RunspacePool = FakePs, FakePool
    ws = types.ModuleType("pypsrp.wsman")
    ws.WSMan = FakeWSMan
    root = types.ModuleType("pypsrp")
    saved = {k: sys.modules.get(k) for k in ("pypsrp", "pypsrp.powershell", "pypsrp.wsman")}
    sys.modules.update({"pypsrp": root, "pypsrp.powershell": ps, "pypsrp.wsman": ws})
    return saved


def restore(saved):
    for key, value in saved.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value


class ConfigTests(unittest.TestCase):
    def test_standard_ist_aus(self):
        self.assertFalse(exchange.clean_config({})["enabled"])
        self.assertTrue(exchange.clean_config({})["verifyCert"])

    def test_bereinigt(self):
        cfg = exchange.clean_config({"enabled": True, "server": " EXCH01.x.local ", "auth": "NTLM", "port": "8443"})
        self.assertEqual((cfg["server"], cfg["auth"], cfg["port"]), ("EXCH01.x.local", "ntlm", 8443))

    def test_port_je_nach_ssl(self):
        self.assertEqual(exchange.clean_config({"ssl": False, "port": 0})["port"], 80)

    def test_ungueltiges(self):
        for bad in (
            {"enabled": True},
            {"server": "https://exch"},
            {"server": "exch;calc"},
            {"auth": "digest"},
            {"port": "abc"},
            {"port": 70000},
            {"domainController": "dc 1"},
        ):
            with self.assertRaises(ValueError, msg=str(bad)):
                exchange.clean_config(bad)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.saved = install_fake()
        FakePs.log, FakePs.next_errors, FakePs.next_output = [], [], ["x"]
        FakePool.created, FakeWSMan.fail, FakeWSMan.last = [], None, None

    def tearDown(self):
        restore(self.saved)

    def test_enable_mailbox_ruft_exchange_shell_auf(self):
        exchange.enable_mailbox(dict(CFG, database="DB1"), USER, "CN=Eva\\, Test,OU=A,DC=x", "dc1.x.local")
        self.assertEqual(
            FakePs.log,
            [
                (
                    "Enable-Mailbox",
                    {"Identity": "CN=Eva\\, Test,OU=A,DC=x", "Database": "DB1", "DomainController": "dc1.x.local"},
                )
            ],
        )
        self.assertEqual(FakePool.created[0].configuration_name, "Microsoft.Exchange")
        kw = FakeWSMan.last.kw
        self.assertEqual(
            (FakeWSMan.last.server, kw["path"], kw["ssl"], kw["port"], kw["auth"]),
            ("exch01.x.local", "/PowerShell", True, 443, "negotiate"),
        )
        self.assertEqual((kw["username"], kw["password"], kw["cert_validation"]), ("admin@x.local", "geheim", True))
        self.assertGreater(kw["read_timeout"], kw["operation_timeout"])

    def test_ohne_datenbank_und_dc(self):
        exchange.enable_mailbox(CFG, USER, "CN=a", "")
        self.assertEqual(FakePs.log[0][1], {"Identity": "CN=a"})

    def test_eigener_dc_hat_vorrang(self):
        exchange.enable_mailbox(dict(CFG, domainController="dc9.x.local"), USER, "CN=a", "dc1.x.local")
        self.assertEqual(FakePs.log[0][1]["DomainController"], "dc9.x.local")

    def test_zertifikatspruefung_abschaltbar(self):
        exchange.enable_mailbox(dict(CFG, verifyCert=False), USER, "CN=a")
        self.assertFalse(FakeWSMan.last.kw["cert_validation"])

    def test_exchange_fehler_wird_gemeldet(self):
        FakePs.next_errors = ["Das Postfach existiert bereits."]
        with self.assertRaises(exchange.ExchangeError) as ctx:
            exchange.enable_mailbox(CFG, USER, "CN=a")
        self.assertIn("existiert bereits", str(ctx.exception))

    def test_verbindungsfehler_ohne_passwort(self):
        FakeWSMan.fail = "Connection refused geheim"
        with self.assertRaises(exchange.ExchangeError) as ctx:
            exchange.enable_mailbox(CFG, USER, "CN=a")
        self.assertIn("nicht erreichbar", str(ctx.exception))
        FakeWSMan.fail = "401 Unauthorized"
        with self.assertRaises(exchange.ExchangeError) as ctx:
            exchange.enable_mailbox(CFG, USER, "CN=a")
        self.assertIn("Anmeldung abgelehnt", str(ctx.exception))

    def test_verbindungstest(self):
        self.assertIn("steht", exchange.check_connection(CFG, USER))
        self.assertEqual(FakePs.log[0], ("Get-Command", {"Name": "Enable-Mailbox"}))
        FakePs.next_output = []
        with self.assertRaises(exchange.ExchangeError) as ctx:
            exchange.check_connection(CFG, USER)
        self.assertIn("Mail Recipients", str(ctx.exception))

    def test_paket_fehlt(self):
        restore(self.saved)
        for key in ("pypsrp", "pypsrp.powershell", "pypsrp.wsman"):
            sys.modules[key] = None  # erzwingt ImportError
        try:
            with self.assertRaises(exchange.ExchangeError) as ctx:
                exchange.enable_mailbox(CFG, USER, "CN=a")
            self.assertIn("pypsrp", str(ctx.exception))
        finally:
            self.saved = install_fake()


if __name__ == "__main__":
    unittest.main()
