"""HTTPS (certificate, start only with TLS), sessions (30 minutes of inactivity) and the reports API."""

import asyncio
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from fastapi import HTTPException  # noqa: E402

from samonboarding import config, reports, sessions, tls  # noqa: E402

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

ROOT = Path(_paths.ROOT)
ADMIN = {"username": "admin", "role": "Administrator", "sid": "s1", "password": "Geheim1!"}
OPERATOR = {"username": "op", "role": "Account Operator", "sid": "s2", "password": "x"}


@unittest.skipUnless(HAVE_CRYPTO, "cryptography nicht installiert")
class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert = os.path.join(self.tmp.name, "tls", "cert.pem")
        self.key = os.path.join(self.tmp.name, "tls", "key.pem")
        self.patches = [
            mock.patch.object(config, "TLS_CERT_FILE", self.cert),
            mock.patch.object(config, "TLS_KEY_FILE", self.key),
            mock.patch.object(config, "TLS_HOSTNAMES", ["samonboarding.firma.local", "10.0.10.20"]),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_create_and_reuse_self_signed(self):
        from cryptography import x509

        cert, key, self_signed = tls.ensure_certificate()
        self.assertTrue(self_signed)
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        with open(cert, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("samonboarding.firma.local", san.get_values_for_type(x509.DNSName))
        self.assertEqual([str(i) for i in san.get_values_for_type(x509.IPAddress)], ["10.0.10.20"])
        before = Path(cert).read_bytes()
        tls.ensure_certificate()
        self.assertEqual(Path(cert).read_bytes(), before)  # existing certificate is kept

    def test_only_one_file_is_an_error(self):
        os.makedirs(os.path.dirname(self.cert))
        open(self.cert, "w").close()
        with self.assertRaises(SystemExit):
            tls.ensure_certificate()


class ServeTests(unittest.TestCase):
    def test_data_not_writable_aborts(self):
        from samonboarding import serve

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(config, "DATA_DIR", Path(tmp) / "fehlt"):
            with self.assertLogs("samonboarding.serve", "CRITICAL"):
                self.assertFalse(serve.data_writable())
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(config, "DATA_DIR", Path(tmp)):
            self.assertTrue(serve.data_writable())
            self.assertEqual(os.listdir(tmp), [])

    def test_start_only_with_tls(self):
        from samonboarding import serve

        fake_uvicorn = mock.MagicMock()
        with mock.patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
            with mock.patch.object(tls, "ensure_certificate", return_value=("c.pem", "k.pem", True)):
                with (
                    mock.patch.object(tls, "activate") as activate,
                    mock.patch.object(serve, "data_writable", return_value=True),
                ):
                    serve.main()
        kwargs = fake_uvicorn.Config.call_args.kwargs
        self.assertEqual((kwargs["ssl_certfile"], kwargs["ssl_keyfile"]), ("c.pem", "k.pem"))
        self.assertEqual(kwargs["port"], config.HTTPS_PORT)
        self.assertFalse(kwargs["access_log"])
        server_config = fake_uvicorn.Config.return_value
        server_config.load.assert_called_once()
        activate.assert_called_once_with(server_config.ssl)  # live replacement hooked in
        fake_uvicorn.Server.return_value.run.assert_called_once()

    def test_docker_starts_https(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('CMD ["python", "-m", "samonboarding.serve"]', docker)
        self.assertIn("EXPOSE 9500", docker)
        self.assertIn('"${HTTPS_PORT:-9500}:${HTTPS_PORT:-9500}"', compose)
        self.assertIn('CMD ["/app/docker-entrypoint.sh", "healthcheck"]', docker)  # health check in the image
        self.assertNotIn("8000", compose)


class EnvFileTests(unittest.TestCase):
    """Own settings live in .env (not replaced on updates), not in docker-compose.yml."""

    def test_compose_reads_env_and_contains_no_own_values(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("    env_file:\n      - .env", compose)
        # no syntax that only newer Docker Compose versions understand (Synology & co.)
        self.assertNotIn("required:", compose)
        self.assertNotIn("path:", compose)
        # environment only for the file marker, no settings
        env_block = compose[compose.index("environment:") :].split("\n    ports:")[0]
        self.assertEqual(env_block.count(":"), 2, env_block)
        for key in ("AD_DOMAIN", "AD_DC_IP", "CUSTOM_OPERATOR_GROUP"):
            self.assertNotIn(key, compose)

    def test_example_contains_all_settings(self):
        import re

        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        keys = set()
        for line in example.splitlines():
            if line and not line.startswith("#"):
                # no comments after values (not every Docker version parses them the same way)
                self.assertRegex(line, r"^[A-Z_]+=[^#\s]*$")
                keys.add(line.split("=", 1)[0])
        documented = set(re.findall(r"^  ([A-Z_]{4,})\b", (ROOT / "samonboarding" / "config.py").read_text(), re.M))
        documented |= {"AD_DOMAIN", "AD_DC_IP", "CUSTOM_OPERATOR_GROUP", "TZ", "DOCKER_SUBNET"}
        documented -= {
            "DATA_DIR",
            "TLS_CERT_FILE",
            "TLS_KEY_FILE",
        }  # paths inside the container, deliberately not in .env
        self.assertEqual(documented - keys, set())

    def test_env_not_in_image_and_not_in_git(self):
        self.assertIn(".env", (ROOT / ".dockerignore").read_text(encoding="utf-8").split())
        self.assertIn(".env", (ROOT / ".gitignore").read_text(encoding="utf-8").split())

    def test_empty_values_give_default(self):
        from samonboarding.config import _env_bool, _env_int

        with mock.patch.dict(os.environ, {"X_BOOL": "", "X_INT": " "}):
            self.assertTrue(_env_bool("X_BOOL", True))
            self.assertEqual(_env_int("X_INT", 7), 7)


class HttpsMiddlewareTests(unittest.TestCase):
    def setUp(self):
        from samonboarding import main

        self.app = main.app

    def _mw(self, name):
        return [m for m in self.app.middlewares if m.__name__ == name][0]

    def _call(self, mw, scheme, env=None):
        from fastapi import Request

        class Resp:
            def __init__(self):
                self.headers = {}
                self.status_code = 200

        async def nxt(req):
            return Resp()

        with mock.patch.dict(os.environ, env or {}, clear=False):
            return asyncio.run(mw(Request(scheme=scheme, path="/api/me"), nxt))

    def test_http_is_rejected(self):
        if not hasattr(self.app, "middlewares"):
            self.skipTest("nur mit Ersatzmodulen pruefbar")
        mw = self._mw("_https_only")
        with mock.patch.dict(os.environ, {"ALLOW_HTTP": ""}):
            self.assertEqual(self._call(mw, "http").status_code, 403)
        self.assertEqual(self._call(mw, "https").status_code, 200)

    def _guard(self, method="POST", headers=None):
        from fastapi import Request

        class Resp:
            status_code = 200
            headers = {}

        async def nxt(req):
            return Resp()

        return asyncio.run(
            self._mw("_request_guard")(
                Request(scheme="https", path="/api/x", method=method, headers=headers or {}), nxt
            )
        )

    def test_without_length_and_range(self):
        if not hasattr(self.app, "middlewares"):
            self.skipTest("nur mit Ersatzmodulen pruefbar")
        own = {"host": "srv:9500", "origin": "https://srv:9500"}
        self.assertEqual(self._guard(headers=dict(own, **{"transfer-encoding": "chunked"})).status_code, 411)
        from fastapi import Request

        seen = {}

        class Resp:
            status_code = 200
            headers = {}

        async def nxt(req):
            seen["headers"] = req.scope["headers"]
            return Resp()

        req = Request(scheme="https", path="/static/x.css", headers={"host": "srv:9500", "range": "bytes=0-1,2-3"})
        asyncio.run(self._mw("_request_guard")(req, nxt))
        self.assertNotIn(b"range", [k for k, _ in seen["headers"]])  # CVE-2025-62727

    def test_foreign_site_and_oversized_requests(self):
        if not hasattr(self.app, "middlewares"):
            self.skipTest("nur mit Ersatzmodulen pruefbar")
        own = {"host": "srv:9500", "origin": "https://srv:9500"}
        self.assertEqual(self._guard(headers=own).status_code, 200)
        self.assertEqual(self._guard(headers={"host": "srv:9500", "origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(
            self._guard(headers={"host": "srv:9500", "referer": "https://evil.example/x"}).status_code, 403
        )
        self.assertEqual(self._guard(headers={"host": "srv:9500", "referer": "https://srv:9500/"}).status_code, 200)
        self.assertEqual(
            self._guard(method="GET", headers={"host": "srv:9500", "origin": "https://evil.example"}).status_code, 200
        )
        self.assertEqual(self._guard(headers=dict(own, **{"content-length": str(50 * 1024 * 1024)})).status_code, 413)

    def test_no_api_docs_without_login(self):
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        for needed in ("docs_url=None", "redoc_url=None", "openapi_url=None"):
            self.assertIn(needed, main)

    def test_hsts_only_with_own_certificate(self):
        if not hasattr(self.app, "middlewares"):
            self.skipTest("nur mit Ersatzmodulen pruefbar")
        mw = self._mw("_security_headers")
        own = self._call(mw, "https", {"SAMONBOARDING_TLS_SELF_SIGNED": "0"})
        self.assertIn("Strict-Transport-Security", own.headers)
        selfsigned = self._call(mw, "https", {"SAMONBOARDING_TLS_SELF_SIGNED": "1"})
        self.assertNotIn("Strict-Transport-Security", selfsigned.headers)


class SessionTests(unittest.TestCase):
    def tearDown(self):
        sessions.active_sessions.clear()

    def test_inactivity_ends_session_activity_extends_it(self):
        token = sessions.create_session({"username": "admin"})
        s = sessions.active_sessions[token]
        self.assertAlmostEqual(s["expires"], time.time() + config.SESSION_IDLE_SECONDS, delta=5)
        s["expires"] = time.time() + 10  # almost expired
        sessions.get_current_user(token)
        self.assertGreater(sessions.active_sessions[token]["expires"], time.time() + config.SESSION_IDLE_SECONDS - 5)
        sessions.active_sessions[token]["expires"] = time.time() - 1
        with self.assertRaises(HTTPException) as ctx:
            sessions.get_current_user(token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertNotIn(token, sessions.active_sessions)

    def test_ui_logs_out(self):
        html = (ROOT / "samonboarding" / "web" / "index.html").read_text(encoding="utf-8")
        for needed in (
            "function startIdleWatch",
            "function sessionEnded",
            "res.status === 401",
            "startIdleWatch(data.idleMinutes)",
        ):
            self.assertIn(needed, html)


class ReportsApiTests(unittest.TestCase):
    def setUp(self):
        from samonboarding.routers import reports as rr

        self.rr = rr
        self.tmp = tempfile.TemporaryDirectory()
        self.p = mock.patch.object(config, "REPORTS_DB_FILE", os.path.join(self.tmp.name, "reports.db"))
        self.p.start()
        # the role is checked live in AD on deletion - here without a DC: assume still Administrator
        from samonboarding.routers import deletion

        self.recheck = mock.patch.object(deletion, "recheck_admin")
        self.recheck_mock = self.recheck.start()

    def tearDown(self):
        self.recheck.stop()
        self.p.stop()
        self.tmp.cleanup()

    def test_admins_only(self):
        for fn in (
            lambda: self.rr.reports_summary(OPERATOR),
            lambda: self.rr.reports_audit(user=OPERATOR),
            lambda: self.rr.reports_log(user=OPERATOR),
        ):
            with self.assertRaises(HTTPException) as ctx:
                fn()
            self.assertEqual(ctx.exception.status_code, 403)

    def test_read(self):
        reports.write_audit("admin", "login")
        reports.write_log("ERROR", "x", "kaputt")
        self.assertEqual(self.rr.reports_audit(user=ADMIN)["entries"][0]["action"], "login")
        self.assertEqual(self.rr.reports_log(level="error", user=ADMIN)["entries"][0]["message"], "kaputt")
        summary = self.rr.reports_summary(ADMIN)
        self.assertEqual((summary["audit"]["retentionDays"], summary["log"]["retentionDays"]), (365, 90))

    def _delete(self, **kw):
        from samonboarding.models import ReportsDeleteModel

        return self.rr.reports_delete(ReportsDeleteModel(**kw), ADMIN)

    def test_delete_with_password_and_audit_trail(self):
        from datetime import datetime, timedelta, timezone

        reports.write_audit("admin", "alt", ts=datetime.now(timezone.utc) - timedelta(days=40))
        reports.write_audit("admin", "neu")
        with self.assertRaises(HTTPException) as ctx:
            self._delete(kind="audit", olderThanDays=30, password="falsch")
        self.assertEqual(ctx.exception.status_code, 403)
        out = self._delete(kind="audit", olderThanDays=30, password=ADMIN["password"])
        self.assertEqual(out["removed"], 1)
        actions = [e["action"] for e in reports.query_audit()[0]]
        self.assertIn("reports-delete", actions)  # the deletion itself is recorded
        self.assertIn("neu", actions)
        self.assertNotIn("alt", actions)

    def test_delete_all_and_invalid_input(self):
        reports.write_log("INFO", "x", "a")
        self.assertEqual(self._delete(kind="log", olderThanDays=0, password=ADMIN["password"])["removed"], 1)
        for kw in ({"kind": "foo"}, {"kind": "log", "olderThanDays": -1}):
            with self.assertRaises(HTTPException) as ctx:
                self._delete(password=ADMIN["password"], **kw)
            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
