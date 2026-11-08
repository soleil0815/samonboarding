"""Smoke test with the REAL packages (FastAPI, Starlette): starts the application in memory and sends requests.

Run by update.sh when pinning new Python packages (the unit tests otherwise run with
stub modules). Not a unittest module (name does not start with test_), needs no network and no DC.

    python tests/smoke_app.py      -> exit code 0 = all good
"""

import asyncio
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def call(app, path, scheme="https", method="GET"):
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"srv:9500")],
        "client": ("127.0.0.1", 50000),
        "server": ("srv", 9500),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers = {k.decode().lower(): v.decode() for k, v in start.get("headers", [])}
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], headers, body


def main():
    os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="samonb-smoke-")
    os.environ.pop("ALLOW_HTTP", None)
    sys.path.insert(0, ROOT)
    from samonboarding.main import app

    problems = []

    def expect(cond, text):
        if not cond:
            problems.append(text)

    async def run():
        status, headers, body = await call(app, "/api/public-config")
        expect(status == 200, f"/api/public-config: Status {status} statt 200")
        try:
            json.loads(body or b"null")
        except ValueError:
            problems.append("/api/public-config liefert kein JSON")
        for name in ("content-security-policy", "x-frame-options", "x-content-type-options"):
            expect(name in headers, f"Sicherheits-Header {name} fehlt")
        expect(headers.get("cache-control") == "no-store", "Cache-Control no-store fehlt bei /api/")
        expect("total;dur=" in headers.get("server-timing", ""), "Server-Timing fehlt bei /api/")

        status, headers, _ = await call(app, "/api/public-config", scheme="http")
        expect(status == 403, f"HTTP ohne TLS: Status {status} statt 403")
        expect("x-frame-options" in headers, "Sicherheits-Header fehlen bei abgewiesener Anfrage")

        for path in ("/api/me", "/api/manual"):
            status, _, _ = await call(app, path)
            expect(status == 401, f"{path} ohne Anmeldung: Status {status} statt 401")

        status, _, _ = await call(app, "/api/login", method="POST")
        expect(status in (400, 401, 422), f"/api/login ohne Daten: Status {status}")

        status, _, body = await call(app, "/")
        expect(status == 200 and b"<html" in body.lower(), f"Startseite: Status {status}")
        status, headers, _ = await call(app, "/")
        expect("server-timing" not in headers, "Server-Timing nur bei /api/")

    asyncio.run(run())
    if problems:
        print("Rauchtest FEHLGESCHLAGEN:")
        for p in problems:
            print("  - " + p)
        return 1
    print("Rauchtest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
