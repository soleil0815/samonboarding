"""Runs the smoke test (real FastAPI app, ASGI calls): security and cache headers of page and API."""

import os
import subprocess
import sys
import unittest

import _paths

try:
    import fastapi  # noqa: F401

    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


@unittest.skipUnless(HAVE_FASTAPI, "FastAPI not installed")
class SmokeHeaderTests(unittest.TestCase):
    def test_smoke_app(self):
        out = subprocess.run(  # noqa: S603 - fixed own test script
            [sys.executable, os.path.join(_paths.TESTS, "smoke_app.py")],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=_paths.ROOT,
        )
        self.assertEqual(out.returncode, 0, out.stdout[-2000:] + out.stderr[-2000:])
        self.assertIn("Rauchtest OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
