"""Shared test paths; makes sure the project is importable."""

import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def web_source():
    """Page and interface script together (since 2.3.0 the script is its own file, samonboarding/web/app.js)."""
    web = os.path.join(ROOT, "samonboarding", "web")
    parts = []
    for name in ("index.html", "app.js"):
        with open(os.path.join(web, name), encoding="utf-8") as fh:
            parts.append(fh.read())
    return "\n".join(parts)
