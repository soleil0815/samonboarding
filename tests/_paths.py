"""Gemeinsame Pfade der Tests; sorgt dafuer, dass das Projekt importierbar ist."""

import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
