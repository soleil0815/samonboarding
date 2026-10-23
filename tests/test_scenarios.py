"""Fuehrt die Szenario-Skripte (simuliertes AD und Dateiserver) als eigene Prozesse aus.

Die Szenarien brauchen keine installierten Pakete: fastapi, ldap3 und pydantic werden durch kleine Ersatzmodule
in tests/scenarios/stubs ersetzt. Sie pruefen die Anwendungslogik (Rollen, Onboarding, Loeschen usw.) im Ganzen.
"""

import glob
import os
import subprocess
import sys
import unittest

import _paths

SCENARIOS = os.path.join(_paths.TESTS, "scenarios")


def run(script):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run(
        [sys.executable, os.path.join(SCENARIOS, script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=300,
        check=False,
    )
    return done.returncode, done.stdout + done.stderr


class ScenarioTests(unittest.TestCase):
    pass


def make_test(script):
    def test(self):
        code, output = run(script)
        failed = [line for line in output.splitlines() if line.startswith("FAIL")]
        self.assertEqual(failed, [], "\n".join(failed))
        self.assertEqual(code, 0, output[-2000:])

    return test


for path in sorted(glob.glob(os.path.join(SCENARIOS, "scenario_*.py"))):
    name = os.path.basename(path)
    setattr(ScenarioTests, "test_" + name[len("scenario_") : -3], make_test(name))


if __name__ == "__main__":
    unittest.main()
