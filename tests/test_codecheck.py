"""Code-Pruefung: ruff mit Sicherheits- und Fehlerregeln, Typpruefung mit pyright im Workflow - beides vor dem Bau,
mit festen Versionen."""

import re
import unittest
from pathlib import Path

import _paths
import tomllib

ROOT = Path(_paths.ROOT)


def pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def lint_step():
    flow = (ROOT / ".github" / "workflows" / "image.yml").read_text(encoding="utf-8")
    start = flow.index("- name: Check code (ruff, pyright)")
    return flow[start : flow.index("- name:", start + 10)]


class RuffTests(unittest.TestCase):
    def test_regeln(self):
        lint = pyproject()["tool"]["ruff"]["lint"]
        for rule in ("E", "F", "I", "W", "S", "B", "UP", "SIM"):  # S = Sicherheitsmuster, B = typische Fehler
            self.assertIn(rule, lint["select"])
        self.assertIn("fastapi.Depends", lint["flake8-bugbear"]["extend-immutable-calls"])

    def test_sicherheitsregeln_im_programm_nicht_pauschal_aus(self):
        """Ausnahmen gelten nur fuer Tests und Bau-Skripte; im Programm steht jede Ausnahme mit Grund an der Zeile."""
        for pattern, rules in pyproject()["tool"]["ruff"]["lint"]["per-file-ignores"].items():
            if pattern.startswith("samonboarding"):
                self.assertFalse([r for r in rules if r.startswith("S") or r.startswith("B")], pattern)
        for path in (ROOT / "samonboarding").rglob("*.py"):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "# noqa" in line:
                    self.assertRegex(line, r"# noqa: [A-Z]+\d+", f"{path.name}:{number} ohne Regel")

    def test_kein_sql_mit_fremden_tabellennamen(self):
        from samonboarding import reports

        with self.assertRaises(ValueError):
            reports._page("audit; DROP TABLE audit", [], [], None, 10, dict)


class PyrightTests(unittest.TestCase):
    def test_konfiguration(self):
        conf = pyproject()["tool"]["pyright"]
        self.assertEqual(conf["include"], ["samonboarding", "app.py", "scripts"])
        self.assertEqual(conf["typeCheckingMode"], "basic")
        image = (ROOT / "images.lock").read_text(encoding="utf-8")
        version = re.search(r"PYTHON_IMAGE=python:(\d+\.\d+)\.", image).group(1)
        self.assertEqual(conf["pythonVersion"], version)  # gleiche Python-Version wie im Image

    def test_im_workflow_mit_den_paketen_des_images(self):
        step = lint_step()
        self.assertIn("pip install --quiet --disable-pip-version-check --no-deps -r requirements.txt", step)
        self.assertIn("\"pyright==$(sed -n 's/^pyright==//p' requirements-dev.txt)\"", step)
        self.assertIn("/tmp/lint/bin/pyright --pythonpath /tmp/lint/bin/python", step)
        self.assertLess(step.index("ruff check ."), step.index("/tmp/lint/bin/pyright"))
        self.assertRegex((ROOT / "requirements-dev.txt").read_text(encoding="utf-8"), r"(?m)^pyright==\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
