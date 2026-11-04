"""Code checks: ruff with security and bug rules, type checking with pyright in the workflow - both before the build,
with pinned versions."""

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
    def test_rules(self):
        lint = pyproject()["tool"]["ruff"]["lint"]
        for rule in ("E", "F", "I", "W", "S", "B", "UP", "SIM"):  # S = security patterns, B = common bugs
            self.assertIn(rule, lint["select"])
        self.assertIn("fastapi.Depends", lint["flake8-bugbear"]["extend-immutable-calls"])

    def test_security_rules_not_disabled_wholesale_in_program(self):
        """Exemptions only for tests and build scripts; in the program each exemption is on its line with a reason."""
        for pattern, rules in pyproject()["tool"]["ruff"]["lint"]["per-file-ignores"].items():
            if pattern.startswith("samonboarding"):
                self.assertFalse([r for r in rules if r.startswith("S") or r.startswith("B")], pattern)
        for path in (ROOT / "samonboarding").rglob("*.py"):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "# noqa" in line:
                    self.assertRegex(line, r"# noqa: [A-Z]+\d+", f"{path.name}:{number} ohne Regel")

    def test_no_sql_with_foreign_table_names(self):
        from samonboarding import reports

        with self.assertRaises(ValueError):
            reports._page("audit; DROP TABLE audit", [], [], None, 10, dict)


class PyrightTests(unittest.TestCase):
    def test_configuration(self):
        conf = pyproject()["tool"]["pyright"]
        self.assertEqual(conf["include"], ["samonboarding", "app.py", "scripts"])
        self.assertEqual(conf["typeCheckingMode"], "basic")
        image = (ROOT / "images.lock").read_text(encoding="utf-8")
        version = re.search(r"PYTHON_IMAGE=python:(\d+\.\d+)\.", image).group(1)
        self.assertEqual(conf["pythonVersion"], version)  # same Python version as in the image

    def test_in_workflow_with_the_image_packages(self):
        step = lint_step()
        self.assertIn("pip install --quiet --disable-pip-version-check --no-deps -r requirements.txt", step)
        self.assertIn("\"pyright==$(sed -n 's/^pyright==//p' requirements-dev.txt)\"", step)
        self.assertIn("/tmp/lint/bin/pyright --pythonpath /tmp/lint/bin/python", step)
        self.assertLess(step.index("ruff check ."), step.index("/tmp/lint/bin/pyright"))
        self.assertRegex((ROOT / "requirements-dev.txt").read_text(encoding="utf-8"), r"(?m)^pyright==\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
