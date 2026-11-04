"""Ready for a public repository: contribution rules, issue forms, no blank issues, security reports only private."""

import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)
GITHUB = ROOT / ".github"


class PublicRepoTests(unittest.TestCase):
    def test_contributing(self):
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        for needed in ("SECURITY.md", "AGPL-3.0-or-later", "git commit -s", "No real data", "read-only token"):
            self.assertIn(needed, text)
        for name in ("README.md", "README.de.md"):
            self.assertIn("(CONTRIBUTING.md)", (ROOT / name).read_text(encoding="utf-8"), name)

    def test_issue_forms(self):
        # (no YAML parser: the tests also run in the image, which has no PyYAML)
        config = (GITHUB / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
        self.assertIn("blank_issues_enabled: false\n", config)
        self.assertIn("url: https://github.com/soleil0815/samonboarding/security/advisories/new\n", config)
        form = (GITHUB / "ISSUE_TEMPLATE" / "bug_report.yml").read_text(encoding="utf-8")
        for needed in ("version", "directory", "steps", "expected"):
            self.assertIn(f"    id: {needed}\n", form)
        self.assertIn("**Security vulnerabilities:** please do not report them here", form)
        self.assertIn("git commit -s", (GITHUB / "pull_request_template.md").read_text(encoding="utf-8"))

    def test_example_group_explained(self):
        """CO-ADMIN is only an example name - the guide says so."""
        self.assertIn("CO-ADMIN is only an example", (ROOT / ".env.example").read_text(encoding="utf-8"))
        self.assertIn("`CO-ADMIN` is only an example", (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn("`CO-ADMIN` ist nur ein Beispiel", (ROOT / "README.de.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
