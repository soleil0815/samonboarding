"""License: copyright notice as in SAMAUDIT (NOTICE, file headers), complete list of third-party components,
license texts of the fonts and icons in the image."""

import json
import re
import subprocess
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)
AUTHOR = "Die SAMONBOARDING-Autoren"
HEADER = ["# SPDX-License-Identifier: AGPL-3.0-or-later", f"# Copyright (C) 2026 {AUTHOR}"]


def program_files():
    """All program files: the package, the entry point, the scripts in the image and the build scripts."""
    files = [ROOT / "app.py", ROOT / "docker-entrypoint.sh", ROOT / "update.sh"]
    files += sorted((ROOT / "samonboarding").rglob("*.py"))
    files += sorted(p for p in (ROOT / "scripts").iterdir() if p.suffix in (".py", ".sh"))
    return [p for p in files if "__pycache__" not in p.parts]


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


class LicenseTests(unittest.TestCase):
    def test_header_in_every_program_file(self):
        files = program_files()
        self.assertGreater(len(files), 40)
        for path in files:
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines[0].startswith("#!"):
                lines = lines[1:]
            self.assertEqual(lines[:2], HEADER, path.relative_to(ROOT))

    def test_notice_and_license(self):
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn(f"Copyright (C) 2026 {AUTHOR} / The SAMONBOARDING authors", notice)
        self.assertIn("SPDX-License-Identifier: AGPL-3.0-or-later", notice)
        self.assertIn("https://github.com/soleil0815/samonboarding", notice)
        self.assertIn("THIRD-PARTY-NOTICES.md", notice)
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["license"], "AGPL-3.0-or-later")
        for name in ("README.de.md", "README.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("(NOTICE)", text, name)
            self.assertIn("(THIRD-PARTY-NOTICES.md)", text, name)

    def test_no_personal_name_as_author(self):
        """The author is only the neutral designation - no name, no e-mail address."""
        for path in [*program_files(), ROOT / "NOTICE", ROOT / "THIRD-PARTY-NOTICES.md"]:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip("# ").startswith("Copyright (C) 2026"):
                    self.assertIn(AUTHOR, line, path.relative_to(ROOT))
                    self.assertNotIn("@", line, path.relative_to(ROOT))

    def test_notices_in_image(self):
        """NOTICE and THIRD-PARTY-NOTICES.md are included in the image (COPY . . - not excluded)."""
        ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        for name in ("LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md"):
            self.assertNotIn(name, ignored)
            self.assertTrue((ROOT / name).exists(), name)
        self.assertIn("COPY . .", (ROOT / "Dockerfile").read_text(encoding="utf-8"))

    def test_every_python_dependency_listed(self):
        notices = norm((ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8"))
        packages = re.findall(r"^([A-Za-z0-9_.-]+)==", (ROOT / "requirements.txt").read_text(encoding="utf-8"), re.M)
        self.assertGreater(len(packages), 10)
        for name in packages:
            self.assertRegex(notices, rf"(?<![a-z0-9-]){re.escape(norm(name))}(?![a-z0-9-])", name)

    def test_fonts_and_icons_with_license_text(self):
        notices = (ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        deps = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["dependencies"]
        files = {
            "@fontsource/manrope": "LICENSE-Manrope.txt",
            "@fontsource/jetbrains-mono": "LICENSE-JetBrains-Mono.txt",
            "@fortawesome/fontawesome-free": "LICENSE-Font-Awesome.txt",
            "tailwindcss": "LICENSE-Tailwind-CSS.txt",
        }
        self.assertEqual(sorted(deps), sorted(files))  # new packages need an entry
        for package, target in files.items():
            self.assertIn(package, notices)
            self.assertIn(f"`{target}`", notices)
            copy = rf"cp node_modules/{re.escape(package)}/LICENSE(\.txt)? dist/vendor/licenses/{target}"
            self.assertRegex(docker, copy)
        static = Path("/app/static/vendor")
        if static.is_dir():  # only when testing inside the image
            for target in files.values():
                self.assertGreater((static / "licenses" / target).stat().st_size, 500, target)

    def test_scripts_still_run(self):
        """The header comes after the shebang line, the scripts stay valid."""
        for name in ("update.sh", "docker-entrypoint.sh", "scripts/install-trivy.sh"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertTrue(text.startswith("#!/bin/sh\n"), name)
            subprocess.run(["sh", "-n", str(ROOT / name)], check=True)


if __name__ == "__main__":
    unittest.main()
