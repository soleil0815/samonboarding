"""Lizenz: Urheber-Hinweis wie bei SAMAUDIT (NOTICE, Kopfzeilen), vollstaendige Liste der Fremdkomponenten,
Lizenztexte der Schriften und Icons im Image."""

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
    """Alle Programmdateien: das Paket, der Einstiegspunkt, die Skripte im Image und die Bau-Skripte."""
    files = [ROOT / "app.py", ROOT / "docker-entrypoint.sh", ROOT / "update.sh"]
    files += sorted((ROOT / "samonboarding").rglob("*.py"))
    files += sorted(p for p in (ROOT / "scripts").iterdir() if p.suffix in (".py", ".sh"))
    return [p for p in files if "__pycache__" not in p.parts]


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


class LicenseTests(unittest.TestCase):
    def test_kopfzeile_in_jeder_programmdatei(self):
        files = program_files()
        self.assertGreater(len(files), 40)
        for path in files:
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines[0].startswith("#!"):
                lines = lines[1:]
            self.assertEqual(lines[:2], HEADER, path.relative_to(ROOT))

    def test_notice_und_lizenz(self):
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

    def test_kein_personenname_als_urheber(self):
        """Urheber ist nur die neutrale Bezeichnung - kein Name, keine E-Mail-Adresse."""
        for path in [*program_files(), ROOT / "NOTICE", ROOT / "THIRD-PARTY-NOTICES.md"]:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip("# ").startswith("Copyright (C) 2026"):
                    self.assertIn(AUTHOR, line, path.relative_to(ROOT))
                    self.assertNotIn("@", line, path.relative_to(ROOT))

    def test_hinweise_im_image(self):
        """NOTICE und THIRD-PARTY-NOTICES.md kommen mit ins Image (COPY . . - nicht ausgeschlossen)."""
        ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        for name in ("LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md"):
            self.assertNotIn(name, ignored)
            self.assertTrue((ROOT / name).exists(), name)
        self.assertIn("COPY . .", (ROOT / "Dockerfile").read_text(encoding="utf-8"))

    def test_jede_python_abhaengigkeit_aufgefuehrt(self):
        notices = norm((ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8"))
        packages = re.findall(r"^([A-Za-z0-9_.-]+)==", (ROOT / "requirements.txt").read_text(encoding="utf-8"), re.M)
        self.assertGreater(len(packages), 10)
        for name in packages:
            self.assertRegex(notices, rf"(?<![a-z0-9-]){re.escape(norm(name))}(?![a-z0-9-])", name)

    def test_schriften_und_icons_mit_lizenztext(self):
        notices = (ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        deps = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["dependencies"]
        files = {
            "@fontsource/manrope": "LICENSE-Manrope.txt",
            "@fontsource/jetbrains-mono": "LICENSE-JetBrains-Mono.txt",
            "@fortawesome/fontawesome-free": "LICENSE-Font-Awesome.txt",
            "tailwindcss": "LICENSE-Tailwind-CSS.txt",
        }
        self.assertEqual(sorted(deps), sorted(files))  # neue Pakete brauchen einen Eintrag
        for package, target in files.items():
            self.assertIn(package, notices)
            self.assertIn(f"`{target}`", notices)
            copy = rf"cp node_modules/{re.escape(package)}/LICENSE(\.txt)? dist/vendor/licenses/{target}"
            self.assertRegex(docker, copy)
        static = Path("/app/static/vendor")
        if static.is_dir():  # nur bei den Tests im Image
            for target in files.values():
                self.assertGreater((static / "licenses" / target).stat().st_size, 500, target)

    def test_skripte_laufen_noch(self):
        """Die Kopfzeile steht nach der Shebang-Zeile, die Skripte bleiben gueltig."""
        for name in ("update.sh", "docker-entrypoint.sh", "scripts/install-trivy.sh"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertTrue(text.startswith("#!/bin/sh\n"), name)
            subprocess.run(["sh", "-n", str(ROOT / name)], check=True)


if __name__ == "__main__":
    unittest.main()
