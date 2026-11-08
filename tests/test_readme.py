"""README: images present, with descriptions, small enough, not in the image."""

import re
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


class ReadmeImageTests(unittest.TestCase):
    def test_images_in_both_languages(self):
        for name, suffix in (("README.de.md", ""), ("README.md", "-en")):
            text = (ROOT / name).read_text(encoding="utf-8")
            images = IMAGE_RE.findall(text)
            self.assertEqual(
                [path for _, path in images],
                [f"docs/images/{n}{suffix}.png" for n in ("anmeldung", "start", "onboarding", "loeschen")],
                name,
            )
            for alt, path in images:
                self.assertGreater(len(alt), 20, path)  # description for screen readers
                file = ROOT / path
                self.assertTrue(file.exists(), path)
                self.assertTrue(file.read_bytes().startswith(b"\x89PNG"), path)
                self.assertLess(file.stat().st_size, 500_000, path)

    def test_images_not_in_docker_image(self):
        self.assertIn("docs/", (ROOT / ".dockerignore").read_text(encoding="utf-8").split())


if __name__ == "__main__":
    unittest.main()
