"""Oberflaechen-Logik (JavaScript in index.html) mit einer einfachen Fake-DOM-Umgebung unter Node.

Wird uebersprungen, wenn Node.js nicht installiert ist.
"""

import glob
import os
import shutil
import subprocess
import unittest

import _paths

UI = os.path.join(_paths.TESTS, "ui")
NODE = shutil.which("node")


class UiTests(unittest.TestCase):
    pass


def make_test(path):
    def test(self):
        done = subprocess.run([NODE, path], capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
        output = done.stdout + done.stderr
        self.assertEqual(done.returncode, 0, output[-2000:])
        self.assertNotIn("Assertion failed", output)
        self.assertIn("fertig", output)

    return unittest.skipUnless(NODE, "Node.js nicht installiert")(test)


for file in sorted(glob.glob(os.path.join(UI, "*.test.js"))):
    setattr(UiTests, "test_" + os.path.basename(file)[: -len(".test.js")], make_test(file))


if __name__ == "__main__":
    unittest.main()
