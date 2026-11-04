"""Reproducible build: exact versions (Python, npm, base images) and update.sh."""

import json
import re
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)


def lines(name):
    return [
        line.strip()
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


class PythonPinsTests(unittest.TestCase):
    def test_all_packages_exact(self):
        reqs = lines("requirements.txt")
        self.assertGreater(len(reqs), 10)  # including dependencies, not only the direct packages
        for req in reqs:
            self.assertRegex(req, r"^[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.+-]*$")
        names = {r.split("==")[0].lower().replace("_", "-") for r in reqs}
        for direct in ("fastapi", "uvicorn", "ldap3", "pydantic", "smbprotocol", "pypsrp", "starlette", "cryptography"):
            self.assertIn(direct, names)

    def test_direct_packages_are_in_lock_file(self):
        locked = {r.split("==")[0].lower().replace("_", "-") for r in lines("requirements.txt")}
        for req in lines("requirements.in"):
            name = re.split(r"[<>=!~ ]", req, maxsplit=1)[0].lower().replace("_", "-")
            self.assertIn(name, locked)

    def test_dev_tools_exact(self):
        for req in lines("requirements-dev.txt"):
            if not req.startswith("-r"):
                self.assertIn("==", req)

    def test_starlette_at_least_1_3_1(self):
        """Vulnerabilities up to Starlette 1.3.0 (CVE-2025-62727, CVE-2026-54283 and others)."""
        text = (ROOT / "requirements.in").read_text(encoding="utf-8")
        self.assertIn("starlette>=1.3.1,<2", text)
        self.assertRegex(text, r"(?m)^fastapi>=0\.129")

    def test_pinning_only_on_github_or_by_script(self):
        """Nothing is pinned or built on the server - scripts/pins.py does that (GitHub, development)."""
        self.assertTrue((ROOT / "scripts" / "pins.py").exists())
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertNotIn("pins.py", text)
        self.assertIn("--lock no longer exists", text)

    def test_dockerfile_installs_only_lock_file(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("pip install --no-cache-dir --no-deps -r requirements.txt && pip check", docker)


class ImagePinsTests(unittest.TestCase):
    def test_base_images_with_version_and_digest(self):
        lock = dict(
            line.split("=", 1)
            for line in (ROOT / "images.lock").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )
        self.assertRegex(lock["PYTHON_IMAGE"], r"^python:3\.13\.\d+-slim-trixie@sha256:[0-9a-f]{64}$")
        self.assertRegex(lock["NODE_IMAGE"], r"^node:24\.\d+\.\d+-trixie-slim@sha256:[0-9a-f]{64}$")
        self.assertRegex(lock["DEBIAN_SNAPSHOT"], r"^\d{8}T\d{6}Z$")
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for key in ("PYTHON_IMAGE", "NODE_IMAGE", "DEBIAN_SNAPSHOT"):
            self.assertIn(f"ARG {key}\n", docker)  # no default: no build with a changing tag
        self.assertIn("FROM ${PYTHON_IMAGE}", docker)
        self.assertIn("FROM ${NODE_IMAGE} AS assets", docker)
        self.assertNotRegex(docker, r"FROM (python|node):")
        # all Debian packages (including those of the base image) from the fixed snapshot, only from its own release
        self.assertIn("snapshot.debian.org/archive/%s/%s", docker)
        self.assertIn("full-upgrade", docker)
        self.assertIn("$VERSION_CODENAME-security", docker)
        self.assertNotIn("APT_REFRESH", docker)
        packages = lines("os-packages.lock")
        self.assertGreater(len(packages), 50)
        for line in packages:
            self.assertRegex(line, r"^(amd64|arm64) [a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?=[0-9A-Za-z.+~:-]+$")
        self.assertEqual({line.split(" ")[0] for line in packages}, {"amd64", "arm64"})


class NpmPinsTests(unittest.TestCase):
    def test_package_json_and_lock_file_exact(self):
        deps = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["dependencies"]
        self.assertTrue(deps["tailwindcss"].startswith("3."))  # major version stays
        self.assertTrue(deps["@fortawesome/fontawesome-free"].startswith("6."))
        for name, version in deps.items():
            self.assertRegex(version, r"^\d+\.\d+\.\d+$", name)
        lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["packages"][""]["dependencies"], deps)  # npm ci requires exactly this
        for path, info in lock["packages"].items():
            if path:  # indirect packages too, with exact version and checksum
                self.assertRegex(info["version"], r"^\d+\.\d+\.\d+", path)
                self.assertTrue(info.get("integrity", "").startswith("sha512-"), path)
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("npm ci --no-audit --no-fund --ignore-scripts", docker)


class ContainerTests(unittest.TestCase):
    def test_container_without_root(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER ${APP_UID}:${APP_UID}", docker)
        self.assertLess(docker.index("pip install"), docker.index("USER "))  # install first, then drop privileges
        self.assertIn("ARG APP_UID=10001", docker)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("- ALL", compose)

    def test_backups_not_in_image_or_git(self):
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
        self.assertIn("backups/", dockerignore)
        self.assertIn("data/", dockerignore)
        self.assertIn("backups/", (ROOT / ".gitignore").read_text(encoding="utf-8").split())


if __name__ == "__main__":
    unittest.main()
