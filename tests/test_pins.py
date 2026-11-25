"""scripts/pins.py: version limits, security update numbering, plan, Trivy (simulated) and base end-of-life warning."""

import datetime as dt
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import _paths

ROOT = Path(_paths.ROOT)
sys.path.insert(0, str(ROOT / "scripts"))
import pins  # noqa: E402

from samonboarding.routers import news  # noqa: E402

PY = "python:3.13.16-slim-trixie@sha256:" + "a" * 64
NODE = "node:24.21.0-trixie-slim@sha256:" + "b" * 64


def lock(py=PY, node=NODE, snapshot="20261025T040000Z"):
    return f"PYTHON_IMAGE={py}\nNODE_IMAGE={node}\nDEBIAN_SNAPSHOT={snapshot}\n"


def npm_lock(**versions):
    packages = {"": {"dependencies": {}}}
    for name, version in versions.items():
        packages[f"node_modules/{name.replace('__', '/')}"] = {"version": version}
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = pins.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class LimitTests(unittest.TestCase):
    def test_limits_within_major_version(self):
        allowed = [("2.9.1", "2.9.2"), ("2.9.1", "2.99.0"), ("1.14.0", "1.17.0"), ("50.0.2", "50.1.0")]
        forbidden = [("2.9.1", "3.0.0"), ("1.14.0", "2.0.0")]
        for old, new in allowed:
            self.assertTrue(pins.within_limit(old, new), (old, new))
        for old, new in forbidden:
            self.assertFalse(pins.within_limit(old, new), (old, new))

    def test_before_1_0_within_minor_version(self):
        self.assertTrue(pins.within_limit("0.54.0", "0.54.9"))
        self.assertTrue(pins.within_limit("0.162.0", "0.162.3"))
        self.assertFalse(pins.within_limit("0.54.0", "0.55.0"))
        self.assertFalse(pins.within_limit("0.162.0", "0.163.0"))
        self.assertEqual(pins.upper_bound("0.54.0"), "0.55")
        self.assertEqual(pins.upper_bound("2.9.1"), "3")

    def test_calendar_versions_without_limit(self):
        """Root certificates (certifi) and time zone data (tzdata) may always be updated to the latest version."""
        self.assertTrue(pins.within_limit("2026.6.17", "2026.10.23"))
        self.assertTrue(pins.within_limit("2025.2", "2026.1"))
        self.assertIsNone(pins.upper_bound("2026.10.23"))
        self.assertTrue(pins.is_calendar("2025.2"))
        self.assertFalse(pins.is_calendar("50.0.2"))

    def test_python_limits_from_lock_file(self):
        text = "# Kopf\ncertifi==2026.10.23\nldap3==2.9.1\nuvicorn==0.54.0\npydantic_core==2.50.1\n"
        constraints = pins.python_constraints(text).splitlines()
        self.assertEqual(
            constraints,
            ["certifi>=2026.10.23", "ldap3>=2.9.1,<3", "uvicorn>=0.54.0,<0.55", "pydantic_core>=2.50.1,<3"],
        )

    def test_npm_ranges(self):
        self.assertEqual(pins.npm_range("3.4.17"), "^3.4.17")
        self.assertEqual(pins.npm_range("0.3.2"), "~0.3.2")

    def test_base_images_stay_in_their_series(self):
        py_tags = ["3.13.16-slim-trixie", "3.13.17-slim-trixie", "3.13.9-slim-trixie", "3.14.1-slim-trixie",
                   "3.13.18-slim-bookworm", "3.13-slim-trixie", "3.13.18rc1-slim-trixie", "3.13.17-trixie"]  # fmt: skip
        self.assertEqual(pins.newest_python_tag(("3", "13", "trixie"), py_tags), "3.13.17-slim-trixie")
        node_tags = ["24.21.0-trixie-slim", "24.22.1-trixie-slim", "24.9.0-trixie-slim", "25.1.0-trixie-slim",
                     "24.23.0-bookworm-slim", "24-trixie-slim", "24.22.1-trixie"]  # fmt: skip
        self.assertEqual(pins.newest_node_tag(("24", "trixie"), node_tags), "24.22.1-trixie-slim")
        with self.assertRaises(pins.PinError):
            pins.newest_python_tag(("3", "13", "trixie"), ["3.14.1-slim-trixie"])

    def test_tag_without_patch_version_is_read_as_series(self):
        self.assertEqual(pins.python_series("3.13-slim-trixie"), ("3", "13", "trixie"))
        self.assertEqual(pins.node_series("24-trixie-slim"), ("24", "trixie"))
        with self.assertRaises(pins.PinError):
            pins.python_series("3.13-trixie")  # not a slim image


class CompareTests(unittest.TestCase):
    def base(self):
        return {
            "images.lock": lock(),
            "os-packages.lock": "libssl3t64=3.5.1-1\nbash=5.2.37-2\n",
            "requirements.txt": "uvicorn==0.54.0\ncertifi==2026.6.17\n",
            "package-lock.json": npm_lock(tailwindcss="3.4.17"),
        }

    def test_debian_packages_per_architecture(self):
        """Debian rebuilds some packages for only one architecture (+b1) - both versions are tracked."""
        text = "# Kopf\namd64 grep=3.11-4\narm64 grep=3.11-4+b1\namd64 bash=5.2\narm64 bash=5.2\n"
        self.assertEqual(pins.parse_os_lock(text), {"bash": "5.2", "grep": "amd64 3.11-4, arm64 3.11-4+b1"})
        self.assertEqual(pins.parse_os_lock_archs(text)["arm64"]["grep"], "3.11-4+b1")
        written = pins.os_lock_text(pins.parse_os_lock_archs(text), "20261025T040000Z")
        self.assertEqual(pins.parse_os_lock_archs(written), pins.parse_os_lock_archs(text))

    def test_os_lock_merged_from_both_platforms(self):
        """Security update: each platform pins its packages on its own runner; the parts become one lock again."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / pins.IMAGES_LOCK).write_text(lock(), encoding="utf-8")
            amd, arm = root / "os-amd64.txt", root / "os-arm64.txt"
            amd.write_text("amd64 bash=5.2\namd64 grep=3.11-4\n", encoding="utf-8")
            arm.write_text("arm64 bash=5.2\narm64 grep=3.11-4+b1\n", encoding="utf-8")
            old_root, pins.ROOT = pins.ROOT, root
            old_read = pins.read_text
            pins.read_text = lambda name, r=root: old_read(name, r)
            try:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(pins.main(["os-lock-merge", str(amd), str(arm)]), 0)
                    merged = pins.parse_os_lock_archs((root / pins.OS_LOCK).read_text(encoding="utf-8"))
                    self.assertEqual(merged["arm64"]["grep"], "3.11-4+b1")
                    self.assertEqual(set(merged), {"amd64", "arm64"})
                    self.assertEqual(pins.main(["os-lock-merge", str(amd)]), 1)  # a platform missing
                    self.assertEqual(pins.main(["os-lock-merge", str(amd), str(amd), str(arm)]), 1)  # twice
            finally:
                pins.ROOT, pins.read_text = old_root, old_read

    def test_only_new_snapshot_is_no_change(self):
        old = self.base()
        new = dict(old, **{"images.lock": lock(snapshot="20261102T040000Z")})
        changes, violations = pins.compare(old, new)
        self.assertEqual(violations, [])
        self.assertFalse(pins.has_changes(changes))

    def test_allowed_changes_with_list(self):
        old = self.base()
        new = {
            "images.lock": lock(py="python:3.13.17-slim-trixie@sha256:" + "c" * 64),
            "os-packages.lock": "libssl3t64=3.5.4-1~deb13u1\nbash=5.2.37-2\nnewpkg=1.0-1\n",
            "requirements.txt": "uvicorn==0.54.3\ncertifi==2026.10.23\n",
            "package-lock.json": npm_lock(tailwindcss="3.4.19"),
        }
        changes, violations = pins.compare(old, new)
        self.assertEqual(violations, [])
        self.assertTrue(pins.has_changes(changes))
        self.assertEqual(changes["debian"]["changed"], [("libssl3t64", "3.5.1-1", "3.5.4-1~deb13u1")])
        self.assertEqual(changes["debian"]["added"], [("newpkg", "1.0-1")])
        md = pins.changes_markdown(changes, "de")
        for text in ("Basis-Images", "3.13.16-slim-trixie", "3.13.17-slim-trixie", "libssl3t64 `3.5.1-1` → `3.5.4-1~deb13u1`",
                     "uvicorn `0.54.0` → `0.54.3`", "certifi", "tailwindcss", "nicht im Image"):  # fmt: skip
            self.assertIn(text, md)

    def test_violated_limits_stop(self):
        old = self.base()
        cases = {
            "Python image leaves": lock(py="python:3.14.1-slim-trixie@sha256:" + "c" * 64),
            "Node image leaves": lock(node="node:25.1.0-trixie-slim@sha256:" + "c" * 64),
            "without digest": lock(py="python:3.13.17-slim-trixie"),
        }
        for expected, images in cases.items():
            _, violations = pins.compare(old, dict(old, **{"images.lock": images}))
            self.assertTrue(any(expected in v for v in violations), (expected, violations))
        _, violations = pins.compare(old, dict(old, **{"requirements.txt": "uvicorn==0.55.0\ncertifi==2026.6.17\n"}))
        self.assertEqual(violations, ["python: uvicorn 0.54.0 -> 0.55.0 leaves its series"])
        _, violations = pins.compare(old, dict(old, **{"package-lock.json": npm_lock(tailwindcss="4.0.0")}))
        self.assertEqual(violations, ["npm: tailwindcss 3.4.17 -> 4.0.0 leaves its series"])


class TagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "samonboarding").mkdir()
        (self.root / "samonboarding" / "config.py").write_text('VERSION = "1.48.0"\n', encoding="utf-8")
        self.changelog("")

    def tearDown(self):
        self.tmp.cleanup()

    def changelog(self, entries):
        text = "# Changelog\n\nIntro.\n\n" + entries + "## 1.48.0 – 2026-10-26\n- Neu\n\n## 1.47.1 – 2026-10-25\n- x\n"
        (self.root / "CHANGELOG.de.md").write_text(text, encoding="utf-8")

    def test_counter_starts_at_one_and_increases(self):
        self.assertEqual(pins.next_tag(self.root), "1.48.0-s1")
        self.assertEqual(pins.current_tag(self.root), "1.48.0")
        self.changelog("## 1.48.0-s2 – 2026-11-09\n- Sicherheit: x\n\n## 1.48.0-s1 – 2026-11-02\n- Sicherheit: x\n\n")
        self.assertEqual(pins.next_tag(self.root), "1.48.0-s3")
        self.assertEqual(pins.current_tag(self.root), "1.48.0-s2")

    def test_new_program_version_resets_the_counter(self):
        self.changelog("## 1.47.1-s4 – 2026-11-02\n- Sicherheit: x\n\n")  # belongs to the old version
        self.assertEqual(pins.next_tag(self.root), "1.48.0-s1")

    def test_version_order(self):
        order = ["1.47.1", "1.47.1-s1", "1.47.1-s2", "1.47.1-s10", "1.48.0", "1.48.0-s1", "1.49.0"]
        keys = [pins.tag_key(t) for t in order]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(pins.tag_key("latest"))
        self.assertTrue(pins.is_highest("1.48.0-s1", ["1.48.0", "1.47.1-s3", "latest", "sha-abc"]))
        self.assertFalse(pins.is_highest("1.48.0-s1", ["1.48.0-s2"]))
        self.assertFalse(pins.is_highest("1.47.1-s5", ["1.48.0"]))

    def test_plan_release(self):
        result = pins.plan("release", False, ["1.47.1", "latest"], self.root)
        self.assertEqual(
            (result["action"], result["tag"], result["latest"], result["commit"]), ("publish", "1.48.0", True, False)
        )
        result = pins.plan("release", False, ["1.48.0", "1.47.1"], self.root)
        self.assertEqual(result["action"], "skip")  # a published tag is never overwritten

    def test_plan_security_update(self):
        result = pins.plan("security-update", True, ["1.48.0"], self.root)
        self.assertEqual(
            (result["action"], result["tag"], result["commit"], result["latest"]), ("publish", "1.48.0-s1", True, True)
        )
        # registry is ahead of the changelog (e.g. after an aborted run): still never overwrite
        self.assertEqual(pins.plan("security-update", True, ["1.48.0", "1.48.0-s1"], self.root)["tag"], "1.48.0-s2")

    def test_plan_without_change(self):
        self.assertEqual(pins.plan("security-update", False, ["1.48.0"], self.root)["action"], "nothing")
        self.changelog("## 1.48.0-s1 – 2026-11-02\n- Sicherheit: x\n\n")
        # entry already committed but image not published (push failed): catch up now
        result = pins.plan("security-update", False, ["1.48.0"], self.root)
        self.assertEqual((result["action"], result["tag"], result["commit"]), ("publish", "1.48.0-s1", False))

    def test_security_update_never_publishes_an_unreleased_version(self):
        """Code audit 2026-11b: VERSION 1.48.0 is merged but not released yet - patch day must wait for the release."""
        for changed in (True, False):
            result = pins.plan("security-update", changed, ["1.47.1", "1.47.1-s1"], self.root)
            self.assertEqual((result["action"], result["commit"]), ("nothing", False))

    def test_tag_x_y_for_newest_of_series(self):
        result = pins.plan("security-update", True, ["1.48.0"], self.root)
        self.assertEqual((result["minor"], result["minor_latest"]), ("1.48", True))
        # a security update for an older series gets "1.47" - but only if it is the newest there
        self.assertTrue(pins.plan("release", False, ["1.49.0", "1.47.1"], self.root)["minor_latest"])
        self.assertFalse(pins.plan("release", False, ["1.48.0"], self.root)["minor_latest"])  # skip: nothing

    def test_latest_only_for_highest_version(self):
        result = pins.plan("security-update", True, ["1.48.0", "1.49.0"], self.root)
        self.assertEqual(result["action"], "publish")
        self.assertFalse(result["latest"])

    def test_release_text_from_changelog(self):
        changes = {"images": [], "debian": {"changed": [["openssl", "3.5.1-1", "3.5.4-1"]], "added": [], "removed": []},
                   "python": {"changed": [], "added": [], "removed": []}, "npm": {"changed": [], "added": [], "removed": []}}  # fmt: skip
        for lang, name in pins.CHANGELOGS.items():
            path = self.root / name
            text = (
                path.read_text(encoding="utf-8") if path.exists() else "# Changelog\n\n## 1.48.0 – 2026-10-26\n- New\n"
            )
            path.write_text(pins.insert_changelog(text, pins.changelog_entry("1.48.0-s1", changes, lang, "2026-11-02")))
        notes = pins.release_notes("1.48.0-s1", "ghcr.io/x/y", self.root)
        self.assertTrue(notes.startswith("Security update: same program"))
        self.assertLess(notes.index("Security: security update"), notes.index("**Deutsch**"))  # English first
        self.assertIn("openssl `3.5.1-1` → `3.5.4-1`", notes)
        self.assertIn("**Deutsch**", notes)
        self.assertIn("Sicherheit: Sicherheitsupdate ohne Programmänderung", notes)
        self.assertIn("Security: security update without program changes", notes)
        self.assertIn("`ghcr.io/x/y:1.48.0-s1`", notes)
        self.assertNotIn("## 1.48.0 ", notes)  # only its own entry
        self.assertIn("New program version", pins.release_notes("1.48.0", "ghcr.io/x/y", self.root))
        with self.assertRaises(pins.PinError):
            pins.release_notes("1.48.0-s2", "ghcr.io/x/y", self.root)
        self.assertEqual(pins.changelog_section("## 1.4.10 – x\n- a\n## 1.4.1 – y\n- b\n", "1.4.1"), "- b")

    def test_changelog_entry_shown_as_security_update(self):
        changes = {"images": [], "debian": {"changed": [["openssl", "3.5.1-1", "3.5.4-1"]], "added": [], "removed": []},
                   "python": {"changed": [], "added": [], "removed": []}, "npm": {"changed": [], "added": [], "removed": []}}  # fmt: skip
        text = (self.root / "CHANGELOG.de.md").read_text(encoding="utf-8")
        new = pins.insert_changelog(text, pins.changelog_entry("1.48.0-s1", changes, "de", "2026-11-02"))
        self.assertTrue(new.startswith("# Changelog\n\nIntro.\n\n## 1.48.0-s1 – 2026-11-02\n"))
        entries = news.parse(new)
        self.assertEqual(entries[0]["version"], "1.48.0-s1")
        self.assertEqual(entries[0]["items"][0]["kind"], "security")
        self.assertIn("openssl `3.5.1-1` → `3.5.4-1`", entries[0]["items"][1]["sub"])
        self.assertEqual(entries[1]["version"], "1.48.0")
        en = pins.changelog_entry("1.48.0-s1", changes, "en", "2026-11-02")
        self.assertIn("Security: security update without program changes", en)


FINDINGS = {
    "Results": [
        {
            "Target": "samonboarding (debian 13)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-2", "PkgName": "libx", "InstalledVersion": "1", "FixedVersion": "", "Severity": "CRITICAL"},
                {"VulnerabilityID": "CVE-3", "PkgName": "liby", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "MEDIUM"},
                {"VulnerabilityID": "CVE-4", "PkgName": "libz", "InstalledVersion": "1", "FixedVersion": "3", "Severity": "CRITICAL"},
            ],
        }
    ]
}  # fmt: skip


class TrivyTests(unittest.TestCase):
    def test_only_high_critical_with_fix_counts(self):
        found = pins.trivy_findings(FINDINGS)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].startswith("HIGH CVE-1 openssl 1 -> 2"))
        self.assertTrue(found[1].startswith("CRITICAL CVE-4 libz 1 -> 3"))
        self.assertEqual(pins.trivy_findings({"Results": [{"Target": "x"}]}), [])

    def test_trivyignore_needs_reason_and_expiry(self):
        today = dt.date(2026, 10, 25)
        good = (
            "# Kopf\n\n# libfoo: nur im Druckdienst, der nie laeuft - geprueft 2026-10-25\nCVE-2026-1 exp:2027-01-31\n"
        )
        self.assertEqual(pins.trivyignore_problems(good, today), [])
        self.assertEqual(pins.trivyignore_problems((ROOT / ".trivyignore").read_text(encoding="utf-8"), today), [])
        problems = pins.trivyignore_problems(
            "# Grund\nCVE-2026-1\n\nCVE-2026-2 exp:2027-01-31\n# Grund\nCVE-3 exp:2028-06-01\n", today
        )
        self.assertEqual(len(problems), 3)
        self.assertIn("expiry date", problems[0])
        self.assertIn("reason is missing", problems[1])
        self.assertIn("more than a year", problems[2])

    def fake_trivy(self, report, code=0):
        """Simulated Trivy: writes the report to wherever --output points."""
        bindir = Path(self.tmp.name) / "bin"
        bindir.mkdir(exist_ok=True)
        (Path(self.tmp.name) / "report.json").write_text(json.dumps(report), encoding="utf-8")
        script = bindir / "trivy"
        script.write_text(
            "#!/bin/sh\n"
            f'[ "{code}" = 0 ] || {{ echo "db download failed" >&2; exit {code}; }}\n'
            'while [ $# -gt 0 ]; do [ "$1" = --output ] && out="$2"; shift; done\n'
            f'cp "{self.tmp.name}/report.json" "$out"\n',
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return str(bindir)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.environ.get("PATH", "")

    def tearDown(self):
        os.environ["PATH"] = self.path
        self.tmp.cleanup()

    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_flow_with_simulated_trivy(self):
        os.environ["PATH"] = self.fake_trivy(FINDINGS) + os.pathsep + self.path
        code, out, err = run_main("scan", "samonboarding:test", "--label", "1.48.0-s1 amd64", "--hint", "Abhilfe: X")
        self.assertEqual(code, 1)  # release stopped
        self.assertIn("Trivy found 2 vulnerabilities", out)  # cause readable in the run
        self.assertIn("CVE-4", err)
        self.assertIn("Abhilfe: X", err)

        os.environ["PATH"] = (
            self.fake_trivy({"Results": [{"Target": "x", "Vulnerabilities": []}]}) + os.pathsep + self.path
        )
        code, out, _ = run_main("scan", "samonboarding:test")
        self.assertEqual(code, 0)
        self.assertIn("no HIGH/CRITICAL", out)

        os.environ["PATH"] = self.fake_trivy({}, code=2) + os.pathsep + self.path
        code, _, err = run_main("scan", "samonboarding:test")
        self.assertEqual(code, 1)  # Trivy itself failed: publish nothing in that case either
        self.assertIn("could not scan", err)


HEAD = "# Kopf\n#\n# Empty = nothing is ignored.\n"
MANUAL = "# libfoo: nur im Druckdienst - geprueft 2026-11-01\nCVE-M exp:2027-03-01\n"
ZSTD = {
    "VulnerabilityID": "CVE-Z",
    "PkgName": "libzstd1",
    "InstalledVersion": "1.5.7+dfsg-1",
    "FixedVersion": "1.5.7+dfsg-1+deb13u1",
    "Severity": "HIGH",
}
SSL = {
    "VulnerabilityID": "CVE-S",
    "PkgName": "libssl3t64",
    "InstalledVersion": "3.5.1-1",
    "FixedVersion": "3.5.1-1+deb13u2",
    "Severity": "CRITICAL",
}
PYPKG = {"VulnerabilityID": "CVE-P", "PkgName": "cryptography", "InstalledVersion": "46.0.1",
         "FixedVersion": "46.0.2", "Severity": "HIGH"}  # fmt: skip


def report(*vulns):
    return {"Results": [{"Target": "img (debian 13.8)", "Vulnerabilities": list(vulns)}]}


class TemporaryExceptionTests(unittest.TestCase):
    """Automatic temporary exceptions: fix announced, but not installable in the build yet (2026-11)."""

    today = dt.date(2026, 11, 25)

    def needed(self, *vulns):
        found = pins.trivy_vulns(report(*vulns))
        return pins.auto_needed({"kept": {}, "expired": {}, "new": {v["id"]: [v] for v in found}})

    def test_new_exception_high_14_critical_7_days(self):
        text = pins.apply_auto_exceptions(HEAD + "\n" + MANUAL, self.needed(ZSTD, SSL), self.today)
        entries = {e["id"]: e for e in pins.trivyignore_entries(text)}
        self.assertEqual(entries["CVE-Z"]["exp"], dt.date(2026, 12, 9))
        self.assertEqual(entries["CVE-S"]["exp"], dt.date(2026, 12, 2))
        self.assertTrue(entries["CVE-Z"]["auto"] and entries["CVE-S"]["auto"])
        self.assertFalse(entries["CVE-M"]["auto"])  # the manual part stays as it is
        self.assertIn("libzstd1 1.5.7+dfsg-1 (fix 1.5.7+dfsg-1+deb13u1)", entries["CVE-Z"]["reason"])
        self.assertTrue(text.startswith(HEAD + "\n" + MANUAL))
        self.assertEqual(pins.trivyignore_problems(text, self.today), [])  # reason and expiry date: like by hand
        self.assertEqual(pins.manual_trivyignore(text).strip(), (HEAD + "\n" + MANUAL).strip())

    def test_never_extended_removed_when_fixed_never_renewed_after_expiry(self):
        first = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today)
        later = pins.apply_auto_exceptions(first, self.needed(ZSTD), self.today + dt.timedelta(days=10))
        self.assertEqual(later, first)  # same date, same reason - the time limit is never extended
        fixed = pins.apply_auto_exceptions(first, {}, self.today + dt.timedelta(days=3))
        self.assertEqual(fixed.strip(), HEAD.strip())  # fix in the build: entry gone
        after = pins.apply_auto_exceptions(first, self.needed(ZSTD), self.today + dt.timedelta(days=15))
        self.assertEqual(after, first)  # expired but still found: stays as it is (never a fresh date), scan stops
        on_expiry_day = self.today + dt.timedelta(days=14)
        groups = pins.classify_vulns(pins.trivy_vulns(report(ZSTD)), pins.trivyignore_entries(first), on_expiry_day)
        self.assertEqual(set(groups["expired"]), {"CVE-Z"})  # like Trivy: from the expiry date on it counts again
        self.assertEqual(pins.apply_auto_exceptions(first, pins.auto_needed(groups), on_expiry_day), first)
        manual_expired = HEAD + "\n# geprueft\nCVE-Z exp:2026-11-01\n"
        self.assertNotIn("automatic", pins.apply_auto_exceptions(manual_expired, self.needed(ZSTD), self.today))
        manual_valid = HEAD + "\n# geprueft\nCVE-Z exp:2027-01-01\n"
        self.assertNotIn("automatic", pins.apply_auto_exceptions(manual_valid, self.needed(ZSTD), self.today))

    def test_severity_raised_shortens_and_hand_edits_are_refused(self):
        first = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today)
        critical = dict(ZSTD, Severity="CRITICAL")
        raised = pins.apply_auto_exceptions(first, self.needed(critical), self.today + dt.timedelta(days=3))
        entry = pins.trivyignore_entries(raised)[0]
        self.assertEqual((entry["exp"], entry["severity"]), (dt.date(2026, 12, 2), "CRITICAL"))  # 7 days from the start
        self.assertEqual(pins.trivyignore_problems(raised, self.today), [])
        extended = first.replace("CVE-Z exp:2026-12-09", "CVE-Z exp:2027-06-01")
        self.assertIn("longer than 14 days", pins.trivyignore_problems(extended, self.today)[0])
        by_hand_below = first + "\n# geprueft\nCVE-Q exp:2027-01-01\n"
        self.assertIn("move it above", pins.trivyignore_problems(by_hand_below, self.today)[0])
        # a reason by hand that happens to start like an automatic one, above the line, stays a manual exception
        manual = HEAD + "\n# automatic backup tool: never runs - checked\nCVE-B exp:2027-01-01\n"
        self.assertFalse(pins.trivyignore_entries(manual)[0]["auto"])
        self.assertIn("CVE-B exp:2027-01-01", pins.apply_auto_exceptions(manual, {}, self.today))

    def test_classify(self):
        text = HEAD + "\n# geprueft\nCVE-S exp:2026-11-01\n\n# geprueft\nCVE-P exp:2027-01-01\n"
        text = pins.apply_auto_exceptions(text, self.needed(ZSTD), self.today)
        groups = pins.classify_vulns(
            pins.trivy_vulns(report(ZSTD, SSL, PYPKG)), pins.trivyignore_entries(text), self.today
        )
        self.assertEqual(
            (set(groups["kept"]), set(groups["expired"]), set(groups["new"])), ({"CVE-Z"}, {"CVE-S"}, set())
        )
        later = self.today + dt.timedelta(days=15)
        groups = pins.classify_vulns(pins.trivy_vulns(report(ZSTD)), pins.trivyignore_entries(text), later)
        self.assertEqual(set(groups["expired"]), {"CVE-Z"})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.environ.get("PATH", "")

    def tearDown(self):
        os.environ["PATH"] = self.path
        self.tmp.cleanup()

    fake_trivy = TrivyTests.fake_trivy

    def scan(self, ignore, vulns, *argv):
        os.environ["PATH"] = self.fake_trivy(report(*vulns)) + os.pathsep + self.path
        with (
            mock.patch.object(pins, "read_text", lambda name, root=None: ignore),
            mock.patch.object(pins.dt, "date", wraps=dt.date) as fake_date,
        ):
            fake_date.today.return_value = self.today
            return run_main("scan", "img", *argv)

    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_release_and_security_update_do_not_stop_but_record(self):
        out_file = Path(self.tmp.name) / "auto.json"
        code, out, _ = self.scan(HEAD, [ZSTD], "--auto-out", str(out_file))
        self.assertEqual(code, 0)
        self.assertIn("temporary exception", out)
        self.assertEqual(json.loads(out_file.read_text())["CVE-Z"]["severity"], "HIGH")
        # an expired exception always stops - also the security update
        expired = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today - dt.timedelta(days=20))
        code, _, err = self.scan(expired, [ZSTD], "--auto-out", str(out_file))
        self.assertEqual(code, 1)
        self.assertIn("expired", err)

    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_strict_scan_respects_valid_exception(self):
        valid = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today - dt.timedelta(days=2))
        code, out, _ = self.scan(valid, [ZSTD])
        self.assertEqual(code, 0)
        self.assertIn("Temporary exception until 2026-12-07", out)
        code, _, err = self.scan(valid, [ZSTD, SSL])
        self.assertEqual(code, 1)  # a finding without an exception still stops
        self.assertIn("CVE-S", err)

    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_pull_request_only_stops_for_what_it_brings_in(self):
        old = {
            "os-packages.lock": "amd64 libzstd1=1.5.7+dfsg-1\narm64 libzstd1=1.5.7+dfsg-1\n",
            "requirements.txt": "cryptography==46.0.0\n",
        }
        with mock.patch.object(pins, "git_show", lambda rev, name: old.get(name, "")):
            pins.inherited.__dict__.pop("cache", None)
            code, out, _ = self.scan(HEAD, [ZSTD], "--inherited-from", "HEAD^1")
            self.assertEqual(code, 0)  # same version already on main: the security update there handles it
            self.assertIn("already on main", out)
            code, _, err = self.scan(HEAD, [ZSTD, PYPKG], "--inherited-from", "HEAD^1")
            self.assertEqual(code, 1)  # cryptography 46.0.1 is new in this pull request
            self.assertIn("CVE-P", err)
            self.assertNotIn("CVE-Z", err.split("vulnerabilities")[1].split("\n", 1)[1])
            # an exception is per CVE: another package with the same CVE that the PR brings in still stops it
            valid = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today)
            other = dict(ZSTD, PkgName="zstd", InstalledVersion="1.5.7+dfsg-1")
            code, _, err = self.scan(valid, [ZSTD, other], "--inherited-from", "HEAD^1")
            self.assertEqual(code, 1)
            self.assertIn("CVE-Z zstd", err)
        pins.inherited.__dict__.pop("cache", None)

    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_report_only_for_the_daily_start(self):
        valid = pins.apply_auto_exceptions(HEAD, self.needed(ZSTD), self.today)
        self.assertEqual(self.scan(valid, [ZSTD], "--report-only")[0], 3)  # behind an exception: try again
        self.assertEqual(self.scan(HEAD, [], "--report-only")[0], 0)
        self.assertEqual(self.scan(HEAD + "\n# geprueft\nCVE-Z exp:2027-01-01\n", [], "--report-only")[0], 0)

    def test_trivyignore_auto_command_and_release_notes(self):
        root = Path(self.tmp.name)
        (root / ".trivyignore").write_text(HEAD, encoding="utf-8")
        for lang, name in pins.CHANGELOGS.items():
            (root / name).write_text(f"# Changelog\n\n## 2.11.0 – 2026-11-23\n- Eintrag {lang}\n", encoding="utf-8")
        parts = []
        for n, vuln in enumerate((ZSTD, SSL)):
            path = root / f"auto-{n}.json"
            path.write_text(json.dumps(self.needed(vuln)), encoding="utf-8")
            parts.append(str(path))
        with mock.patch.object(pins, "ROOT", root):
            code, out, _ = run_main("trivyignore-auto", *parts, str(root / "missing.json"))
            self.assertEqual(code, 0)
            self.assertIn("2 automatic temporary exception(s)", out)
            text = (root / ".trivyignore").read_text(encoding="utf-8")
            self.assertIn("CVE-Z exp:", text)
            self.assertIn("CVE-S exp:", text)
            notes = pins.release_notes("2.11.0", "ghcr.io/x/samonboarding", root)
            self.assertIn("Temporary exceptions", notes)
            self.assertIn("CVE-S", notes)
            code, out, _ = run_main("trivyignore-auto")  # nothing found any more: removed
            self.assertNotIn("CVE-", (root / ".trivyignore").read_text(encoding="utf-8"))
            self.assertNotIn("Temporary exceptions", pins.release_notes("2.11.0", "ghcr.io/x/samonboarding", root))


class RunTests(unittest.TestCase):
    @unittest.skipIf(os.name != "posix", "nur unter Linux")
    def test_failure_cause_readable_in_run(self):
        code, out, err = run_main(
            "run", "Build amd64", "--", "sh", "-c", "echo step 1; echo 'E: Unable to locate package x'; exit 2"
        )
        self.assertEqual(code, 1)
        self.assertIn("Build amd64 failed", err)
        self.assertIn("E: Unable to locate package x", err)
        self.assertEqual(run_main("run", "Probe", "--", "true")[0], 0)


class EolTests(unittest.TestCase):
    def test_levels(self):
        today = dt.date(2026, 10, 25)
        self.assertEqual(pins.eol_level("2028-08-09", today)[0], "ok")
        self.assertEqual(pins.eol_level("2027-08-01", today), ("warning", 280))  # under 12 months: notice
        self.assertEqual(pins.eol_level("2027-03-01", today)[0], "error")  # under 6 months: failed run

    def test_base_from_images_lock(self):
        self.assertEqual(
            [c[:2] for c in pins.base_cycles(lock())], [("debian", "13"), ("python", "3.13"), ("nodejs", "24")]
        )

    def run_eol(self, dates, today):
        old = pins.read_text
        pins.read_text = lambda name, root=ROOT: lock() if name == pins.IMAGES_LOCK else old(name, root)
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                pins.cmd_eol(None, fetch=lambda product, cycle: dates.get(product), today=today)
            return None, out.getvalue()
        except pins.PinError as e:
            return str(e), out.getvalue()
        finally:
            pins.read_text = old

    def test_warning_and_failed_run(self):
        today = dt.date(2026, 10, 25)
        error, _ = self.run_eol({"debian": "2028-08-09", "python": "2029-10-31", "nodejs": "2028-04-30"}, today)
        self.assertIsNone(error)
        error, out = self.run_eol({"debian": "2027-08-01", "python": "2029-10-31", "nodejs": "2028-04-30"}, today)
        self.assertIsNone(error)
        self.assertIn("plan the change", out)
        error, _ = self.run_eol({"debian": "2027-03-01", "python": "2029-10-31", "nodejs": "2028-04-30"}, today)
        self.assertIn("raise the base now", error)
        error, out = self.run_eol({}, today)  # endoflife.date not reachable: stored data, with a notice
        self.assertIsNone(error)
        self.assertIn("not reachable", out)


if __name__ == "__main__":
    unittest.main()
