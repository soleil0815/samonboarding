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
