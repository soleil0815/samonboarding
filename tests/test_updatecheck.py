"""Version check: a newer release on GitHub is shown to administrators. No network in these tests."""

import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import diagnose, updatecheck  # noqa: E402
from samonboarding.routers import auth  # noqa: E402

RELEASES = [
    {"tag_name": "v2.6.2", "draft": False, "prerelease": False},
    {"tag_name": "v2.6.2-s1", "draft": False, "prerelease": False},
    {"tag_name": "v2.7.0", "draft": False, "prerelease": False},
    {"tag_name": "v2.8.0", "draft": True, "prerelease": False},  # not published yet
    {"tag_name": "v2.9.0-rc1", "draft": False, "prerelease": False},  # not a release number
    {"tag_name": "v3.0.0", "draft": False, "prerelease": True},
    "nonsense",
]


class ParseTests(unittest.TestCase):
    def test_only_published_release_numbers(self):
        self.assertEqual(updatecheck.parse_releases(RELEASES), ["2.6.2", "2.6.2-s1", "2.7.0"])

    def test_unexpected_answer_is_an_error(self):
        with self.assertRaises(ValueError):
            updatecheck.parse_releases({"message": "API rate limit exceeded"})


class PinTests(unittest.TestCase):
    def test_pin_from_env(self):
        self.assertEqual(updatecheck.pin({}), ("", ""))
        self.assertEqual(updatecheck.pin({"SAMONBOARDING_VERSION": ""}), ("", ""))
        self.assertEqual(updatecheck.pin({"SAMONBOARDING_VERSION": "latest"}), ("", ""))
        self.assertEqual(updatecheck.pin({"SAMONBOARDING_VERSION": "2.6"}), ("line", "2.6"))
        self.assertEqual(updatecheck.pin({"SAMONBOARDING_VERSION": "2.6.2"}), ("exact", "2.6.2"))
        self.assertEqual(updatecheck.pin({"SAMONBOARDING_VERSION": "2.6.2-s1"}), ("exact", "2.6.2-s1"))

    def test_switch_on_and_off(self):
        self.assertTrue(updatecheck.enabled({}))
        self.assertTrue(updatecheck.enabled({"UPDATE_CHECK": ""}))  # empty = default, like every setting
        self.assertTrue(updatecheck.enabled({"UPDATE_CHECK": "true"}))
        self.assertFalse(updatecheck.enabled({"UPDATE_CHECK": "false"}))
        self.assertFalse(updatecheck.enabled({"UPDATE_CHECK": "0"}))


class EvaluateTests(unittest.TestCase):
    VERSIONS = ["2.6.1", "2.6.2", "2.6.2-s1", "2.6.3", "2.7.0", "2.7.0-s1"]

    def test_up_to_date(self):
        self.assertIsNone(updatecheck.evaluate("2.7.0-s1", self.VERSIONS))
        self.assertIsNone(updatecheck.evaluate("2.8.0", self.VERSIONS))  # own build newer than any release

    def test_newest_without_pin(self):
        note = updatecheck.evaluate("2.6.2", self.VERSIONS)
        self.assertEqual(note["latest"], "2.7.0-s1")
        self.assertEqual(note["level"], "version")
        self.assertFalse(note["switch"])
        self.assertIsNone(note["outside"])
        self.assertEqual(note["url"], "https://github.com/soleil0815/samonboarding/releases/tag/v2.7.0-s1")

    def test_security_update_of_the_same_version(self):
        note = updatecheck.evaluate("2.7.0", self.VERSIONS)
        self.assertEqual((note["latest"], note["level"]), ("2.7.0-s1", "security"))

    def test_line_pin_stays_in_its_line_and_names_the_newer_line(self):
        note = updatecheck.evaluate("2.6.2", self.VERSIONS, ("line", "2.6"))
        self.assertEqual(note["latest"], "2.6.3")
        self.assertFalse(note["switch"])  # "docker compose pull" fetches the newest 2.6.x
        self.assertEqual((note["outside"], note["outsideLine"]), ("2.7.0-s1", "2.7"))

    def test_line_pin_newest_of_its_line_only_the_newer_line(self):
        note = updatecheck.evaluate("2.6.3", self.VERSIONS, ("line", "2.6"))
        self.assertIsNone(note["latest"])
        self.assertEqual(note["outside"], "2.7.0-s1")
        self.assertNotIn("level", note)

    def test_exact_pin_needs_the_switch_command(self):
        note = updatecheck.evaluate("2.6.2", self.VERSIONS, ("exact", "2.6.2"))
        self.assertEqual(note["latest"], "2.6.3")
        self.assertTrue(note["switch"])

    def test_versions_compare_as_numbers(self):
        note = updatecheck.evaluate("2.9.0", ["2.10.0", "2.9.0"])
        self.assertEqual(note["latest"], "2.10.0")


class FakeAnswer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(updatecheck._state)
        self.addCleanup(updatecheck._state.update, self.saved)
        updatecheck._state.update(checkedAt=None, ok=None, problem=None, versions=[])

    def test_request_sends_nothing_about_the_installation(self):
        seen = {}

        def urlopen(request, timeout):
            seen["request"], seen["timeout"] = request, timeout
            return FakeAnswer(json.dumps(RELEASES).encode())

        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertTrue(updatecheck.check())
        request = seen["request"]
        self.assertEqual(
            request.full_url, "https://api.github.com/repos/soleil0815/samonboarding/releases?per_page=100"
        )
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        headers = {k.lower(): v for k, v in request.header_items()}
        self.assertEqual(set(headers), {"user-agent", "accept"})
        self.assertEqual(headers["user-agent"], "SAMONBOARDING-update-check")  # no version, no identifier
        self.assertLessEqual(seen["timeout"], 30)
        self.assertEqual(updatecheck._state["versions"], ["2.6.2", "2.6.2-s1", "2.7.0"])

    def test_own_proxy_setting_only_for_the_check(self):
        seen = {}

        class Opener:
            def open(self, request, timeout):
                return FakeAnswer(json.dumps(RELEASES).encode())

        def build_opener(handler):
            seen["proxies"] = handler.proxies
            return Opener()

        with (
            mock.patch.dict(os.environ, {"UPDATE_CHECK_PROXY": "http://proxy.firma.local:3128"}),
            mock.patch("urllib.request.build_opener", build_opener),
        ):
            self.assertTrue(updatecheck.check())
        self.assertEqual(seen["proxies"], {"https": "http://proxy.firma.local:3128"})

    def test_too_large_answer_is_refused(self):
        big = FakeAnswer(b"[" + b" " * (updatecheck.MAX_BYTES + 10) + b"]")
        with mock.patch("urllib.request.urlopen", lambda r, timeout: big):
            self.assertFalse(updatecheck.check())
        self.assertEqual(updatecheck._state["problem"], "answer")

    def test_failures_are_quiet_and_keep_the_last_list(self):
        updatecheck._state["versions"] = ["2.7.0"]
        cases = [
            (urllib.error.URLError("proxy.intern.firma.local refused"), "network"),
            (urllib.error.HTTPError("u", 403, "rate limit", None, None), "http-403"),
            (TimeoutError("timed out"), "timeout"),
            (ValueError("bad json"), "answer"),
        ]
        for error, problem in cases:

            def fetch(error=error):
                raise error

            with self.assertLogs("samonboarding.updatecheck", "INFO") as logs:
                self.assertFalse(updatecheck.check(fetch=fetch))
            self.assertEqual(updatecheck._state["problem"], problem)
            self.assertNotIn("firma.local", "\n".join(logs.output))  # only the class, never the message
        self.assertEqual(updatecheck._state["versions"], ["2.7.0"])

    def test_notice_and_status(self):
        updatecheck.check(fetch=lambda: RELEASES)
        with (
            mock.patch.object(updatecheck, "installed", return_value="2.6.2"),
            mock.patch.dict(os.environ, {"SAMONBOARDING_VERSION": "", "UPDATE_CHECK": ""}),
        ):
            self.assertEqual(updatecheck.notice()["latest"], "2.7.0")
            status = updatecheck.status()
            self.assertEqual(status["ergebnis"], "ok")
            self.assertEqual(status["neuesteVeroeffentlicht"], "2.7.0")
            hints = diagnose.hints({"programm": {"updatePruefung": status}})
            self.assertIn("Neuere Version veröffentlicht: 2.7.0 (installiert 2.6.2).", hints)
            with mock.patch.dict(os.environ, {"UPDATE_CHECK": "false"}):
                self.assertIsNone(updatecheck.notice())

    def test_no_notice_before_the_first_check(self):
        self.assertIsNone(updatecheck.notice())

    def test_failed_check_is_a_diagnostic_hint(self):
        status = {"eingeschaltet": True, "ergebnis": "network", "installiert": "2.6.2"}
        hints = diagnose.hints({"programm": {"updatePruefung": status}})
        self.assertTrue(any("Versionsprüfung bei GitHub nicht möglich (network)" in h for h in hints))

    def test_switched_off_starts_no_thread(self):
        with (
            mock.patch.dict(os.environ, {"UPDATE_CHECK": "false"}),
            mock.patch("threading.Thread") as thread,
        ):
            updatecheck.start_thread()
        thread.assert_not_called()


class InstalledTests(unittest.TestCase):
    def test_security_update_counter_from_the_changelog(self):
        self.assertEqual(updatecheck.installed().split("-s")[0], updatecheck.VERSION)


class HostNoticeTests(unittest.TestCase):
    def test_only_administrators_see_the_update(self):
        note = updatecheck.evaluate("2.6.2", ["2.6.2-s1"])
        with mock.patch.object(updatecheck, "notice", return_value=note):
            admin = auth.get_host_notices({"role": "Administrator"})
            operator = auth.get_host_notices({"role": "Operator"})
        self.assertIn(dict(note, kind="update"), admin["notices"])
        self.assertEqual(note["level"], "security")  # not overwritten by the notice kind
        self.assertEqual(operator, {"notices": []})


if __name__ == "__main__":
    unittest.main()
