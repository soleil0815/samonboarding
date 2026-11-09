"""Privacy: retention periods and subject access reports."""

import json
import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from samonboarding import audit, config, offboard_store, privacy, reports  # noqa: E402
from samonboarding.routers import privacy_info  # noqa: E402

ROOT = Path(_paths.ROOT)
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def line(days_ago, **extra):
    ts = (NOW - timedelta(days=days_ago)).astimezone().isoformat(timespec="seconds")
    return json.dumps({"ts": ts, "actor": "admin", "action": "test", **extra}) + "\n"


def ago(days):
    return NOW - timedelta(days=days)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.tmp.name, "audit.log")
        self.patches = [
            mock.patch.object(config, "AUDIT_LOG_FILE", self.log_file),
            mock.patch.object(config, "OFFBOARD_DB_FILE", os.path.join(self.tmp.name, "offboarding.db")),
            mock.patch.object(config, "REPORTS_DB_FILE", os.path.join(self.tmp.name, "reports.db")),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_old_changes_are_removed(self):
        reports.write_audit("admin", "alt", ts=ago(400))
        reports.write_audit("admin", "neu", ts=ago(10))
        self.assertEqual(privacy.purge_audit(365, NOW), 1)
        self.assertEqual([e["action"] for e in reports.query_audit()[0]], ["neu"])

    def test_old_log_is_removed_after_90_days(self):
        reports.write_log("INFO", "x", "alt", ts=ago(91))
        reports.write_log("INFO", "x", "neu", ts=ago(89))
        self.assertEqual(privacy.purge_log(90, NOW), 1)
        self.assertEqual([e["message"] for e in reports.query_log()[0]], ["neu"])

    def test_period_zero_means_unlimited(self):
        reports.write_audit("admin", "uralt", ts=ago(5000))
        self.assertEqual(privacy.purge_audit(0, NOW), 0)
        self.assertEqual(privacy.purge_log(0, NOW), 0)
        self.assertEqual(privacy.purge_offboarding(0, NOW), 0)

    def test_audit_writes_to_database(self):
        audit.audit("admin", "pwdreset", "CN=Max,DC=x", sam="musterm", leer="", liste=[])
        entry = reports.query_audit()[0][0]
        self.assertEqual((entry["actor"], entry["action"], entry["ok"]), ("admin", "pwdreset", True))
        self.assertEqual(entry["details"], {"sam": "musterm"})  # empty values are not stored
        self.assertIn('"action": "pwdreset"', reports.audit_jsonl())

    def test_secure_delete_enabled(self):
        with reports._db() as conn:
            self.assertEqual(conn.execute("PRAGMA secure_delete").fetchone()[0], 1)

    def test_legacy_audit_log_is_imported_and_removed(self):
        with open(self.log_file + ".1", "w", encoding="utf-8") as f:
            f.write(line(20, target="aelter", ok=False, error="x"))
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(line(5, target="neuer", sam="musterm") + "kaputte zeile\n")
        self.assertEqual(reports.import_legacy_audit(), 2)
        self.assertFalse(os.path.exists(self.log_file) or os.path.exists(self.log_file + ".1"))
        rows = reports.query_audit()[0]
        self.assertEqual([r["target"] for r in rows], ["neuer", "aelter"])
        self.assertEqual(rows[1]["ok"], False)
        self.assertEqual(rows[0]["details"], {"sam": "musterm"})
        self.assertEqual(reports.import_legacy_audit(), 0)  # nothing left

    def test_search_filter_and_pages(self):
        for i in range(5):
            reports.write_audit("admin", "login", ok=(i != 2), details={"n": i})
        reports.write_audit("op", "pwdreset", "CN=Max_100%,DC=x")
        page, nxt = reports.query_audit(limit=4)
        self.assertEqual(len(page), 4)
        rest, nxt2 = reports.query_audit(limit=4, before=nxt)
        self.assertEqual((len(rest), nxt2), (2, None))
        self.assertEqual(len(reports.query_audit(result="fail")[0]), 1)
        self.assertEqual(len(reports.query_audit(q="Max_100%")[0]), 1)
        self.assertEqual(len(reports.query_audit(q="100%x")[0]), 0)  # % and _ are not wildcards
        reports.write_log("WARNING", "a", "w")
        reports.write_log("ERROR", "a", "e")
        reports.write_log("INFO", "a", "i")
        self.assertEqual(len(reports.query_log(level="warning")[0]), 2)
        self.assertEqual(len(reports.query_log(level="error")[0]), 1)
        self.assertEqual(reports.counts()["audit"]["count"], 6)

    def test_log_handler_stores_traceback(self):
        handler = reports.DbLogHandler()
        logger = logging.getLogger("samonboarding.testtraceback")
        logger.addHandler(handler)
        logger.propagate = False
        try:
            try:
                raise RuntimeError("Ursache am Ende")
            except RuntimeError:
                logger.exception("Unerwarteter Fehler")
            logging.getLogger("samonboarding.reports").warning("auch Meldungen dieses Moduls")
        finally:
            logger.removeHandler(handler)
        msg = reports.query_log(level="error")[0][0]["message"]
        self.assertTrue(msg.startswith("Unerwarteter Fehler") and "Traceback" in msg)
        self.assertTrue(msg.rstrip().endswith("RuntimeError: Ursache am Ende"))

    def test_long_message_keeps_start_and_end(self):
        text = "A" * 3000 + "MITTE" + "B" * 3000 + "ENDE"
        out = reports._shorten(text)
        self.assertLessEqual(len(out), reports.MAX_MESSAGE)
        self.assertTrue(out.startswith("AAA") and out.endswith("ENDE") and "[...]" in out)

    def test_uvicorn_errors_end_up_in_log(self):
        with mock.patch.object(reports, "_handler", None):
            root, uv = logging.getLogger(), logging.getLogger("uvicorn.error")
            before_root, before_uv = list(root.handlers), list(uv.handlers)
            try:
                reports.install_log_handler()
                added = [h for h in uv.handlers if h not in before_uv]
                self.assertEqual(len(added), 1)
                self.assertEqual(added[0].level, logging.WARNING)
            finally:
                root.handlers[:] = before_root
                uv.handlers[:] = before_uv

    def test_log_handler_writes_from_info(self):
        handler = reports.DbLogHandler()
        logger = logging.getLogger("samonboarding.testhandler")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        try:
            logger.debug("unsichtbar")
            logger.warning("Achtung %s", "musterm")
        finally:
            logger.removeHandler(handler)
        rows = reports.query_log()[0]
        self.assertEqual([(r["level"], r["message"]) for r in rows], [("WARNING", "Achtung musterm")])

    def _record(self, sam, days_ago):
        rid = offboard_store.record(
            user_guid="",
            sam=sam,
            name=sam,
            original_dn=f"CN={sam},OU=A,DC=x",
            original_ou="OU=A,DC=x",
            was_enabled=True,
            groups=["G"],
            actor="admin",
        )
        ts = (NOW - timedelta(days=days_ago)).isoformat(timespec="seconds")
        with offboard_store._db() as conn:
            conn.execute("UPDATE offboarded SET offboarded_at = ? WHERE id = ?", (ts, rid))
        return rid

    def test_old_restore_records_are_removed(self):
        self._record("alt", 200)
        keep = self._record("neu", 20)
        busy = self._record("inarbeit", 300)
        self.assertTrue(offboard_store.claim(busy))  # a restore in progress is not deleted
        self.assertEqual(privacy.purge_offboarding(180, NOW), 1)
        self.assertEqual([r["id"] for r in offboard_store.list_open()], [keep])
        self.assertIsNotNone(offboard_store.get(busy))

    def test_run_retention_never_raises(self):
        with mock.patch.object(privacy, "purge_audit", side_effect=OSError("x")):
            self.assertEqual(privacy.run_retention(NOW)["audit"], 0)

    def test_subject_report(self):
        reports.write_audit("admin", "pwdreset", "CN=Max Muster,OU=A,DC=x", details={"sam": "MusterM"})
        reports.write_audit("admin", "pwdreset", "andere")
        reports.write_log("WARNING", "x", "Fehler bei musterm")
        self._record("musterm", 1)
        report = privacy.subject_report("musterm")
        self.assertEqual(len(report["auditEntries"]), 1)
        self.assertEqual(len(report["logEntries"]), 1)
        self.assertEqual(report["offboardingRecords"][0]["sam"], "musterm")
        self.assertEqual(report["retention"]["logDays"], config.LOG_RETENTION_DAYS)
        with self.assertRaises(ValueError):
            privacy.subject_report("  ")

    def test_command_line(self):
        out = []
        with mock.patch("builtins.print", side_effect=lambda *a, **k: out.append(a[0])):
            self.assertEqual(privacy.main(["auskunft", "niemand"]), 0)
            self.assertEqual(privacy.main(["falsch"]), 2)
        self.assertEqual(json.loads(out[0])["auditEntries"], [])


class PrivacyApiTests(unittest.TestCase):
    def test_info_without_personal_data(self):
        info = privacy_info.privacy_info()
        self.assertEqual(set(info), {"auditDays", "logDays", "offboardDays", "sessionIdleMinutes"})

    def test_subject_report_admins_only(self):
        with self.assertRaises(Exception) as ctx:
            privacy_info.privacy_report("musterm", {"username": "op", "role": "Account Operator"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_subject_report_needs_name(self):
        with self.assertRaises(Exception) as ctx:
            privacy_info.privacy_report("  ", {"username": "admin", "role": "Administrator"})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_subject_report_is_audited(self):
        fake = {"auditEntries": [1, 2], "logEntries": [], "offboardingRecords": []}
        with mock.patch.object(privacy_info.privacy, "subject_report", return_value=fake) as rep:
            with mock.patch.object(privacy_info, "audit") as aud:
                out = privacy_info.privacy_report(" musterm ", {"username": "admin", "role": "Administrator"})
        rep.assert_called_once_with("musterm")
        self.assertIs(out, fake)
        self.assertEqual(aud.call_args.args[1:3], ("privacy-report", "musterm"))
        self.assertEqual(aud.call_args.kwargs["auditEntries"], 2)

    def test_user_interface(self):
        html = _paths.web_source()
        for needed in (
            'id="privacy-modal"',
            'id="nav-privacy"',
            'class="privacy-link" data-on-click="openPrivacy()"',
            "/api/privacy-info",
            "/api/privacy/report?sam=",
        ):
            self.assertIn(needed, html)

    def test_no_dockhand_label_anymore(self):
        """The old label that disabled Dockhand updates stays out (Dockhand and similar tools should update)."""
        for name in ("docker-compose.yml", "update.sh", "Dockerfile"):
            self.assertNotIn("dockhand.update", (ROOT / name).read_text(encoding="utf-8").lower())


class DefaultsTests(unittest.TestCase):
    def test_default_periods(self):
        self.assertEqual(config.AUDIT_RETENTION_DAYS, 365)
        self.assertEqual(config.LOG_RETENTION_DAYS, 90)
        self.assertEqual(config.SESSION_IDLE_SECONDS, 30 * 60)
        self.assertEqual(config.OFFBOARD_RETENTION_DAYS, 180)

    def test_cleanup_at_startup(self):
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        self.assertIn("lifespan=_lifespan", main)
        self.assertIn("privacy.start_retention_thread()", main)


if __name__ == "__main__":
    unittest.main()
