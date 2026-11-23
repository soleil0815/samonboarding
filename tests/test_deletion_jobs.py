"""Deletion as a server job (2.11.0): runs without the request, belongs to the administrator, sends its mail."""

import contextvars
import os
import sys
import threading
import unittest
from unittest import mock

import _paths

try:
    import fastapi  # noqa: F401
except ImportError:  # without installed packages: use the scenario stub modules
    sys.path.insert(0, os.path.join(_paths.TESTS, "scenarios", "stubs"))

from fastapi import HTTPException  # noqa: E402

from samonboarding.routers import deletion  # noqa: E402

ADMIN = {"username": "Admin1", "role": "Administrator"}
PLAN = {"dn": "CN=Anna,OU=Disabled,DC=firma,DC=local", "sam": "anna", "name": "Anna Alt"}
MARK = contextvars.ContextVar("mark", default="")


class JobThreadTests(unittest.TestCase):
    def tearDown(self):
        deletion._jobs.clear()

    def test_job_runs_in_its_own_thread_with_the_requests_context(self):
        seen, done = {}, threading.Event()

        def target(value):
            seen.update(thread=threading.current_thread(), value=value, mark=MARK.get())
            done.set()

        MARK.set("de")
        deletion._start_job(target, 7)
        self.assertTrue(done.wait(5))
        self.assertIsNot(seen["thread"], threading.current_thread())  # not tied to the request (or the browser)
        self.assertFalse(isinstance(seen["thread"], threading._MainThread))
        self.assertEqual((seen["value"], seen["mark"]), (7, "de"))  # language of the mails is kept

    def test_single_job_records_the_result_and_sends_the_mail(self):
        job = deletion._new_job(ADMIN, "single", [PLAN])
        sent = []
        result = {"status": "success", "message": "Konto anna wurde gelöscht.", "results": [], "accountDeleted": True}

        def fake_run(user, cfg, plan, mail, on_locked=None):
            mail(plan["name"], plan["sam"], [], True, None)
            return result

        def queue(bg, *a):
            self.assertTrue(job["finished"])  # a slow mail server does not keep the job (and the account) running
            bg.add_task(sent.append, a)

        with (
            mock.patch.object(deletion, "run_deletion", fake_run),
            mock.patch.object(deletion, "_queue_mail", queue),
            mock.patch.object(deletion, "drop_plan") as drop,
        ):
            deletion.run_single_job(job["id"], ADMIN, {}, PLAN, "P1")
        self.assertEqual(len(sent), 1)  # sent right away - the request is long over
        self.assertEqual(sent[0][1], "Anna Alt")
        item = job["items"][0]
        self.assertEqual((item["status"], item["accountDeleted"]), ("success", True))
        self.assertTrue(job["finished"] and job["done"] == 1 and job["finishedAt"])
        drop.assert_called_with("P1")  # the plan is single use, whatever happened

    def test_single_job_error_is_kept_with_its_code(self):
        job = deletion._new_job(ADMIN, "single", [PLAN])

        def fail(*a, **k):
            raise HTTPException(status_code=409, detail="Seit der Simulation hat sich etwas geändert")

        with mock.patch.object(deletion, "run_deletion", fail), mock.patch.object(deletion, "drop_plan"):
            deletion.run_single_job(job["id"], ADMIN, {}, PLAN, "P1")
        item = job["items"][0]
        self.assertEqual((item["status"], item["code"]), ("error", 409))
        self.assertTrue(job["finished"])

    def test_job_belongs_to_the_administrator_not_the_session(self):
        job = deletion._new_job(ADMIN, "single", [PLAN])
        self.assertIs(deletion._own_job(job["id"], {"username": "admin1", "sid": "new"}), job)
        with self.assertRaises(HTTPException) as e:
            deletion._own_job(job["id"], {"username": "admin2"})
        self.assertEqual(e.exception.status_code, 404)
        self.assertNotIn("owner", deletion._public(job))

    def test_old_finished_jobs_expire_without_a_new_deletion(self):
        job = deletion._new_job(ADMIN, "single", [PLAN])
        job.update(finished=True, finishedAt=1.0)
        self.assertEqual(deletion.list_deletion_jobs(user=ADMIN)["jobs"], [])
        with self.assertRaises(HTTPException) as e:
            deletion.get_deletion_job(job["id"], user=ADMIN)
        self.assertEqual(e.exception.status_code, 404)

    def test_running_jobs_never_expire(self):
        job = deletion._new_job(ADMIN, "single", [PLAN])
        job["startedAt"] = 1.0
        self.assertEqual(len(deletion.list_deletion_jobs(user=ADMIN)["jobs"]), 1)

    def test_hiding_removes_the_job_and_older_finished_ones_from_memory(self):
        old, new, running = (deletion._new_job(ADMIN, "single", [PLAN]) for _ in range(3))
        other = deletion._new_job({"username": "admin2"}, "single", [PLAN])
        for n, j in enumerate((old, new, other)):
            j.update(finished=True, finishedAt=9e9, startedAt=10.0 + n)
        running["startedAt"] = 5.0  # older but still running: stays
        deletion.dismiss_deletion_job(new["id"], user=ADMIN)
        self.assertEqual(set(deletion._jobs), {running["id"], other["id"]})
        with self.assertRaises(HTTPException) as e:
            deletion.dismiss_deletion_job(running["id"], user=ADMIN)
        self.assertEqual(e.exception.status_code, 409)

    def test_old_finished_jobs_are_removed(self):
        old = deletion._new_job(ADMIN, "single", [PLAN])
        old.update(finished=True, finishedAt=1.0)
        deletion._new_job(ADMIN, "single", [PLAN])
        self.assertNotIn(old["id"], deletion._jobs)


if __name__ == "__main__":
    unittest.main()
