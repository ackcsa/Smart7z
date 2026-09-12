import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from runtime_startup import SchedulerStartup, SchedulerStartupResult


class TestSchedulerStartup(unittest.TestCase):
    def test_result_is_claimed_once_and_not_disposed_after_transfer(self):
        ready = threading.Event()
        scheduler = mock.Mock()
        result = SchedulerStartupResult(scheduler, {})
        startup = SchedulerStartup(lambda: result, ready.set)
        startup.start()
        self.assertTrue(ready.wait(3))
        self.assertEqual(startup.take_result(), (result, None))
        self.assertEqual(startup.take_result(), (None, None))
        self.assertTrue(startup.cancel_and_join())
        scheduler.stop.assert_not_called()

    def test_cancel_during_initialization_disposes_late_scheduler(self):
        entered = threading.Event()
        release = threading.Event()
        notify = mock.Mock()
        scheduler = mock.Mock()

        def build():
            entered.set()
            if not release.wait(3):
                raise TimeoutError("Startup fixture gate timed out")
            return SchedulerStartupResult(scheduler, {})

        startup = SchedulerStartup(build, notify)
        startup.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertFalse(startup.cancel_and_join(timeout=0))
        finally:
            release.set()
            self.assertTrue(startup.cancel_and_join())
        scheduler.stop.assert_called_once_with()
        notify.assert_not_called()
        self.assertEqual(startup.take_result(), (None, None))

    def test_cancel_after_ready_disposes_unclaimed_scheduler(self):
        ready = threading.Event()
        scheduler = mock.Mock()
        startup = SchedulerStartup(lambda: SchedulerStartupResult(scheduler, {}), ready.set)
        startup.start()
        self.assertTrue(ready.wait(3))
        self.assertTrue(startup.cancel_and_join())
        scheduler.stop.assert_called_once_with()
        self.assertEqual(startup.take_result(), (None, None))

    def test_failed_disposal_can_be_retried(self):
        ready = threading.Event()
        scheduler = mock.Mock()
        scheduler.stop.side_effect = [False, True]
        startup = SchedulerStartup(lambda: SchedulerStartupResult(scheduler, {}), ready.set)
        startup.start()
        self.assertTrue(ready.wait(3))
        self.assertFalse(startup.cancel_and_join())
        self.assertTrue(startup.cancel_and_join())
        self.assertEqual(scheduler.stop.call_count, 2)

    def test_initialization_error_is_returned_without_throwing_on_worker(self):
        ready = threading.Event()
        error = PermissionError("fixture staging denied")
        startup = SchedulerStartup(mock.Mock(side_effect=error), ready.set)
        startup.start()
        self.assertTrue(ready.wait(3))
        self.assertEqual(startup.take_result(), (None, error))
        self.assertTrue(startup.cancel_and_join())

    def test_constructor_failure_releases_lock_and_session_before_retry(self):
        from config import DEFAULT_CONFIG
        from recovery import RecoveryJournal
        from scheduler import Scheduler

        for target in (
            "scheduler.RecoveryJournal.recover",
            "scheduler.create_owned_session",
            "scheduler.Executor",
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                config = {
                    **DEFAULT_CONFIG,
                    "temp_dir": str(Path(temp, "staging")),
                    "_recovery_journal_path": str(Path(temp, "recovery.json")),
                }
                error = None
                with mock.patch(target, side_effect=OSError("fixture startup failure")):
                    try:
                        Scheduler("unused-7z.exe", config)
                    except OSError as caught:
                        error = caught
                self.assertIsNotNone(error)
                self.assertIsNotNone(error.__traceback__)
                with RecoveryJournal(config["_recovery_journal_path"]) as journal:
                    self.assertTrue(journal.available, journal.load_error)
                self.assertEqual(list(Path(config["temp_dir"]).glob("Smart7z_Session_*")), [])
                retry = Scheduler("unused-7z.exe", config)
                self.assertTrue(retry.stop())


if __name__ == "__main__":
    unittest.main()
