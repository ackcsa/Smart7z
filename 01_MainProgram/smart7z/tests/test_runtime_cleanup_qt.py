from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import windows_adapters
from config import DEFAULT_CONFIG
from models import Job, JobState
from scheduler import Scheduler

try:
    from PySide6.QtWidgets import QApplication

    import ui_qt
except ModuleNotFoundError:
    QApplication = None
    ui_qt = None


def _scheduler_config(temp_dir: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    config["temp_dir"] = temp_dir
    config["target_dir"] = os.path.join(temp_dir, "output")
    config["_recovery_journal_path"] = os.path.join(
        temp_dir, "recovery-v1.json"
    )
    return config


def _same_path(expected: Path):
    expected_key = os.path.normcase(os.path.abspath(str(expected)))

    def matches(candidate) -> bool:
        return os.path.normcase(os.path.abspath(str(candidate))) == expected_key

    return matches


class TestOwnedSessionCleanup(unittest.TestCase):
    def test_stale_session_with_only_owner_marker_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)

            with mock.patch.object(
                windows_adapters, "_is_pid_running", return_value=False
            ):
                windows_adapters.cleanup_stale_sessions(temp)

            self.assertFalse(session.exists())

    def test_stale_session_with_empty_stego_scaffold_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            (session / "stego").mkdir()

            with mock.patch.object(
                windows_adapters, "_is_pid_running", return_value=False
            ):
                windows_adapters.cleanup_stale_sessions(temp)

            self.assertFalse(session.exists())

    def test_nonempty_stego_scaffold_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            stego = session / "stego"
            stego.mkdir()
            payload = stego / "carve_pending.zip"
            payload.write_bytes(b"pending")

            self.assertFalse(
                windows_adapters.cleanup_owned_session(session_path, token)
            )
            self.assertTrue(session.is_dir())
            self.assertEqual(payload.read_bytes(), b"pending")

    def test_unknown_session_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            unknown = session / "unknown-state.bin"
            unknown.write_bytes(b"keep")

            self.assertFalse(
                windows_adapters.cleanup_owned_session(session_path, token)
            )
            self.assertTrue(session.is_dir())
            self.assertEqual(unknown.read_bytes(), b"keep")

    def test_symlink_and_reparse_points_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            stego = session / "stego"
            stego.mkdir()

            cases = (
                ("session_symlink", "islink", session),
                ("stego_symlink", "islink", stego),
                ("session_reparse", "is_reparse_point", session),
                ("stego_reparse", "is_reparse_point", stego),
            )
            for label, detector, flagged_path in cases:
                with self.subTest(case=label):
                    target = (
                        windows_adapters.os.path
                        if detector == "islink"
                        else windows_adapters
                    )
                    with mock.patch.object(
                        target, detector, side_effect=_same_path(flagged_path)
                    ):
                        cleaned = windows_adapters.cleanup_owned_session(
                            session_path, token
                        )

                    self.assertFalse(cleaned)
                    self.assertTrue(session.is_dir())
                    self.assertTrue(stego.is_dir())

    def test_mismatched_owner_token_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)

            self.assertFalse(
                windows_adapters.cleanup_owned_session(
                    session_path, "0" * 32
                )
            )
            self.assertTrue(session.is_dir())

    def test_current_process_owned_session_is_not_collected_as_stale(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)

            with mock.patch.object(
                windows_adapters,
                "_is_pid_running",
                side_effect=lambda pid: pid == os.getpid(),
            ) as is_running:
                windows_adapters.cleanup_stale_sessions(temp)

            is_running.assert_called_once_with(os.getpid())
            self.assertTrue(session.is_dir())


class TestSchedulerSessionCleanup(unittest.TestCase):
    def test_stop_removes_executor_artifacts_and_owned_session(self):
        with tempfile.TemporaryDirectory() as temp:
            scheduler = Scheduler("7z.exe", _scheduler_config(temp))
            session = Path(scheduler._session_root)
            source = Path(temp) / "queued.zip"
            source.write_bytes(b"archive")
            job = Job(path=str(source))
            self.assertTrue(scheduler.submit(job))

            job.temp_root = scheduler.executor._create_temp_root(
                job, str(Path(temp) / "output"), "staging"
            )
            partial = Path(job.temp_root) / "partial.bin"
            partial.write_bytes(b"partial")
            (session / "stego").mkdir()

            try:
                self.assertTrue(scheduler.stop())
            finally:
                if session.exists():
                    scheduler.stop()

            self.assertIsNone(job.temp_root)
            self.assertFalse(partial.exists())
            self.assertFalse(session.exists())
            self.assertEqual(scheduler._session_roots, {})


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class TestQtShutdownSessionCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication(
            ["smart7z-runtime-cleanup-tests"]
        )
        ui_qt._configure_qt_application(cls.qt_app)

    def test_context_auto_close_stops_scheduler_and_clears_session_state(self):
        with tempfile.TemporaryDirectory() as temp:
            config = _scheduler_config(temp)
            with (
                mock.patch.object(ui_qt, "load_config", return_value=config),
                mock.patch.object(
                    ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"
                ),
                mock.patch.object(
                    ui_qt, "cleanup_stale_sessions", return_value=[]
                ),
            ):
                window = ui_qt.Smart7zQtWindow()

            scheduler = window.scheduler
            self.assertIsNotNone(scheduler)
            session = Path(scheduler._session_root)
            completed = Job(path=str(Path(temp) / "complete.zip"))
            completed.state = JobState.COMPLETE
            window.jobs[completed.task_id] = completed
            window._context_auto_close_armed = True
            generation = window._context_auto_close_generation

            try:
                window.show()
                self.qt_app.processEvents()
                with mock.patch.object(
                    scheduler, "stop", wraps=scheduler.stop
                ) as stop:
                    window._maybe_auto_close_context(generation)
                    self.qt_app.processEvents()

                stop.assert_called_once_with()
                self.assertTrue(window._shutdown_complete)
                self.assertIsNone(window.scheduler)
                self.assertFalse(session.exists())
                self.assertFalse(window._context_auto_close_armed)
            finally:
                window._shutdown(force=True)
                window.close()
                window.deleteLater()
                self.qt_app.processEvents()


if __name__ == "__main__":
    unittest.main()
