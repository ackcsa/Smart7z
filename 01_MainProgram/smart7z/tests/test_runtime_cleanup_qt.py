from __future__ import annotations

import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import windows_adapters
from config import DEFAULT_CONFIG
from models import Job, JobState, TERMINAL_STATES
from scheduler import Scheduler

try:
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QApplication

    import ui_qt
except ModuleNotFoundError:
    QApplication = None
    QCloseEvent = None
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
    def test_unfinished_jobs_tracks_owned_lifecycle_without_current_job(self):
        with tempfile.TemporaryDirectory() as temp:
            scheduler = Scheduler("7z.exe", _scheduler_config(temp))
            try:
                self.assertFalse(scheduler.has_unfinished_jobs())
                job = Job(path=str(Path(temp) / "queued.zip"))
                self.assertTrue(scheduler.submit(job))
                self.assertTrue(scheduler.has_unfinished_jobs())

                self.assertIs(scheduler.task_queue.get_nowait(), job)
                scheduler.task_queue.task_done()
                for state in (
                    JobState.PASSWORD_REQUIRED,
                    JobState.STEGO_CANDIDATE_REVIEW,
                    JobState.COMPLETE,
                ):
                    job.record_state(state)
                    self.assertTrue(scheduler.has_unfinished_jobs())

                scheduler._finish_job(job)
                self.assertFalse(scheduler.has_unfinished_jobs())
                scheduler.current_job = job
                self.assertTrue(scheduler.has_unfinished_jobs())
                scheduler.current_job = None
            finally:
                self.assertTrue(scheduler.stop())

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

    @contextmanager
    def make_window(self, temp, **kwargs):
        with (
            mock.patch.object(ui_qt, "load_config", return_value=_scheduler_config(temp)),
            mock.patch.object(ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"),
            mock.patch.object(ui_qt, "cleanup_stale_sessions", return_value=[]),
            mock.patch.object(ui_qt, "save_config"),
        ):
            window = ui_qt.Smart7zQtWindow(**kwargs)
            try:
                yield window
            finally:
                window._shutdown(force=True)
                window.close()
                window.deleteLater()
                self.qt_app.processEvents()

    def test_close_rejects_every_nonterminal_state_without_stopping(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window(temp) as window:
            for state in JobState:
                if state in TERMINAL_STATES:
                    continue
                with self.subTest(state=state):
                    job = Job(path=str(Path(temp) / "pending.zip"), state=state)
                    window.jobs = {job.task_id: job}
                    with (
                        mock.patch.object(
                            ui_qt.QMessageBox, "question",
                            return_value=ui_qt.QMessageBox.StandardButton.No,
                        ) as question,
                        mock.patch.object(window, "_shutdown") as shutdown,
                        mock.patch.object(window, "_flush_pending_config_edits") as flush,
                    ):
                        event = QCloseEvent()
                        window.closeEvent(event)
                        self.assertFalse(event.isAccepted())
                        question.assert_called_once()
                        self.assertEqual(
                            question.call_args.args[-1],
                            ui_qt.QMessageBox.StandardButton.No,
                        )
                        self.assertIn("未完成", question.call_args.args[2])
                        self.assertIn("重新添加", question.call_args.args[2])
                        shutdown.assert_not_called()
                        flush.assert_not_called()
                        self.assertFalse(window._closing)

    def test_close_confirms_queued_and_deferred_before_ui_delivery(self):
        for deferred in (False, True):
            with self.subTest(deferred=deferred), tempfile.TemporaryDirectory() as temp:
                with self.make_window(temp) as window:
                    scheduler = window.scheduler
                    if deferred:
                        scheduler.pause_intake()
                    source = Path(temp) / "pending.zip"
                    source.write_bytes(b"untouched source")
                    job = Job(path=str(source))
                    accepted = []
                    submitter = threading.Thread(
                        target=lambda: accepted.append(scheduler.submit(job))
                    )
                    submitter.start()
                    submitter.join(timeout=3)
                    self.assertFalse(submitter.is_alive())
                    self.assertEqual(accepted, [True])
                    self.assertEqual(window.jobs, {})
                    self.assertIsNone(scheduler.current_job)
                    self.assertEqual(scheduler.deferred_intake_size(), int(deferred))
                    with mock.patch.object(
                        ui_qt.QMessageBox, "question",
                        return_value=ui_qt.QMessageBox.StandardButton.No,
                    ) as question:
                        event = QCloseEvent()
                        window.closeEvent(event)
                    self.assertFalse(event.isAccepted())
                    question.assert_called_once()
                    self.assertTrue(scheduler.has_job(job.task_id))
                    self.assertFalse(scheduler.cancel_event.is_set())
                    self.assertEqual(source.read_bytes(), b"untouched source")

    def test_close_confirms_startup_pending_inputs_without_scheduler(self):
        for scan in (False, True):
            with self.subTest(scan=scan), tempfile.TemporaryDirectory() as temp:
                with self.make_window(temp, defer_scheduler=True) as window:
                    window._startup_pending = True
                    self.assertIsNone(window.scheduler)
                    source = Path(temp) / "pending.zip"
                    source.write_bytes(b"untouched source")
                    accepted = (
                        window._start_scan([temp])
                        if scan else window._enqueue_path(str(source))
                    )
                    self.assertTrue(accepted)
                    with mock.patch.object(
                        ui_qt.QMessageBox, "question",
                        return_value=ui_qt.QMessageBox.StandardButton.No,
                    ) as question:
                        event = QCloseEvent()
                        window.closeEvent(event)
                    self.assertFalse(event.isAccepted())
                    question.assert_called_once()
                    pending = (
                        window._pending_scan_requests
                        if scan else window._pending_startup_jobs
                    )
                    self.assertEqual(len(pending), 1)
                    self.assertFalse(window._closing)

    def test_close_confirms_active_scan_without_scheduler(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.make_window(temp, defer_scheduler=True) as window:
                window._scan_active = True
                with mock.patch.object(
                    ui_qt.QMessageBox, "question",
                    return_value=ui_qt.QMessageBox.StandardButton.No,
                ) as question:
                    event = QCloseEvent()
                    window.closeEvent(event)
                self.assertFalse(event.isAccepted())
                question.assert_called_once()
                self.assertFalse(window._scan_cancel.is_set())

    def test_close_yes_cancels_queued_job_and_releases_session(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window(temp) as window:
            source = Path(temp) / "pending.zip"
            source.write_bytes(b"untouched source")
            scheduler = window.scheduler
            session = Path(scheduler._session_root)
            job = Job(path=str(source), cleanup_policy_snapshot="permanent")
            self.assertTrue(scheduler.submit(job))
            with mock.patch.object(
                ui_qt.QMessageBox, "question",
                return_value=ui_qt.QMessageBox.StandardButton.Yes,
            ) as question:
                event = QCloseEvent()
                window.closeEvent(event)
            self.assertTrue(event.isAccepted())
            question.assert_called_once()
            self.assertTrue(window._shutdown_complete)
            self.assertIsNone(window.scheduler)
            self.assertEqual(job.state, JobState.INTERRUPTED)
            self.assertFalse(session.exists())
            self.assertEqual(source.read_bytes(), b"untouched source")

    def test_close_empty_or_only_terminal_jobs_skips_confirmation(self):
        for states in ((), tuple(TERMINAL_STATES)):
            with self.subTest(states=states), tempfile.TemporaryDirectory() as temp:
                with self.make_window(temp) as window:
                    for state in states:
                        job = Job(path=str(Path(temp) / f"{state.value}.zip"), state=state)
                        window.jobs[job.task_id] = job
                    with mock.patch.object(ui_qt.QMessageBox, "question") as question:
                        event = QCloseEvent()
                        window.closeEvent(event)
                    self.assertTrue(event.isAccepted())
                    question.assert_not_called()
                    self.assertTrue(window._shutdown_complete)

    def test_close_confirmation_prevents_reentrant_auto_close(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window(temp) as window:
            job = Job(path=str(Path(temp) / "pending.zip"))
            window.jobs[job.task_id] = job
            window._context_auto_close_armed = True
            nested_event = QCloseEvent()

            def reject_after_completion(*_args):
                job.record_state(JobState.COMPLETE)
                window.closeEvent(nested_event)
                return ui_qt.QMessageBox.StandardButton.No

            with (
                mock.patch.object(
                    ui_qt.QMessageBox, "question", side_effect=reject_after_completion
                ) as question,
                mock.patch.object(window, "_shutdown") as shutdown,
            ):
                event = QCloseEvent()
                window.closeEvent(event)
                self.assertFalse(event.isAccepted())
                self.assertFalse(nested_event.isAccepted())
                question.assert_called_once()
                shutdown.assert_not_called()
                self.assertFalse(window._close_confirmation_pending)
                self.assertFalse(window._context_auto_close_armed)

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

    def test_close_event_flushes_pending_target_dir_edit(self):
        """关窗必须补一次配置同步，收拢未触发 editingFinished 的文本框编辑。

        回归：修复前 target_edit 只接 editingFinished，用户在框内输入后不移动
        焦点、直接关窗，编辑内容会丢失（实测复现，见 .tmp_task 探针）。
        这里走真实 closeEvent 路径。
        """
        with tempfile.TemporaryDirectory() as temp:
            config = _scheduler_config(temp)
            saved = []
            with (
                mock.patch.object(ui_qt, "load_config", return_value=config),
                mock.patch.object(
                    ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"
                ),
                mock.patch.object(
                    ui_qt, "cleanup_stale_sessions", return_value=[]
                ),
                mock.patch.object(
                    ui_qt,
                    "save_config",
                    side_effect=lambda cfg, path=None: saved.append(dict(cfg)),
                ),
            ):
                window = ui_qt.Smart7zQtWindow()
                try:
                    new_target = str(Path(temp) / "OUT")
                    window.target_edit.setText(new_target)
                    # 不移动焦点、不派发 editingFinished —— 模拟"打完字直接关窗"
                    event = QCloseEvent()
                    window.closeEvent(event)
                finally:
                    window._shutdown(force=True)
                    window.close()
                    window.deleteLater()
                    self.qt_app.processEvents()

            self.assertTrue(saved, "关窗应至少触发一次配置同步")
            self.assertEqual(saved[-1].get("target_dir"), new_target)

    def test_close_event_cancels_when_config_save_fails(self):
        """手册承诺：保存失败时提示并取消本次关闭。回归此契约。"""
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
                mock.patch.object(
                    ui_qt, "save_config", side_effect=OSError("disk is read-only")
                ),
                mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            ):
                window = ui_qt.Smart7zQtWindow()
                try:
                    window.target_edit.setText(str(Path(temp) / "OUT"))
                    event = QCloseEvent()
                    window.closeEvent(event)

                    self.assertFalse(event.isAccepted(), "保存失败必须取消关闭")
                    critical.assert_called_once()
                    # 关闭被取消，窗口不该进入已关闭状态
                    self.assertFalse(window._shutdown_complete)
                finally:
                    window._shutdown(force=True)
                    window.close()
                    window.deleteLater()
                    self.qt_app.processEvents()

    def test_close_event_without_pending_edit_does_not_write_config(self):
        """无悬空编辑时不得写盘。

        回归：第一版 _flush_pending_config_edits 无条件调 _sync_config，把内存里
        的配置整体落盘。配置路径被重定向（测试注入临时配置）时会污染真实配置
        文件，并让 verify_project 的 input_fingerprint 报 input_changed。
        """
        with tempfile.TemporaryDirectory() as temp:
            config = _scheduler_config(temp)
            saved = []
            with (
                mock.patch.object(ui_qt, "load_config", return_value=config),
                mock.patch.object(
                    ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"
                ),
                mock.patch.object(
                    ui_qt, "cleanup_stale_sessions", return_value=[]
                ),
                mock.patch.object(
                    ui_qt,
                    "save_config",
                    side_effect=lambda cfg, path=None: saved.append(dict(cfg)),
                ),
            ):
                window = ui_qt.Smart7zQtWindow()
                try:
                    self.assertFalse(window._pending_config_edits())
                    event = QCloseEvent()
                    window.closeEvent(event)
                    self.assertTrue(event.isAccepted(), "无悬空编辑应允许关闭")
                finally:
                    window._shutdown(force=True)
                    window.close()
                    window.deleteLater()
                    self.qt_app.processEvents()

            self.assertEqual(saved, [], "无悬空编辑不该触发任何写盘")

    def test_pending_config_edits_tracks_textbox_against_committed_value(self):
        """悬空判定：文本框与已提交配置不一致才算脏。"""
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
                try:
                    self.assertFalse(window._pending_config_edits())
                    window.target_edit.setText(str(Path(temp) / "OTHER"))
                    self.assertTrue(window._pending_config_edits())
                    window.target_edit.setText(
                        str(config.get("target_dir", ""))
                    )
                    self.assertFalse(window._pending_config_edits())
                finally:
                    window._shutdown(force=True)
                    window.close()
                    window.deleteLater()
                    self.qt_app.processEvents()


if __name__ == "__main__":
    unittest.main()
