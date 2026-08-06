from __future__ import annotations

import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QMimeData, QPointF, QUrl, Qt
    from PySide6.QtGui import QDropEvent
    from PySide6.QtWidgets import QApplication, QLineEdit, QToolButton

    import ui_qt
    from config import DEFAULT_CONFIG
    from models import ArchiveCandidate, CleanupPolicy, Job, JobState
except ModuleNotFoundError:
    QApplication = None
    ui_qt = None


class _FakeRunner:
    def supported_formats(self, timeout=15):
        return ()


class _BehaviorScheduler:
    def __init__(self, _sevenzip, config, event_cb=None):
        self.event_cb = event_cb
        self.config = dict(config)
        self.current_job = None
        self.recovery_messages = []
        self.processing_enabled = threading.Event()
        self.runner = _FakeRunner()
        self.submitted_jobs = []
        self.password_responses = []
        self.skipped_password_jobs = []
        self.stego_selections = []
        self.refresh_calls = []
        self.session_main_password = None
        self.io_busy = False

    def start(self):
        return None

    def stop(self):
        return None

    def submit(self, job):
        self.submitted_jobs.append(job)
        if self.event_cb is not None:
            self.event_cb("job_submitted", job)
        return True

    def enable_processing(self):
        self.processing_enabled.set()

    def disable_processing(self):
        self.processing_enabled.clear()

    def refresh_config(self, config):
        self.refresh_calls.append(dict(config))
        self.config = dict(config)

    def set_session_main_password(self, password):
        self.session_main_password = password

    def submit_password_response(self, job, password):
        self.password_responses.append((job, password))

    def skip_password_job(self, job):
        self.skipped_password_jobs.append(job)

    def submit_stego_selection(self, job, index):
        self.stego_selections.append((job, index))

    def is_io_busy(self):
        return self.io_busy

    def deferred_intake_size(self):
        return 0


class _ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, **_unused):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}
        self._alive = False

    def start(self):
        self._alive = True
        try:
            if self._target is not None:
                self._target(*self._args, **self._kwargs)
        finally:
            self._alive = False

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):
        return None


@contextmanager
def _blocked_signals(*controls):
    previous = [control.blockSignals(True) for control in controls]
    try:
        yield
    finally:
        for control, was_blocked in zip(controls, previous):
            control.blockSignals(was_blocked)


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class TestQtHighRiskBehaviors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication(
            ["smart7z-qt-behavior-tests"]
        )
        ui_qt._configure_qt_application(cls.qt_app)

    @contextmanager
    def make_window(self, config_overrides=None, **kwargs):
        config = dict(DEFAULT_CONFIG)
        config["temp_dir"] = tempfile.gettempdir()
        config.update(config_overrides or {})
        with (
            mock.patch.object(ui_qt, "load_config", return_value=config),
            mock.patch.object(ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"),
            mock.patch.object(ui_qt, "Scheduler", _BehaviorScheduler),
            mock.patch.object(ui_qt, "cleanup_stale_sessions", return_value=[]),
        ):
            window = ui_qt.Smart7zQtWindow(**kwargs)
            self.qt_app.processEvents()
            try:
                yield window
            finally:
                window._shutdown(force=True)
                window.close()
                window.deleteLater()
                self.qt_app.processEvents()

    def test_scan_mode_menu_is_exclusive_and_persists_each_mode(self):
        expected_modes = {
            ui_qt.SCAN_MODE_DEEP,
            ui_qt.SCAN_MODE_STEGANOGRAPHIER,
            ui_qt.SCAN_MODE_NORMAL,
        }
        with self.make_window() as window, mock.patch.object(
            ui_qt, "save_config"
        ) as save:
            self.assertTrue(window.scan_action_group.isExclusive())
            self.assertEqual(set(window.scan_actions), expected_modes)

            for mode in (
                ui_qt.SCAN_MODE_DEEP,
                ui_qt.SCAN_MODE_NORMAL,
                ui_qt.SCAN_MODE_STEGANOGRAPHIER,
            ):
                with self.subTest(mode=mode):
                    window.scan_actions[mode].trigger()
                    self.qt_app.processEvents()
                    checked = {
                        key
                        for key, action in window.scan_actions.items()
                        if action.isChecked()
                    }
                    self.assertEqual(checked, {mode})
                    self.assertEqual(
                        window.config["deep_scan"],
                        mode == ui_qt.SCAN_MODE_DEEP,
                    )
                    self.assertEqual(
                        window.config["steganographier_compat_mode"],
                        mode == ui_qt.SCAN_MODE_STEGANOGRAPHIER,
                    )

            self.assertEqual(save.call_count, 3)

    def test_settings_dialog_round_trips_wait_for_disk_space(self):
        with self.make_window({"wait_disk_space": False}) as window:
            dialog = ui_qt.SettingsDialog(window.config, window)
            try:
                self.assertFalse(dialog.wait_space_check.isChecked())
                dialog.wait_space_check.click()
                self.assertTrue(dialog.wait_space_check.isChecked())
                self.assertTrue(dialog.values()["wait_disk_space"])
            finally:
                dialog.close()
                dialog.deleteLater()

    def test_activity_shelf_is_transient_and_uses_prompt_priority(self):
        with self.make_window() as window:
            window.resize(1000, 720)
            window.show()
            self.qt_app.processEvents()
            self.assertTrue(window.activity_shelf.isHidden())

            window._show_scan_activity()
            self.qt_app.processEvents()
            self.assertFalse(window.activity_shelf.isHidden())
            self.assertIs(
                window.activity_stack.currentWidget(), window.scan_activity_page
            )

            stego_job = Job(
                path=r"C:\cover.bin",
                original_path=r"C:\cover.bin",
                stego_candidates=[
                    ArchiveCandidate(
                        embedded_format="zip", start_offset=8, end_offset=24
                    )
                ],
            )
            window._queue_stego_prompt(stego_job)
            self.assertIs(
                window.activity_stack.currentWidget(), window.stego_activity_page
            )

            password_job = Job(
                path=r"C:\protected.7z", original_path=r"C:\protected.7z"
            )
            window._queue_password_prompt(password_job)
            self.assertIs(
                window.activity_stack.currentWidget(), window.password_activity_page
            )

            window._current_pwd_job = None
            window._show_next_password_prompt()
            self.assertIs(
                window.activity_stack.currentWidget(), window.stego_activity_page
            )

            window._current_stego_job = None
            window._show_next_stego_prompt()
            self.assertIs(
                window.activity_stack.currentWidget(), window.scan_activity_page
            )

            window._scan_active = False
            window._sync_activity_visibility()
            self.assertTrue(window.activity_shelf.isHidden())

    def test_qt_runtime_logs_stable_catalog_messages(self):
        with self.make_window() as window:
            self.assertIn("[APP_READY]", window.log_output.toPlainText())
            window.log_output.clear()

            job = Job(path=r"C:\blocked.zip", original_path=r"C:\blocked.zip")
            job.source_retention_reason = "manifest_limit"
            job.error_message = "manifest entry limit exceeded"
            window._handle_scheduler_event(
                "state_change",
                job,
                (JobState.FAILED, job.error_message, 0),
                {},
            )
            window._handle_scheduler_event(
                "user_notice",
                job,
                ("operator review required",),
                {},
            )
            window._handle_scheduler_event("password_promoted", job, (), {})

            log_text = window.log_output.toPlainText()
            self.assertIn("[ARCHIVE_BLOCKED]", log_text)
            self.assertIn("[USER_NOTICE]", log_text)
            self.assertIn("[PASSWORD_PROMOTED]", log_text)

    def test_password_submit_resets_sensitive_controls_and_hides_shelf(self):
        with self.make_window() as window:
            window.show()
            job = Job(
                path=r"C:\protected.7z", original_path=r"C:\protected.7z"
            )
            window._queue_password_prompt(job)
            reveal = next(
                button
                for button in window.password_activity_page.findChildren(QToolButton)
                if button.isCheckable()
            )
            window.password_edit.setText("one-time-secret")
            reveal.setChecked(True)
            self.qt_app.processEvents()
            self.assertEqual(
                window.password_edit.echoMode(), QLineEdit.EchoMode.Normal
            )

            window._submit_password()
            self.qt_app.processEvents()

            self.assertEqual(window.scheduler.password_responses, [(job, "one-time-secret")])
            self.assertEqual(
                (
                    window.password_edit.text(),
                    window.password_edit.echoMode(),
                    reveal.isChecked(),
                    window.activity_shelf.isHidden(),
                ),
                ("", QLineEdit.EchoMode.Password, False, True),
            )

    def test_details_splitter_is_adjustable_collapsible_and_restores_size(self):
        with self.make_window() as window:
            window.resize(1000, 720)
            window.show()
            self.qt_app.processEvents()
            initial = window.workspace_splitter.sizes()

            window.workspace_splitter.setSizes([360, 240])
            self.qt_app.processEvents()
            adjusted = window.workspace_splitter.sizes()
            self.assertGreater(adjusted[1], initial[1] + 40)

            window._toggle_inspector()
            self.qt_app.processEvents()
            collapsed = window.workspace_splitter.sizes()
            self.assertFalse(window._inspector_expanded)
            self.assertLess(collapsed[1], adjusted[1])

            window._toggle_inspector()
            self.qt_app.processEvents()
            restored = window.workspace_splitter.sizes()
            self.assertTrue(window._inspector_expanded)
            self.assertAlmostEqual(restored[1], adjusted[1], delta=12)

    def test_task_table_defaults_to_original_file_size_ascending(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            root = Path(temp)

            def make_job(name, original_size, working_size):
                original = root / f"{name}-original.bin"
                working = root / f"{name}-working.bin"
                original.write_bytes(b"o" * original_size)
                working.write_bytes(b"w" * working_size)
                return Job(
                    path=str(working),
                    original_path=str(original),
                    original_basename=original.name,
                )

            jobs = (
                make_job("middle", 100, 1),
                make_job("large", 300, 2),
                make_job("small", 20, 3),
            )
            for job in jobs:
                window._upsert_job(job)
            self.qt_app.processEvents()

            model = window.job_table.model()
            visible_jobs = [
                model.index(row, 0).data(ui_qt.JobTableModel.JobRole)
                for row in range(model.rowCount())
            ]
            original_sizes = [
                os.path.getsize(job.original_path) for job in visible_jobs
            ]
            self.assertEqual(original_sizes, sorted(original_sizes))

    def test_drop_event_marks_files_as_explicit_input(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            archive = Path(temp) / "dragged.bin"
            archive.write_bytes(b"payload")
            mime = QMimeData()
            mime.setUrls([QUrl.fromLocalFile(str(archive))])
            event = QDropEvent(
                QPointF(12, 12),
                Qt.DropAction.CopyAction,
                mime,
                Qt.MouseButton.LeftButton,
                Qt.KeyboardModifier.NoModifier,
            )

            window.dropEvent(event)
            self.qt_app.processEvents()

            self.assertTrue(event.isAccepted())
            self.assertEqual(len(window.scheduler.submitted_jobs), 1)
            self.assertTrue(window.scheduler.submitted_jobs[0].explicit_input)

    def test_deep_folder_scan_prefers_steganographier_compat_candidate(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            source = Path(temp) / "cover.bin"
            source.write_bytes(b"cover-data")
            candidate = ArchiveCandidate(
                embedded_format="zip", start_offset=2, end_offset=8
            )
            calls = []

            def compat_probe(*_args, **_kwargs):
                calls.append("steganographier")
                return [candidate]

            def classifier(*_args, **_kwargs):
                calls.append("classifier")
                raise AssertionError("classifier must not run after a compat hit")

            def generic_probe(*_args, **_kwargs):
                calls.append("generic")
                raise AssertionError("generic deep scan must not preempt compat")

            snapshot = dict(window.config)
            snapshot["deep_scan"] = True
            snapshot["steganographier_compat_mode"] = True
            with (
                mock.patch.object(ui_qt.threading, "Thread", _ImmediateThread),
                mock.patch.object(
                    ui_qt,
                    "find_steganographier_candidates",
                    side_effect=compat_probe,
                ),
                mock.patch.object(
                    ui_qt, "classify_automatic_candidate", side_effect=classifier
                ),
                mock.patch.object(ui_qt, "find_candidates", side_effect=generic_probe),
            ):
                self.assertTrue(
                    window._start_scan(
                        [temp], auto_start=False, config_snapshot=snapshot
                    )
                )
                self.qt_app.processEvents()

            self.assertEqual(calls, ["steganographier"])
            self.assertEqual(len(window.scheduler.submitted_jobs), 1)
            submitted = window.scheduler.submitted_jobs[0]
            self.assertFalse(submitted.explicit_input)
            self.assertEqual(submitted.stego_candidates, [candidate])

    def test_first_save_failure_rolls_back_config_and_controls(self):
        with self.make_window() as window:
            previous = dict(window.config)
            candidate = dict(previous)
            candidate.update(
                {
                    "target_dir": r"C:\rolled-back-target",
                    "extract_to_source": not previous["extract_to_source"],
                    "extract_mode": "direct",
                    "nested_extraction": not previous["nested_extraction"],
                    "cleanup_policy": CleanupPolicy.RECYCLE.value,
                    "del_archive": False,
                    "deep_scan": True,
                    "steganographier_compat_mode": False,
                }
            )
            controls = (
                window.target_edit,
                window.extract_source_check,
                window.staging_check,
                window.nested_check,
                *window.cleanup_buttons.values(),
                *window.scan_actions.values(),
            )
            with _blocked_signals(*controls):
                window.target_edit.setText(candidate["target_dir"])
                window.extract_source_check.setChecked(candidate["extract_to_source"])
                window.staging_check.setChecked(False)
                window.nested_check.setChecked(candidate["nested_extraction"])
                window.cleanup_buttons[CleanupPolicy.RECYCLE.value].setChecked(True)
                window.scan_actions[ui_qt.SCAN_MODE_DEEP].setChecked(True)

            with mock.patch.object(
                ui_qt, "save_config", side_effect=OSError("first write failed")
            ) as save:
                self.assertFalse(window._apply_config(candidate, silent=True))

            self.assertEqual(save.call_count, 1)
            self.assertEqual(window.scheduler.refresh_calls, [])
            self.assertEqual(window.config, previous)
            self.assertEqual(window.target_edit.text(), previous["target_dir"])
            self.assertEqual(
                window.extract_source_check.isChecked(),
                previous["extract_to_source"],
            )
            self.assertEqual(
                window.staging_check.isChecked(),
                previous["extract_mode"] == "staging",
            )
            self.assertEqual(
                window.nested_check.isChecked(),
                previous["nested_extraction"],
            )
            self.assertTrue(
                window.cleanup_buttons[previous["cleanup_policy"]].isChecked()
            )
            self.assertTrue(
                window.scan_actions[
                    window._scan_mode_from_config(previous)
                ].isChecked()
            )

    def test_context_menu_completion_auto_closes(self):
        with self.make_window() as window:
            job = Job(path=r"C:\done.zip", original_path=r"C:\done.zip")
            job.state = JobState.COMPLETE
            window.jobs[job.task_id] = job
            window._context_auto_close_armed = True
            generation = window._context_auto_close_generation

            with mock.patch.object(
                ui_qt.Smart7zQtWindow, "close", autospec=True
            ) as close:
                window._maybe_auto_close_context(generation)

            close.assert_called_once_with()

    def test_context_menu_abnormal_or_active_state_does_not_close(self):
        with self.make_window() as window:
            complete = Job(path=r"C:\done.zip", original_path=r"C:\done.zip")
            complete.state = JobState.COMPLETE
            failed = Job(path=r"C:\failed.zip", original_path=r"C:\failed.zip")
            failed.state = JobState.FAILED
            generation = window._context_auto_close_generation

            with mock.patch.object(
                ui_qt.Smart7zQtWindow, "close", autospec=True
            ) as close:
                window.jobs = {failed.task_id: failed}
                window._context_auto_close_armed = True
                window._maybe_auto_close_context(generation)

                window.jobs = {complete.task_id: complete}
                window._context_auto_close_abnormal = True
                window._maybe_auto_close_context(generation)

                window._context_auto_close_abnormal = False
                window.scheduler.current_job = Job(
                    path=r"C:\active.zip", original_path=r"C:\active.zip"
                )
                window._maybe_auto_close_context(generation)

                window.scheduler.current_job = None
                window._scan_active = True
                window._maybe_auto_close_context(generation)

            close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
