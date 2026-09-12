from __future__ import annotations

import os
import tempfile
import threading
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QEventLoop, QMimeData, QPointF, QTimer, QUrl, Qt
    from PySide6.QtGui import QDropEvent
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLineEdit, QToolButton
except ModuleNotFoundError as error:
    if not (error.name == "PySide6" or error.name.startswith("PySide6.")):
        raise
    QApplication = None
    ui_qt = None
else:
    import ui_qt
    from config import DEFAULT_CONFIG
    from models import ArchiveCandidate, CleanupPolicy, ErrorCategory, Job, JobState


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

    def has_unfinished_jobs(self):
        return self.current_job is not None or any(
            not job.is_terminal for job in self.submitted_jobs
        )

    def deferred_intake_size(self):
        return 0

    def resume_intake(self):
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

    def test_main_password_spaces_survive_edit_and_config_apply(self):
        with self.make_window() as window:
            value = " fixture password "
            window.main_password_edit.setText(value)
            self.assertEqual(window.scheduler.session_main_password, value)
            with mock.patch.object(ui_qt, "save_config"):
                self.assertTrue(window._sync_config())
            self.assertEqual(window.scheduler.session_main_password, value)
            window.main_password_edit.clear()
            self.assertIsNone(window.scheduler.session_main_password)

    def test_cleanup_policy_switch_and_start_only_affect_new_intake(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            files = [Path(temp, name) for name in ("old.zip", "new.zip", "external.zip")]
            for path in files:
                path.write_bytes(b"fixture")
            with mock.patch.object(ui_qt, "save_config"):
                self.assertTrue(window._enqueue_path(str(files[0])))
                self.assertTrue(window._apply_config({**window.config, "cleanup_policy": "permanent"}))
                self.assertTrue(window._enqueue_path(str(files[1])))
                self.assertTrue(window._enqueue_path(
                    str(files[2]), config_snapshot={**window.config, "cleanup_policy": "keep"}
                ))
                window._start_processing()
            self.assertEqual(
                [job.cleanup_policy_snapshot for job in window.scheduler.submitted_jobs],
                ["keep", "permanent", "keep"],
            )

    def test_cancel_scan_rejects_real_queued_signals_without_starting_queue(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            path = Path(temp, "cancelled.zip")
            path.write_bytes(b"fixture")
            window._scan_active = True
            window._scan_auto_start = True
            generation = window._scan_generation

            def emit_late_results():
                window.bridge.scan_candidate.emit(str(path), dict(window.config), [], False, generation)
                window.bridge.scan_finished.emit(1, "", generation)

            worker = threading.Thread(target=emit_late_results)
            worker.start()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            with mock.patch.object(window, "log_event") as log_event:
                window._cancel_scan()
                self.qt_app.processEvents()
            self.assertEqual(window.scheduler.submitted_jobs, [])
            self.assertFalse(window.scheduler.processing_enabled.is_set())
            self.assertFalse(window._scan_active)
            self.assertNotIn("SCAN_COMPLETE", [call.args[0] for call in log_event.call_args_list])

    def test_new_scan_is_not_finished_or_rearmed_by_previous_scan_signals(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            root = Path(temp)
            old_path = root / "old.zip"
            old_path.write_bytes(b"old fixture")
            new_root = root / "new"
            new_root.mkdir()
            new_path = new_root / "new.zip"
            with zipfile.ZipFile(new_path, "w") as archive:
                archive.writestr("payload.txt", "new fixture")
            window._scan_active = True
            old_generation = window._scan_generation

            def emit_old_results():
                window.bridge.scan_candidate.emit(str(old_path), dict(window.config), [], True, old_generation)
                window.bridge.scan_finished.emit(1, "", old_generation)

            worker = threading.Thread(target=emit_old_results)
            worker.start()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            window._cancel_scan()
            self.assertTrue(window._start_scan(
                [str(new_root)], auto_start=False,
                config_snapshot={**window.config, "deep_scan": False, "steganographier_compat_mode": False},
            ))
            new_worker = window._scan_thread
            new_worker.join(timeout=3)
            self.assertFalse(new_worker.is_alive())
            self.qt_app.processEvents()
            self.assertEqual(
                [Path(job.path) for job in window.scheduler.submitted_jobs],
                [new_path],
            )
            self.assertFalse(window.scheduler.processing_enabled.is_set())
            self.assertFalse(window._scan_active)

    def test_silent_config_failure_has_status_and_log_feedback(self):
        with self.make_window() as window:
            with (
                mock.patch.object(ui_qt, "save_config", side_effect=OSError("fixture read only")),
                mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            ):
                self.assertFalse(window._apply_config(
                    {**window.config, "nested_extraction": True}, silent=True
                ))
            critical.assert_not_called()
            self.assertIn("CONFIG_APPLY_FAILED", window.log_output.toPlainText())
            self.assertIn("fixture read only", window.log_output.toPlainText())
            self.assertIn("失败", window.statusBar().currentMessage())
            self.assertFalse(window.config["nested_extraction"])

    def test_skipped_jobs_are_ended_but_never_reported_as_success(self):
        with self.make_window() as window:
            skipped = Job(path="skipped.zip")
            skipped.record_state(JobState.SKIPPED)
            window._upsert_job(skipped)
            window._update_summary()
            self.assertNotIn("全部完成", window.status_state.text())
            self.assertIn("0 成功", window.progress_summary_text.text())
            self.assertIn("1 已结束", window.progress_summary_text.text())
            self.assertEqual(window.total_progress.value(), 100)
            success = Job(path="success.zip")
            success.record_state(JobState.COMPLETE)
            window._upsert_job(success)
            window._update_summary()
            self.assertIn("1 成功", window.progress_summary_text.text())
            self.assertIn("2 已结束", window.progress_summary_text.text())

    def test_failure_details_show_reason_advice_and_actual_last_phase(self):
        with self.make_window() as window:
            job = Job(path="broken.zip")
            job.record_state(JobState.LISTING)
            job.record_state(JobState.FAILED)
            job.error_category = ErrorCategory.MISSING_VOLUME
            job.error_message = "Missing archive.003 <not HTML>"
            window._update_details(job)
            self.assertIn(job.error_message, window.detail_error.text())
            self.assertIn("missing_volume", window.detail_error.text())
            self.assertIn("补齐", window.detail_action.text())
            self.assertIn("2/5", window.detail_phase.text())
            self.assertNotIn("5/5", window.detail_phase.text())
            self.assertEqual(window.detail_error.textFormat(), Qt.TextFormat.PlainText)
            window._update_details(None)
            self.assertTrue(window.detail_error.isHidden())
            self.assertTrue(window.detail_action.isHidden())
            self.assertEqual(window.detail_values["output"].toolTip(), "")

    def test_deferred_table_model_preserves_column_layout(self):
        with self.make_window() as window:
            window.resize(920, 640)
            window.show()
            window._upsert_job(Job(path="long-" * 50 + ".zip"))
            self.qt_app.processEvents()
            table = window.job_table
            header = table.horizontalHeader()
            self.assertEqual(header.sectionResizeMode(0), ui_qt.QHeaderView.ResizeMode.Stretch)
            self.assertGreater(table.columnWidth(0), 200)
            self.assertEqual(table.columnWidth(1), 70)
            self.assertEqual(table.columnWidth(6), 122)
            self.assertLessEqual(abs(sum(table.columnWidth(column) for column in range(7)) - table.viewport().width()), 2)

    def test_slow_real_recovery_keeps_ui_responsive_and_retains_pending_policy(self):
        from recovery import RecoveryJournal
        from scheduler import Scheduler

        with tempfile.TemporaryDirectory() as temp:
            config = {
                "temp_dir": str(Path(temp, "staging")),
                "_recovery_journal_path": str(Path(temp, "recovery.json")),
            }
            with self.make_window(config, defer_scheduler=True) as window:
                window._apply_deferred_icons()
                entered = threading.Event()
                release = threading.Event()
                real_recover = RecoveryJournal.recover

                def gated_recovery(journal, *args, **kwargs):
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("Recovery fixture gate timed out")
                    return real_recover(journal, *args, **kwargs)

                beats = []
                heartbeat = QTimer()
                heartbeat.setInterval(10)
                heartbeat.setTimerType(Qt.TimerType.PreciseTimer)
                loop = QEventLoop()

                def beat():
                    beats.append(True)
                    if len(beats) >= 3:
                        loop.quit()

                heartbeat.timeout.connect(beat)
                with (
                    mock.patch.object(ui_qt, "Scheduler", Scheduler),
                    mock.patch.object(RecoveryJournal, "recover", new=gated_recovery),
                    mock.patch.object(ui_qt, "save_config"),
                ):
                    heartbeat.start()
                    try:
                        window._setup_scheduler(background=True)
                        self.assertTrue(entered.wait(3))
                        QTimer.singleShot(1500, loop.quit)
                        loop.exec()
                        self.assertGreaterEqual(len(beats), 3)
                        self.assertTrue(window._startup_pending)
                        path = Path(temp, "queued.zip")
                        path.write_bytes(b"fixture")
                        self.assertTrue(window.process_ipc_args([str(path)], False, "keep"))
                        self.assertTrue(window._apply_config({**window.config, "cleanup_policy": "permanent"}))
                    finally:
                        release.set()
                        heartbeat.stop()
                    for _ in range(300):
                        if not window._startup_pending:
                            break
                        QTest.qWait(10)
                    self.assertIsNotNone(window.scheduler)
                    self.assertFalse(window._startup_pending)
                    self.assertEqual(len(window.jobs), 1)
                    job = next(iter(window.jobs.values()))
                    self.assertEqual(job.cleanup_policy_snapshot, "keep")
                    self.assertEqual(window.scheduler.config["cleanup_policy"], "permanent")
                    self.assertFalse(window.scheduler.processing_enabled.is_set())

    def test_startup_queue_cancellation_dedup_and_password_transfer(self):
        from runtime_startup import SchedulerStartupResult

        with tempfile.TemporaryDirectory() as temp, self.make_window(defer_scheduler=True) as window:
            path = Path(temp, "queued.zip")
            path.write_bytes(b"fixture")
            window._startup_pending = True
            self.assertTrue(window._enqueue_path(str(path)))
            self.assertFalse(window._enqueue_path(str(path)))
            job = next(iter(window.jobs.values()))
            with mock.patch.object(window, "_selected_jobs", return_value=[job]):
                window._cancel_selected()
            self.assertEqual(window._pending_startup_jobs, [])
            self.assertEqual(window.jobs, {})
            self.assertTrue(window._enqueue_path(str(path)))
            window._main_password_changed(" secret ")
            config = {**window.config, "7z_path": r"C:\7z.exe"}
            scheduler = _BehaviorScheduler(config["7z_path"], config, window._scheduler_callback)
            self.assertTrue(window._install_startup_scheduler(SchedulerStartupResult(scheduler, config)))
            self.assertEqual(len(scheduler.submitted_jobs), 1)
            self.assertFalse(window._enqueue_path(str(path)))
            self.assertEqual(scheduler.session_main_password, " secret ")

    def test_failed_startup_keeps_ownership_until_shutdown_can_stop_it(self):
        from runtime_startup import SchedulerStartupResult

        with self.make_window(defer_scheduler=True) as window:
            config = {**window.config, "7z_path": r"C:\7z.exe"}
            scheduler = mock.Mock()
            scheduler.start.side_effect = RuntimeError("fixture start failed")
            scheduler.stop.side_effect = [False, False, True]
            with (
                mock.patch.object(window, "_create_startup_scheduler", return_value=SchedulerStartupResult(scheduler, config)) as build,
                mock.patch.object(ui_qt.QMessageBox, "critical"),
            ):
                window._setup_scheduler()
                self.assertIs(window._failed_startup_scheduler, scheduler)
                self.assertIsNone(window.scheduler)
                self.assertTrue(window.startup_blocked)
                window._setup_scheduler()
                build.assert_called_once()
                self.assertIs(window._failed_startup_scheduler, scheduler)
                self.assertTrue(window._shutdown(force=True))
                self.assertIsNone(window._failed_startup_scheduler)
                self.assertEqual(scheduler.stop.call_count, 3)

    def test_temp_permission_failure_is_visible_and_retryable(self):
        with self.make_window(defer_scheduler=True) as window:
            with (
                mock.patch.object(window, "_prepare_temp_dir", side_effect=PermissionError("fixture denied")),
                mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            ):
                window._setup_scheduler()
            self.assertTrue(window.startup_blocked)
            self.assertFalse(window._startup_pending)
            self.assertIsNone(window.scheduler)
            critical.assert_called_once()
            self.assertEqual(window.start_button.text(), "重试启动")
            self.assertTrue(window.start_button.isEnabled())
            with mock.patch.object(ui_qt, "save_config"):
                window._start_processing()
            for _ in range(300):
                if not window._startup_pending:
                    break
                QTest.qWait(10)
            self.assertIsNotNone(window.scheduler)
            self.assertFalse(window.startup_blocked)

    def test_activity_shelf_is_initially_hidden(self):
        with self.make_window() as window:
            window.resize(1000, 720)
            window.show()
            self.qt_app.processEvents()
            self.assertTrue(window.activity_shelf.isHidden())

    def test_password_prompt_stays_above_late_stego_prompt(self):
        with self.make_window() as window:
            password_job = Job(path=r"C:\protected.7z")
            window._queue_password_prompt(password_job)
            window.password_edit.setText("in-progress")
            stego = Job(path=r"C:\cover.bin", stego_candidates=[ArchiveCandidate()])
            window._queue_stego_prompt(stego)
            window._show_scan_activity()
            self.assertIs(window.activity_stack.currentWidget(), window.password_activity_page)
            self.assertEqual(window.password_edit.text(), "in-progress")
            window._remove_finished_ids({password_job.task_id})
            self.assertIs(window.activity_stack.currentWidget(), window.stego_activity_page)

    def test_candidate_preselection_and_explicit_competitor_choice(self):
        with self.make_window() as window:
            job = Job(
                path=r"C:\cover.bin",
                stego_candidates=[
                    ArchiveCandidate(embedded_format="zip", start_offset=8, end_offset=24),
                    ArchiveCandidate(embedded_format="zip", start_offset=40, end_offset=80),
                ],
            )
            window._queue_stego_prompt(job)
            self.assertEqual(window.stego_combo.currentIndex(), -1)
            window._submit_stego()
            self.assertEqual(window.scheduler.stego_selections, [])
            self.assertIs(window._current_stego_job, job)
            window.stego_combo.setCurrentIndex(1)
            window._submit_stego()
            self.assertEqual(window.scheduler.stego_selections, [(job, 1)])
            job.stego_recommended_index = 0
            window._queue_stego_prompt(job)
            self.assertEqual(window.stego_combo.currentData(), 0)
            self.assertIn("推荐", window.stego_combo.currentText())
            self.assertIn("8 - 24", window.stego_combo.itemData(0, Qt.ItemDataRole.ToolTipRole))

    def test_prompt_rows_stay_on_top_in_both_sort_directions(self):
        with self.make_window() as window:
            normal = Job(path="a.zip")
            password = Job(path="z.zip", state=JobState.PASSWORD_REQUIRED)
            stego = Job(path="m.zip", state=JobState.STEGO_CANDIDATE_REVIEW)
            for job in (normal, password, stego):
                window._upsert_job(job)
            for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
                window.job_model.sort(0, order)
                self.assertEqual(list(window.job_model.jobs()), [password, stego, normal])
            window.job_table.selectRow(window.job_model.row_for_id(normal.task_id))
            password.state = JobState.COMPLETE
            window._upsert_job(password)
            self.assertIs(window._selected_job(), normal)
            self.assertIs(window.job_model.job_at(0), stego)

    def test_activity_shelf_is_transient_and_uses_prompt_priority(self):
        with self.make_window() as window:
            window.resize(1000, 720)
            window.show()
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

    def test_scan_mode_label_follows_snapshot_while_scanning(self):
        """扫描进行中标签必须显示冻结的快照模式，不能跟随实时配置漂移。

        回归：修复前 _scan_mode_label() 直接读 self.config，用户在扫描期间
        切换菜单会让标签与真正在跑的模式不符（实测复现见 .tmp_task 探针）。
        """
        with self.make_window() as window:
            normal_snapshot = {
                "deep_scan": False,
                "steganographier_compat_mode": False,
            }
            deep_live = {"deep_scan": True, "steganographier_compat_mode": False}

            # 扫描中：实时配置已切到深度，标签必须仍报快照的普通模式
            window.config = deep_live
            window._scan_active = True
            window._scan_config_snapshot = normal_snapshot
            self.assertEqual(window._scan_mode_label(), "普通模式")
            self.assertEqual(
                window._scan_mode_from_config(window._scan_config_snapshot),
                ui_qt.SCAN_MODE_NORMAL,
            )

            # 反向：快照深、实时普通
            window.config = normal_snapshot
            window._scan_config_snapshot = deep_live
            self.assertEqual(window._scan_mode_label(), "深度扫描模式")

            # 空闲：跟随实时配置
            window._scan_active = False
            window._scan_config_snapshot = None
            window.config = deep_live
            self.assertEqual(window._scan_mode_label(), "深度扫描模式")

            # 扫描中但快照缺失：回落到实时配置，不抛异常
            window._scan_active = True
            window._scan_config_snapshot = None
            window.config = {"deep_scan": False, "steganographier_compat_mode": True}
            self.assertEqual(window._scan_mode_label(), "仅兼容隐写者模式")

    def test_long_path_is_elided_with_full_tooltip(self):
        """超长路径必须中间省略，并用 tooltip 提供完整路径。

        回归：修复前 detail_path.setText(459 字符路径) 让 sizeHint 达 5508px
        （窗口宽 1180px），布局被撑爆且无 tooltip 可看全路径（实测复现）。
        """
        long_path = "C:\\Users\\23700\\Downloads\\" + "\\".join(
            f"nested_directory_level_{i:02d}_with_descriptive_name" for i in range(8)
        ) + "\\final_archive_with_a_quite_long_name_2026-09-11.7z"

        with self.make_window() as window:
            # 纯函数：短路径不动，超长路径压缩且保留两端
            self.assertEqual(ui_qt.elide_path_middle(r"C:\a\b.zip"), r"C:\a\b.zip")
            elided = ui_qt.elide_path_middle(long_path)
            self.assertLess(len(elided), len(long_path))
            self.assertIn("...", elided)
            self.assertTrue(elided.startswith("C:\\"))
            self.assertTrue(elided.endswith("2026-09-11.7z"))

            job = Job(path=long_path, original_path=long_path)
            window._update_details(job)

            self.assertEqual(window.detail_path.text(), elided)
            self.assertEqual(window.detail_path.toolTip(), long_path)
            self.assertLess(window.detail_path.sizeHint().width(), 1180)

            # 未选中任务时必须清掉 tooltip，避免残留上一个任务的路径
            window._update_details(None)
            self.assertEqual(window.detail_path.toolTip(), "")

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
