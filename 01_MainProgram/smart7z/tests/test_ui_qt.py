from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    import ui_qt
    from config import DEFAULT_CONFIG
    from models import Job, JobState
except ModuleNotFoundError:
    QApplication = None
    QTest = None
    ui_qt = None


class _FakeScheduler:
    def __init__(self, _sevenzip, _config, event_cb=None):
        self.event_cb = event_cb
        self.current_job = None
        self.recovery_messages = []
        self.processing_enabled = threading.Event()
        self.config = dict(_config)
        self.session_main_password = None
        self.cancel_current_calls = 0
        self.cancel_jobs_calls = []
        self.cancel_remaining_calls = 0
        self.fail_refresh = False

    def start(self):
        return None

    def stop(self):
        return None

    def submit(self, job):
        if self.event_cb is not None:
            self.event_cb("job_submitted", job)
        return True

    def enable_processing(self):
        self.processing_enabled.set()

    def disable_processing(self):
        self.processing_enabled.clear()

    def resume_intake(self):
        return 0

    def refresh_config(self, config):
        if self.fail_refresh:
            self.fail_refresh = False
            raise OSError("refresh failed")
        self.config = dict(config)

    def set_session_main_password(self, password):
        self.session_main_password = password

    def cancel_current(self):
        self.cancel_current_calls += 1

    def cancel_jobs(self, task_ids):
        self.cancel_jobs_calls.append(set(task_ids))
        return []

    def cancel_remaining(self):
        self.cancel_remaining_calls += 1
        self.processing_enabled.clear()

    def clear_finished(self, task_ids=None):
        return []

    def is_io_busy(self):
        return False

    def deferred_intake_size(self):
        return 0


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class TestQtUiLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication(["smart7z-qt-tests"])
        ui_qt._configure_qt_application(cls.qt_app)

    @contextmanager
    def make_window(self, **kwargs):
        config = dict(DEFAULT_CONFIG)
        config["temp_dir"] = tempfile.gettempdir()
        with (
            mock.patch.object(ui_qt, "load_config", return_value=config),
            mock.patch.object(ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"),
            mock.patch.object(ui_qt, "Scheduler", _FakeScheduler),
            mock.patch.object(ui_qt, "cleanup_stale_sessions", return_value=[]),
        ):
            window = ui_qt.Smart7zQtWindow(**kwargs)
            try:
                yield window
            finally:
                window._shutdown(force=True)
                window.close()
                window.deleteLater()
                self.qt_app.processEvents()

    def test_compact_inspector_replaces_large_phase_track(self):
        with self.make_window() as window:
            window.resize(920, 640)
            window.show()
            self.qt_app.processEvents()

            self.assertFalse(hasattr(window, "phase_track"))
            self.assertEqual(window.detail_phase.text(), "阶段 · -")
            self.assertLessEqual(window.workspace_splitter.sizes()[1], 145)

    def test_menu_bar_actions_are_not_clipped(self):
        with self.make_window() as window:
            window.resize(920, 640)
            window.show()
            self.qt_app.processEvents()

            menu_bar = window.menuBar()
            self.assertEqual(
                [action.text() for action in menu_bar.actions()],
                ["右键菜单", "文件扫描模式", "选项"],
            )
            for action in menu_bar.actions():
                action_rect = menu_bar.actionGeometry(action)
                self.assertTrue(action.isVisible())
                self.assertGreater(action_rect.width(), 0)
                self.assertLessEqual(action_rect.height(), menu_bar.height())

    def test_startup_args_wait_for_explicit_activation(self):
        with self.make_window(startup_args=[r"C:\incoming\sample.zip"]) as window:
            with mock.patch.object(window, "_process_external_paths") as process:
                self.qt_app.processEvents()
                process.assert_not_called()

                self.assertTrue(window._start_startup_processing())
                window._process_startup_args()

            process.assert_called_once()
            self.assertFalse(window._start_startup_processing())

    def test_zero_nested_depth_survives_settings_and_config_sync(self):
        with self.make_window() as window:
            window.config["max_nested_depth"] = 0
            dialog = ui_qt.SettingsDialog(window.config, window)
            try:
                self.assertEqual(dialog.depth_spin.value(), 0)
                self.assertEqual(dialog.values()["max_nested_depth"], 0)
                self.assertEqual(window._config_candidate()["max_nested_depth"], 0)
            finally:
                dialog.close()
                dialog.deleteLater()

    def test_password_submit_resets_sensitive_controls(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            job = Job(path=str(Path(temp) / "protected.zip"))
            window.scheduler.submit_password_response = mock.Mock()
            window._current_pwd_job = job
            window._show_password_prompt()
            window.password_edit.setText("one-time-secret")
            window.password_reveal_button.setChecked(True)

            window._submit_password()

            window.scheduler.submit_password_response.assert_called_once_with(
                job, "one-time-secret"
            )
            self.assertEqual(window.password_edit.text(), "")
            self.assertEqual(
                window.password_edit.echoMode(), ui_qt.QLineEdit.EchoMode.Password
            )
            self.assertFalse(window.password_reveal_button.isChecked())
            self.assertFalse(window.activity_shelf.isVisible())

    def test_task_table_defaults_to_original_file_size_ascending(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            root = Path(temp)
            jobs = []
            for name, original_size, working_size in (
                ("middle", 100, 1),
                ("large", 300, 2),
                ("small", 20, 3),
            ):
                original = root / f"{name}-original.bin"
                working = root / f"{name}-working.bin"
                original.write_bytes(b"o" * original_size)
                working.write_bytes(b"w" * working_size)
                jobs.append(Job(path=str(working), original_path=str(original)))
            for job in jobs:
                window.job_model.upsert(job)

            original_sizes = [
                os.path.getsize(window.job_model.job_at(row).original_path)
                for row in range(window.job_model.rowCount())
            ]
            self.assertEqual(original_sizes, sorted(original_sizes))

    def test_shutdown_reports_incomplete_components(self):
        with self.make_window() as window:
            ipc = mock.Mock()
            ipc.close.return_value = False
            window.ipc_server = ipc

            self.assertFalse(window._shutdown(force=True))
            self.assertIs(window.ipc_server, ipc)
            self.assertFalse(window._shutdown_complete)

            ipc.close.return_value = True
            self.assertTrue(window._shutdown(force=True))

    def test_file_and_folder_drop_routes_inputs_and_hides_overlay(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            archive = Path(temp) / "drop.zip"
            archive.write_bytes(b"archive")
            folder = Path(temp) / "folder"
            folder.mkdir()

            urls = []
            for path in (archive, folder):
                url = mock.Mock()
                url.isLocalFile.return_value = True
                url.toLocalFile.return_value = str(path)
                urls.append(url)
            mime_data = mock.Mock()
            mime_data.hasUrls.return_value = True
            mime_data.urls.return_value = urls
            event = mock.Mock()
            event.mimeData.return_value = mime_data

            window.show()
            self.qt_app.processEvents()
            with (
                mock.patch.object(window, "_enqueue_path") as enqueue,
                mock.patch.object(window, "_start_scan") as start_scan,
            ):
                window.dragEnterEvent(event)
                self.assertTrue(window.drop_overlay.isVisible())
                self.assertEqual(window.drop_overlay.geometry(), window.centralWidget().rect())

                window.dropEvent(event)

            enqueue.assert_called_once_with(
                str(archive), auto_start=False, explicit_input=True
            )
            start_scan.assert_called_once_with([str(folder)], auto_start=False)
            self.assertEqual(event.acceptProposedAction.call_count, 2)
            self.assertFalse(window.drop_overlay.isVisible())

    def test_phase_summary_preserves_progress_without_a_track(self):
        self.assertEqual(ui_qt.phase_summary(JobState.QUEUED), "阶段 0/5 · 等待开始")
        self.assertEqual(ui_qt.phase_summary(JobState.EXTRACTING), "阶段 3/5 · 解压")
        self.assertEqual(ui_qt.phase_summary(JobState.COMPLETE), "阶段 5/5 · 提交")

    def test_non_context_ipc_request_disarms_context_auto_close(self):
        with self.make_window() as window:
            window._context_auto_close_armed = True
            with mock.patch.object(window, "_process_external_paths", return_value=True):
                accepted = window.process_ipc_args([r"C:\queued.zip"], context_menu=False)

            self.assertTrue(accepted)
            self.assertFalse(window._context_auto_close_armed)
            self.assertEqual(window._context_auto_close_generation, 1)

    def test_activation_disarms_context_auto_close(self):
        with self.make_window() as window:
            window._context_auto_close_armed = True
            self.assertTrue(window.activate_window())
            self.assertFalse(window._context_auto_close_armed)

    def test_initial_context_presentation_keeps_auto_close_armed(self):
        with self.make_window(
            startup_args=[r"C:\incoming\sample.zip"],
            startup_context_menu=True,
        ) as window:
            self.assertTrue(window._context_auto_close_armed)
            self.assertTrue(
                window.activate_window(disarm_context_auto_close=False)
            )
            self.assertTrue(window._context_auto_close_armed)

    def test_run_app_forwards_before_constructing_qapplication(self):
        accepted = mock.Mock(accepted=True)
        with (
            mock.patch.object(ui_qt, "_forward_launch_request", return_value=accepted),
            mock.patch.object(ui_qt, "QApplication") as qapplication,
        ):
            self.assertEqual(ui_qt.run_app([r"C:\\input.zip"]), 0)

        qapplication.assert_not_called()

    def test_run_app_reuses_bootstrap_forward_result(self):
        accepted = mock.Mock(accepted=True)
        with (
            mock.patch.object(ui_qt, "_forward_launch_request") as forward,
            mock.patch.object(ui_qt, "QApplication") as qapplication,
        ):
            self.assertEqual(
                ui_qt.run_app(
                    [r"C:\\input.zip"], initial_forward_result=accepted
                ),
                0,
            )

        forward.assert_not_called()
        qapplication.assert_not_called()

    def test_icon_font_family_selection_does_not_probe_font_database(self):
        original_family = ui_qt._ICON_FONT_FAMILY
        expected_family = (
            "Segoe Fluent Icons" if sys.platform == "win32" else "Segoe MDL2 Assets"
        )
        try:
            ui_qt._ICON_FONT_FAMILY = None
            with mock.patch.object(
                ui_qt,
                "QFont",
                side_effect=("font-14", "font-16"),
            ) as qfont:
                self.assertEqual(ui_qt._icon_font(14), "font-14")
                self.assertEqual(ui_qt._icon_font(16), "font-16")
        finally:
            ui_qt._ICON_FONT_FAMILY = original_family

        self.assertEqual(
            qfont.call_args_list,
            [
                mock.call(expected_family, 14),
                mock.call(expected_family, 16),
            ],
        )

    def test_activity_shelf_is_lazy_until_first_activity(self):
        with self.make_window() as window:
            self.assertFalse(window._activity_shelf_ready)
            self.assertTrue(window.activity_shelf.isHidden())
            window._show_scan_activity()
            self.assertTrue(window._activity_shelf_ready)
            self.assertFalse(window.activity_shelf.isHidden())
            self.assertIs(
                window.activity_stack.currentWidget(), window.scan_activity_page
            )

    def test_completed_context_window_closes_only_when_still_armed(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            archive = Path(temp) / "done.zip"
            archive.write_bytes(b"archive")
            job = Job(path=str(archive))
            job.state = JobState.COMPLETE
            window.jobs[job.task_id] = job
            window._context_auto_close_armed = True
            generation = window._context_auto_close_generation

            with mock.patch.object(ui_qt.Smart7zQtWindow, "close", autospec=True) as close:
                window._maybe_auto_close_context(generation)

            close.assert_called_once_with()

    def test_main_password_is_visible_session_only_and_not_persisted(self):
        with self.make_window() as window, mock.patch.object(ui_qt, "save_config") as save:
            self.assertEqual(
                window.main_password_edit.echoMode(),
                ui_qt.QLineEdit.EchoMode.Normal,
            )
            window.main_password_edit.setText("session-secret")
            self.qt_app.processEvents()

            self.assertEqual(window._main_password, "session-secret")
            self.assertEqual(window.scheduler.session_main_password, "session-secret")
            self.assertTrue(window._sync_config(silent=True))
            persisted = save.call_args.args[0]
            self.assertNotIn("main_password", persisted)

    def test_command_bar_line_edits_are_deferred_until_first_focus(self):
        with self.make_window() as window:
            self.assertIsInstance(window.target_edit, ui_qt.DeferredLineEdit)
            self.assertIsInstance(window.main_password_edit, ui_qt.DeferredLineEdit)
            self.assertFalse(window.target_edit.isMaterialized())
            self.assertFalse(window.main_password_edit.isMaterialized())
            self.assertEqual(window.findChildren(ui_qt.QLineEdit), [])

            window.show()
            self.qt_app.processEvents()
            self.assertFalse(window.target_edit.isMaterialized())
            self.assertFalse(window.main_password_edit.isMaterialized())

            window.target_edit.setFocus(ui_qt.Qt.FocusReason.OtherFocusReason)
            self.qt_app.processEvents()

            self.assertTrue(window.target_edit.isMaterialized())
            self.assertIsInstance(window.target_edit._editor, ui_qt.QLineEdit)
            self.assertFalse(window.main_password_edit.isMaterialized())

    def test_deferred_line_edit_preserves_value_signals_and_native_properties(self):
        edit = ui_qt.DeferredLineEdit("initial")
        native_reference = ui_qt.QLineEdit()
        changes = []
        edit.textChanged.connect(changes.append)
        edit.setPlaceholderText("placeholder")
        edit.setAccessibleName("deferred input")
        edit.setEchoMode(ui_qt.QLineEdit.EchoMode.Password)
        try:
            edit.setText("secret")
            edit.setText("secret")
            self.assertEqual(edit.text(), "secret")
            self.assertEqual(changes, ["secret"])
            self.assertFalse(edit.isMaterialized())
            self.assertEqual(edit.sizeHint(), native_reference.sizeHint())
            self.assertEqual(edit.minimumSizeHint(), native_reference.minimumSizeHint())

            edit.show()
            edit.setFocus(ui_qt.Qt.FocusReason.OtherFocusReason)
            self.qt_app.processEvents()

            native = edit._editor
            self.assertIsNotNone(native)
            self.assertEqual(native.text(), "secret")
            self.assertEqual(native.placeholderText(), "placeholder")
            self.assertEqual(native.echoMode(), ui_qt.QLineEdit.EchoMode.Password)
            self.assertEqual(native.accessibleName(), "deferred input")
            edit.selectAll()
            self.assertEqual(edit.selectedText(), "secret")
        finally:
            native_reference.close()
            native_reference.deleteLater()
            edit.close()
            edit.deleteLater()
            self.qt_app.processEvents()

    def test_deferred_line_edit_materializes_on_click_and_accepts_typing(self):
        edit = ui_qt.DeferredLineEdit()
        edit.resize(edit.sizeHint())
        try:
            edit.show()
            self.qt_app.processEvents()
            QTest.mouseClick(
                edit,
                ui_qt.Qt.MouseButton.LeftButton,
                pos=edit.rect().center(),
            )
            self.qt_app.processEvents()

            self.assertTrue(edit.isMaterialized())
            self.assertTrue(edit._editor.hasFocus())
            QTest.keyClicks(edit._editor, "typed value")
            self.assertEqual(edit.text(), "typed value")
        finally:
            edit.close()
            edit.deleteLater()
            self.qt_app.processEvents()

    def test_deferred_line_edit_keeps_command_bar_keyboard_order(self):
        with self.make_window() as window:
            window.show()
            window.target_edit.setFocus(ui_qt.Qt.FocusReason.TabFocusReason)
            self.qt_app.processEvents()
            native = window.target_edit._editor
            self.assertIsNotNone(native)
            self.assertTrue(native.hasFocus())

            QTest.keyClick(native, ui_qt.Qt.Key.Key_Backtab)
            self.qt_app.processEvents()
            focused = self.qt_app.focusWidget()
            self.assertIsInstance(focused, ui_qt.QPushButton)
            self.assertEqual(focused.text(), "扫描文件夹")

            window.target_edit.setFocus(ui_qt.Qt.FocusReason.TabFocusReason)
            self.qt_app.processEvents()
            QTest.keyClick(native, ui_qt.Qt.Key.Key_Tab)
            self.qt_app.processEvents()

            browse_buttons = window.findChildren(
                ui_qt.QToolButton, "compactIconButton"
            )
            self.assertTrue(any(button.hasFocus() for button in browse_buttons))

    def test_settings_dialog_is_grouped_and_excludes_target_and_main_password(self):
        with self.make_window() as window:
            self.assertEqual(window.options_action.text(), "选项")
            self.assertIsNone(window.options_action.menu())
            dialog = ui_qt.SettingsDialog(window.config, window)
            try:
                self.assertEqual(dialog.windowTitle(), "选项")
                self.assertEqual(
                    [group.title() for group in dialog.findChildren(ui_qt.QGroupBox)],
                    ["路径", "处理"],
                )
                self.assertFalse(hasattr(dialog, "target_edit"))
                self.assertFalse(hasattr(dialog, "main_password_edit"))
                self.assertEqual(
                    [button.text() for button in dialog.findChildren(ui_qt.QPushButton, "browseButton")],
                    ["浏览…", "浏览…"],
                )
            finally:
                dialog.close()
                dialog.deleteLater()

    def test_settings_path_picker_updates_temp_directory(self):
        with self.make_window() as window:
            dialog = ui_qt.SettingsDialog(window.config, window)
            try:
                with mock.patch.object(
                    ui_qt.QFileDialog,
                    "getExistingDirectory",
                    return_value=r"C:\Temp\picked",
                ):
                    dialog._browse_temp()
                self.assertEqual(dialog.temp_edit.text(), r"C:\Temp\picked")
            finally:
                dialog.close()
                dialog.deleteLater()

    def test_queue_actions_have_fixed_order_and_clear_disabled_states(self):
        with self.make_window() as window:
            buttons = window.queue_panel.findChildren(ui_qt.QPushButton, "queueActionButton")
            self.assertEqual(
                [button.text() for button in buttons],
                ["取消当前", "取消选中", "清除已完成", "取消所有待处理", "隐藏详情"],
            )
            self.assertFalse(window.cancel_current_button.isEnabled())
            self.assertFalse(window.cancel_selected_button.isEnabled())
            self.assertFalse(window.clear_finished_button.isEnabled())
            self.assertFalse(window.cancel_pending_button.isEnabled())

    def test_cancel_selected_only_targets_unfinished_jobs(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            current = Job(path=str(Path(temp) / "current.zip"))
            queued = Job(path=str(Path(temp) / "queued.zip"))
            completed = Job(path=str(Path(temp) / "completed.zip"))
            current.state = JobState.EXTRACTING
            queued.state = JobState.QUEUED
            completed.state = JobState.COMPLETE
            for job in (current, queued, completed):
                window.jobs[job.task_id] = job
                window.job_model.upsert(job)
            window.scheduler.current_job = current
            window.job_table.selectRow(window.job_model.row_for_id(queued.task_id))
            window._update_summary()

            self.assertTrue(window.cancel_selected_button.isEnabled())
            window._cancel_selected()
            self.assertEqual(window.scheduler.cancel_jobs_calls, [{queued.task_id}])
            self.assertEqual(window.scheduler.cancel_current_calls, 0)
            self.assertIn(completed.task_id, window.jobs)

    def test_processing_button_returns_to_start_for_terminal_outcomes(self):
        for state in (JobState.COMPLETE, JobState.FAILED, JobState.INTERRUPTED):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp, self.make_window() as window:
                job = Job(path=str(Path(temp) / "done.zip"))
                job.state = state
                window.jobs[job.task_id] = job
                window.job_model.upsert(job)
                window.scheduler.processing_enabled.set()
                window._processing_requested = True
                window._update_summary()

                self.assertEqual(window.start_button.text(), "开始")
                self.assertFalse(window.start_button.isEnabled())

    def test_cancel_all_pending_keeps_current_and_resets_start_button(self):
        with tempfile.TemporaryDirectory() as temp, self.make_window() as window:
            current = Job(path=str(Path(temp) / "current.zip"))
            pending = Job(path=str(Path(temp) / "pending.zip"))
            current.state = JobState.EXTRACTING
            pending.state = JobState.QUEUED
            for job in (current, pending):
                window.jobs[job.task_id] = job
                window.job_model.upsert(job)
            window.scheduler.current_job = current
            window.scheduler.processing_enabled.set()
            window._update_summary()

            window._cancel_remaining()

            self.assertEqual(window.scheduler.cancel_remaining_calls, 1)
            self.assertEqual(window.scheduler.cancel_current_calls, 0)
            self.assertIs(window.scheduler.current_job, current)
            self.assertEqual(window.start_button.text(), "开始")

    def test_inspector_toggle_uses_explicit_text(self):
        with self.make_window() as window:
            self.assertEqual(window.inspector_toggle.text(), "隐藏详情")
            window._toggle_inspector()
            self.assertEqual(window.inspector_toggle.text(), "显示详情")
            window._toggle_inspector()
            self.assertEqual(window.inspector_toggle.text(), "隐藏详情")

    def test_config_apply_rolls_back_when_scheduler_refresh_fails(self):
        with self.make_window() as window:
            old_config = dict(window.config)
            candidate = dict(old_config)
            candidate["temp_dir"] = r"C:\Temp\new"
            window.scheduler.fail_refresh = True
            with mock.patch.object(ui_qt, "save_config") as save:
                self.assertFalse(window._apply_config(candidate, silent=True))
                self.assertEqual(window.config, old_config)
                self.assertEqual(window.scheduler.config, old_config)
                self.assertEqual(save.call_count, 2)

    def test_table_palette_uses_soft_ops_console_row_colors(self):
        self.assertEqual(ui_qt.COLOR_ROW_ALTERNATE.name().upper(), "#F7FAF9")
        self.assertEqual(ui_qt.COLOR_ROW_HOVER.name().upper(), "#EEF4F2")
        self.assertEqual(ui_qt.COLOR_ROW_SELECTED.name().upper(), "#E2F3F0")
        self.assertIn("alternate-background-color: #f7faf9", ui_qt.QT_STYLESHEET)

    def test_application_palette_replaces_universal_font_and_color_rule(self):
        stylesheet_prefix = ui_qt.QT_STYLESHEET.lstrip().split("QMainWindow", 1)[0]
        self.assertNotIn("* {", stylesheet_prefix)
        palette = self.qt_app.palette()
        self.assertEqual(
            palette.color(ui_qt.QPalette.ColorRole.Text), ui_qt.COLOR_TEXT
        )
        self.assertEqual(
            palette.color(ui_qt.QPalette.ColorRole.PlaceholderText),
            ui_qt.COLOR_MUTED,
        )


if __name__ == "__main__":
    unittest.main()
