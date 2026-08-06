from __future__ import annotations

import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    import ui_qt
    from config import DEFAULT_CONFIG
    from models import Job, JobState
except ModuleNotFoundError:
    QApplication = None
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


def _launch_request(**overrides):
    values = {
        "paths": (r"C:\incoming\sample.zip",),
        "auto_start": True,
        "cleanup_policy": "keep",
        "extract_to_source": False,
        "context_menu": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _forward_result(status, reason="", *, reached_existing=False):
    return SimpleNamespace(
        status=status,
        reason=reason,
        accepted=status == "accepted",
        reached_existing=reached_existing,
    )


def _run_app_window():
    window = mock.Mock()
    window.startup_blocked = False
    window.scheduler = object()
    return window


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class TestQtRunAppLifecycle(unittest.TestCase):
    def _qapplication_patch(self, app):
        qapplication = mock.Mock()
        qapplication.instance.return_value = app
        return mock.patch.object(ui_qt, "QApplication", qapplication)

    def test_accepted_request_exits_without_creating_window(self):
        app = mock.Mock()
        request = _launch_request()
        accepted = _forward_result("accepted", reached_existing=True)

        with (
            self._qapplication_patch(app),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(ui_qt, "_forward_launch_request", return_value=accepted),
            mock.patch.object(ui_qt, "create_mutex") as create_mutex,
            mock.patch.object(ui_qt, "Smart7zQtWindow") as window_type,
            mock.patch.object(ui_qt, "BoundedIPCServer") as ipc_type,
        ):
            exit_code = ui_qt.run_app([r"C:\incoming\sample.zip"])

        self.assertEqual(exit_code, 0)
        create_mutex.assert_not_called()
        window_type.assert_not_called()
        ipc_type.assert_not_called()
        app.exec.assert_not_called()

    def test_server_stopping_waits_and_eventually_forwards(self):
        app = mock.Mock()
        request = _launch_request()
        stopping = _forward_result(
            "rejected",
            "server_stopping",
            reached_existing=True,
        )
        accepted = _forward_result("accepted", reached_existing=True)

        with (
            self._qapplication_patch(app),
            mock.patch.object(ui_qt.sys, "platform", "win32"),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(
                ui_qt,
                "_forward_launch_request",
                side_effect=[stopping, stopping, accepted],
            ) as forward,
            mock.patch.object(ui_qt, "create_mutex", side_effect=[None, None]) as create_mutex,
            mock.patch.object(ui_qt.time, "monotonic", side_effect=[100.0, 100.0]),
            mock.patch.object(ui_qt.time, "sleep") as sleep,
            mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            mock.patch.object(ui_qt, "Scheduler") as scheduler_type,
            mock.patch.object(ui_qt, "Smart7zQtWindow") as window_type,
        ):
            exit_code = ui_qt.run_app([])

        self.assertEqual(exit_code, 0)
        self.assertEqual(forward.call_count, 3)
        self.assertEqual(create_mutex.call_count, 2)
        sleep.assert_called_once_with(ui_qt.INSTANCE_STARTUP_POLL_SECONDS)
        critical.assert_not_called()
        scheduler_type.assert_not_called()
        window_type.assert_not_called()
        app.exec.assert_not_called()

    def test_stopping_instance_exits_then_mutex_is_claimed_and_window_starts(self):
        app = mock.Mock()
        app.exec.return_value = 23
        request = _launch_request(auto_start=False, extract_to_source=True)
        stopping = _forward_result(
            "rejected",
            "server_stopping",
            reached_existing=True,
        )
        unavailable = _forward_result("unavailable", "state_unavailable")
        instance_mutex = object()
        window = _run_app_window()
        ipc = mock.Mock()
        ipc.start.return_value = True

        with (
            self._qapplication_patch(app),
            mock.patch.object(ui_qt.sys, "platform", "win32"),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(
                ui_qt,
                "_forward_launch_request",
                side_effect=[stopping, unavailable],
            ),
            mock.patch.object(
                ui_qt,
                "create_mutex",
                side_effect=[None, instance_mutex],
            ) as create_mutex,
            mock.patch.object(ui_qt, "close_mutex") as close_mutex,
            mock.patch.object(ui_qt, "Smart7zQtWindow", return_value=window) as window_type,
            mock.patch.object(ui_qt, "BoundedIPCServer", return_value=ipc) as ipc_type,
        ):
            exit_code = ui_qt.run_app([])

        self.assertEqual(exit_code, 23)
        self.assertEqual(create_mutex.call_count, 2)
        window_type.assert_called_once_with(
            startup_args=request.paths,
            startup_auto_start=False,
            startup_cleanup_policy=request.cleanup_policy,
            startup_extract_to_source=True,
            startup_context_menu=False,
        )
        ipc_type.assert_called_once_with(window)
        ipc.start.assert_called_once_with()
        window.show.assert_called_once_with()
        window.activate_window.assert_called_once_with()
        window._shutdown.assert_called_once_with(force=True)
        close_mutex.assert_called_once_with(instance_mutex)

    def test_wait_timeout_does_not_create_window_or_scheduler(self):
        app = mock.Mock()
        request = _launch_request()
        stopping = _forward_result(
            "rejected",
            "server_stopping",
            reached_existing=True,
        )

        with (
            self._qapplication_patch(app),
            mock.patch.object(ui_qt.sys, "platform", "win32"),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(ui_qt, "_forward_launch_request", return_value=stopping),
            mock.patch.object(ui_qt, "create_mutex", return_value=None) as create_mutex,
            mock.patch.object(ui_qt, "INSTANCE_STARTUP_WAIT_SECONDS", 0.0),
            mock.patch.object(ui_qt.time, "monotonic", return_value=100.0),
            mock.patch.object(ui_qt.time, "sleep") as sleep,
            mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            mock.patch.object(ui_qt, "Scheduler") as scheduler_type,
            mock.patch.object(ui_qt, "Smart7zQtWindow") as window_type,
        ):
            exit_code = ui_qt.run_app([])

        self.assertEqual(exit_code, 1)
        self.assertEqual(create_mutex.call_count, 2)
        sleep.assert_not_called()
        critical.assert_called_once()
        scheduler_type.assert_not_called()
        window_type.assert_not_called()
        app.exec.assert_not_called()

    def test_ipc_bind_failure_retries_forwarding_before_exiting(self):
        app = mock.Mock()
        request = _launch_request()
        unavailable = _forward_result("unavailable", "state_unavailable")
        accepted = _forward_result("accepted", reached_existing=True)
        instance_mutex = object()
        window = _run_app_window()
        ipc = mock.Mock()
        ipc.start.return_value = False

        with (
            self._qapplication_patch(app),
            mock.patch.object(ui_qt.sys, "platform", "win32"),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(
                ui_qt,
                "_forward_launch_request",
                side_effect=[unavailable, accepted],
            ) as forward,
            mock.patch.object(ui_qt, "create_mutex", return_value=instance_mutex),
            mock.patch.object(ui_qt, "close_mutex") as close_mutex,
            mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
            mock.patch.object(ui_qt, "Smart7zQtWindow", return_value=window),
            mock.patch.object(ui_qt, "BoundedIPCServer", return_value=ipc),
        ):
            exit_code = ui_qt.run_app([])

        self.assertEqual(exit_code, 0)
        self.assertEqual(forward.call_count, 2)
        ipc.start.assert_called_once_with()
        self.assertEqual(window._shutdown.call_count, 2)
        critical.assert_not_called()
        app.exec.assert_not_called()
        close_mutex.assert_called_once_with(instance_mutex)

    def test_mutex_is_released_when_startup_or_shutdown_stages_raise(self):
        unavailable = _forward_result("unavailable", "state_unavailable")

        for failing_stage in ("window", "ipc_start", "app_exec", "shutdown"):
            with self.subTest(failing_stage=failing_stage):
                app = mock.Mock()
                request = _launch_request()
                instance_mutex = object()
                window = _run_app_window()
                window_type = mock.Mock(return_value=window)
                ipc = mock.Mock()
                ipc.start.return_value = True

                if failing_stage == "window":
                    window_type.side_effect = RuntimeError("window failed")
                elif failing_stage == "ipc_start":
                    ipc.start.side_effect = RuntimeError("ipc start failed")
                elif failing_stage == "app_exec":
                    app.exec.side_effect = RuntimeError("app exec failed")
                else:
                    window._shutdown.side_effect = RuntimeError("shutdown failed")

                with (
                    self._qapplication_patch(app),
                    mock.patch.object(ui_qt.sys, "platform", "win32"),
                    mock.patch.object(ui_qt, "_configure_qt_application"),
                    mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
                    mock.patch.object(
                        ui_qt,
                        "_forward_launch_request",
                        return_value=unavailable,
                    ),
                    mock.patch.object(ui_qt, "create_mutex", return_value=instance_mutex),
                    mock.patch.object(ui_qt, "close_mutex") as close_mutex,
                    mock.patch.object(ui_qt, "Smart7zQtWindow", window_type),
                    mock.patch.object(ui_qt, "BoundedIPCServer", return_value=ipc),
                ):
                    with self.assertRaisesRegex(RuntimeError, "failed"):
                        ui_qt.run_app([])

                if failing_stage == "shutdown":
                    close_mutex.assert_not_called()
                else:
                    close_mutex.assert_called_once_with(instance_mutex)
                if failing_stage == "window":
                    window._shutdown.assert_not_called()
                else:
                    window._shutdown.assert_called_once_with(force=True)


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


if __name__ == "__main__":
    unittest.main()
