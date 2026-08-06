from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication

    import runtime_ipc
    import ui_qt
    from config import DEFAULT_CONFIG
except ModuleNotFoundError:
    QApplication = None
    runtime_ipc = None
    ui_qt = None
    DEFAULT_CONFIG = None


class _FakeScheduler:
    def __init__(self, _sevenzip, config, event_cb=None):
        self.event_cb = event_cb
        self.current_job = None
        self.recovery_messages = []
        self.processing_enabled = threading.Event()
        self.config = dict(config)
        self.session_main_password = None
        self.submitted = []
        self.stop_calls = 0
        self.stop_result = True

    def start(self):
        return None

    def stop(self):
        self.stop_calls += 1
        return self.stop_result

    def submit(self, job):
        self.submitted.append(job)
        return True

    def enable_processing(self):
        self.processing_enabled.set()

    def disable_processing(self):
        self.processing_enabled.clear()

    def resume_intake(self):
        return 0

    def refresh_config(self, config):
        self.config = dict(config)

    def set_session_main_password(self, password):
        self.session_main_password = password

    def cancel_current(self):
        return None

    def cancel_jobs(self, _task_ids):
        return []

    def cancel_remaining(self):
        self.processing_enabled.clear()

    def clear_finished(self, _task_ids=None):
        return []

    def is_io_busy(self):
        return False

    def deferred_intake_size(self):
        return 0


def _forward_result(status, reason="", *, reached_existing=False):
    return SimpleNamespace(
        status=status,
        reason=reason,
        accepted=status == "accepted",
        reached_existing=reached_existing,
    )


def _launch_request():
    return SimpleNamespace(
        paths=(),
        auto_start=True,
        cleanup_policy="keep",
        extract_to_source=False,
        context_menu=False,
    )


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class TestQtIpcIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication(
            ["smart7z-qt-ipc-integration-tests"]
        )
        ui_qt._configure_qt_application(cls.qt_app)

    def _pump_until(self, predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.qt_app.processEvents()
            if predicate():
                return True
            time.sleep(0.005)
        self.qt_app.processEvents()
        return bool(predicate())

    @contextmanager
    def _window(self, temp_dir):
        config = dict(DEFAULT_CONFIG)
        config["temp_dir"] = temp_dir
        config["target_dir"] = os.path.join(temp_dir, "output")
        with (
            mock.patch.object(ui_qt, "load_config", return_value=config),
            mock.patch.object(ui_qt, "find_sevenzip", return_value=r"C:\7z.exe"),
            mock.patch.object(ui_qt, "Scheduler", _FakeScheduler),
            mock.patch.object(ui_qt, "cleanup_stale_sessions", return_value=[]),
        ):
            window = ui_qt.Smart7zQtWindow()
        self.qt_app.processEvents()
        try:
            yield window
        finally:
            server = window.ipc_server
            if server is not None:
                try:
                    server.close()
                except Exception:
                    pass
            scheduler = window.scheduler
            if scheduler is not None:
                try:
                    scheduler.stop()
                except Exception:
                    pass
            window.ipc_server = None
            window.scheduler = None
            window._closing = True
            window._shutdown_complete = True
            window.close()
            window.deleteLater()
            self.qt_app.processEvents()

    @staticmethod
    def _start_client(server, path):
        completed = threading.Event()
        result_box = {}

        def worker():
            try:
                result_box["result"] = runtime_ipc.forward_to_existing(
                    [str(path)],
                    port=server.port,
                    token=server.token,
                )
            finally:
                completed.set()

        thread = threading.Thread(target=worker, name="QtIPCIntegrationClient", daemon=True)
        thread.start()
        return thread, completed, result_box

    def test_real_qt_bridge_dispatches_ipc_request_on_application_thread(self):
        with tempfile.TemporaryDirectory() as temp, self._window(temp) as window:
            archive = Path(temp) / "round-trip.zip"
            archive.write_bytes(b"payload")
            state_path = str(Path(temp) / "ipc-state.json")
            server = runtime_ipc.BoundedIPCServer(
                window,
                port=0,
                state_path=state_path,
            )
            window.ipc_server = server
            self.assertTrue(server.start())

            ui_thread_id = threading.get_ident()
            dispatch_thread_ids = []
            original_process = window.process_ipc_args

            def record_dispatch(*args, **kwargs):
                dispatch_thread_ids.append(threading.get_ident())
                return original_process(*args, **kwargs)

            with mock.patch.object(
                window,
                "process_ipc_args",
                side_effect=record_dispatch,
            ):
                client, completed, result_box = self._start_client(server, archive)
                self.assertTrue(
                    self._pump_until(completed.is_set),
                    "IPC client did not receive a Qt-thread acknowledgement",
                )
                client.join(timeout=1.0)

            result = result_box["result"]
            self.assertTrue(result.accepted)
            self.assertEqual(result.status, runtime_ipc.IPC_FORWARD_ACCEPTED)
            self.assertEqual(dispatch_thread_ids, [ui_thread_id])
            self.assertEqual(len(window.scheduler.submitted), 1)
            self.assertEqual(
                os.path.normcase(window.scheduler.submitted[0].path),
                os.path.normcase(os.path.normpath(str(archive))),
            )

    def test_begin_draining_replies_server_stopping_without_dispatch(self):
        with tempfile.TemporaryDirectory() as temp, self._window(temp) as window:
            archive = Path(temp) / "draining.zip"
            archive.write_bytes(b"payload")
            server = runtime_ipc.BoundedIPCServer(
                window,
                port=0,
                state_path=str(Path(temp) / "ipc-state.json"),
            )
            window.ipc_server = server
            self.assertTrue(server.start())

            server.begin_draining()
            result = runtime_ipc.forward_to_existing(
                [str(archive)],
                port=server.port,
                token=server.token,
            )

            self.assertEqual(result.status, runtime_ipc.IPC_FORWARD_REJECTED)
            self.assertEqual(result.reason, "server_stopping")
            self.assertTrue(result.reached_existing)
            self.assertEqual(window.scheduler.submitted, [])

    def test_pending_qt_ticket_is_cancelled_before_ipc_close_returns(self):
        with tempfile.TemporaryDirectory() as temp, self._window(temp) as window:
            archive = Path(temp) / "pending.zip"
            archive.write_bytes(b"payload")
            server = runtime_ipc.BoundedIPCServer(
                window,
                port=0,
                state_path=str(Path(temp) / "ipc-state.json"),
            )
            window.ipc_server = server
            self.assertTrue(server.start())

            posted = threading.Event()
            original_post = window._post_to_ui

            def record_post(callback, *args):
                queued = original_post(callback, *args)
                if queued:
                    posted.set()
                return queued

            client = None
            completed = None
            shutdown_result = None
            elapsed = None
            listener_alive = None
            with (
                mock.patch.object(window, "_post_to_ui", side_effect=record_post),
                mock.patch.object(runtime_ipc, "IPC_ACK_TIMEOUT_SECONDS", 2.0),
            ):
                client, completed, _result_box = self._start_client(server, archive)
                self.assertTrue(posted.wait(1.0), "IPC request was not queued to Qt")
                started = time.monotonic()
                shutdown_result = window._shutdown(force=True)
                elapsed = time.monotonic() - started
                listener_alive = bool(server._thread and server._thread.is_alive())

            try:
                self.assertIs(shutdown_result, True)
                self.assertLess(
                    elapsed,
                    1.25,
                    "shutdown waited for the IPC ACK timeout instead of cancelling the ticket",
                )
                self.assertFalse(listener_alive)
            finally:
                if completed is not None:
                    completed.wait(2.5)
                if client is not None:
                    client.join(timeout=0.5)
                server.close()
                window.ipc_server = None

    def test_shutdown_returns_false_when_ipc_or_scheduler_does_not_stop(self):
        cases = (
            (False, True, "ipc"),
            (True, False, "scheduler"),
        )
        for ipc_stopped, scheduler_stopped, label in cases:
            with self.subTest(component=label), tempfile.TemporaryDirectory() as temp:
                with self._window(temp) as window:
                    ipc = mock.Mock()
                    ipc.close.return_value = ipc_stopped
                    scheduler = mock.Mock()
                    scheduler.stop.return_value = scheduler_stopped
                    window.ipc_server = ipc
                    window.scheduler = scheduler

                    result = window._shutdown(force=True)

                    self.assertIs(result, False)
                    ipc.close.assert_called_once_with()
                    scheduler.stop.assert_called_once_with()

    def test_run_app_does_not_release_mutex_before_shutdown_completes(self):
        app = mock.Mock()
        app.exec.return_value = 0
        qapplication = mock.Mock()
        qapplication.instance.return_value = app
        request = _launch_request()
        instance_mutex = object()
        window = mock.Mock()
        window.startup_blocked = False
        window.scheduler = object()
        ipc = mock.Mock()
        ipc.start.return_value = True
        events = []
        shutdown_results = iter((False, True))

        def shutdown(*, force=False):
            result = next(shutdown_results)
            events.append(("shutdown", result, force))
            return result

        def close_mutex(handle):
            events.append(("close_mutex", handle))
            return True

        window._shutdown.side_effect = shutdown
        with (
            mock.patch.object(ui_qt.sys, "platform", "win32"),
            mock.patch.object(ui_qt, "QApplication", qapplication),
            mock.patch.object(ui_qt, "_configure_qt_application"),
            mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
            mock.patch.object(
                ui_qt,
                "_forward_launch_request",
                return_value=_forward_result(
                    runtime_ipc.IPC_FORWARD_UNAVAILABLE,
                    "state_unavailable",
                ),
            ),
            mock.patch.object(ui_qt, "create_mutex", return_value=instance_mutex),
            mock.patch.object(ui_qt, "close_mutex", side_effect=close_mutex),
            mock.patch.object(ui_qt, "Smart7zQtWindow", return_value=window),
            mock.patch.object(ui_qt, "BoundedIPCServer", return_value=ipc),
        ):
            ui_qt.run_app([])

        self.assertEqual(events[0], ("shutdown", False, True))
        close_indexes = [
            index for index, event in enumerate(events) if event[0] == "close_mutex"
        ]
        if close_indexes:
            close_index = close_indexes[0]
            self.assertIn(
                ("shutdown", True, True),
                events[:close_index],
                "mutex was released before shutdown reported completion",
            )

    def test_reached_rejected_and_indeterminate_never_create_window(self):
        cases = (
            (
                runtime_ipc.IPC_FORWARD_REJECTED,
                "intake_full",
            ),
            (
                runtime_ipc.IPC_FORWARD_INDETERMINATE,
                "dispatch_in_progress",
            ),
        )
        for status, reason in cases:
            with self.subTest(status=status):
                app = mock.Mock()
                qapplication = mock.Mock()
                qapplication.instance.return_value = app
                request = _launch_request()
                with (
                    mock.patch.object(ui_qt, "QApplication", qapplication),
                    mock.patch.object(ui_qt, "_configure_qt_application"),
                    mock.patch.object(ui_qt, "parse_launch_args", return_value=request),
                    mock.patch.object(
                        ui_qt,
                        "_forward_launch_request",
                        return_value=_forward_result(
                            status,
                            reason,
                            reached_existing=True,
                        ),
                    ),
                    mock.patch.object(ui_qt, "create_mutex") as create_mutex,
                    mock.patch.object(ui_qt, "Smart7zQtWindow") as window_type,
                    mock.patch.object(ui_qt, "BoundedIPCServer") as ipc_type,
                    mock.patch.object(ui_qt.QMessageBox, "critical") as critical,
                ):
                    exit_code = ui_qt.run_app([])

                self.assertEqual(exit_code, 1)
                critical.assert_called_once()
                create_mutex.assert_not_called()
                window_type.assert_not_called()
                ipc_type.assert_not_called()
                app.exec.assert_not_called()


if __name__ == "__main__":
    unittest.main()
