"""Runtime-level IPC and Windows integration tests for the Qt application."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

import launch_ipc
import runtime_ipc
import windows_adapters


class TestIpcLifecycle(unittest.TestCase):
    def test_absent_instance_mutex_skips_stale_state_and_socket_probe(self):
        with (
            mock.patch.object(launch_ipc, "_instance_mutex_exists", return_value=False),
            mock.patch.object(launch_ipc, "_read_ipc_state") as read_state,
        ):
            result = launch_ipc.forward_to_existing([r"C:\input.zip"])

        self.assertEqual(result.status, launch_ipc.IPC_FORWARD_UNAVAILABLE)
        self.assertEqual(result.reason, "instance_unavailable")
        self.assertFalse(result.reached_existing)
        read_state.assert_not_called()

    def test_state_file_requires_publisher_pid(self):
        with tempfile.TemporaryDirectory() as temp:
            state_path = Path(temp) / "ipc-state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "version": launch_ipc.IPC_VERSION,
                        "port": 59777,
                        "token": "x" * 43,
                    }
                ),
                encoding="utf-8",
            )

            self.assertIsNone(launch_ipc._read_ipc_state(str(state_path)))

    def test_round_trip_ack_and_listener_shutdown(self):
        received = []
        delivered = threading.Event()

        class App:
            @staticmethod
            def _post_to_ui(callback, *args):
                callback(*args)
                return True

            @staticmethod
            def process_ipc_args(
                paths,
                auto_start=True,
                cleanup_policy="keep",
                extract_to_source=False,
                context_menu=False,
            ):
                received.append(
                    (
                        list(paths),
                        auto_start,
                        cleanup_policy,
                        extract_to_source,
                        context_menu,
                    )
                )
                delivered.set()
                return True

            @staticmethod
            def activate_window():
                return True

        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "ipc_path.zip"
            archive.write_bytes(b"payload")
            state_path = str(Path(temp) / "ipc-state.json")
            server = runtime_ipc.BoundedIPCServer(
                App(), port=0, state_path=state_path
            )
            try:
                self.assertTrue(server.start())
                self.assertTrue(
                    runtime_ipc.try_forward_to_existing(
                        [str(archive)],
                        port=server.port,
                        auto_start=False,
                        cleanup_policy="permanent",
                        extract_to_source=True,
                        context_menu=True,
                        token=server.token,
                    )
                )
                self.assertTrue(delivered.wait(2.0))
                self.assertEqual(
                    received,
                    [
                        (
                            [os.path.normpath(str(archive))],
                            False,
                            "permanent",
                            True,
                            True,
                        )
                    ],
                )
            finally:
                server.close()

            self.assertIsNone(server.sock)
            self.assertIsNone(server._thread)

    def test_rejected_reply_is_distinct_from_unavailable_server(self):
        class App:
            @staticmethod
            def _post_to_ui(callback, *args):
                callback(*args)
                return True

            @staticmethod
            def process_ipc_args(
                _paths,
                _auto_start=True,
                _cleanup_policy="keep",
                _extract_to_source=False,
                _context_menu=False,
            ):
                return False

            @staticmethod
            def activate_window():
                return False

        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "rejected.zip"
            archive.write_bytes(b"payload")
            state_path = str(Path(temp) / "ipc-state.json")
            server = runtime_ipc.BoundedIPCServer(
                App(), port=0, state_path=state_path
            )
            try:
                self.assertTrue(server.start())
                result = runtime_ipc.forward_to_existing(
                    [str(archive)],
                    port=server.port,
                    token=server.token,
                )
            finally:
                server.close()

            self.assertEqual(result.status, runtime_ipc.IPC_FORWARD_REJECTED)
            self.assertEqual(result.reason, "intake_full")
            self.assertTrue(result.reached_existing)

            unavailable = runtime_ipc.forward_to_existing(
                [str(archive)], port=1, token="x" * 43
            )
            self.assertEqual(unavailable.status, runtime_ipc.IPC_FORWARD_UNAVAILABLE)
            self.assertFalse(unavailable.reached_existing)

    def test_pending_dispatch_timeout_cancels_late_ui_callback(self):
        calls = []

        class App:
            @staticmethod
            def process_ipc_args(
                paths,
                auto_start=True,
                cleanup_policy="keep",
                extract_to_source=False,
                context_menu=False,
            ):
                calls.append(
                    (
                        paths,
                        auto_start,
                        cleanup_policy,
                        extract_to_source,
                        context_menu,
                    )
                )
                return True

        server = runtime_ipc.BoundedIPCServer(App())
        ticket = runtime_ipc._IPCDispatchTicket()

        self.assertEqual(ticket.result_after_timeout(), (False, "dispatch_timeout"))
        server._dispatch_request(
            server._generation,
            runtime_ipc.ExternalIntakeRequest((r"C:\input.zip",)),
            ticket,
        )

        self.assertEqual(calls, [])
        self.assertEqual(ticket.result(), (False, "dispatch_timeout"))

    def test_running_dispatch_timeout_is_reported_as_indeterminate(self):
        ticket = runtime_ipc._IPCDispatchTicket()

        self.assertTrue(ticket.begin())
        self.assertEqual(
            ticket.result_after_timeout(),
            (False, "dispatch_in_progress"),
        )
        ticket.finish(True, "accepted")

        self.assertEqual(ticket.result(), (True, "accepted"))

    def test_dispatch_exception_is_reported_without_killing_listener(self):
        disable_calls = []

        class App:
            @staticmethod
            def process_ipc_args(
                _paths,
                _auto_start=True,
                _cleanup_policy="keep",
                _extract_to_source=False,
                _context_menu=False,
            ):
                raise RuntimeError("dispatch failed")

            @staticmethod
            def _disable_context_auto_close(abnormal=False):
                disable_calls.append(abnormal)

        server = runtime_ipc.BoundedIPCServer(App())
        ticket = runtime_ipc._IPCDispatchTicket()

        with self.assertLogs(runtime_ipc.logger, level="ERROR"):
            server._dispatch_request(
                server._generation,
                runtime_ipc.ExternalIntakeRequest((r"C:\input.zip",)),
                ticket,
            )

        self.assertEqual(ticket.result(), (False, "dispatch_error"))
        self.assertEqual(disable_calls, [True])

    def test_client_rejects_invalid_inputs_without_connecting(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "one.zip"
            archive.write_bytes(b"payload")
            self.assertFalse(runtime_ipc.try_forward_to_existing([""], port=1))
            self.assertFalse(
                runtime_ipc.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    auto_start="yes",
                )
            )
            self.assertFalse(
                runtime_ipc.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    cleanup_policy="recycle",
                )
            )
            self.assertFalse(
                runtime_ipc.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    extract_to_source="yes",
                )
            )
            self.assertFalse(
                runtime_ipc.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    context_menu="yes",
                )
            )
            self.assertFalse(
                runtime_ipc.try_forward_to_existing([], port=1, context_menu=True)
            )
            self.assertFalse(
                runtime_ipc.try_forward_to_existing(
                    [str(archive)] * (runtime_ipc.IPC_MAX_PATHS + 1), port=1
                )
            )

    def test_server_path_probe_errors_are_rejected(self):
        server = runtime_ipc.BoundedIPCServer(types.SimpleNamespace())
        payload = json.dumps(
            {
                "version": runtime_ipc.IPC_VERSION,
                "token": server.token,
                "action": "enqueue",
                "paths": [r"C:\broken"],
                "auto_start": True,
            }
        ).encode("utf-8")
        with mock.patch.object(
            runtime_ipc.os.path, "exists", side_effect=OSError("bad path")
        ):
            self.assertIsNone(server._parse_request(payload))

    def test_server_accepts_authenticated_request_and_rejects_invalid_mode(self):
        server = runtime_ipc.BoundedIPCServer(types.SimpleNamespace())
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "authenticated.zip"
            archive.write_bytes(b"payload")
            request = json.dumps(
                {
                    "version": runtime_ipc.IPC_VERSION,
                    "token": server.token,
                    "action": "enqueue",
                    "paths": [str(archive)],
                    "auto_start": True,
                    "cleanup_policy": "permanent",
                    "extract_to_source": True,
                    "context_menu": True,
                }
            ).encode("utf-8")
            parsed = server._parse_request(request)

            self.assertEqual(parsed.action, "enqueue")
            self.assertEqual(parsed.paths, (os.path.normpath(str(archive)),))
            self.assertTrue(parsed.auto_start)
            self.assertEqual(parsed.cleanup_policy, "permanent")
            self.assertTrue(parsed.extract_to_source)
            self.assertTrue(parsed.context_menu)

            invalid = json.dumps(
                {
                    "version": runtime_ipc.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": "yes",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid))

            invalid_policy = json.dumps(
                {
                    "version": runtime_ipc.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": True,
                    "cleanup_policy": "recycle",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid_policy))

            invalid_context = json.dumps(
                {
                    "version": runtime_ipc.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": True,
                    "context_menu": "yes",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid_context))


class TestWindowsAdapterLifecycle(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows named-mutex behavior")
    def test_named_mutex_is_exclusive_until_handle_closes(self):
        name = f"Smart7z_Test_Instance_Mutex_{os.getpid()}_{id(self)}"
        first = windows_adapters.create_mutex(name)
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(windows_adapters.create_mutex(name))
        finally:
            self.assertTrue(windows_adapters.close_mutex(first))

        replacement = windows_adapters.create_mutex(name)
        self.assertIsNotNone(replacement)
        self.assertTrue(windows_adapters.close_mutex(replacement))

    def test_close_mutex_closes_handle(self):
        handle = object()
        with (
            mock.patch.object(windows_adapters.sys, "platform", "win32"),
            mock.patch.object(
                windows_adapters,
                "_CloseHandle",
                return_value=1,
                create=True,
            ) as close,
        ):
            self.assertTrue(windows_adapters.close_mutex(handle))
        close.assert_called_once_with(handle)

    def test_context_menu_quotes_source_and_substituted_path(self):
        executable = r"C:\Program Files\Python\python.exe"
        script = r"C:\Smart App\smart7z.py"
        with (
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "argv", [script]),
            mock.patch.object(windows_adapters.sys, "frozen", False, create=True),
        ):
            keep_command = windows_adapters.build_context_menu_command("keep")
            delete_command = windows_adapters.build_context_menu_command("permanent")
        self.assertEqual(
            keep_command,
            subprocess.list2cmdline(
                [
                    executable,
                    script,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--keep-source",
                ]
            )
            + ' "%1"',
        )
        self.assertEqual(
            delete_command,
            subprocess.list2cmdline(
                [
                    executable,
                    script,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--delete-source",
                ]
            )
            + ' "%1"',
        )

    def test_context_menu_quotes_frozen_target(self):
        executable = r"C:\Program Files\Smart7z\smart7z.exe"
        launcher = r"C:\Program Files\Smart7z\Smart7zShell.exe"
        with (
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "frozen", True, create=True),
            mock.patch.object(windows_adapters.os.path, "isfile", return_value=True),
        ):
            command = windows_adapters.build_context_menu_command("permanent")
        self.assertEqual(
            command,
            subprocess.list2cmdline(
                [
                    launcher,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--delete-source",
                ]
            )
            + ' "%1"',
        )

    def test_context_menu_falls_back_when_shell_launcher_is_missing(self):
        executable = r"C:\Program Files\Smart7z\smart7z.exe"
        with (
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "frozen", True, create=True),
            mock.patch.object(windows_adapters.os.path, "isfile", return_value=False),
        ):
            command = windows_adapters.build_context_menu_command("keep")
        self.assertEqual(
            command,
            subprocess.list2cmdline(
                [
                    executable,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--keep-source",
                ]
            )
            + ' "%1"',
        )

    def test_context_menu_rejects_unsupported_cleanup_policy(self):
        with self.assertRaises(ValueError):
            windows_adapters.build_context_menu_command("recycle")

    def test_context_menu_registers_two_file_and_directory_actions(self):
        class RegistryKey:
            def __init__(self, registry, path):
                self.registry = registry
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

        class FakeWinreg:
            HKEY_CURRENT_USER = object()
            REG_SZ = 1

            def __init__(self):
                self.keys = set()
                self.values = {}

            def CreateKey(self, _root, path):
                self.keys.add(path)
                return RegistryKey(self, path)

            def SetValue(self, key, _name, _kind, value):
                self.values[(key.path, "default")] = value

            def SetValueEx(self, key, name, _reserved, _kind, value):
                self.values[(key.path, name)] = value

            def DeleteKey(self, _root, path):
                if path not in self.keys:
                    raise FileNotFoundError(path)
                self.keys.remove(path)
                self.values = {
                    key: value
                    for key, value in self.values.items()
                    if key[0] != path
                }

        registry = FakeWinreg()
        legacy_keys = set()
        for scope in windows_adapters._CONTEXT_MENU_SCOPES:
            legacy_key = f"{scope}\\Smart7z"
            legacy_command_key = f"{legacy_key}\\command"
            legacy_keys.update((legacy_key, legacy_command_key))
            registry.keys.update((legacy_key, legacy_command_key))
            registry.values[(legacy_key, "default")] = "legacy label"
            registry.values[(legacy_command_key, "default")] = "legacy command"
        executable = r"C:\Program Files\Smart7z\smart7z.exe"
        with (
            mock.patch.object(windows_adapters.sys, "platform", "win32"),
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "frozen", True, create=True),
            mock.patch.object(windows_adapters.os.path, "isfile", return_value=True),
            mock.patch.dict(sys.modules, {"winreg": registry}),
        ):
            self.assertTrue(windows_adapters.register_context_menu())

            self.assertTrue(legacy_keys.isdisjoint(registry.keys))
            self.assertTrue(
                all(path not in legacy_keys for path, _name in registry.values)
            )
            for scope in windows_adapters._CONTEXT_MENU_SCOPES:
                for verb, label, policy in windows_adapters._CONTEXT_MENU_ENTRIES:
                    key_path = f"{scope}\\{verb}"
                    self.assertEqual(registry.values[(key_path, "default")], label)
                    self.assertEqual(
                        registry.values[(f"{key_path}\\command", "default")],
                        windows_adapters.build_context_menu_command(policy),
                    )

            self.assertTrue(windows_adapters.unregister_context_menu())
            self.assertEqual(registry.keys, set())

    def test_stale_session_cleanup_rejects_reparse_points(self):
        with tempfile.TemporaryDirectory() as temp:
            session = Path(temp) / "Smart7z_Session_99999999"
            session.mkdir()
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=True),
                mock.patch.object(windows_adapters, "safe_rmtree") as remove,
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            remove.assert_not_called()
            self.assertTrue(session.is_dir())

    def test_confirmed_stale_plain_session_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertFalse(session.exists())

    def test_stale_session_with_empty_stego_scaffold_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            (session / "stego").mkdir()
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertFalse(session.exists())

    def test_stale_session_with_nonempty_stego_scaffold_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            stego = session / "stego"
            stego.mkdir()
            (stego / "sentinel.txt").write_text("later", encoding="utf-8")
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertTrue(session.exists())

    def test_stale_session_with_unregistered_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            (session / "sentinel.txt").write_text("later", encoding="utf-8")
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertTrue(session.exists())

    @unittest.skipUnless(os.name == "nt", "Windows process handle check")
    def test_current_process_is_detected(self):
        self.assertTrue(windows_adapters._is_pid_running(os.getpid()))


if __name__ == "__main__":
    unittest.main()
