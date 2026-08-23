from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

import runtime_ipc
import windows_adapters


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SHELL_SOURCE = PROJECT_ROOT / "shell_launcher.cs"
CSC = (
    Path(os.environ.get("WINDIR", r"C:\Windows"))
    / "Microsoft.NET"
    / "Framework64"
    / "v4.0.30319"
    / "csc.exe"
)


@unittest.skipUnless(os.name == "nt" and CSC.is_file(), ".NET Framework C# compiler is required")
class TestShellLauncher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.root = Path(cls._temporary.name)
        cls.mutex_name = f"Smart7z_Test_Shell_{uuid.uuid4().hex}"
        source = SHELL_SOURCE.read_text(encoding="utf-8")
        original = 'private const string InstanceMutexName = "Smart7z_Instance_Mutex";'
        replacement = f'private const string InstanceMutexName = "{cls.mutex_name}";'
        if source.count(original) != 1:
            raise AssertionError("shell launcher mutex declaration changed unexpectedly")
        patched_source = cls.root / "shell_launcher.cs"
        patched_source.write_text(
            source.replace(original, replacement),
            encoding="utf-8-sig",
        )

        cls.launcher = cls.root / "Smart7zShell.exe"
        compile_launcher = subprocess.run(
            [
                str(CSC),
                "/nologo",
                "/target:winexe",
                "/platform:x64",
                "/optimize+",
                "/reference:System.dll",
                "/reference:System.Core.dll",
                "/reference:System.Runtime.Serialization.dll",
                "/reference:System.Windows.Forms.dll",
                f"/out:{cls.launcher}",
                str(patched_source),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if compile_launcher.returncode != 0:
            raise AssertionError(
                "shell launcher compilation failed:\n"
                + compile_launcher.stdout
                + compile_launcher.stderr
            )

        stub_source = cls.root / "main_stub.cs"
        stub_source.write_text(
            """
using System;
using System.IO;
using System.Text;

internal static class Program
{
    private static int Main(string[] args)
    {
        string target = Environment.GetEnvironmentVariable("SMART7Z_TEST_ARGS_PATH");
        if (string.IsNullOrEmpty(target))
        {
            return 2;
        }
        File.WriteAllLines(target, args, new UTF8Encoding(false));
        return 0;
    }
}
""".strip(),
            encoding="utf-8-sig",
        )
        cls.main_stub = cls.root / "Smart7z.exe"
        compile_stub = subprocess.run(
            [
                str(CSC),
                "/nologo",
                "/target:winexe",
                "/platform:x64",
                "/optimize+",
                f"/out:{cls.main_stub}",
                str(stub_source),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if compile_stub.returncode != 0:
            raise AssertionError(
                "shell launcher fallback stub compilation failed:\n"
                + compile_stub.stdout
                + compile_stub.stderr
            )
        (cls.root / "portable.flag").touch()

    def test_absent_instance_starts_main_with_exact_arguments(self):
        archive = self.root / "input with spaces.zip"
        archive.write_bytes(b"payload")
        recorded_args = self.root / "fallback-args.txt"
        arguments = [
            "--context-menu",
            "--start",
            "--extract-here",
            "--keep-source",
            str(archive),
        ]
        environment = os.environ.copy()
        environment["SMART7Z_TEST_ARGS_PATH"] = str(recorded_args)

        completed = subprocess.run(
            [str(self.launcher), *arguments],
            env=environment,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 0)
        deadline = time.monotonic() + 5.0
        while not recorded_args.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(recorded_args.is_file())
        self.assertEqual(
            recorded_args.read_text(encoding="utf-8").splitlines(),
            arguments,
        )

    def test_existing_instance_receives_authenticated_context_request(self):
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

        archive = self.root / "warm-forward.zip"
        archive.write_bytes(b"payload")
        state_path = self.root / f"ipc-v{runtime_ipc.IPC_VERSION}.json"
        server = runtime_ipc.BoundedIPCServer(App(), port=0, state_path=str(state_path))
        mutex = None
        try:
            self.assertTrue(server.start())
            mutex = windows_adapters.create_mutex(self.mutex_name)
            self.assertIsNotNone(mutex)
            completed = subprocess.run(
                [
                    str(self.launcher),
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--delete-source",
                    str(archive),
                ],
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertTrue(delivered.wait(2.0))
            self.assertEqual(
                received,
                [
                    (
                        [os.path.normpath(str(archive))],
                        True,
                        "permanent",
                        True,
                        True,
                    )
                ],
            )
        finally:
            server.close()
            if mutex is not None:
                windows_adapters.close_mutex(mutex)


if __name__ == "__main__":
    unittest.main()
