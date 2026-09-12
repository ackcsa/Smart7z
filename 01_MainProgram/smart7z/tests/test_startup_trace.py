import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import startup_trace
import benchmark_startup


class TestStartupTrace(unittest.TestCase):
    def tearDown(self):
        importlib.reload(startup_trace)

    def test_disabled_does_not_read_clock_or_open_files(self):
        with mock.patch.dict(os.environ, {"SMART7Z_STARTUP_TRACE": ""}):
            importlib.reload(startup_trace)
        with (
            mock.patch.object(startup_trace.time, "monotonic") as clock,
            mock.patch("builtins.open") as writer,
        ):
            startup_trace.mark("disabled")
            startup_trace.flush()
        clock.assert_not_called()
        writer.assert_not_called()

    def test_events_buffer_until_flush_and_are_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "trace.log"
            with mock.patch.dict(os.environ, {"SMART7Z_STARTUP_TRACE": str(target)}):
                importlib.reload(startup_trace)
            startup_trace.mark("first\nline")
            self.assertFalse(target.exists())
            for _ in range(300):
                startup_trace.mark("x" * 900)
            startup_trace.flush()
            lines = target.read_text("utf-8").splitlines()
            self.assertEqual(len(lines), 256)
            self.assertIn("startup_clock:", lines[0])
            self.assertTrue(lines[1].endswith("first line"))
            self.assertTrue(all(len(line.split(" ", 1)[1]) <= 800 for line in lines))
            before = target.read_bytes()
            startup_trace.mark("over budget after flush")
            startup_trace.flush()
            self.assertEqual(target.read_bytes(), before)

    def test_unwritable_trace_does_not_break_startup(self):
        with mock.patch.object(startup_trace, "_TARGET", "bad\0path"):
            startup_trace._EVENTS[:] = [(1.0, "event")]
            startup_trace.flush()
            self.assertEqual(startup_trace._EVENTS, [])

    def test_worker_and_ui_events_survive_concurrent_flushes(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "trace.log"
            with mock.patch.dict(os.environ, {"SMART7Z_STARTUP_TRACE": str(target)}):
                importlib.reload(startup_trace)
            barrier = threading.Barrier(4)

            def record(worker):
                barrier.wait(timeout=3)
                for index in range(40):
                    startup_trace.mark(f"worker-{worker}-{index}")
                    startup_trace.flush()

            workers = [threading.Thread(target=record, args=(number,)) for number in range(4)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
            startup_trace.flush()
            lines = target.read_text("utf-8").splitlines()
            self.assertEqual(sum("startup_clock:" in line for line in lines), 1)
            actual = {line.split(" ", 1)[1] for line in lines if "worker-" in line}
            self.assertEqual(actual, {f"worker-{worker}-{index}" for worker in range(4) for index in range(40)})

    def test_fast_forward_does_not_import_qt_with_tracing(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "trace.log"
            environment = {**os.environ, "SMART7Z_STARTUP_TRACE": str(target)}
            code = (
                "import sys,types; "
                "m=types.ModuleType('launch_ipc'); "
                "m.parse_launch_args=lambda args: args; "
                "m._forward_launch_request=lambda args: types.SimpleNamespace(accepted=True); "
                "sys.modules['launch_ipc']=m; "
                "import smart7z; assert smart7z.main([])==0; "
                "assert not any(n=='PySide6' or n.startswith('PySide6.') for n in sys.modules)"
            )
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
                env=environment, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = target.read_text("utf-8")
            self.assertIn("entry:forward:end", text)
            self.assertNotIn("entry:ui_import:start", text)


class TestStartupMeasurement(unittest.TestCase):
    def test_prepare_rejects_missing_icon_before_copying(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / "app"
            app.mkdir()
            for name in ("Smart7z.exe", "7z.exe", "7z.dll"):
                (app / name).touch()
            output = Path(temp) / "prepared"
            with self.assertRaisesRegex(ValueError, "smart7z.ico"):
                benchmark_startup.prepare(output, app)
            self.assertFalse(output.exists())

    def test_summary_keeps_variants_separate(self):
        summary = benchmark_startup.summarize([
            {"variant": "source", "timings_ms": {"ready": 100}},
            {"variant": "frozen", "timings_ms": {"ready": 20}},
            {"variant": "source", "timings_ms": {"ready": 200}},
        ])
        self.assertEqual(summary["source"]["ready"], {"median": 150, "min": 100, "max": 200})
        self.assertEqual(summary["frozen"]["ready"]["median"], 20)

    @unittest.skipUnless(os.name == "nt", "Windows uptime measurement")
    def test_boot_clock_has_positive_uptime_and_plausible_boot_time(self):
        value = benchmark_startup.clock_info()
        self.assertGreater(value["uptime_seconds"], 0)
        self.assertLessEqual(value["boot_time"], startup_trace.time.time())
        self.assertGreater(value["boot_time"], 0)

    def test_same_boot_cannot_be_reported_as_after_reboot(self):
        with self.assertRaisesRegex(ValueError, "No reboot"):
            benchmark_startup.validate_reboot({"boot_time": 100}, {"boot_time": 102})
        benchmark_startup.validate_reboot({"boot_time": 100}, {"boot_time": 200})

    def test_same_boot_repeat_cannot_be_reported_as_first_run(self):
        with self.assertRaisesRegex(ValueError, "Already measured"):
            benchmark_startup.validate_reboot(
                {"boot_time": 100}, {"boot_time": 200}, {"boot_time": 201}
            )
        benchmark_startup.validate_reboot(
            {"boot_time": 100}, {"boot_time": 300}, {"boot_time": 200}
        )

    def test_forwarded_or_incomplete_trace_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            benchmark_startup.parse_timings("1.0 entry:main\n", 0, 2)

    def test_phase_durations_and_process_latency_use_same_clock(self):
        text = "\n".join(
            f"{stamp} {event}" for stamp, event in (
                (10.1, "startup_clock:" + json.dumps(startup_trace.clock_metadata())),
                (10.1, "frozen:runtime_hook"), (10.2, "entry:module"),
                (10.3, "entry:main"), (10.4, "entry:ui_import:start"),
                (10.9, "entry:ui_import:end"), (11.0, "run_app:mutex:True"),
                (11.1, "run_app:show:end"), (11.2, "run_app:initial_events:end"),
                (11.5, "run_app:scheduler_ready"),
            )
        )
        timings = benchmark_startup.parse_timings(text, 10, 12)
        self.assertEqual(timings["pre_runtime_hook"], 100)
        self.assertEqual(timings["runtime_hooks_to_entry"], 100)
        self.assertEqual(timings["ui_import"], 500)
        self.assertEqual(timings["ready"], 1500)
        with self.assertRaisesRegex(ValueError, "wall-time"):
            benchmark_startup.parse_timings(text, 0, 2.297)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            benchmark_startup.parse_timings(
                text, 10, 12,
                parent_clock={**startup_trace.clock_metadata(), "implementation": "different clock"},
            )
