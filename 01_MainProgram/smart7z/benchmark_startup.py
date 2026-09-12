"""Prepare isolated source/frozen startup probes, then run or rerun after reboot."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from startup_trace import clock_metadata

SOURCE = Path(__file__).resolve().parent
SPANS = {
    "app_icon": ("window_init:icon:start", "window_init:icon:end"),
    "entry_to_ui_import": ("entry:main", "entry:ui_import:start"),
    "launch_ipc_import": ("entry:launch_ipc:start", "entry:launch_ipc:end"),
    "forward_probe": ("entry:forward:start", "entry:forward:end"),
    "ui_import": ("entry:ui_import:start", "entry:ui_import:end"),
    "stdlib_import": ("ui_import:stdlib:start", "ui_import:stdlib:end"),
    "qtcore_import": ("ui_import:qtcore:start", "ui_import:qtcore:end"),
    "qtgui_import": ("ui_import:qtgui:start", "ui_import:qtgui:end"),
    "qtwidgets_import": ("ui_import:qtwidgets:start", "ui_import:qtwidgets:end"),
    "application_import": ("ui_import:application:start", "ui_import:application:end"),
    "qapplication": ("run_app:qapplication:start", "run_app:qapplication:end"),
    "configure_qt": ("configure_qt:start", "configure_qt:end"),
    "build_ui": ("window_init:build_ui:start", "window_init:build_ui:end"),
    "menus": ("build_ui:menus:start", "build_ui:menus:end"),
    "command_bar": ("build_ui:command_bar:start", "build_ui:command_bar:end"),
    "option_strip": ("build_ui:option_strip:start", "build_ui:option_strip:end"),
    "queue": ("build_ui:queue:start", "build_ui:queue:end"),
    "inspector": ("build_ui:inspector:start", "build_ui:inspector:end"),
    "details": ("inspector:details:start", "inspector:details:end"),
    "log_widget": ("inspector:log:start", "inspector:log:end"),
    "status": ("build_ui:status:start", "build_ui:status:end"),
    "show_call": ("run_app:show:start", "run_app:show:end"),
    "initial_events": ("run_app:show:end", "run_app:initial_events:end"),
    "scheduler": ("setup_scheduler:start", "run_app:scheduler_ready"),
}


def clock_info():
    get_ticks = ctypes.windll.kernel32.GetTickCount64
    get_ticks.restype = ctypes.c_ulonglong
    uptime = get_ticks() / 1000
    return {"uptime_seconds": uptime, "boot_time": time.time() - uptime}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def prepare(output: Path, app: Path):
    if output.exists():
        raise ValueError("Preparation directory exists; choose a new directory.")
    required = ("Smart7z.exe", "smart7z.ico", "7z.exe", "7z.dll")
    if not all((app / name).is_file() for name in required):
        raise ValueError("App must contain Smart7z.exe, smart7z.ico and the complete 7-Zip backend.")
    output.mkdir(parents=True)
    shutil.copytree(app, output / "frozen")
    source = output / "source"
    source.mkdir()
    for path in SOURCE.glob("*.py"):
        shutil.copy2(path, source / path.name)
    (source / "build_assets").mkdir()
    shutil.copy2(SOURCE / "build_assets" / "smart7z.ico", source / "build_assets" / "smart7z.ico")
    from config import DEFAULT_CONFIG

    for variant, root in (("source", source), ("frozen", output / "frozen")):
        resources = root / "resources" if variant == "source" else root
        resources.mkdir(exist_ok=True)
        password = resources / "code.txt"
        password.write_bytes(b"")
        configuration = {
            **DEFAULT_CONFIG, "cleanup_policy": "keep", "del_archive": False,
            "allow_permanent_fallback": False, "nested_extraction": False,
            "password_file": str(password), "temp_dir": str(output / f"{variant}-temp"),
            "7z_path": str(output / "frozen" / "7z.exe"),
        }
        write_json(resources / "smart7z_config.json", configuration)
    (output / "frozen" / "portable.flag").touch()
    write_json(output / "prepared.json", {
        "prepared_at": time.time(), "clock": clock_info(), "python": sys.executable,
        "source": str(SOURCE), "original_app": str(app),
        "exe_sha256": hashlib.sha256((app / "Smart7z.exe").read_bytes()).hexdigest(),
        "platform": platform.platform(),
    })
    print(f"Prepared isolated probes: {output}")


def parse_timings(text: str, started: float, finished: float, *, parent_clock=None) -> dict:
    import math

    events = {}
    for line in text.splitlines():
        stamp, separator, event = line.partition(" ")
        if separator:
            events.setdefault(event, float(stamp))
    required = ("entry:main", "entry:ui_import:start", "entry:ui_import:end",
                "run_app:initial_events:end", "run_app:scheduler_ready", "run_app:mutex:True")
    if any(name not in events for name in required):
        raise ValueError("Incomplete trace or forwarded request; this is not a fresh startup.")
    child_clock = next(
        (json.loads(name.removeprefix("startup_clock:")) for name in events if name.startswith("startup_clock:")),
        None,
    )
    parent_clock = parent_clock or clock_metadata()
    clock_keys = ("name", "implementation", "monotonic", "adjustable", "platform")
    if child_clock is None or any(child_clock.get(key) != parent_clock.get(key) for key in clock_keys):
        raise ValueError("Parent/child clock metadata is missing or incompatible.")
    if (
        not all(math.isfinite(value) for value in (started, finished, *events.values()))
        or finished < started
        or any(stamp < started or stamp > finished for stamp in events.values())
    ):
        raise ValueError("Trace timestamps exceed the parent process wall-time bounds.")
    timings = {
        name: round((events[end] - events[begin]) * 1000, 3)
        for name, (begin, end) in SPANS.items() if begin in events and end in events
    }
    for name, event in (
        ("entry_latency", "entry:module"), ("show", "run_app:show:end"),
        ("first_events", "run_app:initial_events:end"), ("ready", "run_app:scheduler_ready"),
        ("pre_runtime_hook", "frozen:runtime_hook"),
    ):
        if event in events:
            timings[name] = round((events[event] - started) * 1000, 3)
    if "frozen:runtime_hook" in events:
        timings["runtime_hooks_to_entry"] = round(
            (events["entry:module"] - events["frozen:runtime_hook"]) * 1000, 3
        )
    if any(value < 0 for value in timings.values()):
        raise ValueError("Trace contains non-monotonic phase timestamps.")
    return timings


def run_one(output: Path, session: Path, variant: str, index: int, python: str):
    from launch_ipc import _instance_mutex_exists

    if _instance_mutex_exists():
        raise ValueError("Close the existing Smart7z instance before benchmarking.")
    root = session / f"{index:02d}-{variant}"
    root.mkdir()
    payload = b"Smart7z isolated startup measurement.\n"
    archive = root / "probe.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as writer:
        writer.writestr("payload.txt", payload)
    input_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    trace = root / "startup.log"
    environment = {
        **os.environ, "SMART7Z_STARTUP_TRACE": str(trace), "QT_QPA_PLATFORM": "windows",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in ("PYTHONPATH", "PYTHONHOME", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH"):
        environment.pop(key, None)
    command = (
        [python, "-B", str(output / "source" / "smart7z.py")]
        if variant == "source" else [str(output / "frozen" / "Smart7z.exe")]
    )
    command += ["--context-menu", "--start", "--extract-here", "--keep-source", str(archive)]
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    started = time.monotonic()
    parent_clock = clock_metadata()
    process = subprocess.Popen(command, cwd=output / variant, env=environment, startupinfo=startup)
    try:
        returncode = process.wait(timeout=45)
    except subprocess.TimeoutExpired:
        from sevenzip import terminate_process_tree
        terminate_process_tree(process)
        raise RuntimeError(f"Probe timed out: {variant}. Retained diagnostics under {root}")
    finished = time.monotonic()
    if returncode != 0:
        raise ValueError(f"Probe exited with code {returncode}: {variant}")
    if (root / "payload.txt").read_bytes() != payload:
        raise ValueError("Probe output failed byte verification.")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != input_hash:
        raise ValueError("Probe input was changed.")
    return {
        "variant": variant, "sequence": index, "wall_seconds": finished - started,
        "parent_clock": parent_clock,
        "timings_ms": parse_timings(trace.read_text("utf-8"), started, finished, parent_clock=parent_clock),
        "qtcore_preloaded": "entry:qtcore_preloaded:True" in trace.read_text("utf-8"),
        "trace": str(trace), "output_verified": True,
    }


def summarize(runs):
    summary = {}
    for variant in ("source", "frozen"):
        records = [run["timings_ms"] for run in runs if run["variant"] == variant]
        if records:
            summary[variant] = {
                name: {
                    "median": round(statistics.median(row[name] for row in records), 3),
                    "min": min(row[name] for row in records), "max": max(row[name] for row in records),
                }
                for name in set.intersection(*(set(row) for row in records))
            }
    return summary


def validate_reboot(prepared_clock, current_clock, previous_clock=None):
    if abs(current_clock["boot_time"] - prepared_clock["boot_time"]) < 10:
        raise ValueError("No reboot since preparation; refusing an after-reboot label.")
    if previous_clock and abs(current_clock["boot_time"] - previous_clock["boot_time"]) < 10:
        raise ValueError("Already measured during this boot; reboot again for a first-run observation.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare", type=Path, metavar="APP_DIR")
    parser.add_argument("--after-reboot", action="store_true")
    parser.add_argument("--runs", type=int, default=3, choices=range(1, 11))
    parser.add_argument("--first", choices=("source", "frozen"), default="frozen")
    args = parser.parse_args(argv)
    if os.name != "nt":
        raise ValueError("This probe requires Windows.")
    output = args.output.resolve()
    if args.prepare:
        prepare(output, args.prepare.resolve())
        return 0
    metadata = json.loads((output / "prepared.json").read_text("utf-8"))
    clock = clock_info()
    if args.after_reboot:
        previous = output / "latest.json"
        previous_clock = json.loads(previous.read_text("utf-8"))["clock"] if previous.exists() else None
        validate_reboot(metadata["clock"], clock, previous_clock)
    session = output / f"run-{time.time_ns()}"
    session.mkdir()
    report = {
        "passed": False, "clock": clock, "after_reboot": args.after_reboot,
        "first_variant": args.first, "runs": [],
        "limitations": (
            "Only the first process after a confirmed reboot is a post-reboot observation; "
            "later processes share warmed system caches. No cache purge or physical display latency measurement. "
            "pre_runtime_hook includes native loader, Python bootstrap and trace helper import; not a pure bootloader timer."
        ),
    }
    try:
        for pair in range(args.runs):
            order = [args.first, "source" if args.first == "frozen" else "frozen"]
            if pair % 2:
                order.reverse()
            for variant in order:
                run = run_one(output, session, variant, len(report["runs"]), metadata["python"])
                report["runs"].append(run)
                write_json(session / "results.json", report)
                timing = run["timings_ms"]
                print(f"{variant}: show={timing['show']:.1f}ms ready={timing['ready']:.1f}ms", flush=True)
        report.update(passed=True, summary_ms=summarize(report["runs"]))
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        write_json(session / "results.json", report)
        write_json(output / "latest.json", report)
    print(f"Report: {session / 'results.json'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Startup measurement stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
