"""Compact, repeatable verification. Use --help for suites and build gating."""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib.metadata
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
SUITES = {
    "full": ("test_*.py",),
    "candidates": ("test_candidate_triage.py", "test_runtime_safety.py"),
    "ui": ("test_*qt*.py", "test_ui_runtime.py"),
    "integration": ("test_integration_real7z.py", "test_workflow_regressions.py"),
    "release": ("test_release_build.py", "test_installer_upgrade.py", "test_user_messages.py", "test_automation.py"),
}


def input_fingerprint(source: Path) -> str:
    files = [p for p in source.iterdir() if p.is_file()]
    for directory in ("tests", "resources", "build_assets"):
        folder = source / directory
        if folder.is_dir():
            files.extend(p for p in folder.iterdir() if p.is_file())
    for name in ("README.md", "CHANGELOG.md", "smart7z_user_manual.html", "LICENSE", "COPYRIGHT.md"):
        path = source.parents[1] / name
        if path.is_file():
            files.append(path)
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path).encode("utf-8"))
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def environment_fingerprint() -> dict:
    dependencies = {}
    for name in ("PySide6", "shiboken6", "PyInstaller", "pyinstaller-hooks-contrib"):
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            dependencies[name] = None
    from config import DEFAULT_CONFIG, find_sevenzip

    sevenzip = find_sevenzip(DEFAULT_CONFIG)
    return {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "qt_platform": os.environ.get("QT_QPA_PLATFORM", "offscreen"),
        "dependencies": dependencies,
        "sevenzip": sevenzip,
        "sevenzip_sha256": (
            hashlib.sha256(Path(sevenzip).read_bytes()).hexdigest() if sevenzip else None
        ),
    }


def select_patterns(suite: str, extra: list[str] | None) -> tuple[str, ...]:
    patterns = tuple(extra or SUITES[suite])
    if any("/" in p or "\\" in p or not p.startswith("test_") for p in patterns):
        raise ValueError("Patterns must be test_*.py basenames within tests/.")
    return patterns


def reusable(report: dict, fingerprint: str, environment: dict, patterns: tuple) -> bool:
    return bool(
        report.get("passed")
        and report.get("tests_run", 0) > 0
        and report.get("input_fingerprint") == fingerprint
        and report.get("environment") == environment
        and report.get("patterns") == list(patterns)
        and 0 <= time.time() - report.get("finished_at", 0) < 86400
    )


def release_gate(report: dict) -> bool:
    return bool(
        report.get("passed")
        and report.get("tests_run", 0) > 0
        and report.get("patterns") == ["test_*.py"]
        and not report.get("skipped")
    )


class CompactResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        kind, value, tb = err
        frames = "".join(traceback.format_list(traceback.extract_tb(tb)[-5:]))
        return frames + f"{kind.__name__}: {str(value)[:1200]}\n"


def run_tests(patterns: tuple[str, ...], output: Path) -> dict:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    files = sorted({p for pattern in patterns for p in (SOURCE / "tests").glob(pattern)})
    for path in files:
        suite.addTests(loader.discover(str(SOURCE / "tests"), path.name))
    if suite.countTestCases() == 0:
        raise ValueError("No tests selected; refusing to report success.")
    started = time.perf_counter()
    with output.open("w", encoding="utf-8") as log:
        handler = logging.StreamHandler(log)
        logging.getLogger().addHandler(handler)
        try:
            with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                result = unittest.TextTestRunner(
                    stream=log, resultclass=CompactResult, verbosity=2
                ).run(suite)
        finally:
            logging.getLogger().removeHandler(handler)
    return {
        "passed": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "failures": [{"test": str(t), "detail": d} for t, d in result.failures],
        "errors": [{"test": str(t), "detail": d} for t, d in result.errors],
        "skipped": [(str(t), reason) for t, reason in result.skipped],
        "log": str(output),
    }


def build_release(report: dict, output: Path) -> int:
    if not release_gate(report):
        raise ValueError("Build requires a full passing suite with zero skipped tests.")
    tree = ast.parse((SOURCE / "ui_qt.py").read_text("utf-8"))
    version = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "APP_VERSION" for t in node.targets)
    )
    existing = list((SOURCE / "release").glob(f"Smart7z-{version}-*"))
    if existing or (SOURCE / "build").exists():
        raise ValueError("Existing build or same-version release found. Review and recycle it first.")
    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise ValueError("PowerShell 7 (pwsh) is required for release builds.")
    environment = os.environ.copy()
    cache = output.parent / "tool-cache"
    environment["PYINSTALLER_CONFIG_DIR"] = str(cache / "pyinstaller")
    environment["PIP_CACHE_DIR"] = str(cache / "pip")
    base_python = Path(sys.base_prefix) / "python.exe"
    command = [
        pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
        str(SOURCE / "build_release.ps1"), "-Version", version,
        "-PythonExe", str(base_python),
    ]
    print(f"Building {version}; full log: {output}", flush=True)
    with output.open("w", encoding="utf-8") as log:
        process = subprocess.run(command, cwd=SOURCE, env=environment, stdout=log, stderr=log)
    print(f"Build exit code: {process.returncode}. Log: {output}", flush=True)
    return process.returncode


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, default="full")
    parser.add_argument("--pattern", action="append", help="Override suite; repeatable test filename glob.")
    parser.add_argument("--report-dir", type=Path, default=SOURCE / ".verification")
    parser.add_argument("--reuse", action="store_true", help="Reuse a matching passed report for up to 24 hours.")
    parser.add_argument("--build", action="store_true", help="Build only after a full, unskipped passing suite.")
    args = parser.parse_args(argv)
    os.chdir(SOURCE)
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    output_dir = args.report_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    patterns = select_patterns(args.suite, args.pattern)
    fingerprint = input_fingerprint(SOURCE)
    environment = environment_fingerprint()
    label = "custom" if args.pattern else args.suite
    summary = output_dir / f"test-{label}-latest.json"
    cached = {}
    if args.reuse and summary.is_file():
        try:
            cached = json.loads(summary.read_text("utf-8"))
        except (ValueError, OSError):
            pass
    if reusable(cached, fingerprint, environment, patterns):
        report = cached
        print("Reused matching successful test report.")
    else:
        print(f"Running {label} tests; logs saved under {output_dir}", flush=True)
        log = output_dir / f"test-{label}-{time.time_ns()}.log"
        report = run_tests(patterns, log)
        report.update(
            input_fingerprint=fingerprint, environment=environment,
            patterns=list(patterns), finished_at=time.time(),
        )
        if input_fingerprint(SOURCE) != fingerprint:
            report["passed"] = False
            report["errors"].append({"test": "input_changed", "detail": "Inputs changed during testing. Rerun."})
        summary.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(
        f"Tests: {report['tests_run']}; failures: {len(report['failures'])}; "
        f"errors: {len(report['errors'])}; skipped: {len(report['skipped'])}; "
        f"passed: {report['passed']}\nReport: {summary}"
    )
    for item in (report["failures"] + report["errors"])[:8]:
        print(f"FAIL {item['test']}: {item['detail'][-500:]}")
    if not report["passed"]:
        return 1
    return build_release(report, output_dir / "build-latest.log") if args.build else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(f"Verification stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
