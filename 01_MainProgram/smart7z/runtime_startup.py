"""Scheduler initialization without Qt-thread I/O or abandoned ownership."""

import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional


logger = logging.getLogger(__name__)


def prepare_temp_directory(config: dict) -> str:
    requested = str(config.get("temp_dir") or "").strip()
    if not requested:
        return ""

    def probe(path: str) -> None:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".smart7z_probe_", delete=True):
            pass

    try:
        probe(requested)
        return ""
    except OSError:
        if os.path.normcase(os.path.abspath(requested)) != os.path.normcase(r"C:\Temp_Smart7z"):
            raise
    fallback = os.path.join(tempfile.gettempdir(), "Smart7z")
    probe(fallback)
    config["temp_dir"] = fallback
    return fallback


@dataclass
class SchedulerStartupResult:
    scheduler: Any
    config: dict
    fallback_temp: str = ""


class SchedulerStartup:
    def __init__(self, build: Callable[[], SchedulerStartupResult], notify: Callable[[], None]):
        self._build = build
        self._notify = notify
        self._lock = threading.Lock()
        self._cancelled = False
        self._result: Optional[SchedulerStartupResult] = None
        self._error: Optional[Exception] = None
        self._thread = threading.Thread(target=self._run, name="Smart7zStartup", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        result = None
        error = None
        try:
            result = self._build()
        except Exception as exc:
            error = exc
        with self._lock:
            cancelled = self._cancelled
            if not cancelled:
                self._result, self._error = result, error
        if cancelled:
            if result is not None and not self._dispose(result):
                with self._lock:
                    self._result = result
            return
        self._notify()

    @staticmethod
    def _dispose(result: SchedulerStartupResult) -> bool:
        try:
            return result.scheduler.stop() is not False
        except Exception:
            logger.exception("Could not stop an unclaimed startup scheduler")
            return False

    def take_result(self):
        with self._lock:
            result, error = self._result, self._error
            self._result = self._error = None
            return result, error

    def cancel_and_join(self, timeout: float = 1.0) -> bool:
        with self._lock:
            self._cancelled = True
            result, self._result = self._result, None
        disposed = result is None or self._dispose(result)
        if not disposed:
            with self._lock:
                self._result = result
        if self._thread.ident is not None:
            self._thread.join(timeout=max(0.0, timeout))
        with self._lock:
            return disposed and not self._thread.is_alive() and self._result is None
