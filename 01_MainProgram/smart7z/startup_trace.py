"""Opt-in, bounded startup timing without per-event filesystem writes."""
import _thread
import os
import time

_TARGET = os.environ.get("SMART7Z_STARTUP_TRACE", "").strip()
_EVENTS = []
_MAX_EVENTS = 256
_REMAINING = _MAX_EVENTS
_CLOCK_RECORDED = False
_LOCK = _thread.allocate_lock()


def clock_metadata() -> dict:
    import sys

    info = time.get_clock_info("monotonic")
    return {
        "name": "monotonic",
        "implementation": info.implementation,
        "monotonic": info.monotonic,
        "adjustable": info.adjustable,
        "resolution": info.resolution,
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }


def mark(message: str) -> None:
    global _REMAINING, _CLOCK_RECORDED
    if not _TARGET or _REMAINING <= 0:
        return
    with _LOCK:
        if not _CLOCK_RECORDED:
            import json

            _EVENTS.append((time.monotonic(), "startup_clock:" + json.dumps(clock_metadata(), sort_keys=True)))
            _CLOCK_RECORDED = True
            _REMAINING -= 1
        if _REMAINING <= 0:
            return
        _EVENTS.append((time.monotonic(), message[:800].replace("\n", " ").replace("\r", " ")))
        _REMAINING -= 1


def flush() -> None:
    if not _TARGET or not _EVENTS:
        return
    with _LOCK:
        events = _EVENTS[:]
        _EVENTS.clear()
        try:
            with open(_TARGET, "a", encoding="utf-8") as stream:
                stream.writelines(f"{stamp:.6f} {message}\n" for stamp, message in events)
        except (OSError, ValueError):
            pass


if _TARGET:
    import atexit

    atexit.register(flush)
