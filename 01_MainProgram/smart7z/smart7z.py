"""Smart7z PySide6 desktop entry point."""

from __future__ import annotations

import sys
from startup_trace import flush as _flush_startup_trace, mark as _startup_trace

_startup_trace("entry:module")
_startup_trace(f"entry:qtcore_preloaded:{'PySide6.QtCore' in sys.modules}")


def main(argv=None) -> int:
    _startup_trace("entry:main")
    if argv is None:
        argv = sys.argv[1:]
    fast_result = None
    try:
        # Right-click actions commonly start a short-lived second process.
        # Forward to an already-running instance before importing PySide6 so
        # Explorer does not wait for the full Qt cold-start path.
        _startup_trace("entry:launch_ipc:start")
        from launch_ipc import _forward_launch_request, parse_launch_args
        _startup_trace("entry:launch_ipc:end")

        _startup_trace("entry:forward:start")
        fast_result = _forward_launch_request(parse_launch_args(argv))
        _startup_trace("entry:forward:end")
        if fast_result.accepted:
            _flush_startup_trace()
            return 0
    except Exception:
        # The normal Qt path owns user-facing diagnostics and startup-race
        # handling; a failed fast probe must not prevent a fresh instance.
        pass
    try:
        _startup_trace("entry:ui_import:start")
        from ui_qt import run_app
        _startup_trace("entry:ui_import:end")

        return int(run_app(argv, initial_forward_result=fast_result) or 0)
    except SystemExit as e:
        _flush_startup_trace()
        return int(e.code) if e.code is not None else 0
    except Exception:
        _flush_startup_trace()
        import tempfile
        import traceback
        from pathlib import Path

        error_msg = traceback.format_exc()
        try:
            diagnostic = Path(tempfile.gettempdir()) / "Smart7z-startup-error.log"
            diagnostic.write_text(error_msg[:20000], encoding="utf-8")
        except Exception:
            pass
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0,
                f"程序发生崩溃:\n\n{error_msg}",
                "致命错误",
                0x10,
            )
        except Exception:
            print(error_msg)
            try:
                input("按回车键退出...")
            except EOFError:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
