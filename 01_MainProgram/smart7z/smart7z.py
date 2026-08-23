"""Smart7z PySide6 desktop entry point."""

from __future__ import annotations

import sys


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    fast_result = None
    try:
<<<<<<< HEAD
        # Right-click actions commonly start a short-lived second process.
        # Forward to an already-running instance before importing PySide6 so
        # Explorer does not wait for the full Qt cold-start path.
        from launch_ipc import _forward_launch_request, parse_launch_args

        fast_result = _forward_launch_request(parse_launch_args(argv))
        if fast_result.accepted:
            return 0
    except Exception:
        # The normal Qt path owns user-facing diagnostics and startup-race
        # handling; a failed fast probe must not prevent a fresh instance.
        pass
    try:
        from ui_qt import run_app

        return int(run_app(argv, initial_forward_result=fast_result) or 0)
=======
        from ui_qt import run_app

        return int(run_app(argv) or 0)
>>>>>>> origin/main
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0
    except Exception:
        import tempfile
        import traceback
        from pathlib import Path

        error_msg = traceback.format_exc()
        try:
<<<<<<< HEAD
            diagnostic = Path(tempfile.gettempdir()) / "Smart7z-startup-error.log"
            diagnostic.write_text(error_msg[:20000], encoding="utf-8")
        except Exception:
            pass
        try:
=======
>>>>>>> origin/main
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
