"""Smart7z PySide6 desktop entry point."""

from __future__ import annotations

import sys
import traceback


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        from ui_qt import run_app

        return int(run_app(argv) or 0)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0
    except Exception:
        error_msg = traceback.format_exc()
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
