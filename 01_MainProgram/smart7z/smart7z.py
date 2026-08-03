"""Smart7z entry point — modern serialized runtime bootstrap only.

Legacy ExtractionWorker / Smart7zApp paths are no longer launched.
Core logic lives in models, config, sevenzip, discovery, executor,
scheduler, stego_candidates, nested, path_safety, windows_adapters, ui_app.
"""

from __future__ import annotations

import sys
import traceback


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        from ui_app import run_app

        run_app(argv)
        return 0
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0
    except Exception:
        error_msg = traceback.format_exc()
        try:
            import tkinter
            from tkinter import messagebox

            root = tkinter.Tk()
            root.withdraw()
            messagebox.showerror("致命错误", f"程序发生崩溃:\n\n{error_msg}")
            root.destroy()
        except Exception:
            print(error_msg)
            try:
                input("按回车键退出...")
            except EOFError:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
