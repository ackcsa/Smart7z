"""Lightweight local-path checks shared by startup IPC and Windows helpers."""

from __future__ import annotations

import os
import re
import sys


DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOTE = 4

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes

    _get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    _get_drive_type.argtypes = [ctypes.wintypes.LPCWSTR]
    _get_drive_type.restype = ctypes.wintypes.UINT
else:
    _get_drive_type = None


def is_local_filesystem_path(path: str) -> bool:
    """Accept drive-letter paths while rejecting UNC, devices and remote drives."""

    if not isinstance(path, str) or not path or path.startswith(("\\\\", "//")):
        return False
    absolute = os.path.abspath(os.path.normpath(path))
    drive, _tail = os.path.splitdrive(absolute)
    if not re.fullmatch(r"[A-Za-z]:", drive):
        return False
    if _get_drive_type is None:
        return os.path.isabs(absolute)
    drive_type = int(_get_drive_type(drive + "\\"))
    return drive_type not in (DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR, DRIVE_REMOTE)


__all__ = ["is_local_filesystem_path"]
