import sys
import ctypes
import ctypes.wintypes
from pathlib import Path
from typing import Tuple

from models import ErrorCategory


_DEVICE_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

_is_windows = sys.platform == "win32"

if _is_windows:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _GetFileAttributesW = _kernel32.GetFileAttributesW
    _GetFileAttributesW.argtypes = [ctypes.wintypes.LPCWSTR]
    _GetFileAttributesW.restype = ctypes.wintypes.DWORD

def has_device_name(path: str) -> bool:
    if not path:
        return False
    try:
        p = Path(path)
        for part in p.parts:
            if len(part) == 2 and part[1] == ":":
                continue
            normalized = part.rstrip(" .")
            stem = normalized.split(".", 1)[0]
            base = stem.rstrip(" .").upper()
            if base in _DEVICE_NAMES:
                return True
        return False
    except (ValueError, OSError):
        return True


def is_reparse_escape(path: str) -> bool:
    if not _is_windows:
        return False
    if not path:
        return False
    try:
        # Query the lexical path itself.  Resolving first follows a junction or
        # symlink and then inspects its ordinary target, hiding the reparse
        # attribute that this check is meant to detect.
        abs_path = str(Path(path).absolute())
    except (ValueError, OSError, RuntimeError):
        return True
    try:
        attrs = _GetFileAttributesW(abs_path)
    except (OSError, AttributeError):
        return True
    if attrs == INVALID_FILE_ATTRIBUTES:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _reparse_components(path: Path, root: Path):
    """Yield existing reparse components below *root* without following them."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        return
    current = root
    for part in relative.parts:
        current = current / part
        try:
            exists = current.exists()
        except OSError:
            yield current
            return
        if exists and is_reparse_escape(str(current)):
            yield current


def is_safe_output_path(
    path: str,
    root: str,
) -> Tuple[bool, str]:
    if not path:
        return False, "Empty path"
    if "\x00" in path:
        return False, "Path contains null bytes"
    try:
        path_parts = Path(path).parts
        if Path(path).is_absolute():
            return False, f"Absolute path not allowed: {path}"
        if ".." in path_parts:
            return False, f"Path traversal detected: {path}"
    except (ValueError, TypeError):
        return False, f"Invalid path: {path}"
    if has_device_name(path):
        return False, f"Windows device name in path: {path}"
    for part in path_parts:
        if ":" in part:
            return False, f"Alternate data stream in path: {path}"
        if part.rstrip(" .") != part:
            return False, f"Windows-normalized trailing dot/space in path: {path}"
        if any(ord(char) < 32 for char in part):
            return False, f"Control character in path: {path}"
        if len(part) > 255:
            return False, f"Path component exceeds filesystem limit: {path}"
    try:
        root_path = Path(root)
        if not root_path.is_absolute():
            return False, f"Root must be absolute: {root}"
        lexical_full_path = root_path / path
        full_path = lexical_full_path.resolve()
        resolved_root = root_path.resolve()
        try:
            full_path.relative_to(resolved_root)
        except ValueError:
            return False, f"Path escapes root directory: {path}"
    except (ValueError, OSError, RuntimeError) as e:
        return False, f"Path normalization error: {e}"
    for reparse_path in _reparse_components(lexical_full_path, root_path):
        return False, f"Reparse point escape detected: {path}"
    return True, ""


def resolve_safe(
    source: str,
    destination: str,
) -> Tuple[bool, str]:
    if not source or not destination:
        return False, "Source and destination must not be empty"
    if "\x00" in source or "\x00" in destination:
        return False, "Path contains null bytes"
    src = Path(source)
    dst = Path(destination)
    if not src.exists():
        return False, f"Source does not exist: {source}"
    if dst.exists():
        return False, f"Destination already exists: {destination}"
    if has_device_name(source):
        return False, f"Windows device name in source: {source}"
    if has_device_name(destination):
        return False, f"Windows device name in destination: {destination}"
    if is_reparse_escape(source):
        return False, f"Source is a reparse point escape: {source}"
    dst_parent = dst.parent
    if dst_parent.exists() and is_reparse_escape(str(dst_parent)):
        return False, f"Destination parent is a reparse point escape: {destination}"
    try:
        if ".." in Path(destination).parts:
            return False, f"Destination path traversal detected: {destination}"
    except (ValueError, TypeError):
        return False, f"Invalid destination path: {destination}"
    return True, ""
