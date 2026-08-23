import os
import sys
import ctypes
import ctypes.wintypes
import subprocess
import logging
import re
import json
import stat
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from local_paths import is_local_filesystem_path

logger = logging.getLogger(__name__)

FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_NOERRORUI = 0x0400
FOFX_RECYCLEONDELETE = 0x00080000
FOFX_EARLYFAILURE = 0x00100000

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6
MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_WRITE_THROUGH = 0x00000008

RECYCLE_READY = "RECYCLE_READY"
RECYCLE_FALLBACK_UNAVAILABLE = "RECYCLE_FALLBACK_UNAVAILABLE"
RECYCLE_FALLBACK_TOO_LARGE = "RECYCLE_FALLBACK_TOO_LARGE"

_RECYCLE_UNSUPPORTED_DRIVE_TYPES = frozenset({
    DRIVE_REMOVABLE,
    DRIVE_REMOTE,
    DRIVE_CDROM,
    DRIVE_RAMDISK,
})
_RECYCLE_REGISTRY_ROOT = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume"
)


@dataclass(frozen=True)
class RecycleBinAssessment:
    status: str
    item_size: int = 0
    max_capacity_bytes: int = 0
    volume_root: str = ""
    volume_guid: str = ""

SESSION_OWNER_FILE = ".smart7z-owner.json"
SESSION_OWNER_SCHEMA = 1
_SESSION_NAME_RE = re.compile(r"Smart7z_Session_(\d+)_([0-9a-f]{32})")
_EMPTY_SESSION_SCAFFOLD_DIRS = frozenset({"stego"})

_CONTEXT_MENU_ENTRIES = (
    ("Smart7zExtractHere", "智能解压到此文件夹", "keep"),
    ("Smart7zExtractHereDelete", "智能解压到此文件夹并删除", "permanent"),
)
_CONTEXT_MENU_SCOPES = (
    r"Software\Classes\*\shell",
    r"Software\Classes\Directory\shell",
)
_CONTEXT_MENU_LAUNCHER_NAME = "Smart7zShell.exe"

if sys.platform == 'win32':
    _shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _ole32 = ctypes.WinDLL('ole32', use_last_error=True)

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.wintypes.DWORD),
            ("Data2", ctypes.wintypes.WORD),
            ("Data3", ctypes.wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    def _guid(value: str) -> GUID:
        return GUID.from_buffer_copy(uuid.UUID(value).bytes_le)

    _CLSID_FILE_OPERATION = _guid("3ad05575-8857-4850-9277-11b85bdb8e09")
    _IID_IFILE_OPERATION = _guid("947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8")
    _IID_ISHELL_ITEM = _guid("43826d1e-e718-42ee-bc55-a1e261c37bfe")

    _GetFileAttributesW = _kernel32.GetFileAttributesW
    _GetFileAttributesW.argtypes = [ctypes.wintypes.LPCWSTR]
    _GetFileAttributesW.restype = ctypes.wintypes.DWORD
    _GetDriveTypeW = _kernel32.GetDriveTypeW
    _GetDriveTypeW.argtypes = [ctypes.wintypes.LPCWSTR]
    _GetDriveTypeW.restype = ctypes.wintypes.UINT
    _CreateMutexW = _kernel32.CreateMutexW
    _CreateMutexW.argtypes = [
        ctypes.c_void_p,
        ctypes.wintypes.BOOL,
        ctypes.wintypes.LPCWSTR,
    ]
    _CreateMutexW.restype = ctypes.wintypes.HANDLE
    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [
        ctypes.wintypes.DWORD,
        ctypes.wintypes.BOOL,
        ctypes.wintypes.DWORD,
    ]
    _OpenProcess.restype = ctypes.wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    _CloseHandle.restype = ctypes.wintypes.BOOL
    _MoveFileExW = _kernel32.MoveFileExW
    _MoveFileExW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
    ]
    _MoveFileExW.restype = ctypes.wintypes.BOOL
    _GetVolumePathNameW = _kernel32.GetVolumePathNameW
    _GetVolumePathNameW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
    ]
    _GetVolumePathNameW.restype = ctypes.wintypes.BOOL
    _GetVolumeNameForVolumeMountPointW = (
        _kernel32.GetVolumeNameForVolumeMountPointW
    )
    _GetVolumeNameForVolumeMountPointW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.LPWSTR,
        ctypes.wintypes.DWORD,
    ]
    _GetVolumeNameForVolumeMountPointW.restype = ctypes.wintypes.BOOL
    _CoInitializeEx = _ole32.CoInitializeEx
    _CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]
    _CoInitializeEx.restype = ctypes.c_long
    _CoUninitialize = _ole32.CoUninitialize
    _CoUninitialize.argtypes = []
    _CoUninitialize.restype = None
    _CoCreateInstance = _ole32.CoCreateInstance
    _CoCreateInstance.argtypes = [
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _CoCreateInstance.restype = ctypes.c_long
    _SHCreateItemFromParsingName = _shell32.SHCreateItemFromParsingName
    _SHCreateItemFromParsingName.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _SHCreateItemFromParsingName.restype = ctypes.c_long


def to_long_path(path: str) -> str:
    if os.name == "nt":
        path = os.path.abspath(os.path.normpath(path))
        if len(path) > 200 and not path.startswith('\\\\?\\'):
            if path.startswith('\\\\'):
                return '\\\\?\\UNC\\' + path[2:]
            return '\\\\?\\' + path
    return path


def flush_file_to_disk(path: str) -> None:
    """Flush one regular file through the operating-system storage cache."""

    absolute = os.path.abspath(path)
    info = os.stat(absolute, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"Cannot flush a non-file path: {absolute}")

    original_mode = stat.S_IMODE(info.st_mode)
    made_writable = not bool(info.st_mode & stat.S_IWRITE)
    restored = False
    descriptor = -1
    try:
        if made_writable:
            os.chmod(absolute, original_mode | stat.S_IWRITE)
        descriptor = os.open(
            absolute,
            os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
        if made_writable:
            os.chmod(absolute, original_mode)
            restored = True
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if made_writable and not restored:
            try:
                os.chmod(absolute, original_mode)
            except OSError:
                logger.exception("Could not restore file mode after flush: %s", absolute)


def move_no_replace_durable(source: str, destination: str) -> None:
    """Move without replacement and request write-through namespace persistence."""

    source = os.path.abspath(source)
    destination = os.path.abspath(destination)
    if os.name == "nt":
        if not _MoveFileExW(
            to_long_path(source),
            to_long_path(destination),
            MOVEFILE_WRITE_THROUGH,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    os.rename(source, destination)
    _fsync_directory(os.path.dirname(source))
    if os.path.dirname(source) != os.path.dirname(destination):
        _fsync_directory(os.path.dirname(destination))


def replace_file_durable(source: str, destination: str) -> None:
    """Atomically replace a path and request write-through persistence."""

    source = os.path.abspath(source)
    destination = os.path.abspath(destination)
    if os.name == "nt":
        if not _MoveFileExW(
            to_long_path(source),
            to_long_path(destination),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    os.replace(source, destination)
    _fsync_directory(os.path.dirname(destination))


def _fsync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def make_startupinfo() -> Optional[subprocess.STARTUPINFO]:
    if sys.platform == 'win32':
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return si
    return None


def assess_recycle_bin(path: str) -> RecycleBinAssessment:
    """Return only recycle outcomes that Windows policy makes explicit."""

    if sys.platform != "win32":
        raise OSError("Recycle Bin policy is available only on Windows")
    absolute = os.path.abspath(path)
    info = os.stat(absolute, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"Recycle Bin cleanup requires a regular file: {absolute}")

    volume_root, drive_type, volume_guid = _get_recycle_volume(absolute)
    if drive_type in _RECYCLE_UNSUPPORTED_DRIVE_TYPES:
        return RecycleBinAssessment(
            status=RECYCLE_FALLBACK_UNAVAILABLE,
            item_size=int(info.st_size),
            volume_root=volume_root,
        )
    if drive_type != DRIVE_FIXED:
        raise OSError(f"Could not determine Recycle Bin support for {volume_root}")

    nuke_on_delete, max_capacity_mb = _read_recycle_bin_settings(volume_guid)
    if nuke_on_delete or max_capacity_mb <= 0:
        return RecycleBinAssessment(
            status=RECYCLE_FALLBACK_UNAVAILABLE,
            item_size=int(info.st_size),
            volume_root=volume_root,
            volume_guid=volume_guid,
        )

    max_capacity_bytes = int(max_capacity_mb) * 1024 * 1024
    status = (
        RECYCLE_FALLBACK_TOO_LARGE
        if int(info.st_size) > max_capacity_bytes
        else RECYCLE_READY
    )
    return RecycleBinAssessment(
        status=status,
        item_size=int(info.st_size),
        max_capacity_bytes=max_capacity_bytes,
        volume_root=volume_root,
        volume_guid=volume_guid,
    )


def _get_recycle_volume(path: str) -> Tuple[str, int, str]:
    volume_path = ctypes.create_unicode_buffer(32768)
    if not _GetVolumePathNameW(path, volume_path, len(volume_path)):
        raise ctypes.WinError(ctypes.get_last_error())
    volume_root = volume_path.value
    drive_type = int(_GetDriveTypeW(volume_root))
    if drive_type != DRIVE_FIXED:
        return volume_root, drive_type, ""

    volume_name = ctypes.create_unicode_buffer(1024)
    if not _GetVolumeNameForVolumeMountPointW(
        volume_root, volume_name, len(volume_name)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    match = re.search(r"(\{[0-9A-Fa-f-]{36}\})", volume_name.value)
    if not match:
        raise OSError(f"Windows returned an invalid volume name: {volume_name.value!r}")
    return volume_root, drive_type, match.group(1)


def _read_recycle_bin_settings(volume_guid: str) -> Tuple[int, int]:
    import winreg

    key_path = f"{_RECYCLE_REGISTRY_ROOT}\\{volume_guid}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            nuke_on_delete, nuke_type = winreg.QueryValueEx(key, "NukeOnDelete")
            max_capacity, capacity_type = winreg.QueryValueEx(key, "MaxCapacity")
    except OSError as exc:
        raise OSError(
            f"Could not read Recycle Bin settings for volume {volume_guid}"
        ) from exc
    if nuke_type != winreg.REG_DWORD or capacity_type != winreg.REG_DWORD:
        raise OSError(f"Recycle Bin settings have invalid types for {volume_guid}")
    if not isinstance(nuke_on_delete, int) or not isinstance(max_capacity, int):
        raise OSError(f"Recycle Bin settings have invalid values for {volume_guid}")
    return int(nuke_on_delete), int(max_capacity)


def send_to_recycle_bin(path: str) -> bool:
    """Recycle *path* without allowing Shell to substitute permanent deletion."""

    if sys.platform != "win32":
        raise OSError("Recycle Bin cleanup is available only on Windows")
    if not os.path.lexists(path):
        return True
    absolute = os.path.abspath(path)
    initialized = False
    operation = ctypes.c_void_p()
    shell_item = ctypes.c_void_p()
    try:
        result = int(_CoInitializeEx(None, 0x00000002))
        _check_hresult(result, "CoInitializeEx")
        initialized = True

        result = int(
            _CoCreateInstance(
                ctypes.byref(_CLSID_FILE_OPERATION),
                None,
                0x00000001,
                ctypes.byref(_IID_IFILE_OPERATION),
                ctypes.byref(operation),
            )
        )
        _check_hresult(result, "CoCreateInstance(CLSID_FileOperation)")

        result = int(
            _SHCreateItemFromParsingName(
                absolute,
                None,
                ctypes.byref(_IID_ISHELL_ITEM),
                ctypes.byref(shell_item),
            )
        )
        _check_hresult(result, "SHCreateItemFromParsingName")

        flags = (
            FOF_SILENT
            | FOF_NOCONFIRMATION
            | FOF_NOERRORUI
            | FOFX_RECYCLEONDELETE
            | FOFX_EARLYFAILURE
        )
        set_flags = _com_method(
            operation, 5, ctypes.c_long, ctypes.wintypes.DWORD
        )
        _check_hresult(int(set_flags(operation, flags)), "SetOperationFlags")

        delete_item = _com_method(
            operation, 18, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p
        )
        _check_hresult(
            int(delete_item(operation, shell_item, None)), "DeleteItem"
        )

        perform = _com_method(operation, 21, ctypes.c_long)
        _check_hresult(int(perform(operation)), "PerformOperations")

        aborted = ctypes.wintypes.BOOL()
        get_aborted = _com_method(
            operation,
            22,
            ctypes.c_long,
            ctypes.POINTER(ctypes.wintypes.BOOL),
        )
        _check_hresult(
            int(get_aborted(operation, ctypes.byref(aborted))),
            "GetAnyOperationsAborted",
        )
        return not bool(aborted.value) and not os.path.lexists(absolute)
    finally:
        _release_com(shell_item)
        _release_com(operation)
        if initialized:
            _CoUninitialize()


def _com_method(interface, index: int, restype, *argtypes):
    if not interface or not interface.value:
        raise OSError("COM interface is unavailable")
    vtable = ctypes.cast(
        interface, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
    ).contents
    address = vtable[index]
    if not address:
        raise OSError(f"COM method {index} is unavailable")
    prototype = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
    return prototype(address)


def _release_com(interface) -> None:
    if not interface or not interface.value:
        return
    try:
        release = _com_method(interface, 2, ctypes.wintypes.ULONG)
        release(interface)
    finally:
        interface.value = None


def _check_hresult(result: int, operation: str) -> None:
    if int(result) & 0x80000000:
        unsigned = int(result) & 0xFFFFFFFF
        raise OSError(f"{operation} failed (HRESULT 0x{unsigned:08X})")


def delete_permanently(path: str) -> bool:
    if not os.path.exists(path):
        return True
    if os.path.isdir(path):
        safe_rmtree(path)
    else:
        os.remove(path)
    return not os.path.exists(path)


def safe_rmtree(path: str, ignore_errors: bool = False):
    if os.path.exists(path):
        import shutil
        shutil.rmtree(path, ignore_errors=ignore_errors, onerror=_force_remove_readonly)


def _force_remove_readonly(func, path, excinfo):
    try:
        os.chmod(path, 128)
        func(path)
    except OSError:
        raise


def build_context_menu_command(cleanup_policy: str = "keep") -> str:
    """Build a quoted extract-here command with an explicit cleanup policy."""
    if cleanup_policy not in {"keep", "permanent"}:
        raise ValueError(f"Unsupported context-menu cleanup policy: {cleanup_policy!r}")
    cleanup_flag = (
        "--delete-source" if cleanup_policy == "permanent" else "--keep-source"
    )
    executable = os.path.abspath(sys.executable)
    if getattr(sys, "frozen", False):
        launcher = os.path.join(os.path.dirname(executable), _CONTEXT_MENU_LAUNCHER_NAME)
        if os.path.isfile(launcher):
            executable = launcher
        prefix = subprocess.list2cmdline(
            [
                executable,
                "--context-menu",
                "--start",
                "--extract-here",
                cleanup_flag,
            ]
        )
        return f'{prefix} "%1"'
    script = os.path.abspath(sys.argv[0] or os.path.join(get_app_dir(), "smart7z.py"))
    if not script.lower().endswith(".py"):
        script = os.path.join(get_app_dir(), "smart7z.py")
    prefix = subprocess.list2cmdline(
        [
            executable,
            script,
            "--context-menu",
            "--start",
            "--extract-here",
            cleanup_flag,
        ]
    )
    return f'{prefix} "%1"'


def register_context_menu() -> bool:
    if not sys.platform.startswith('win'):
        return False
    exe_path = os.path.abspath(sys.executable)
    if not exe_path.lower().endswith('.exe'):
        return False
    try:
        import winreg
        if not _delete_context_menu_keys(winreg):
            return False
        for scope in _CONTEXT_MENU_SCOPES:
            for verb, label, cleanup_policy in _CONTEXT_MENU_ENTRIES:
                key_path = f"{scope}\\{verb}"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    winreg.SetValue(key, "", winreg.REG_SZ, label)
                    winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, exe_path)
                with winreg.CreateKey(
                    winreg.HKEY_CURRENT_USER, f"{key_path}\\command"
                ) as key:
                    winreg.SetValue(
                        key,
                        "",
                        winreg.REG_SZ,
                        build_context_menu_command(cleanup_policy),
                    )
        return True
    except (OSError, PermissionError):
        logger.exception("Context-menu registration failed")
        try:
            _delete_context_menu_keys(winreg)
        except Exception:
            logger.exception("Context-menu registration rollback failed")
        return False


def unregister_context_menu() -> bool:
    if not sys.platform.startswith('win'):
        return False
    try:
        import winreg
        return _delete_context_menu_keys(winreg)
    except (OSError, PermissionError, ImportError):
        logger.exception("Context-menu removal failed")
        return False


def _delete_context_menu_keys(winreg_module) -> bool:
    errors = []
    verbs = [entry[0] for entry in _CONTEXT_MENU_ENTRIES] + ["Smart7z"]
    key_paths = []
    for scope in _CONTEXT_MENU_SCOPES:
        for verb in verbs:
            key_paths.extend((f"{scope}\\{verb}\\command", f"{scope}\\{verb}"))
    for key_path in key_paths:
        try:
            winreg_module.DeleteKey(winreg_module.HKEY_CURRENT_USER, key_path)
        except FileNotFoundError:
            continue
        except (OSError, PermissionError) as exc:
            errors.append((key_path, exc))
    for key_path, exc in errors:
        logger.warning("Context-menu key removal failed for %s: %s", key_path, exc)
    return not errors


def create_mutex(name: str = "Smart7z_Instance_Mutex"):
    if sys.platform != 'win32':
        return None
    try:
        ctypes.set_last_error(0)
        handle = _CreateMutexW(None, False, name)
        if not handle:
            return None
        if ctypes.get_last_error() == 183:
            _CloseHandle(handle)
            return None
        return handle
    except Exception:
        return None


def close_mutex(handle) -> bool:
    """Close a named-mutex handle returned by :func:`create_mutex`."""

    if handle is None:
        return True
    if sys.platform != 'win32':
        return False
    try:
        return bool(_CloseHandle(handle))
    except Exception:
        return False


def is_reparse_point(path: str) -> bool:
    if sys.platform != 'win32':
        return False
    try:
        attrs = _GetFileAttributesW(path)
        if attrs == INVALID_FILE_ATTRIBUTES:
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def find_sevenzip(configured_path: str = "") -> Optional[str]:
    if configured_path and os.path.exists(configured_path):
        return configured_path

    app_dir = get_app_dir()
    local = os.path.join(app_dir, "7z.exe")
    if os.path.exists(local):
        return os.path.abspath(local)

    for candidate in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]:
        if os.path.exists(candidate):
            return candidate

    return None


def get_app_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def create_owned_session(base_temp_dir: str) -> Tuple[str, str]:
    """Create an exclusive per-process session directory with an owner nonce."""

    base = os.path.abspath(base_temp_dir)
    os.makedirs(base, exist_ok=True)
    for _attempt in range(20):
        token = uuid.uuid4().hex
        session = os.path.join(base, f"Smart7z_Session_{os.getpid()}_{token}")
        try:
            os.mkdir(session)
        except FileExistsError:
            continue
        marker = os.path.join(session, SESSION_OWNER_FILE)
        payload = {
            "schema": SESSION_OWNER_SCHEMA,
            "pid": os.getpid(),
            "token": token,
            "created_ns": time.time_ns(),
        }
        try:
            with open(marker, "x", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, ensure_ascii=True, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            safe_rmtree(session, ignore_errors=True)
            raise
        return session, token
    raise FileExistsError("Could not allocate a unique Smart7z session directory")


def _read_owned_session(path: str) -> Optional[Tuple[int, str]]:
    absolute = os.path.abspath(path)
    match = _SESSION_NAME_RE.fullmatch(os.path.basename(absolute))
    if not match:
        return None
    if (
        not os.path.isdir(absolute)
        or os.path.islink(absolute)
        or is_reparse_point(absolute)
    ):
        return None
    marker = os.path.join(absolute, SESSION_OWNER_FILE)
    try:
        if (
            not os.path.isfile(marker)
            or os.path.islink(marker)
            or is_reparse_point(marker)
            or os.path.getsize(marker) > 4096
        ):
            return None
        with open(marker, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    pid = int(match.group(1))
    token = match.group(2)
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SESSION_OWNER_SCHEMA
        or payload.get("pid") != pid
        or payload.get("token") != token
        or not isinstance(payload.get("created_ns"), int)
    ):
        return None
    return pid, token


def cleanup_owned_session(
    session_path: str,
    expected_token: str,
    expected_pid: Optional[int] = None,
) -> bool:
    """Remove only the exact session whose marker matches our owner nonce."""

    owner = _read_owned_session(session_path)
    expected = os.getpid() if expected_pid is None else int(expected_pid)
    if owner != (expected, expected_token):
        return False
    try:
        for name in set(os.listdir(session_path)) - {SESSION_OWNER_FILE}:
            if name not in _EMPTY_SESSION_SCAFFOLD_DIRS:
                return False
            scaffold = os.path.join(session_path, name)
            if (
                not os.path.isdir(scaffold)
                or os.path.islink(scaffold)
                or is_reparse_point(scaffold)
            ):
                return False
            try:
                os.rmdir(scaffold)
            except OSError:
                return False
        if set(os.listdir(session_path)) != {SESSION_OWNER_FILE}:
            return False
    except OSError:
        return False
    safe_rmtree(os.path.abspath(session_path))
    return not os.path.lexists(session_path)


def cleanup_stale_sessions(base_temp_dir: str, protected_paths=None):
    if not os.path.exists(base_temp_dir):
        return
    base = os.path.abspath(base_temp_dir)
    protected = {
        os.path.normcase(os.path.realpath(os.path.abspath(path)))
        for path in (protected_paths or ())
        if isinstance(path, str) and path
    }
    try:
        for item in os.listdir(base):
            match = _SESSION_NAME_RE.fullmatch(item)
            if not match:
                continue
            path_to_del = os.path.abspath(os.path.join(base, item))
            if os.path.normcase(os.path.realpath(path_to_del)) in protected:
                continue
            try:
                owner = _read_owned_session(path_to_del)
                if (
                    os.path.commonpath((base, path_to_del)) != base
                    or owner is None
                ):
                    continue
            except ValueError:
                continue
            old_pid = int(match.group(1))
            if not _is_pid_running(old_pid):
                try:
                    cleanup_owned_session(
                        path_to_del,
                        owner[1],
                        expected_pid=old_pid,
                    )
                except OSError:
                    logger.exception("Stale-session cleanup failed: %s", path_to_del)
    except OSError:
        logger.exception("Could not enumerate stale sessions: %s", base_temp_dir)


def _is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == 'win32':
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        ctypes.set_last_error(0)
        handle = _OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            _CloseHandle(handle)
            return True
        # Access denied means the process exists but cannot be queried.  It is
        # never safe to treat that as a stale-session signal.
        if ctypes.get_last_error() == 5:
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
