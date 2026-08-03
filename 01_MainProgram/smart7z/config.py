"""Configuration module for Smart7z.

- Atomic load/save via temp file + rename
- Legacy migration (del_archive -> cleanup_policy) before defaults merge
- Path resolution (password_file, temp_dir, target_dir)
- SevenZip discovery
- Injectable config path for isolated tests
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import warnings
from typing import Any, Dict, Optional

from models import CleanupPolicy

CONFIG_VERSION = 1

DEFAULT_CONFIG: Dict[str, Any] = {
    "7z_path": "",
    "target_dir": "",
    "extract_to_source": True,
    "wait_disk_space": True,
    "del_archive": False,
    "deep_scan": False,
    "steganographier_compat_mode": True,
    "temp_dir": r"C:\Temp_Smart7z",
    "password_file": "code.txt",
    "extract_mode": "staging",
    "config_version": CONFIG_VERSION,
    "cleanup_policy": CleanupPolicy.KEEP.value,
    "nested_extraction": False,
    "max_nested_depth": 2,
    "space_wait_timeout": 7200,
    "max_manifest_entries": 200_000,
    "max_output_files": 200_000,
    # Zero means an automatically approved cap derived from the manifest/free
    # space.  It never means unlimited extraction.
    "max_output_bytes": 0,
    "max_nested_children": 50,
    "max_nested_output_bytes": 0,
}

_CONFIG_TYPES: Dict[str, type] = {
    "7z_path": str,
    "target_dir": str,
    "extract_to_source": bool,
    "wait_disk_space": bool,
    "del_archive": bool,
    "deep_scan": bool,
    "steganographier_compat_mode": bool,
    "temp_dir": str,
    "password_file": str,
    "extract_mode": str,
    "config_version": int,
    "cleanup_policy": str,
    "nested_extraction": bool,
    "max_nested_depth": int,
    "space_wait_timeout": int,
    "max_manifest_entries": int,
    "max_output_files": int,
    "max_output_bytes": int,
    "max_nested_children": int,
    "max_nested_output_bytes": int,
}

_VALID_EXTRACT_MODES = {"staging", "direct"}
_VALID_CLEANUP_POLICIES = {p.value for p in CleanupPolicy}
_RETIRED_CONFIG_KEYS = frozenset({"trusted_input"})
PORTABLE_MARKER_NAME = "portable.flag"
STATE_DIR_NAME = "Smart7z"
# Source checkouts keep writable state together under resources. Frozen
# installed builds continue to use LOCALAPPDATA, and portable builds retain
# their existing executable-directory layout.
SOURCE_STATE_DIR_NAME = "resources"

# Injectable for unit tests. None => use default app-dir path.
_config_path_override: Optional[str] = None
_app_dir_override: Optional[str] = None


def set_config_path(path: Optional[str]) -> None:
    global _config_path_override
    _config_path_override = path


def set_app_dir(path: Optional[str]) -> None:
    global _app_dir_override
    _app_dir_override = path


def get_app_dir() -> str:
    if _app_dir_override:
        return _app_dir_override
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def is_portable_mode() -> bool:
    return os.path.isfile(os.path.join(get_app_dir(), PORTABLE_MARKER_NAME))


def get_state_root() -> str:
    if _app_dir_override:
        return _app_dir_override
    if not getattr(sys, "frozen", False):
        return os.path.join(get_app_dir(), SOURCE_STATE_DIR_NAME)
    if is_portable_mode():
        return get_app_dir()
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    return os.path.join(os.path.abspath(base), STATE_DIR_NAME)


def get_state_path(filename: str) -> str:
    if not filename or os.path.basename(filename) != filename:
        raise ValueError("State filename must be a single path component")
    return os.path.join(get_state_root(), filename)


def get_config_path() -> str:
    if _config_path_override:
        return _config_path_override
    return get_state_path("smart7z_config.json")


def _resolve_relative_to_app(path: str) -> str:
    if not path or os.path.isabs(path):
        return path
    return os.path.join(get_app_dir(), path)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _validate_type(key: str, value: Any) -> Any:
    expected = _CONFIG_TYPES.get(key)
    if expected is None:
        return value
    if isinstance(value, expected):
        return value
    if expected is bool:
        return _coerce_bool(value)
    if expected is int:
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                pass
    if expected is str:
        return str(value)
    raise TypeError(
        f"Config key '{key}' expected {expected.__name__}, got {type(value).__name__}"
    )


def _validate_config(config: Dict[str, Any]) -> None:
    for key, value in list(config.items()):
        if key in _CONFIG_TYPES:
            config[key] = _validate_type(key, value)
    extract_mode = config.get("extract_mode")
    if extract_mode is not None and extract_mode not in _VALID_EXTRACT_MODES:
        raise ValueError(f"Invalid extract_mode: {extract_mode!r}")
    cleanup_policy = config.get("cleanup_policy")
    if cleanup_policy is not None and cleanup_policy not in _VALID_CLEANUP_POLICIES:
        raise ValueError(f"Invalid cleanup_policy: {cleanup_policy!r}")
    for key in (
        "space_wait_timeout",
        "max_manifest_entries",
        "max_output_files",
        "max_output_bytes",
        "max_nested_children",
        "max_nested_output_bytes",
    ):
        if config.get(key, 0) < 0:
            raise ValueError(f"Config key '{key}' cannot be negative")
    if config.get("max_nested_depth", 0) < 0:
        raise ValueError("Config key 'max_nested_depth' cannot be negative")


def map_del_archive_to_cleanup_policy(del_archive: Any) -> str:
    """Pure mapping used by migration and tests.

    Legacy semantics:
      False / missing / None  -> RECYCLE (Recycle Bin)
      True                    -> PERMANENT
    """
    if del_archive is None:
        return CleanupPolicy.RECYCLE.value
    return (
        CleanupPolicy.PERMANENT.value
        if _coerce_bool(del_archive)
        else CleanupPolicy.RECYCLE.value
    )


def is_legacy_raw(raw: Dict[str, Any]) -> bool:
    return "config_version" not in raw


def migrate_legacy_raw(raw: Dict[str, Any], app_dir: Optional[str] = None) -> Dict[str, Any]:
    """Migrate a legacy config dict before merging new defaults.

    Must be called on the *raw* object so defaults cannot hide missing keys.
    """
    migrated = dict(raw)
    if "cleanup_policy" not in migrated:
        migrated["cleanup_policy"] = map_del_archive_to_cleanup_policy(
            migrated.get("del_archive", False)
        )
    base = app_dir or get_app_dir()
    for key in ("temp_dir", "target_dir"):
        val = migrated.get(key, "")
        if val and not os.path.isabs(val):
            migrated[key] = os.path.join(base, val)
    migrated["config_version"] = CONFIG_VERSION
    # Keep del_archive in sync for UI compatibility.
    policy = migrated.get("cleanup_policy", CleanupPolicy.KEEP.value)
    migrated["del_archive"] = policy == CleanupPolicy.PERMANENT.value
    return migrated


def _merge_defaults(raw: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(DEFAULT_CONFIG)
    merged.update(raw)
    return merged


def _resolve_relative_paths(config: Dict[str, Any]) -> bool:
    changed = False
    for key in ("temp_dir", "target_dir"):
        val = config.get(key, "")
        if val and not os.path.isabs(val):
            config[key] = _resolve_relative_to_app(val)
            changed = True
    return changed


def _backup_config_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    bak = path + ".bak"
    if os.path.exists(bak):
        bak = f"{path}.{time.strftime('%Y%m%d%H%M%S')}.bak"
    try:
        shutil.copy2(path, bak)
        return bak
    except OSError as e:
        warnings.warn(
            f"[Smart7z] Failed to backup config before migration: {e}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    cfg_path = path or get_config_path()
    source_path = cfg_path
    relocating = False
    if path is None and not os.path.exists(cfg_path):
        legacy_path = os.path.join(get_app_dir(), "smart7z_config.json")
        if (
            os.path.abspath(legacy_path) != os.path.abspath(cfg_path)
            and os.path.isfile(legacy_path)
        ):
            source_path = legacy_path
            relocating = True
    if not os.path.exists(source_path):
        return dict(DEFAULT_CONFIG)

    try:
        with open(source_path, "r", encoding="utf-8") as f:
            content = f.read()
        if not content.strip():
            raise json.JSONDecodeError("empty configuration", content, 0)
        raw = json.loads(content)
    except (json.JSONDecodeError, OSError) as e:
        warnings.warn(
            f"[Smart7z] Configuration file is malformed or unreadable: {e}. "
            f"Falling back to defaults (cleanup KEEP). File: {source_path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return dict(DEFAULT_CONFIG)

    if not isinstance(raw, dict):
        warnings.warn(
            f"[Smart7z] Configuration file does not contain a JSON object. "
            f"Falling back to defaults. File: {source_path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return dict(DEFAULT_CONFIG)

    needs_persist = relocating
    for retired_key in _RETIRED_CONFIG_KEYS:
        if retired_key in raw:
            raw.pop(retired_key, None)
            needs_persist = True
    if is_legacy_raw(raw):
        if not relocating:
            _backup_config_file(source_path)
        raw = migrate_legacy_raw(raw)
        needs_persist = True

    config = _merge_defaults(raw)
    try:
        _validate_config(config)
    except (TypeError, ValueError) as e:
        warnings.warn(
            f"[Smart7z] Configuration validation failed: {e}. "
            f"Falling back to defaults (cleanup KEEP). File: {source_path}",
            RuntimeWarning,
            stacklevel=2,
        )
        return dict(DEFAULT_CONFIG)

    # Malformed cleanup must never become destructive via silent fallback.
    if config.get("cleanup_policy") not in _VALID_CLEANUP_POLICIES:
        config["cleanup_policy"] = CleanupPolicy.KEEP.value

    if _resolve_relative_paths(config):
        needs_persist = True

    if needs_persist:
        try:
            save_config(config, path=cfg_path)
        except (OSError, TypeError, ValueError) as e:
            warnings.warn(
                f"[Smart7z] Failed to persist migrated config: {e}. "
                f"Original file left unchanged.",
                RuntimeWarning,
                stacklevel=2,
            )
    return config


def save_config(config: Dict[str, Any], path: Optional[str] = None) -> None:
    cfg_path = path or get_config_path()
    dir_name = os.path.dirname(cfg_path) or "."
    os.makedirs(dir_name, exist_ok=True)

    # Persist the supported schema only. This preserves every historical key
    # in DEFAULT_CONFIG without serializing unrelated runtime state.
    clean: Dict[str, Any] = {
        key: config.get(key, default) for key, default in DEFAULT_CONFIG.items()
    }
    _validate_config(clean)

    fd, tmp_path = tempfile.mkstemp(
        dir=dir_name, suffix=".tmp", prefix="smart7z_config_"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, cfg_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_password_file_path(config: Dict[str, Any]) -> str:
    path = config.get("password_file", DEFAULT_CONFIG["password_file"])
    if os.path.isabs(path):
        return path
    state_root = os.path.abspath(get_state_root())
    destination = os.path.abspath(os.path.join(state_root, path))
    try:
        if os.path.commonpath((state_root, destination)) != state_root:
            raise ValueError("Relative password path escapes the writable state root")
    except ValueError as exc:
        raise ValueError("Invalid relative password path") from exc
    legacy = os.path.abspath(os.path.join(get_app_dir(), path))
    if (
        os.path.abspath(destination) != os.path.abspath(legacy)
        and _password_file_has_data(legacy)
        and not _password_file_has_data(destination)
    ):
        # Upgrade installs preserve app-local code.txt.  If the newer state
        # location is absent or only an empty placeholder, keep using the
        # existing password book in place instead of shadowing it.
        return legacy
    return destination


def _password_file_has_data(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def find_sevenzip(config: Any = None) -> Optional[str]:
    """Accept a config dict or a configured path string for compatibility."""
    if isinstance(config, str):
        configured = config
        cfg: Dict[str, Any] = {"7z_path": config}
    elif isinstance(config, dict):
        cfg = config
        configured = config.get("7z_path", "")
    else:
        cfg = {}
        configured = ""

    candidates = []
    if configured:
        candidates.append(configured)
    app_dir = get_app_dir()
    candidates.append(os.path.join(app_dir, "7z.exe"))
    candidates.append(r"C:\Program Files\7-Zip\7z.exe")
    candidates.append(r"C:\Program Files (x86)\7-Zip\7z.exe")
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def resolve_sevenzip(config: Dict[str, Any]) -> Dict[str, Any]:
    configured = config.get("7z_path", "")
    if configured and os.path.isfile(configured):
        return config
    found = find_sevenzip(config)
    if found:
        config["7z_path"] = found
    return config


def cleanup_policy_from_config(config: Dict[str, Any]) -> CleanupPolicy:
    value = config.get("cleanup_policy", CleanupPolicy.KEEP.value)
    try:
        return CleanupPolicy(value)
    except ValueError:
        return CleanupPolicy.KEEP
