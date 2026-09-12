"""Persistent ownership journal for Smart7z temporary and cleanup artifacts.

The journal never deletes by filename prefix alone.  Automatic recovery requires
an atomic journal entry, a detached random owner marker, the recorded parent and
name prefix, and a stable filesystem object identity to agree.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import tempfile
import threading
import time
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from windows_adapters import move_no_replace_durable, replace_file_durable


logger = logging.getLogger(__name__)

RECOVERY_SCHEMA = 1
MARKER_SCHEMA = 1
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 4096
MAX_MARKER_BYTES = 4096
MARKER_DIR_NAME = "recovery-markers-v1"
SOURCE_CONFLICT_DIR_NAME = "Smart7z_源文件恢复冲突"
_PROCESS_INSTANCE_TOKEN = uuid.uuid4().hex

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def default_recovery_journal_path() -> str:
    from config import get_state_path

    return get_state_path("recovery-v1.json")


def _canonical(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _is_link_or_reparse(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return True
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return bool(os.path.islink(path) or attributes & 0x0400)


def _identity(path: str, full: bool = False) -> Optional[Dict[str, Any]]:
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    is_link = bool(os.path.islink(path))
    is_reparse = bool(attributes & 0x0400)
    result: Dict[str, Any] = {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "is_dir": bool(stat.S_ISDIR(info.st_mode)),
        "is_file": bool(stat.S_ISREG(info.st_mode)),
        "is_link": is_link,
        "is_reparse": is_reparse,
    }
    if full:
        result.update(
            {
                "size": int(info.st_size),
                "mtime_ns": int(info.st_mtime_ns),
            }
        )
    return result


def _identity_matches(
    path: str, expected: Dict[str, Any], full: bool = False
) -> bool:
    current = _identity(path, full=full)
    if current is None or not isinstance(expected, dict):
        return False
    keys = ("device", "inode", "is_dir", "is_file", "is_link")
    if "is_reparse" in expected:
        keys += ("is_reparse",)
    elif current.get("is_reparse"):
        return False
    if full:
        keys += ("size", "mtime_ns")
    # A zero inode is not a sufficiently stable ownership proof for automatic
    # deletion or restoration.
    if int(expected.get("inode", 0) or 0) == 0:
        return False
    if not all(current.get(key) == expected.get(key) for key in keys):
        return False
    return True


def _artifact_snapshot(path: str) -> Optional[Dict[str, Any]]:
    absolute = os.path.abspath(path)
    if _is_link_or_reparse(absolute):
        return None
    if os.path.isfile(absolute):
        identity = _identity(absolute, full=True)
        return {"kind": "file", "identity": identity} if identity else None
    if not os.path.isdir(absolute):
        return None

    digest = hashlib.sha256()
    count = 0
    try:
        for root, dirs, files in os.walk(absolute, followlinks=False):
            dirs.sort()
            files.sort()
            for name in dirs:
                full = os.path.join(root, name)
                if _is_link_or_reparse(full):
                    return None
                rel = os.path.relpath(full, absolute).replace(os.sep, "/")
                digest.update(f"D\0{rel}\0".encode("utf-8", "surrogatepass"))
                count += 1
            for name in files:
                full = os.path.join(root, name)
                if _is_link_or_reparse(full):
                    return None
                rel = os.path.relpath(full, absolute).replace(os.sep, "/")
                info = os.stat(full, follow_symlinks=False)
                digest.update(
                    (
                        f"F\0{rel}\0{int(info.st_size)}\0"
                        f"{int(info.st_mtime_ns)}\0"
                    ).encode(
                        "utf-8", "surrogatepass"
                    )
                )
                count += 1
    except OSError:
        return None
    return {
        "kind": "directory",
        "count": count,
        "fingerprint": digest.hexdigest(),
    }


def _artifact_snapshot_matches(path: str, expected: Any) -> bool:
    if (
        isinstance(expected, dict)
        and expected.get("kind") == "directory"
        and int(expected.get("count", -1)) == 0
        and os.path.isdir(path)
    ):
        try:
            with os.scandir(path) as entries:
                return next(entries, None) is None
        except OSError:
            return False
    return isinstance(expected, dict) and _artifact_snapshot(path) == expected


class RecoveryJournal:
    """Thread-safe atomic journal with conservative startup recovery."""

    def __init__(self, path: Optional[str] = None):
        self.path = os.path.abspath(path or default_recovery_journal_path())
        self.marker_dir = os.path.join(os.path.dirname(self.path), MARKER_DIR_NAME)
        self._lock = threading.RLock()
        self._process_lock_stream = None
        self._closed = False
        self._entries: Dict[str, Dict[str, Any]] = {}
        self.load_error = ""
        self.last_error = ""
        if self._acquire_process_lock():
            self._load()

    @property
    def available(self) -> bool:
        return not self.load_error and not self._closed

    def _acquire_process_lock(self) -> bool:
        """Hold one journal writer lock for this object's lifetime."""

        lock_path = self.path + ".lock"
        try:
            os.makedirs(os.path.dirname(lock_path), exist_ok=True)
            if os.path.lexists(lock_path) and _is_link_or_reparse(lock_path):
                raise OSError("recovery lock path is a link or reparse point")
            stream = open(lock_path, "a+b")
            if _is_link_or_reparse(lock_path):
                raise OSError("recovery lock path changed during open")
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
                os.fsync(stream.fileno())
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            try:
                stream.close()
            except (NameError, OSError):
                pass
            self.load_error = (
                "recovery journal lock is unavailable: " + str(exc)
            )
            logger.warning("Recovery journal lock unavailable: %s", exc)
            return False
        self._process_lock_stream = stream
        return True

    def close(self) -> None:
        with self._lock:
            stream = self._process_lock_stream
            self._process_lock_stream = None
            self._closed = True
        if stream is None:
            return
        try:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            logger.warning("Could not explicitly release recovery journal lock")
        finally:
            stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            if _is_link_or_reparse(self.path):
                raise ValueError("recovery journal is a link or reparse point")
            if os.path.getsize(self.path) > MAX_JOURNAL_BYTES:
                raise ValueError("recovery journal exceeds its safety limit")
            with open(self.path, "r", encoding="utf-8") as stream:
                payload = json.load(stream)
            if (
                not isinstance(payload, dict)
                or payload.get("schema") != RECOVERY_SCHEMA
                or not isinstance(payload.get("entries"), dict)
            ):
                raise ValueError("recovery journal schema is invalid")
            entries = payload["entries"]
            if len(entries) > MAX_JOURNAL_ENTRIES:
                raise ValueError("recovery journal has too many entries")
            self._entries = {
                str(entry_id): entry
                for entry_id, entry in entries.items()
                if isinstance(entry_id, str) and isinstance(entry, dict)
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self.load_error = str(exc)
            logger.error("Recovery journal could not be loaded: %s", exc)

    def _persist_locked(self) -> None:
        if self._closed or self._process_lock_stream is None:
            raise OSError("Recovery journal is closed or not exclusively locked")
        if self.load_error:
            raise OSError(f"Recovery journal is unavailable: {self.load_error}")
        if len(self._entries) > MAX_JOURNAL_ENTRIES:
            raise OSError("Recovery journal entry limit reached")
        parent = os.path.dirname(self.path)
        os.makedirs(parent, exist_ok=True)
        payload = {
            "schema": RECOVERY_SCHEMA,
            "updated_ns": time.time_ns(),
            "entries": self._entries,
        }
        fd, temporary = tempfile.mkstemp(
            prefix="recovery_", suffix=".tmp", dir=parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                json.dump(payload, stream, ensure_ascii=True, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if os.path.getsize(temporary) > MAX_JOURNAL_BYTES:
                raise OSError("Recovery journal exceeds its safety limit")
            replace_file_durable(temporary, self.path)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _create_marker_locked(
        self, entry_id: str, target: str, kind: str
    ) -> Tuple[str, str]:
        os.makedirs(self.marker_dir, exist_ok=True)
        if _is_link_or_reparse(self.marker_dir):
            raise OSError("recovery marker directory is a link or reparse point")
        token = uuid.uuid4().hex
        marker_path = os.path.join(
            self.marker_dir, f"{entry_id}_{token}.json"
        )
        payload = {
            "schema": MARKER_SCHEMA,
            "entry_id": entry_id,
            "token": token,
            "kind": kind,
            "target": os.path.abspath(target),
        }
        fd, temporary = tempfile.mkstemp(
            prefix="marker_", suffix=".tmp", dir=self.marker_dir
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                json.dump(payload, stream, ensure_ascii=True, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            move_no_replace_durable(temporary, marker_path)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return marker_path, token

    def _marker_valid(self, entry_id: str, entry: Dict[str, Any]) -> bool:
        marker_path = entry.get("marker_path")
        token = entry.get("marker_token")
        if not isinstance(marker_path, str) or not isinstance(token, str):
            return False
        try:
            marker_parent = os.path.abspath(os.path.dirname(marker_path))
            if (
                os.path.normcase(marker_parent)
                != os.path.normcase(os.path.abspath(self.marker_dir))
                or _is_link_or_reparse(self.marker_dir)
            ):
                return False
            if (
                not os.path.isfile(marker_path)
                or _is_link_or_reparse(marker_path)
                or os.path.getsize(marker_path) > MAX_MARKER_BYTES
            ):
                return False
            with open(marker_path, "r", encoding="utf-8") as stream:
                marker = json.load(stream)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False
        return bool(
            isinstance(marker, dict)
            and marker.get("schema") == MARKER_SCHEMA
            and marker.get("entry_id") == entry_id
            and marker.get("token") == token
            and marker.get("kind") == entry.get("kind")
            and marker.get("target") == entry.get("marker_target")
        )

    def _remove_marker(
        self, entry_id: str, entry: Dict[str, Any]
    ) -> None:
        for field, token_field, target_field in (
            ("marker_path", "marker_token", "marker_target"),
            ("pending_marker_path", "pending_marker_token", "pending_path"),
        ):
            marker_path = entry.get(field)
            if not isinstance(marker_path, str):
                continue
            marker_entry = dict(entry)
            marker_entry.update(
                {
                    "marker_path": marker_path,
                    "marker_token": entry.get(token_field),
                    "marker_target": entry.get(target_field),
                }
            )
            if not self._marker_valid(entry_id, marker_entry):
                logger.warning(
                    "Untrusted recovery marker was preserved: %s", marker_path
                )
                continue
            try:
                os.unlink(marker_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("Could not remove recovery marker: %s", marker_path)

    def _add_entry(
        self, entry_id: str, entry: Dict[str, Any]
    ) -> Optional[str]:
        with self._lock:
            if self.load_error:
                self.last_error = self.load_error
                return None
            self._entries[entry_id] = entry
            try:
                self._persist_locked()
                return entry_id
            except OSError as exc:
                self._entries.pop(entry_id, None)
                self.last_error = str(exc)
                self._remove_marker(entry_id, entry)
                logger.warning("Recovery journal registration failed: %s", exc)
                return None

    def _remove_entry(self, entry_id: str) -> bool:
        with self._lock:
            entry = self._entries.pop(entry_id, None)
            if entry is None:
                return True
            try:
                self._persist_locked()
            except OSError as exc:
                self._entries[entry_id] = entry
                self.last_error = str(exc)
                logger.warning("Recovery journal resolution failed: %s", exc)
                return False
        self._remove_marker(entry_id, entry)
        return True

    def register_artifact(
        self,
        path: str,
        task_id: str,
        artifact_kind: str,
        name_prefix: str,
        disposition: str = "delete",
    ) -> Optional[str]:
        absolute = os.path.abspath(path)
        identity = _identity(absolute)
        if (
            identity is None
            or identity.get("is_link")
            or identity.get("is_reparse")
            or not os.path.basename(absolute).startswith(name_prefix)
        ):
            self.last_error = "artifact ownership precondition failed"
            return None
        entry_id = uuid.uuid4().hex
        with self._lock:
            try:
                marker_path, marker_token = self._create_marker_locked(
                    entry_id, absolute, "artifact"
                )
            except OSError as exc:
                self.last_error = str(exc)
                return None
        entry = {
            "kind": "artifact",
            "artifact_kind": str(artifact_kind),
            "task_id": str(task_id),
            "created_ns": time.time_ns(),
            "path": absolute,
            "parent": os.path.dirname(absolute),
            "name_prefix": str(name_prefix),
            "identity": identity,
            "disposition": disposition,
            "marker_path": marker_path,
            "marker_token": marker_token,
            "marker_target": absolute,
        }
        if disposition == "delete":
            snapshot = _artifact_snapshot(absolute)
            if snapshot is None:
                self._remove_marker(entry_id, entry)
                self.last_error = "artifact deletion snapshot failed"
                return None
            entry["delete_snapshot"] = snapshot
        return self._add_entry(entry_id, entry)

    def prepare_artifact_move(
        self, source: str, destination: str, destination_prefix: str
    ) -> bool:
        source_key = _canonical(source)
        destination = os.path.abspath(destination)
        with self._lock:
            found = self._find_artifact_locked(source_key)
            if found is None:
                return False
            entry_id, entry = found
            if os.path.lexists(destination):
                return False
            previous = dict(entry)
            try:
                marker_path, marker_token = self._create_marker_locked(
                    entry_id, destination, "artifact"
                )
                entry.update(
                    {
                        "pending_path": destination,
                        "pending_parent": os.path.dirname(destination),
                        "pending_name_prefix": destination_prefix,
                        "pending_identity": dict(entry.get("identity") or {}),
                        "pending_marker_path": marker_path,
                        "pending_marker_token": marker_token,
                        "pending_previous_disposition": entry.get(
                            "disposition", "delete"
                        ),
                        "disposition": "preserve",
                    }
                )
                self._persist_locked()
                return True
            except OSError as exc:
                pending_marker = entry.get("pending_marker_path")
                entry.clear()
                entry.update(previous)
                if isinstance(pending_marker, str):
                    try:
                        os.unlink(pending_marker)
                    except OSError:
                        pass
                self.last_error = str(exc)
                return False

    def commit_artifact_move(self, source: str, destination: str) -> bool:
        source_key = _canonical(source)
        destination_key = _canonical(destination)
        with self._lock:
            found = self._find_artifact_locked(source_key)
            if found is None:
                return False
            _entry_id, entry = found
            previous = dict(entry)
            pending_path = entry.get("pending_path")
            if (
                not isinstance(pending_path, str)
                or _canonical(pending_path) != destination_key
                or not _identity_matches(
                    destination, entry.get("pending_identity") or {}
                )
            ):
                return False
            old_marker = entry.get("marker_path")
            entry.update(
                {
                    "path": os.path.abspath(destination),
                    "parent": entry.pop("pending_parent"),
                    "name_prefix": entry.pop("pending_name_prefix"),
                    "identity": entry.pop("pending_identity"),
                    "marker_path": entry.pop("pending_marker_path"),
                    "marker_token": entry.pop("pending_marker_token"),
                    "marker_target": os.path.abspath(destination),
                    # A moved commit stage contains recoverable user output.
                    # Recovery may only delete it again after publication has
                    # completed and the executor explicitly releases it.
                    "disposition": "preserve",
                }
            )
            entry.pop("pending_path", None)
            entry.pop("pending_previous_disposition", None)
            try:
                self._persist_locked()
            except OSError as exc:
                entry.clear()
                entry.update(previous)
                self.last_error = str(exc)
                return False
        if isinstance(old_marker, str):
            try:
                os.unlink(old_marker)
            except OSError:
                pass
        return True

    def cancel_artifact_move(self, source: str) -> None:
        source_key = _canonical(source)
        with self._lock:
            found = self._find_artifact_locked(source_key)
            if found is None:
                return
            _entry_id, entry = found
            marker = entry.pop("pending_marker_path", None)
            previous_disposition = entry.pop(
                "pending_previous_disposition", entry.get("disposition", "delete")
            )
            entry["disposition"] = previous_disposition
            entry.pop("pending_marker_token", None)
            entry.pop("pending_path", None)
            entry.pop("pending_parent", None)
            entry.pop("pending_name_prefix", None)
            entry.pop("pending_identity", None)
            try:
                self._persist_locked()
            except OSError as exc:
                self.last_error = str(exc)
        if isinstance(marker, str):
            try:
                os.unlink(marker)
            except OSError:
                pass

    def set_artifact_disposition(self, path: str, disposition: str) -> bool:
        path_key = _canonical(path)
        snapshot = None
        if disposition == "delete":
            snapshot = _artifact_snapshot(path)
            if snapshot is None:
                self.last_error = "artifact deletion snapshot failed"
                return False
        with self._lock:
            found = self._find_artifact_locked(path_key)
            if found is None:
                return False
            _entry_id, entry = found
            previous = entry.get("disposition")
            previous_snapshot = entry.get("delete_snapshot")
            entry["disposition"] = str(disposition)
            if disposition == "delete":
                entry["delete_snapshot"] = snapshot
            else:
                entry.pop("delete_snapshot", None)
            try:
                self._persist_locked()
                return True
            except OSError as exc:
                entry["disposition"] = previous
                if previous_snapshot is None:
                    entry.pop("delete_snapshot", None)
                else:
                    entry["delete_snapshot"] = previous_snapshot
                self.last_error = str(exc)
                return False

    def unregister_artifact(self, path: str) -> bool:
        path_key = _canonical(path)
        with self._lock:
            found = self._find_artifact_locked(path_key)
            if found is None:
                return True
            entry_id, _entry = found
        return self._remove_entry(entry_id)

    def _find_artifact_locked(
        self, path_key: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        for entry_id, entry in self._entries.items():
            if entry.get("kind") != "artifact":
                continue
            for field in ("path", "pending_path"):
                value = entry.get(field)
                if isinstance(value, str) and _canonical(value) == path_key:
                    return entry_id, entry
        return None

    def register_session(
        self, path: str, token: str, pid: int
    ) -> Optional[str]:
        absolute = os.path.abspath(path)
        identity = _identity(absolute)
        if identity is None or not identity.get("is_dir"):
            return None
        entry_id = uuid.uuid4().hex
        with self._lock:
            try:
                marker_path, marker_token = self._create_marker_locked(
                    entry_id, absolute, "session"
                )
            except OSError as exc:
                self.last_error = str(exc)
                return None
        entry = {
            "kind": "session",
            "created_ns": time.time_ns(),
            "path": absolute,
            "pid": int(pid),
            "process_token": _PROCESS_INSTANCE_TOKEN,
            "token": str(token),
            "identity": identity,
            "marker_path": marker_path,
            "marker_token": marker_token,
            "marker_target": absolute,
        }
        return self._add_entry(entry_id, entry)

    def unregister_session(self, path: str) -> bool:
        path_key = _canonical(path)
        with self._lock:
            for entry_id, entry in self._entries.items():
                if (
                    entry.get("kind") == "session"
                    and isinstance(entry.get("path"), str)
                    and _canonical(entry["path"]) == path_key
                ):
                    break
            else:
                return True
        return self._remove_entry(entry_id)

    def register_source_stage(
        self,
        task_id: str,
        original_path: str,
        staged_path: str,
        staging_dir: str,
        expected_identity: Dict[str, Any],
        cleanup_policy: str,
    ) -> Optional[str]:
        staging_dir = os.path.abspath(staging_dir)
        original_path = os.path.abspath(original_path)
        staged_path = os.path.abspath(staged_path)
        staging_identity = _identity(staging_dir)
        if (
            staging_identity is None
            or not staging_identity.get("is_dir")
            or staging_identity.get("is_link")
            or staging_identity.get("is_reparse")
            or os.path.dirname(original_path) != os.path.dirname(staging_dir)
            or os.path.dirname(staged_path) != staging_dir
            or os.path.basename(staged_path) != os.path.basename(original_path)
            or not os.path.basename(staging_dir).startswith(".smart7z_cleanup_")
        ):
            self.last_error = "source-stage ownership precondition failed"
            return None
        entry_id = uuid.uuid4().hex
        with self._lock:
            try:
                marker_path, marker_token = self._create_marker_locked(
                    entry_id, staging_dir, "source_stage"
                )
            except OSError as exc:
                self.last_error = str(exc)
                return None
        entry = {
            "kind": "source_stage",
            "task_id": str(task_id),
            "created_ns": time.time_ns(),
            "original_path": original_path,
            "staged_path": staged_path,
            "staging_dir": staging_dir,
            "staging_identity": staging_identity,
            "source_identity": dict(expected_identity),
            "cleanup_policy": str(cleanup_policy),
            "marker_path": marker_path,
            "marker_token": marker_token,
            "marker_target": staging_dir,
        }
        return self._add_entry(entry_id, entry)

    def complete_source_stage(self, entry_id: Optional[str]) -> bool:
        if not entry_id:
            return True
        return self._remove_entry(entry_id)

    def source_stage_ready(self, entry_id: Optional[str]) -> bool:
        """Revalidate a cleanup intent immediately before moving its source."""

        if not entry_id:
            return False
        with self._lock:
            entry = self._entries.get(entry_id)
            if not isinstance(entry, dict) or entry.get("kind") != "source_stage":
                return False
            original = entry.get("original_path")
            staged = entry.get("staged_path")
            staging_dir = entry.get("staging_dir")
            if not all(
                isinstance(value, str) for value in (original, staged, staging_dir)
            ):
                return False
            return bool(
                self._marker_valid(entry_id, entry)
                and os.path.lexists(staging_dir)
                and not _is_link_or_reparse(staging_dir)
                and _identity_matches(
                    staging_dir, entry.get("staging_identity") or {}
                )
                and not os.path.lexists(staged)
                and _identity_matches(
                    original, entry.get("source_identity") or {}, full=True
                )
            )

    def recover(self, source_conflict_mode: str = "visible") -> List[str]:
        """Recover old owned artifacts without overwriting user data."""

        messages: List[str] = []
        if self.load_error:
            return [f"Recovery journal unavailable: {self.load_error}"]
        # Source moves first, then ordinary artifacts, and sessions last so an
        # unresolved child can keep its owning session intact.
        order = {"source_stage": 0, "artifact": 1, "session": 2}
        with self._lock:
            entries = sorted(
                list(self._entries.items()),
                key=lambda item: order.get(item[1].get("kind"), 99),
            )
        for entry_id, entry in entries:
            kind = entry.get("kind")
            try:
                if kind == "source_stage":
                    resolved, message = self._recover_source_stage(
                        entry_id, entry, source_conflict_mode
                    )
                elif kind == "artifact":
                    resolved, message = self._recover_artifact(entry_id, entry)
                elif kind == "session":
                    resolved, message = self._recover_session(entry_id, entry)
                else:
                    resolved, message = False, f"Unknown recovery entry: {entry_id}"
            except OSError as exc:
                resolved, message = False, f"Recovery deferred for {entry_id}: {exc}"
            if message:
                messages.append(message)
            if resolved:
                self._remove_entry(entry_id)
        return messages

    def _recover_artifact(
        self, entry_id: str, entry: Dict[str, Any]
    ) -> Tuple[bool, str]:
        candidates = [
            (
                entry.get("path"),
                entry.get("parent"),
                entry.get("name_prefix"),
                entry.get("identity"),
                entry,
            )
        ]
        if entry.get("pending_path"):
            pending_entry = dict(entry)
            pending_entry.update(
                {
                    "marker_path": entry.get("pending_marker_path"),
                    "marker_token": entry.get("pending_marker_token"),
                    "marker_target": entry.get("pending_path"),
                }
            )
            candidates.append(
                (
                    entry.get("pending_path"),
                    entry.get("pending_parent"),
                    entry.get("pending_name_prefix"),
                    entry.get("pending_identity"),
                    pending_entry,
                )
            )

        existing = []
        conflicts = []
        for path, parent, prefix, identity, marker_entry in candidates:
            if not isinstance(path, str) or not os.path.lexists(path):
                continue
            if (
                not isinstance(parent, str)
                or os.path.dirname(os.path.abspath(path)) != os.path.abspath(parent)
                or not isinstance(prefix, str)
                or not os.path.basename(path).startswith(prefix)
                or not self._marker_valid(entry_id, marker_entry)
                or not _identity_matches(path, identity or {})
            ):
                conflicts.append(path)
                continue
            existing.append(path)

        if conflicts:
            return False, "Owned artifact validation failed; preserved: " + ", ".join(conflicts)
        if not existing:
            return True, "Removed stale recovery record for an absent artifact"
        if entry.get("disposition") != "delete":
            return False, "Recoverable commit stage preserved: " + ", ".join(existing)
        for path in existing:
            if not _artifact_snapshot_matches(path, entry.get("delete_snapshot")):
                return False, "Owned artifact content changed; preserved: " + path
        for path in existing:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        return True, "Deleted owned temporary artifact: " + ", ".join(existing)

    def _recover_source_stage(
        self,
        entry_id: str,
        entry: Dict[str, Any],
        conflict_mode: str,
    ) -> Tuple[bool, str]:
        original = entry.get("original_path")
        staged = entry.get("staged_path")
        staging_dir = entry.get("staging_dir")
        if not all(isinstance(value, str) for value in (original, staged, staging_dir)):
            return False, f"Malformed source recovery entry: {entry_id}"
        original = os.path.abspath(original)
        staged = os.path.abspath(staged)
        staging_dir = os.path.abspath(staging_dir)
        if (
            os.path.dirname(original) != os.path.dirname(staging_dir)
            or os.path.dirname(staged) != staging_dir
            or os.path.basename(staged) != os.path.basename(original)
            or not os.path.basename(staging_dir).startswith(".smart7z_cleanup_")
            or not self._marker_valid(entry_id, entry)
        ):
            return False, f"Source recovery ownership validation failed: {staging_dir}"
        if os.path.lexists(staging_dir) and not _identity_matches(
            staging_dir, entry.get("staging_identity") or {}
        ):
            return False, f"Source recovery directory identity changed: {staging_dir}"
        if os.path.lexists(staging_dir) and _is_link_or_reparse(staging_dir):
            return False, f"Source recovery directory became a reparse point: {staging_dir}"

        staged_exists = os.path.lexists(staged)
        original_exists = os.path.lexists(original)
        if staged_exists and not _identity_matches(
            staged, entry.get("source_identity") or {}, full=True
        ):
            return False, f"Staged source identity changed; preserved: {staged}"

        if staged_exists and not original_exists:
            move_no_replace_durable(staged, original)
            if not _identity_matches(
                original, entry.get("source_identity") or {}, full=True
            ):
                return False, f"Restored source identity could not be verified: {original}"
            if not self._remove_empty_dir(staging_dir):
                return False, f"Restored source; recovery directory retained: {staging_dir}"
            return True, f"Restored source after interrupted cleanup: {original}"

        if staged_exists and original_exists:
            if conflict_mode == "visible":
                conflict_path = self._move_source_conflict(entry, staged)
                if conflict_path:
                    if not self._remove_empty_dir(staging_dir):
                        return (
                            False,
                            "Source conflict was made visible; recovery directory "
                            f"retained: {staging_dir}",
                        )
                    return True, f"Source recovery conflict retained at: {conflict_path}"
            return False, f"Source recovery conflict preserved: {staged}"

        if not self._remove_empty_dir(staging_dir):
            return False, f"Source recovery directory is not empty: {staging_dir}"
        if original_exists:
            return True, f"Source cleanup recovery record resolved: {original}"
        return True, f"Source cleanup had already completed: {original}"

    @staticmethod
    def _move_source_conflict(entry: Dict[str, Any], staged: str) -> str:
        original = os.path.abspath(entry["original_path"])
        raw_task_id = str(entry.get("task_id") or "unknown")
        task_id = "".join(
            char
            for char in raw_task_id
            if (char.isascii() and char.isalnum()) or char in "-_"
        )[:64] or "unknown"
        visible_root = os.path.join(
            os.path.dirname(original), SOURCE_CONFLICT_DIR_NAME
        )
        root = os.path.join(visible_root, task_id)
        for directory in (visible_root, root):
            if os.path.lexists(directory) and (
                not os.path.isdir(directory)
                or _is_link_or_reparse(directory)
            ):
                return ""
        os.makedirs(root, exist_ok=True)
        if any(
            _is_link_or_reparse(directory)
            for directory in (visible_root, root)
        ):
            return ""
        candidate = os.path.join(root, os.path.basename(original))
        if os.path.lexists(candidate):
            stem = Path(candidate).stem
            suffix = Path(candidate).suffix
            for index in range(2, 10000):
                alternate = os.path.join(root, f"{stem} ({index}){suffix}")
                if not os.path.lexists(alternate):
                    candidate = alternate
                    break
            else:
                return ""
        expected_identity = entry.get("source_identity") or {}
        if (
            any(
                _is_link_or_reparse(directory)
                for directory in (visible_root, root)
            )
            or not _identity_matches(staged, expected_identity, full=True)
        ):
            return ""
        move_no_replace_durable(staged, candidate)
        if not _identity_matches(candidate, expected_identity, full=True):
            try:
                if not os.path.lexists(staged):
                    move_no_replace_durable(candidate, staged)
            except OSError:
                logger.exception("Could not roll back an unverified conflict move")
            return ""
        return candidate

    def _recover_session(
        self, entry_id: str, entry: Dict[str, Any]
    ) -> Tuple[bool, str]:
        path = entry.get("path")
        token = entry.get("token")
        pid = entry.get("pid")
        if not isinstance(path, str) or not isinstance(token, str) or not isinstance(pid, int):
            return False, f"Malformed session recovery entry: {entry_id}"
        if not os.path.lexists(path):
            return True, "Removed stale recovery record for an absent session"
        if not self._marker_valid(entry_id, entry) or not _identity_matches(
            path, entry.get("identity") or {}
        ):
            return False, f"Session ownership validation failed; preserved: {path}"

        with self._lock:
            for other_id, other in self._entries.items():
                if other_id == entry_id:
                    continue
                for field in ("path", "pending_path", "staging_dir"):
                    child = other.get(field)
                    if not isinstance(child, str):
                        continue
                    try:
                        if os.path.commonpath((path, child)) == os.path.abspath(path):
                            return False, f"Session retained for unresolved recovery item: {path}"
                    except ValueError:
                        continue

        from windows_adapters import _is_pid_running, cleanup_owned_session

        same_process_instance = bool(
            pid == os.getpid()
            and entry.get("process_token") == _PROCESS_INSTANCE_TOKEN
        )
        if same_process_instance or (pid != os.getpid() and _is_pid_running(pid)):
            return False, ""
        if cleanup_owned_session(path, token, expected_pid=pid):
            return True, f"Deleted stale owned session: {path}"
        return False, f"Owned session cleanup was deferred: {path}"

    @staticmethod
    def _remove_empty_dir(path: str) -> bool:
        # Newer Windows builds remove non-empty directories on os.rmdir, so
        # verify emptiness explicitly instead of relying on rmdir failing.
        try:
            with os.scandir(path) as entries:
                if next(entries, None) is not None:
                    logger.warning("Recovery directory is not empty: %s", path)
                    return False
        except FileNotFoundError:
            return True
        except OSError:
            logger.warning("Recovery directory cannot be inspected: %s", path)
            return False
        try:
            os.rmdir(path)
        except FileNotFoundError:
            return True
        except OSError:
            logger.warning("Recovery directory could not be removed: %s", path)
            return False
        return True

    def unresolved_entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(entry) for entry in self._entries.values()]

    def protected_session_paths(self) -> List[str]:
        with self._lock:
            return [
                os.path.abspath(entry["path"])
                for entry in self._entries.values()
                if entry.get("kind") == "session"
                and isinstance(entry.get("path"), str)
            ]
