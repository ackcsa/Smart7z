"""Modern Tkinter UI for Smart7z serial runtime."""

from __future__ import annotations

import datetime
import hmac
import json
import logging
import os
import queue
import re
import secrets
import socket
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from archive_classifier import classify_automatic_candidate
from config import (
    find_sevenzip,
    get_app_dir,
    get_state_path,
    load_config,
    save_config,
)
from discovery import is_multipart_child, logical_archive_key
from models import CleanupPolicy, Job, JobState, TERMINAL_STATES
from scheduler import Scheduler
from stego_candidates import find_candidates
from steganographier_compat import find_steganographier_candidates
from user_messages import (
    CLEANUP_NOTICE_CODES,
    format_user_message,
    user_message_code,
    user_message_red_spans,
)
from windows_adapters import (
    cleanup_stale_sessions,
    close_mutex,
    create_mutex,
    is_local_filesystem_path,
    is_reparse_point,
    register_context_menu,
    unregister_context_menu,
)

logger = logging.getLogger(__name__)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False
    DND_FILES = None
    TkinterDnD = None

STATUS_DISPLAY = {
    JobState.QUEUED: "等待中",
    JobState.DISCOVERING: "发现中",
    JobState.GROUPED: "多卷组",
    JobState.STANDALONE: "单文件",
    JobState.STEGO_CANDIDATE_REVIEW: "隐写候选",
    JobState.LISTING: "列表读取",
    JobState.PASSWORD_ATTEMPT: "密码尝试",
    JobState.PASSWORD_REQUIRED: "需密码",
    JobState.PLANNED: "已计划",
    JobState.SPACE_WAIT: "空间等待",
    JobState.EXTRACTING: "解压中",
    JobState.VERIFYING: "校验中",
    JobState.COMMITTING: "提交中",
    JobState.COMPLETE: "完成",
    JobState.PARTIAL_RECOVERY: "部分恢复",
    JobState.FAILED: "失败",
    JobState.SKIPPED: "跳过",
    JobState.INTERRUPTED: "中断",
}

PROCESSING_STATES = frozenset({
    JobState.DISCOVERING, JobState.GROUPED, JobState.STANDALONE,
    JobState.LISTING, JobState.PASSWORD_ATTEMPT, JobState.PLANNED,
    JobState.SPACE_WAIT, JobState.EXTRACTING, JobState.VERIFYING,
    JobState.COMMITTING,
})

TREE_COLUMNS = (
    ("file", "文件名", 320),
    ("size", "大小", 80),
    ("state", "状态", 90),
    ("progress", "进度", 60),
    ("attempts", "尝试", 50),
    ("policy", "清理策略", 80),
    ("retention", "源包处理", 120),
)

# State sorting follows operational urgency instead of enum or display text.
STATE_SORT_RANK = {
    JobState.INTERRUPTED: 0,
    JobState.PARTIAL_RECOVERY: 1,
    JobState.FAILED: 2,
    JobState.SKIPPED: 2,
    JobState.PASSWORD_REQUIRED: 3,
    JobState.STEGO_CANDIDATE_REVIEW: 3,
    JobState.QUEUED: 4,
    JobState.COMPLETE: 6,
}
STATE_SORT_RANK.update({state: 5 for state in PROCESSING_STATES})

MAX_RECOVERY_LOG_DETAILS = 8
MAX_UI_LOG_CHARS = 1600
LOG_RED_COLOR = "#b42318"
LOG_RED_KEYWORD_TAG = "log_red_keyword"
LOG_RED_LINE_TAG = "log_red_line"

ARCHIVE_BLOCK_REASONS = frozenset({
    "manifest_limit",
    "output_file_quota",
    "summary_manifest_blocked",
    "output_byte_quota",
    "nested_output_quota",
    "no_output_capacity",
})

_RECOVERY_ROUTINE_PREFIXES = (
    "Removed stale recovery record for an absent artifact",
    "Deleted owned temporary artifact:",
    "Restored source after interrupted cleanup:",
    "Source cleanup recovery record resolved:",
    "Source cleanup had already completed:",
    "Removed stale recovery record for an absent session",
    "Deleted stale owned session:",
)

_RECOVERY_ALWAYS_SHOW_PREFIXES = (
    "Source recovery conflict retained at:",
)

ARCHIVE_EXTS = frozenset({
    ".7z", ".rar", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".cab", ".001",
})

IPC_PORT = 59777
IPC_MAX_BYTES = 256 * 1024
IPC_MAX_PATHS = 2000
IPC_VERSION = 3
IPC_STATE_MAX_BYTES = 4096
IPC_ACK_TIMEOUT_SECONDS = 5.0
INSTANCE_STARTUP_WAIT_SECONDS = 15.0
INSTANCE_STARTUP_POLL_SECONDS = 0.1
PENDING_INTAKE_LIMIT = 4096
CONTEXT_AUTO_CLOSE_GRACE_MS = 1500
SCAN_PROGRESS_MIN_INTERVAL_SECONDS = 0.08
SCAN_MODE_DEEP = "deep"
SCAN_MODE_STEGANOGRAPHIER = "steganographier"
SCAN_MODE_NORMAL = "normal"

EXTERNAL_CLEANUP_POLICIES = frozenset({
    CleanupPolicy.KEEP.value,
    CleanupPolicy.PERMANENT.value,
})

IPC_FORWARD_ACCEPTED = "accepted"
IPC_FORWARD_REJECTED = "rejected"
IPC_FORWARD_INDETERMINATE = "indeterminate"
IPC_FORWARD_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class IPCForwardResult:
    status: str
    reason: str = ""
    server_reached: bool = False

    @property
    def accepted(self) -> bool:
        return self.status == IPC_FORWARD_ACCEPTED

    @property
    def reached_existing(self) -> bool:
        return self.server_reached


@dataclass(frozen=True)
class ExternalIntakeRequest:
    paths: Tuple[str, ...]
    auto_start: bool = True
    cleanup_policy: str = CleanupPolicy.KEEP.value
    extract_to_source: bool = False
    context_menu: bool = False

    @property
    def action(self) -> str:
        return "enqueue" if self.paths else "activate"


def _ipc_state_path() -> str:
    return get_state_path(f"ipc-v{IPC_VERSION}.json")


def _read_ipc_state(path: Optional[str] = None) -> Optional[dict]:
    state_path = path or _ipc_state_path()
    try:
        with open(state_path, "rb") as stream:
            raw = stream.read(IPC_STATE_MAX_BYTES + 1)
        if len(raw) > IPC_STATE_MAX_BYTES:
            return None
        state = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(state, dict) or state.get("version") != IPC_VERSION:
        return None
    token = state.get("token")
    port = state.get("port")
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    return state


def _normalize_ipc_path(path: str) -> Optional[str]:
    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not os.path.isabs(path)
    ):
        return None
    try:
        normalized = os.path.abspath(os.path.normpath(path))
        if not is_local_filesystem_path(normalized):
            return None
        resolved = os.path.realpath(normalized)
        if not is_local_filesystem_path(resolved) or not os.path.exists(normalized):
            return None
    except (OSError, ValueError):
        return None
    return normalized


def parse_launch_args(args):
    """Return paths plus the requested start, cleanup, and destination modes.

    Plain path arguments retain the CLI-A behavior and start immediately.
    ``--queue`` opts out, while ``--start`` lets shell integrations state the
    automatic behavior explicitly.  Cleanup defaults to keeping source files;
    shell integrations may also force extraction beside each source.  The last
    flag in each mode group wins.
    """

    paths = []
    auto_start = True
    cleanup_policy = CleanupPolicy.KEEP.value
    extract_to_source = False
    context_menu = False
    parse_options = True
    for value in list(args or []):
        if parse_options and value == "--":
            parse_options = False
        elif parse_options and value == "--queue":
            auto_start = False
        elif parse_options and value == "--start":
            auto_start = True
        elif parse_options and value == "--keep-source":
            cleanup_policy = CleanupPolicy.KEEP.value
        elif parse_options and value == "--delete-source":
            cleanup_policy = CleanupPolicy.PERMANENT.value
        elif parse_options and value == "--extract-here":
            extract_to_source = True
        elif parse_options and value == "--context-menu":
            context_menu = True
        else:
            paths.append(value)
    return ExternalIntakeRequest(
        paths=tuple(paths),
        auto_start=auto_start,
        cleanup_policy=cleanup_policy,
        extract_to_source=extract_to_source,
        context_menu=context_menu,
    )


class _IPCDispatchTicket:
    """Make timeout cancellation atomic with Tk-side dispatch start."""

    def __init__(self):
        self.completed = threading.Event()
        self._lock = threading.Lock()
        self._state = "pending"
        self._accepted = False
        self._reason = "not_accepted"

    def begin(self) -> bool:
        with self._lock:
            if self._state != "pending":
                return False
            self._state = "running"
            return True

    def finish(self, accepted: bool, reason: str) -> None:
        with self._lock:
            if self._state != "running":
                return
            self._accepted = bool(accepted)
            self._reason = str(reason or "not_accepted")
            self._state = "finished"
            self.completed.set()

    def cancel_pending(self, reason: str) -> bool:
        with self._lock:
            if self._state != "pending":
                return False
            self._accepted = False
            self._reason = reason
            self._state = "cancelled"
            self.completed.set()
            return True

    def result_after_timeout(self):
        with self._lock:
            if self._state == "pending":
                self._accepted = False
                self._reason = "dispatch_timeout"
                self._state = "cancelled"
                self.completed.set()
            if self._state == "running":
                return False, "dispatch_in_progress"
            return self._accepted, self._reason

    def result(self):
        with self._lock:
            return self._accepted, self._reason


class BoundedIPCServer:
    def __init__(
        self,
        app,
        port: int = IPC_PORT,
        state_path: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.app = app
        self.port = port
        self.state_path = state_path or _ipc_state_path()
        self.token = token or secrets.token_urlsafe(32)
        self.sock = None
        self._running = False
        self._thread = None
        self._lifecycle_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._connections = set()
        self._generation = 0
        self._draining = False

    def start(self) -> bool:
        with self._lifecycle_lock:
            if self.sock is not None or (
                self._thread is not None and self._thread.is_alive()
            ):
                return False
            self._stop_event.clear()
            self._draining = False
        listener = None
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
                )
            else:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))
            self.port = int(listener.getsockname()[1])
            listener.listen(5)
            listener.settimeout(1.0)
            self._publish_state()
            with self._lifecycle_lock:
                self.sock = listener
                self._running = True
                self._generation += 1
                generation = self._generation
                self._thread = threading.Thread(
                    target=self._listen,
                    args=(listener, generation),
                    name="Smart7zIPC",
                    daemon=True,
                )
                self._thread.start()
            return True
        except OSError as e:
            logger.error("IPC bind failed: %s", e)
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            self.close()
            return False

    def _publish_state(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.state_path))
        os.makedirs(parent, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="ipc_", suffix=".tmp", dir=parent)
        try:
            payload = {
                "version": IPC_VERSION,
                "port": self.port,
                "pid": os.getpid(),
                "token": self.token,
            }
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                json.dump(payload, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
        finally:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _listen(self, listener, generation):
        while not self._stop_event.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lifecycle_lock:
                if (
                    self._stop_event.is_set()
                    or generation != self._generation
                ):
                    try:
                        conn.close()
                    except OSError:
                        pass
                    break
                self._connections.add(conn)
            try:
                with conn:
                    data = self._recv_message(conn)
                    if data is None:
                        self._send_reply(conn, False, "invalid_frame")
                        continue
                    request = self._parse_request(data)
                    if request is not None:
                        with self._lifecycle_lock:
                            dispatch_allowed = bool(
                                not self._stop_event.is_set()
                                and not self._draining
                                and generation == self._generation
                            )
                        if not dispatch_allowed:
                            self._send_reply(conn, False, "server_stopping")
                            continue
                        ticket = _IPCDispatchTicket()
                        queued = self.app._post_to_tk(
                            self._dispatch_request,
                            generation,
                            request,
                            ticket,
                        )
                        if not queued:
                            ticket.cancel_pending("server_stopping")
                            self._send_reply(conn, False, "server_stopping")
                        else:
                            if ticket.completed.wait(IPC_ACK_TIMEOUT_SECONDS):
                                accepted, reason = ticket.result()
                            else:
                                accepted, reason = ticket.result_after_timeout()
                            self._send_reply(conn, accepted, reason)
                    else:
                        self._send_reply(conn, False, "invalid_paths")
            except (OSError, RuntimeError, tk.TclError):
                logger.exception("IPC connection error")
            finally:
                with self._lifecycle_lock:
                    self._connections.discard(conn)

    def _dispatch_request(
        self,
        generation,
        request,
        ticket,
    ):
        if not ticket.begin():
            return
        accepted = False
        reason = "server_stopping"
        try:
            with self._lifecycle_lock:
                active = bool(
                    not self._stop_event.is_set()
                    and not self._draining
                    and generation == self._generation
                )
            if active:
                if request.action == "activate":
                    accepted = bool(self.app.activate_window())
                else:
                    accepted = bool(
                        self.app.process_ipc_args(
                            request.paths,
                            request.auto_start,
                            request.cleanup_policy,
                            request.extract_to_source,
                            request.context_menu,
                        )
                    )
                reason = "accepted" if accepted else "intake_full"
        except Exception:
            reason = "dispatch_error"
            disable_auto_close = getattr(
                self.app, "_disable_context_auto_close", None
            )
            if callable(disable_auto_close):
                try:
                    disable_auto_close(abnormal=True)
                except Exception:
                    logger.exception(
                        "Could not disable context-menu auto-close after dispatch failure"
                    )
            logger.exception("IPC business dispatch failed")
        finally:
            ticket.finish(accepted, reason)

    def _recv_message(self, conn):
        conn.settimeout(5.0)
        header = self._recv_exact(conn, 4)
        if header is None:
            return None
        (length,) = struct.unpack("!I", header)
        if length <= 0 or length > IPC_MAX_BYTES:
            return None
        return self._recv_exact(conn, length)

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            try:
                part = conn.recv(n - len(buf))
            except OSError:
                return None
            if not part:
                return None
            buf += part
        return buf

    @staticmethod
    def _send_reply(conn, accepted: bool, reason: str) -> None:
        payload = json.dumps(
            {"accepted": bool(accepted), "reason": reason},
            ensure_ascii=True,
        ).encode("ascii")
        try:
            conn.sendall(struct.pack("!I", len(payload)) + payload)
        except OSError:
            return

    def _parse_request(self, data):
        try:
            text = data.decode("utf-8")
            payload = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict) or payload.get("version") != IPC_VERSION:
            return None
        supplied_token = payload.get("token")
        if not isinstance(supplied_token, str) or not hmac.compare_digest(
            supplied_token, self.token
        ):
            return None
        action = payload.get("action", "enqueue")
        if action not in {"enqueue", "activate"}:
            return None
        raw_paths = payload.get("paths", [])
        auto_start = payload.get("auto_start")
        if not isinstance(auto_start, bool):
            return None
        cleanup_policy = payload.get(
            "cleanup_policy", CleanupPolicy.KEEP.value
        )
        if (
            not isinstance(cleanup_policy, str)
            or cleanup_policy not in EXTERNAL_CLEANUP_POLICIES
        ):
            return None
        extract_to_source = payload.get("extract_to_source", False)
        if not isinstance(extract_to_source, bool):
            return None
        context_menu = payload.get("context_menu", False)
        if not isinstance(context_menu, bool):
            return None

        if not isinstance(raw_paths, list) or len(raw_paths) > IPC_MAX_PATHS:
            return None
        if action == "enqueue" and not raw_paths:
            return None
        if action == "activate" and raw_paths:
            return None
        if action == "activate" and context_menu:
            return None
        paths = []
        for item in raw_paths:
            normalized = _normalize_ipc_path(item)
            if normalized is None:
                return None
            paths.append(normalized)
        return ExternalIntakeRequest(
            paths=tuple(paths),
            auto_start=auto_start,
            cleanup_policy=cleanup_policy,
            extract_to_source=extract_to_source,
            context_menu=context_menu,
        )

    def close(self) -> bool:
        with self._lifecycle_lock:
            self._running = False
            self._draining = True
            self._stop_event.set()
            listener = self.sock
            self.sock = None
            connections = list(self._connections)
            thread = self._thread
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if (
            thread is not None
            and thread is not threading.current_thread()
            and thread.is_alive()
        ):
            thread.join(timeout=1.5)
        fully_stopped = bool(thread is None or not thread.is_alive())
        if fully_stopped:
            with self._lifecycle_lock:
                if self._thread is thread:
                    self._thread = None
                self._connections.clear()
        state = _read_ipc_state(self.state_path)
        if state is not None and hmac.compare_digest(state["token"], self.token):
            try:
                os.unlink(self.state_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("Could not remove IPC state file: %s", self.state_path)
        return fully_stopped

    def begin_draining(self) -> None:
        """Reject new dispatch while retaining the bound singleton port."""

        with self._lifecycle_lock:
            self._draining = True
            self._running = False
            connections = list(self._connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass


def forward_to_existing(
    args,
    port=None,
    auto_start=True,
    cleanup_policy=CleanupPolicy.KEEP.value,
    extract_to_source=False,
    context_menu=False,
    token=None,
    state_path: Optional[str] = None,
) -> IPCForwardResult:
    if not isinstance(auto_start, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_auto_start")
    if (
        not isinstance(cleanup_policy, str)
        or cleanup_policy not in EXTERNAL_CLEANUP_POLICIES
    ):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_cleanup_policy")
    if not isinstance(extract_to_source, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_destination_mode")
    if not isinstance(context_menu, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_context_menu")
    normalized = []
    for value in args:
        if not isinstance(value, str) or not value or "\x00" in value:
            return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_paths")
        path = _normalize_ipc_path(os.path.abspath(value))
        if path is None:
            return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_paths")
        normalized.append(path)
        if len(normalized) > IPC_MAX_PATHS:
            return IPCForwardResult(IPC_FORWARD_REJECTED, "too_many_paths")
    if context_menu and not normalized:
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_context_menu")
    if token is None:
        state = _read_ipc_state(state_path)
        if state is None:
            return IPCForwardResult(IPC_FORWARD_UNAVAILABLE, "state_unavailable")
        token = state["token"]
        if port is None:
            port = state["port"]
    if port is None:
        port = IPC_PORT
    dispatch_attempted = False
    try:
        request = {
            "version": IPC_VERSION,
            "token": token,
            "action": "enqueue" if normalized else "activate",
            "paths": normalized,
            "auto_start": auto_start,
            "cleanup_policy": cleanup_policy,
            "extract_to_source": extract_to_source,
            "context_menu": context_menu,
        }
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
        if len(payload) > IPC_MAX_BYTES:
            return IPCForwardResult(IPC_FORWARD_REJECTED, "request_too_large")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            s.settimeout(IPC_ACK_TIMEOUT_SECONDS + 1.0)
            dispatch_attempted = True
            s.sendall(struct.pack("!I", len(payload)) + payload)
            s.shutdown(socket.SHUT_WR)
            header = BoundedIPCServer._recv_exact(s, 4)
            if header is None:
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "reply_header_unavailable",
                    server_reached=True,
                )
            (reply_length,) = struct.unpack("!I", header)
            if reply_length <= 0 or reply_length > 4096:
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "invalid_reply",
                    server_reached=True,
                )
            reply = BoundedIPCServer._recv_exact(s, reply_length)
            if reply is None:
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "reply_body_unavailable",
                    server_reached=True,
                )
            try:
                response = json.loads(reply.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "invalid_reply",
                    server_reached=True,
                )
            if not isinstance(response, dict):
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "invalid_reply",
                    server_reached=True,
                )
            reason = str(response.get("reason") or "not_accepted")
            if response.get("accepted") is True:
                return IPCForwardResult(
                    IPC_FORWARD_ACCEPTED, reason, server_reached=True
                )
            if reason == "dispatch_in_progress":
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE, reason, server_reached=True
                )
            return IPCForwardResult(
                IPC_FORWARD_REJECTED, reason, server_reached=True
            )
    except socket.timeout:
        status = (
            IPC_FORWARD_INDETERMINATE
            if dispatch_attempted
            else IPC_FORWARD_UNAVAILABLE
        )
        return IPCForwardResult(
            status, "socket_timeout", server_reached=dispatch_attempted
        )
    except (
        ConnectionRefusedError,
        OSError,
    ):
        status = (
            IPC_FORWARD_INDETERMINATE
            if dispatch_attempted
            else IPC_FORWARD_UNAVAILABLE
        )
        return IPCForwardResult(
            status,
            "connection_lost" if dispatch_attempted else "connection_unavailable",
            server_reached=dispatch_attempted,
        )


def try_forward_to_existing(
    args,
    port=None,
    auto_start=True,
    cleanup_policy=CleanupPolicy.KEEP.value,
    extract_to_source=False,
    context_menu=False,
    token=None,
    state_path: Optional[str] = None,
) -> bool:
    """Compatibility wrapper for callers that only need accepted/not accepted."""

    return forward_to_existing(
        args,
        port=port,
        auto_start=auto_start,
        cleanup_policy=cleanup_policy,
        extract_to_source=extract_to_source,
        context_menu=context_menu,
        token=token,
        state_path=state_path,
    ).accepted


class Smart7zAppModern:
    def __init__(
        self,
        root,
        startup_args=None,
        startup_auto_start=True,
        startup_cleanup_policy=CleanupPolicy.KEEP.value,
        startup_extract_to_source=False,
        startup_context_menu=False,
    ):
        self.root = root
        self.root.title("Smart 7z Ultra - 智能解压缩")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
        self.config = load_config()
        self.config["_app_dir"] = get_app_dir()
        self.scheduler = None
        self.startup_blocked = False
        self.jobs = {}
        self.job_tree_ids = {}
        self._job_sequence = {}
        self._next_job_sequence = 0
        self.seen_paths = set()
        self.log_lines = 0
        self.max_log_lines = 500
        self.ipc_server = None
        self.current_pwd_job = None
        self.pending_pwd_jobs = []
        self.current_stego_job = None
        self.pending_stego_jobs = []
        self._clear_after_terminal = set()
        self._suppressed_job_ids = set()
        self._scan_thread = None
        self._scan_threads = set()
        self._scan_cancel = threading.Event()
        self._scan_generation = 0
        self._scan_progress_generation = -1
        self._scan_autostart_generations = set()
        self._pending_intake = []
        self._pending_intake_keys = set()
        self._closing = False
        self._shutdown_thread = None
        self._shutdown_done = threading.Event()
        self._shutdown_started = 0.0
        self._shutdown_extended = False
        self._tk_queue = queue.SimpleQueue()
        self._tk_thread_id = threading.get_ident()
        self.startup_args = list(startup_args or [])
        self.startup_auto_start = bool(startup_auto_start)
        self.startup_cleanup_policy = (
            startup_cleanup_policy
            if isinstance(startup_cleanup_policy, str)
            and startup_cleanup_policy in EXTERNAL_CLEANUP_POLICIES
            else CleanupPolicy.KEEP.value
        )
        self.startup_extract_to_source = bool(startup_extract_to_source)
        self.startup_context_menu = bool(startup_context_menu)
        self._context_auto_close_armed = bool(
            self.startup_context_menu and self.startup_args
        )
        self._context_auto_close_abnormal = False
        self._context_auto_close_generation = 0
        self._setup_variables()
        self._setup_ui()
        self._setup_menu()
        self._setup_scheduler()
        self._setup_dnd()
        self.root.after(25, self._drain_tk_queue)
        self.root.after(100, self._process_cli_args)
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        protected_sessions = (
            self.scheduler.recovery_journal.protected_session_paths()
            if self.scheduler is not None
            else []
        )
        threading.Thread(
            target=cleanup_stale_sessions,
            args=(
                (self.config.get("temp_dir") or tempfile.gettempdir()),
                protected_sessions,
            ),
            daemon=True,
        ).start()
        self.log_event("APP_READY")

    def _setup_variables(self):
        self.var_extract_to_source = tk.BooleanVar(value=self.config.get("extract_to_source", True))
        self.var_wait_space = tk.BooleanVar(value=self.config.get("wait_disk_space", True))
        self.var_staging_mode = tk.BooleanVar(value=(self.config.get("extract_mode", "staging") == "staging"))
        deep_scan = bool(self.config.get("deep_scan", False))
        steganographier_compat = bool(
            self.config.get("steganographier_compat_mode", True)
        ) and not deep_scan
        scan_mode = (
            SCAN_MODE_DEEP
            if deep_scan
            else (
                SCAN_MODE_STEGANOGRAPHIER
                if steganographier_compat
                else SCAN_MODE_NORMAL
            )
        )
        self.var_deep_scan = tk.BooleanVar(value=deep_scan)
        self.var_steganographier_compat = tk.BooleanVar(
            value=steganographier_compat
        )
        self.var_scan_deep_mode = tk.BooleanVar(
            value=scan_mode == SCAN_MODE_DEEP
        )
        self.var_scan_steganographier_mode = tk.BooleanVar(
            value=scan_mode == SCAN_MODE_STEGANOGRAPHIER
        )
        self.var_scan_normal_mode = tk.BooleanVar(
            value=scan_mode == SCAN_MODE_NORMAL
        )
        self.var_nested = tk.BooleanVar(value=self.config.get("nested_extraction", False))
        self.var_cleanup_policy = tk.StringVar(value=self.config.get("cleanup_policy", "keep"))

    def _setup_ui(self):
        self._setup_toolbar()
        self._setup_path_row()
        self._setup_queue_actions()
        self._setup_prompt_area()
        self._setup_work_area()

    def _setup_work_area(self):
        self.work_pane = tk.PanedWindow(
            self.root,
            orient=tk.VERTICAL,
            sashrelief=tk.RAISED,
            sashwidth=6,
            showhandle=True,
            opaqueresize=True,
        )
        self.work_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.queue_panel = tk.Frame(self.work_pane)
        self._setup_job_table(self.queue_panel)
        self._setup_progress(self.queue_panel)
        self._setup_details_panel(self.work_pane)
        self._setup_log()

        self.work_pane.add(
            self.queue_panel,
            minsize=140,
            stretch="always",
        )
        self.work_pane.add(
            self.inspector_tabs,
            minsize=80,
            stretch="never",
        )

    def _setup_toolbar(self):
        self.toolbar_area = tk.Frame(self.root)
        self.toolbar_area.pack(fill=tk.X)

        self.primary_toolbar = tk.Frame(self.toolbar_area)
        self.primary_toolbar.pack(fill=tk.X, padx=5, pady=(5, 2))
        self.btn_add_files = tk.Button(
            self.primary_toolbar,
            text="添加文件",
            width=12,
            command=self._add_files,
        )
        self.btn_add_files.pack(side=tk.LEFT)
        self.btn_scan_folder = tk.Button(
            self.primary_toolbar,
            text="扫描文件夹",
            width=12,
            command=self._scan_folder,
        )
        self.btn_scan_folder.pack(side=tk.LEFT, padx=5)
        self.btn_start = tk.Button(
            self.primary_toolbar,
            text="开始",
            width=20,
            font=("Microsoft YaHei UI", 10, "bold"),
            command=self._start_processing,
        )
        self.btn_start.pack(side=tk.LEFT)

        self.extract_options_frame = tk.Frame(
            self.toolbar_area,
        )
        self.extract_options_frame.pack(fill=tk.X, padx=5, pady=(0, 4))
        self.extract_option_controls = []
        for label, variable, command in (
            ("解压到原目录", self.var_extract_to_source, None),
            ("暂存模式", self.var_staging_mode, None),
            ("嵌套解压", self.var_nested, None),
        ):
            control = tk.Checkbutton(
                self.extract_options_frame,
                text=label,
                variable=variable,
                command=command,
            )
            control.pack(side=tk.LEFT)
            self.extract_option_controls.append(control)

        tk.Label(self.extract_options_frame, text="清理:").pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self.cleanup_policy_controls = []
        for label, value in (("保留", "keep"), ("回收站", "recycle"), ("永久删除", "permanent")):
            control = tk.Radiobutton(
                self.extract_options_frame,
                text=label,
                variable=self.var_cleanup_policy,
                value=value,
                command=self._on_cleanup_policy_change,
            )
            control.pack(side=tk.LEFT)
            self.cleanup_policy_controls.append(control)

    def _setup_path_row(self):
        frame = tk.LabelFrame(self.root, text="路径与密码", padx=5, pady=5)
        frame.pack(fill=tk.X, padx=5, pady=2)
        row1 = tk.Frame(frame)
        row1.pack(fill=tk.X)
        tk.Label(row1, text="目标目录:").pack(side=tk.LEFT)
        self.entry_target = tk.Entry(row1)
        self.entry_target.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry_target.insert(0, self.config.get("target_dir", ""))
        tk.Button(row1, text="浏览", command=self._sel_target).pack(side=tk.LEFT)
        row2 = tk.Frame(frame)
        row2.pack(fill=tk.X, pady=2)
        tk.Label(row2, text="暂存目录:").pack(side=tk.LEFT)
        self.entry_temp = tk.Entry(row2)
        self.entry_temp.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry_temp.insert(0, self.config.get("temp_dir", r"C:\Temp_Smart7z"))
        tk.Button(row2, text="浏览", command=self._sel_temp).pack(side=tk.LEFT)
        row3 = tk.Frame(frame)
        row3.pack(fill=tk.X)
        tk.Label(row3, text="密码文件:").pack(side=tk.LEFT)
        self.entry_pwd = tk.Entry(row3)
        self.entry_pwd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry_pwd.insert(0, self.config.get("password_file", "code.txt"))
        tk.Button(row3, text="浏览", command=self._sel_pwd).pack(side=tk.LEFT)
        tk.Label(row3, text="主密码:").pack(side=tk.LEFT, padx=(8, 0))
        self.entry_main_pwd = tk.Entry(row3, width=18)
        self.entry_main_pwd.pack(side=tk.LEFT, padx=4)
        tk.Label(row3, text="嵌套深度:").pack(side=tk.LEFT, padx=(8, 0))
        self.spin_nested_depth = tk.Spinbox(row3, from_=0, to=20, width=4)
        self.spin_nested_depth.pack(side=tk.LEFT)
        self.spin_nested_depth.delete(0, tk.END)
        self.spin_nested_depth.insert(0, str(self.config.get("max_nested_depth", 2)))

    def _setup_queue_actions(self):
        self.queue_actions_frame = tk.Frame(self.root)
        self.queue_actions_frame.pack(fill=tk.X, padx=5, pady=(2, 0))
        self.pending_intake_label = tk.Label(
            self.queue_actions_frame,
            text="待接纳: 0",
            width=12,
            anchor=tk.W,
        )
        self.pending_intake_label.pack(side=tk.LEFT)
        self.btn_cancel_current = tk.Button(
            self.queue_actions_frame,
            text="取消当前",
            width=10,
            command=self._cancel_current,
        )
        self.btn_cancel_current.pack(side=tk.LEFT)
        self.btn_cancel_all = tk.Button(
            self.queue_actions_frame,
            text="取消所有",
            width=10,
            command=self._cancel_remaining,
        )
        self.btn_cancel_all.pack(side=tk.LEFT, padx=5)
        self.btn_clear_selected = tk.Button(
            self.queue_actions_frame,
            text="清除所选",
            width=10,
            command=self._clear_selected,
        )
        self.btn_clear_selected.pack(side=tk.LEFT)
        self.btn_clear_finished = tk.Button(
            self.queue_actions_frame,
            text="清除已完成",
            width=10,
            command=self._clear_finished,
        )
        self.btn_clear_finished.pack(side=tk.LEFT, padx=5)

    def _setup_prompt_area(self):
        # The host is packed only while a password or candidate prompt exists.
        self.prompt_host = tk.Frame(self.root)
        self._setup_password_prompt()
        self._setup_stego_prompt()

    def _setup_job_table(self, parent):
        frame = tk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        cols = tuple(column for column, _text, _width in TREE_COLUMNS)
        self.tree = ttk.Treeview(
            frame,
            columns=cols,
            show="headings",
            selectmode="extended",
            height=5,
        )
        self._sort_column = "size"
        self._sort_descending = False
        for col, text, width in TREE_COLUMNS:
            self.tree.heading(
                col,
                text=text,
                command=lambda selected=col: self._sort_tree(selected),
            )
            self.tree.column(col, width=width)
        scr = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scr.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_job)
        self._update_tree_headings()

    def _setup_progress(self, parent):
        self.scan_progress_frame = tk.Frame(parent)
        self.scan_progress_label = tk.Label(
            self.scan_progress_frame,
            text="扫描文件",
            width=34,
            anchor=tk.W,
        )
        self.scan_progress_label.pack(side=tk.LEFT)
        self.scan_progress = ttk.Progressbar(
            self.scan_progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            maximum=100,
        )
        self.scan_progress.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=(5, 0),
        )
        self.scan_progress_frame.pack_forget()

        self.progress_frame = tk.Frame(parent)
        self.progress_frame.pack(fill=tk.X, pady=(2, 0))
        tk.Label(self.progress_frame, text="当前").pack(side=tk.LEFT)
        self.file_progress = ttk.Progressbar(
            self.progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
        )
        self.file_progress.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=(5, 12),
        )
        tk.Label(self.progress_frame, text="总计").pack(side=tk.LEFT)
        self.total_progress = ttk.Progressbar(
            self.progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
        )
        self.total_progress.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=(5, 0),
        )

    def _setup_password_prompt(self):
        self.pwd_frame = tk.LabelFrame(self.prompt_host, text="密码输入")
        self.pwd_label = tk.Label(
            self.pwd_frame,
            text="需要密码:",
            anchor="w",
        )
        self.pwd_label.pack(fill=tk.X, padx=5, pady=(2, 0))
        self.pwd_input_row = tk.Frame(self.pwd_frame)
        self.pwd_input_row.pack(fill=tk.X, padx=5, pady=(2, 5))
        self.pwd_entry = tk.Entry(self.pwd_input_row)
        self.pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.btn_submit_password = tk.Button(
            self.pwd_input_row,
            text="确定",
            command=self._submit_password,
        )
        self.btn_submit_password.pack(side=tk.LEFT, padx=(0, 5))
        self.btn_skip_password = tk.Button(
            self.pwd_input_row,
            text="跳过",
            command=self._skip_password,
        )
        self.btn_skip_password.pack(side=tk.LEFT)
        self.pwd_frame.pack_forget()

    def _setup_stego_prompt(self):
        self.stego_frame = tk.LabelFrame(self.prompt_host, text="隐写候选选择")
        self.stego_label = tk.Label(self.stego_frame, text="选择候选:")
        self.stego_label.pack(side=tk.LEFT, padx=5)
        self.stego_list = tk.Listbox(self.stego_frame, height=4, width=70)
        self.stego_list.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(self.stego_frame, text="使用所选", command=self._submit_stego).pack(side=tk.LEFT, padx=5)
        tk.Button(self.stego_frame, text="跳过", command=self._skip_stego).pack(side=tk.LEFT, padx=5)
        self.stego_frame.pack_forget()

    def _setup_details_panel(self, parent):
        self.inspector_tabs = ttk.Notebook(parent)
        self.details_frame = tk.Frame(self.inspector_tabs)
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            height=3,
            state="disabled",
            font=("Consolas", 9),
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.inspector_tabs.add(self.details_frame, text="任务详情")

    def _setup_log(self):
        self.log_frame = tk.Frame(self.inspector_tabs)
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            height=3,
            state="disabled",
            font=("Consolas", 9),
        )
        self.log_text.tag_configure(
            LOG_RED_KEYWORD_TAG,
            foreground=LOG_RED_COLOR,
            font=("Consolas", 9, "bold"),
        )
        self.log_text.tag_configure(
            LOG_RED_LINE_TAG,
            foreground=LOG_RED_COLOR,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.inspector_tabs.add(self.log_frame, text="运行日志")

    def _setup_menu(self):
        self.menubar = tk.Menu(self.root)
        self.context_menu_menu = tk.Menu(self.menubar, tearoff=0)
        self.context_menu_menu.add_command(
            label="添加右键菜单", command=self._register_menu
        )
        self.context_menu_menu.add_command(
            label="删除右键菜单", command=self._unregister_menu
        )
        self.menubar.add_cascade(
            label="右键菜单", menu=self.context_menu_menu
        )

        self.file_scan_mode_menu = tk.Menu(self.menubar, tearoff=0)
        for label, mode, variable in (
            (
                "深度扫描模式（全文件读取）",
                SCAN_MODE_DEEP,
                self.var_scan_deep_mode,
            ),
            (
                "仅兼容隐写者模式（非全读取）",
                SCAN_MODE_STEGANOGRAPHIER,
                self.var_scan_steganographier_mode,
            ),
            (
                "普通模式",
                SCAN_MODE_NORMAL,
                self.var_scan_normal_mode,
            ),
        ):
            self.file_scan_mode_menu.add_checkbutton(
                label=label,
                variable=variable,
                command=lambda selected=mode: self._select_scan_mode(selected),
            )
        self.menubar.add_cascade(
            label="文件扫描模式",
            menu=self.file_scan_mode_menu,
        )

        self.options_menu = tk.Menu(self.menubar, tearoff=0)
        self.options_menu.add_checkbutton(
            label="空间不足时等待",
            variable=self.var_wait_space,
        )
        self.menubar.add_cascade(
            label="选项",
            menu=self.options_menu,
        )
        self.root.config(menu=self.menubar)

    @staticmethod
    def _scan_mode_from_config(config):
        if bool(config.get("deep_scan", False)):
            return SCAN_MODE_DEEP
        if bool(config.get("steganographier_compat_mode", True)):
            return SCAN_MODE_STEGANOGRAPHIER
        return SCAN_MODE_NORMAL

    def _selected_scan_mode(self):
        if self.var_scan_deep_mode.get():
            return SCAN_MODE_DEEP
        if self.var_scan_steganographier_mode.get():
            return SCAN_MODE_STEGANOGRAPHIER
        return SCAN_MODE_NORMAL

    def _select_scan_mode(self, mode):
        if mode not in {
            SCAN_MODE_DEEP,
            SCAN_MODE_STEGANOGRAPHIER,
            SCAN_MODE_NORMAL,
        }:
            mode = SCAN_MODE_NORMAL
        self.var_scan_deep_mode.set(mode == SCAN_MODE_DEEP)
        self.var_scan_steganographier_mode.set(
            mode == SCAN_MODE_STEGANOGRAPHIER
        )
        self.var_scan_normal_mode.set(mode == SCAN_MODE_NORMAL)
        self.var_deep_scan.set(mode == SCAN_MODE_DEEP)
        self.var_steganographier_compat.set(
            mode == SCAN_MODE_STEGANOGRAPHIER
        )

    def _on_steganographier_compat_change(self):
        if self.var_steganographier_compat.get():
            self._select_scan_mode(SCAN_MODE_STEGANOGRAPHIER)
        else:
            self._select_scan_mode(SCAN_MODE_NORMAL)

    def _on_deep_scan_change(self):
        if self.var_deep_scan.get():
            self._select_scan_mode(SCAN_MODE_DEEP)
        else:
            self._select_scan_mode(SCAN_MODE_NORMAL)

    def _setup_dnd(self):
        if not DND_AVAILABLE:
            return
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self._on_drop)
        except (AttributeError, RuntimeError, tk.TclError):
            logger.exception("DnD setup failed")

    def _setup_scheduler(self):
        sz_path = find_sevenzip(self.config)
        if not sz_path:
            messagebox.showerror("配置错误", "找不到 7z.exe。请安装 7-Zip 或将 7z.exe 放在程序目录后重启。")
            self.startup_blocked = True
            return
        else:
            self.config["7z_path"] = sz_path
        try:
            self.scheduler = Scheduler(
                sz_path, self.config, event_cb=self._on_scheduler_event
            )
            self.scheduler.start()
            self._log_recovery_messages(self.scheduler.recovery_messages)
        except OSError as exc:
            self.scheduler = None
            self.startup_blocked = True
            messagebox.showerror("临时目录错误", str(exc))

    def _log_recovery_messages(self, messages) -> None:
        routine_count = 0
        always_show = []
        review_messages = []
        for raw_message in messages:
            message = str(raw_message).strip()
            if not message:
                continue
            if message.startswith(_RECOVERY_ROUTINE_PREFIXES):
                routine_count += 1
            elif message.startswith(_RECOVERY_ALWAYS_SHOW_PREFIXES):
                always_show.append(message)
            else:
                review_messages.append(message)

        if always_show or review_messages:
            self._disable_context_auto_close(abnormal=True)

        if routine_count:
            self.log_event("RECOVERY_AUTO_RESOLVED", count=routine_count)

        for message in always_show + review_messages:
            logger.warning("Startup recovery needs review: %s", message)
        for message in always_show + review_messages[:MAX_RECOVERY_LOG_DETAILS]:
            self.log_event("RECOVERY_REVIEW", detail=message)

        omitted = len(review_messages) - MAX_RECOVERY_LOG_DETAILS
        if omitted > 0:
            journal_path = ""
            if self.scheduler is not None:
                journal = getattr(self.scheduler, "recovery_journal", None)
                journal_path = str(getattr(journal, "path", "") or "")
            self.log_event(
                "RECOVERY_MORE",
                count=omitted,
                detail=journal_path,
            )

    def _on_scheduler_event(self, event_type, job, *args, **kwargs):
        self._post_to_tk(
            self._handle_event, event_type, job, *args, **kwargs
        )

    def _post_to_tk(self, callback, *args) -> bool:
        """Queue a callback only while the Tk lifetime is still active."""

        if self._closing:
            return False
        self._tk_queue.put((callback, args))
        return True

    def _drain_tk_queue(self) -> None:
        if self._closing:
            return
        for _index in range(200):
            try:
                callback, args = self._tk_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args)
            except Exception:
                self._disable_context_auto_close(abnormal=True)
                logger.exception("Tk callback failed")
        try:
            self.root.after(25, self._drain_tk_queue)
        except (RuntimeError, tk.TclError):
            return

    def _handle_event(self, event_type, job, *args, **kwargs):
        if event_type in {
            "intake_full",
            "user_notice",
            "password_required",
            "stego_review_required",
            "job_partial",
            "job_failed",
            "job_interrupted",
            "job_skipped",
            "job_duplicate",
        }:
            self._disable_context_auto_close(abnormal=True)
        elif event_type == "state_change":
            state = args[0] if args else job.state
            if state in {
                JobState.PARTIAL_RECOVERY,
                JobState.FAILED,
                JobState.SKIPPED,
                JobState.INTERRUPTED,
                JobState.PASSWORD_REQUIRED,
                JobState.STEGO_CANDIDATE_REVIEW,
            }:
                self._disable_context_auto_close(abnormal=True)
        if job.task_id in self._suppressed_job_ids:
            if event_type in (
                "job_complete", "job_partial", "job_failed",
                "job_interrupted", "job_skipped",
            ):
                self._suppressed_job_ids.discard(job.task_id)
                self._clear_after_terminal.discard(job.task_id)
            return
        if event_type == "job_submitted":
            self._add_job_to_tree(job)
        elif event_type == "job_deferred":
            self._update_pending_intake_display()
        elif event_type == "intake_full":
            self.log_event(
                "INTAKE_FULL",
                context=Path(job.display_path).name,
            )
        elif event_type == "job_resubmitted":
            self._update_job_in_tree(job)
        elif event_type == "job_duplicate":
            pass
        elif event_type == "user_notice":
            message = args[0] if args else ""
            self._update_job_in_tree(job)
            self._update_details(job)
            if message:
                context = Path(job.display_path).name
                if user_message_code(message) in CLEANUP_NOTICE_CODES:
                    self._append_log_line(f"{context}: {message}")
                else:
                    self.log_event(
                        "USER_NOTICE",
                        context=context,
                        detail=message,
                    )
        elif event_type == "state_change":
            state = args[0] if args else job.state
            progress = args[2] if len(args) > 2 else -1
            if progress is not None and progress >= 0:
                job.progress = progress
                self.file_progress["value"] = progress
            self._update_job_in_tree(job)
            context = Path(job.display_path).name
            if state == JobState.FAILED:
                if (
                    job.source_retention_reason in ARCHIVE_BLOCK_REASONS
                    or job.source_retention_reason.startswith("unsafe_")
                ):
                    self.log_event(
                        "ARCHIVE_BLOCKED",
                        context=context,
                        detail=job.error_message,
                    )
                else:
                    category = getattr(job.error_category, "name", None)
                    self.log_event(
                        "JOB_FAILED",
                        context=context,
                        category=category or "UNCLASSIFIED",
                    )
            elif state == JobState.PARTIAL_RECOVERY:
                self.log_event("JOB_PARTIAL_RECOVERY", context=context)
            elif state == JobState.INTERRUPTED:
                self.log_event("JOB_INTERRUPTED", context=context)
            elif state == JobState.PASSWORD_REQUIRED:
                self.log_event("JOB_PASSWORD_REQUIRED", context=context)
        elif event_type == "password_required":
            self._show_password_prompt(job)
            self._update_job_in_tree(job)
        elif event_type == "stego_review_required":
            self._show_stego_prompt(job)
            self._update_job_in_tree(job)
        elif event_type == "password_promoted":
            self.log_event("PASSWORD_PROMOTED")
        elif event_type in (
            "job_complete", "job_partial", "job_failed", "job_interrupted",
            "job_skipped",
        ):
            self._dismiss_prompts_for_job(job)
            self._update_job_in_tree(job)
            self._update_details(job)
            self._update_total_progress()
            if event_type == "job_complete":
                self.file_progress["value"] = 100
                self._schedule_context_auto_close_check()
            if job.task_id in self._clear_after_terminal:
                removed = [job.task_id]
                if self.scheduler:
                    removed = self.scheduler.clear_finished({job.task_id})
                if removed:
                    self._remove_jobs_from_ui(set(removed))
                    self._clear_after_terminal.discard(job.task_id)
                elif not self._closing:
                    self.root.after(50, self._retry_clear_job, job.task_id)

    def _add_job_to_tree(self, job):
        self.jobs[job.task_id] = job
        if job.task_id not in self._job_sequence:
            self._job_sequence[job.task_id] = self._next_job_sequence
            self._next_job_sequence += 1
        if job.task_id in self.job_tree_ids:
            self._update_job_in_tree(job)
            return
        item = self.tree.insert("", tk.END, values=(
            Path(job.display_path).name, self._format_size(job),
            STATUS_DISPLAY.get(job.state, job.state.value), f"{job.progress}%",
            job.attempt_count, self._cleanup_policy_display(job),
            job.source_retention_reason or "-",
        ))
        self.job_tree_ids[job.task_id] = item
        self._apply_tree_sort()

    def _update_job_in_tree(self, job):
        if job.task_id not in self.job_tree_ids:
            self._add_job_to_tree(job)
            return
        item = self.job_tree_ids[job.task_id]
        self.tree.item(item, values=(
            Path(job.display_path).name, self._format_size(job),
            STATUS_DISPLAY.get(job.state, job.state.value), f"{job.progress}%",
            job.attempt_count,
            self._cleanup_policy_display(job),
            job.source_retention_reason or ("可清理" if job.cleanup_eligible else "-"),
        ))
        self._apply_tree_sort()

    def _sort_tree(self, column):
        if column not in {name for name, _text, _width in TREE_COLUMNS}:
            return
        if self._sort_column == column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = column
            self._sort_descending = False
        self._update_tree_headings()
        self._apply_tree_sort()

    def _update_tree_headings(self):
        for column, label, _width in TREE_COLUMNS:
            suffix = ""
            if column == self._sort_column:
                suffix = " ▼" if self._sort_descending else " ▲"
            self.tree.heading(
                column,
                text=label + suffix,
                command=lambda selected=column: self._sort_tree(selected),
            )

    def _apply_tree_sort(self):
        if not self._sort_column:
            return
        rows = [
            (task_id, item)
            for task_id, item in self.job_tree_ids.items()
            if task_id in self.jobs
        ]
        if self._sort_column == "state" and self._sort_descending:
            rows.sort(
                key=lambda pair: (
                    -self._tree_sort_key("state", self.jobs[pair[0]])[0],
                    self._job_sequence.get(pair[0], 0),
                )
            )
        else:
            rows.sort(
                key=lambda pair: self._tree_sort_key(
                    self._sort_column, self.jobs[pair[0]]
                ),
                reverse=self._sort_descending,
            )
        for index, (_task_id, item) in enumerate(rows):
            try:
                self.tree.move(item, "", index)
            except tk.TclError:
                continue

    def _tree_sort_key(self, column, job):
        sequence = self._job_sequence.get(job.task_id, 0)
        if column == "file":
            value = Path(job.display_path).name.casefold()
        elif column == "size":
            value = self._job_size_bytes(job)
        elif column == "state":
            value = STATE_SORT_RANK.get(job.state, 5)
        elif column == "progress":
            value = int(job.progress)
        elif column == "attempts":
            value = int(job.attempt_count)
        elif column == "policy":
            value = self._cleanup_policy_display(job).casefold()
        else:
            value = (
                job.source_retention_reason
                or ("可清理" if job.cleanup_eligible else "-")
            ).casefold()
        return value, sequence

    def _update_details(self, job):
        lines = [
            f"任务: {job.display_path}",
            f"状态: {STATUS_DISPLAY.get(job.state, job.state.value)}",
            f"ID: {job.task_id}",
            f"入队清理策略: {self._cleanup_policy_display(job)}",
        ]
        if job.extract_to_source_override:
            lines.append("输出位置: 源文件所在目录（外部请求指定）")
        if job.manifest:
            lines += [f"格式: {job.manifest.format}", f"条目: {len(job.manifest.members)}", f"加密: {job.manifest.is_encrypted}"]
        if job.extraction_result:
            lines.append(f"7z返回码: {job.extraction_result.return_code}")
        if job.verification_result:
            vr = job.verification_result
            lines.append(f"验证: expected={vr.expected_count}, actual={vr.actual_count}")
            if vr.missing:
                lines.append(f"缺失: {vr.missing[:20]}")
        if job.archive_set:
            lines.append(f"分卷: {len(job.archive_set.volumes)} 卷, 完整={job.archive_set.is_complete}")
            if job.archive_set.missing_indexes:
                lines.append(f"缺失卷索引: {job.archive_set.missing_indexes}")
            if not job.archive_set.cleanup_safe:
                lines.append(
                    "分卷源文件保留: "
                    + (job.archive_set.cleanup_reason or "卷元数据未确认")
                )
        if job.final_destination:
            lines.append(f"输出: {job.final_destination}")
        if job.source_retention_reason:
            lines.append(f"源文件处理: {job.source_retention_reason}")
        if job.user_notices:
            lines.append("用户通知:")
            lines.extend(f"  {message}" for message in job.user_notices)
        if job.stego_candidates:
            lines.append(f"隐写候选: {len(job.stego_candidates)}")
            for i, c in enumerate(job.stego_candidates[:5]):
                lines.append(f"  [{i}] {c.embedded_format} @{c.start_offset}-{c.end_offset} {c.confidence.value}")
        if job.error_category:
            category = getattr(job.error_category, "name", str(job.error_category))
            lines.append(f"错误分类: {category}")
        if job.error_message:
            lines.append(f"消息: {job.error_message}")
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, "\n".join(lines))
        self.details_text.config(state="disabled")

    def _show_password_prompt(self, job):
        if self.current_pwd_job and self.current_pwd_job.task_id != job.task_id:
            if all(existing.task_id != job.task_id for existing in self.pending_pwd_jobs):
                self.pending_pwd_jobs.append(job)
            return
        self.current_pwd_job = job
        self.pwd_label.config(text=f"需要密码: {Path(job.display_path).name}")
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.focus_set()
        self.pwd_frame.pack(fill=tk.X, padx=5, pady=5)
        self._sync_prompt_host_visibility()

    def _submit_password(self):
        job = self.current_pwd_job
        password = self.pwd_entry.get()
        self.current_pwd_job = None
        self.pwd_entry.delete(0, tk.END)
        self.pwd_frame.pack_forget()
        if job and self.scheduler:
            self.scheduler.submit_password_response(job, password)
        self._show_next_password_prompt()

    def _skip_password(self):
        job = self.current_pwd_job
        self.current_pwd_job = None
        self.pwd_entry.delete(0, tk.END)
        self.pwd_frame.pack_forget()
        if job and self.scheduler:
            self.scheduler.skip_password_job(job)
        self._show_next_password_prompt()

    def _show_next_password_prompt(self):
        if self.current_pwd_job is None and self.pending_pwd_jobs:
            self._show_password_prompt(self.pending_pwd_jobs.pop(0))
        else:
            self._sync_prompt_host_visibility()

    def _show_stego_prompt(self, job):
        if self.current_stego_job and self.current_stego_job.task_id != job.task_id:
            if all(existing.task_id != job.task_id for existing in self.pending_stego_jobs):
                self.pending_stego_jobs.append(job)
            return
        self.current_stego_job = job
        self.stego_list.delete(0, tk.END)
        for i, c in enumerate(job.stego_candidates):
            self.stego_list.insert(tk.END, f"[{i}] {c.embedded_format} offset={c.start_offset}-{c.end_offset} size={c.size} conf={c.confidence.value} mode={c.mode}")
        self.stego_frame.pack(fill=tk.X, padx=5, pady=5)
        self._sync_prompt_host_visibility()

    def _submit_stego(self):
        job = self.current_stego_job
        self.current_stego_job = None
        if not job:
            self.stego_frame.pack_forget()
            self._sync_prompt_host_visibility()
            return
        sel = self.stego_list.curselection()
        idx = int(sel[0]) if sel else 0
        self.stego_frame.pack_forget()
        if self.scheduler:
            self.scheduler.submit_stego_selection(job, idx)
        self._show_next_stego_prompt()

    def _skip_stego(self):
        job = self.current_stego_job
        self.current_stego_job = None
        self.stego_frame.pack_forget()
        if job and self.scheduler:
            self.scheduler.submit_stego_selection(job, None)
        self._show_next_stego_prompt()

    def _show_next_stego_prompt(self):
        if self.current_stego_job is None and self.pending_stego_jobs:
            self._show_stego_prompt(self.pending_stego_jobs.pop(0))
        else:
            self._sync_prompt_host_visibility()

    def _sync_prompt_host_visibility(self):
        if self.current_pwd_job is not None or self.current_stego_job is not None:
            self.prompt_host.pack(
                fill=tk.X,
                before=self.work_pane,
            )
        else:
            self.prompt_host.pack_forget()

    def _dismiss_prompts_for_job(self, job):
        task_id = job.task_id
        self.pending_pwd_jobs = [
            pending for pending in self.pending_pwd_jobs
            if pending.task_id != task_id
        ]
        self.pending_stego_jobs = [
            pending for pending in self.pending_stego_jobs
            if pending.task_id != task_id
        ]
        if self.current_pwd_job and self.current_pwd_job.task_id == task_id:
            self.current_pwd_job = None
            self.pwd_entry.delete(0, tk.END)
            self.pwd_frame.pack_forget()
            self._show_next_password_prompt()
        if self.current_stego_job and self.current_stego_job.task_id == task_id:
            self.current_stego_job = None
            self.stego_frame.pack_forget()
            self._show_next_stego_prompt()
        self._sync_prompt_host_visibility()

    def _on_select_job(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        for tid, item in self.job_tree_ids.items():
            if item == sel[0]:
                job = self.jobs.get(tid)
                if job:
                    self._update_details(job)
                break

    def _update_total_progress(self):
        total = len(self.jobs)
        if total == 0:
            self.total_progress["value"] = 0
            return
        done = sum(1 for j in self.jobs.values() if j.state in TERMINAL_STATES)
        self.total_progress["value"] = (done / total) * 100

    def _add_files(self):
        files = filedialog.askopenfilenames(filetypes=[("Archives", "*.7z *.rar *.zip *.tar *.gz *.iso *.001"), ("All Files", "*.*")])
        for f in files:
            self._enqueue_path(f)

    def _scan_folder(self):
        d = filedialog.askdirectory()
        if d:
            self._start_background_scan([d])

    def _start_background_scan(
        self,
        roots,
        auto_start=False,
        config_snapshot=None,
    ):
        if config_snapshot is None:
            config_snapshot = dict(self.config)
            scan_mode = self._selected_scan_mode()
            config_snapshot["deep_scan"] = scan_mode == SCAN_MODE_DEEP
            config_snapshot["steganographier_compat_mode"] = (
                scan_mode == SCAN_MODE_STEGANOGRAPHIER
            )
            config_snapshot["cleanup_policy"] = self.var_cleanup_policy.get()
        else:
            config_snapshot = dict(config_snapshot)
        normalized_roots = []
        for root in roots:
            if not isinstance(root, str):
                continue
            normalized = os.path.normcase(os.path.realpath(os.path.abspath(root)))
            if normalized not in normalized_roots:
                normalized_roots.append(normalized)
        if not normalized_roots:
            return False
        if self._pending_intake:
            accepted = self._defer_intake_request(
                "scan", normalized_roots, auto_start, False, config_snapshot
            )
            return accepted
        if self._scan_thread is not None:
            accepted = self._queue_scan_request(
                normalized_roots, auto_start, config_snapshot
            )
            return accepted
        return self._launch_background_scan(
            normalized_roots, auto_start, config_snapshot
        )

    def _queue_scan_request(self, roots, auto_start, config_snapshot) -> bool:
        return self._defer_intake_request(
            "scan", roots, auto_start, False, config_snapshot
        )

    def _show_scan_progress(self, generation: int) -> None:
        self._scan_progress_generation = generation
        self.scan_progress["value"] = 0
        self.scan_progress_label.config(text="扫描文件: 正在准备")
        self.scan_progress_frame.pack(
            fill=tk.X,
            pady=(0, 2),
            before=self.progress_frame,
        )

    def _update_scan_progress(
        self,
        generation: int,
        scanned_count: int,
        found_count: int,
        path: str,
        progress: int,
    ) -> None:
        if (
            generation != self._scan_generation
            or generation != self._scan_progress_generation
            or self._closing
        ):
            return
        name = os.path.basename(path) or path
        if len(name) > 42:
            name = "..." + name[-39:]
        self.scan_progress_label.config(
            text=(
                f"扫描文件 {max(1, scanned_count)}，"
                f"已发现 {found_count}: {name}"
            )
        )
        self.scan_progress["value"] = max(0, min(100, int(progress)))

    def _hide_scan_progress(self, generation: Optional[int] = None) -> None:
        if (
            generation is not None
            and generation != self._scan_progress_generation
        ):
            return
        self._scan_progress_generation = -1
        self.scan_progress["value"] = 0
        self.scan_progress_label.config(text="扫描文件")
        self.scan_progress_frame.pack_forget()

    def _launch_background_scan(
        self, roots, auto_start=False, config_snapshot=None
    ) -> bool:
        self._scan_cancel.clear()
        self._scan_generation += 1
        generation = self._scan_generation
        scan_config = dict(config_snapshot or self.config)
        deep = bool(scan_config.get("deep_scan", False))
        compat = bool(
            scan_config.get("steganographier_compat_mode", True)
        ) and not deep

        def scan_cancelled() -> bool:
            return bool(
                self._scan_cancel.is_set()
                or self._closing
                or generation != self._scan_generation
            )

        def worker():
            count = 0
            scanned_count = 0
            failure = None
            last_progress_time = 0.0
            last_progress_path = ""
            last_progress_value = -1

            def post_scan_progress(
                path: str,
                progress: int,
                display_count: int,
                *,
                force: bool = False,
            ) -> None:
                nonlocal last_progress_path
                nonlocal last_progress_time
                nonlocal last_progress_value
                if scan_cancelled():
                    return
                value = max(0, min(100, int(progress)))
                now = time.monotonic()
                same_file = path == last_progress_path
                meaningful_step = same_file and abs(
                    value - last_progress_value
                ) >= 5
                if (
                    not force
                    and now - last_progress_time
                    < SCAN_PROGRESS_MIN_INTERVAL_SECONDS
                    and not meaningful_step
                ):
                    return
                if not self._post_to_tk(
                    self._update_scan_progress,
                    generation,
                    display_count,
                    count,
                    path,
                    value,
                ):
                    return
                last_progress_path = path
                last_progress_time = now
                last_progress_value = value

            try:
                archive_exts = set(ARCHIVE_EXTS)
                if self.scheduler:
                    archive_exts.update(
                        self.scheduler.runner.supported_formats(timeout=15)
                    )
                archive_exts = frozenset(
                    extension.casefold()
                    for extension in archive_exts
                    if isinstance(extension, str) and extension.startswith(".")
                )
                if scan_cancelled():
                    return
                for root_dir in roots:
                    for root, dirs, files in os.walk(root_dir, followlinks=False):
                        if scan_cancelled():
                            break
                        dirs[:] = [
                            name
                            for name in dirs
                            if not os.path.islink(os.path.join(root, name))
                            and not is_reparse_point(os.path.join(root, name))
                        ]
                        for f in files:
                            while (
                                self.scheduler
                                and self.scheduler.is_io_busy()
                                and not scan_cancelled()
                            ):
                                time.sleep(0.2)
                            if scan_cancelled():
                                break
                            full = os.path.join(root, f)
                            if is_multipart_child(full):
                                continue

                            current_number = scanned_count + 1
                            post_scan_progress(full, 0, current_number)

                            def report_file_progress(
                                completed_bytes: int,
                                total_bytes: int,
                            ) -> None:
                                if total_bytes <= 0:
                                    value = 100
                                else:
                                    value = int(
                                        (completed_bytes / total_bytes) * 100
                                    )
                                post_scan_progress(
                                    full,
                                    value,
                                    current_number,
                                )

                            decision = classify_automatic_candidate(
                                full,
                                archive_exts,
                                cancel_check=scan_cancelled,
                                progress_cb=report_file_progress,
                                allow_full_embedded_scan=deep,
                            )
                            if scan_cancelled():
                                break
                            candidates = list(decision.candidates)
                            should_queue = decision.should_queue
                            if compat and not should_queue:
                                candidates = find_steganographier_candidates(
                                    full,
                                    cancel_check=scan_cancelled,
                                )
                                should_queue = bool(candidates)
                            if (
                                deep
                                and decision.reason == "no_archive_structure"
                            ):
                                candidates = find_candidates(
                                    full,
                                    cancel_check=scan_cancelled,
                                    progress_cb=report_file_progress,
                                )
                                should_queue = bool(candidates)
                            if scan_cancelled():
                                break
                            if should_queue:
                                count += 1
                                if not self._post_to_tk(
                                    self._enqueue_scanned_path,
                                    generation,
                                    full,
                                    auto_start,
                                    scan_config,
                                    candidates,
                                ):
                                    return
                            scanned_count += 1
                            post_scan_progress(
                                full,
                                100,
                                scanned_count,
                            )
            except Exception as exc:
                failure = f"{type(exc).__name__}: {exc}"
                logger.exception("Background folder scan failed")
            finally:
                if last_progress_path:
                    post_scan_progress(
                        last_progress_path,
                        100,
                        max(1, scanned_count),
                        force=True,
                    )
                self._post_to_tk(
                    self._finish_background_scan,
                    generation,
                    count,
                    threading.current_thread(),
                    failure,
                )

        self._show_scan_progress(generation)
        self._scan_thread = threading.Thread(target=worker, name="Smart7zScan", daemon=True)
        self._scan_threads.add(self._scan_thread)
        self._scan_thread.start()
        return True

    def _enqueue_scanned_path(
        self,
        generation,
        path,
        auto_start,
        config_snapshot,
        precomputed_candidates=None,
    ) -> bool:
        if (
            generation != self._scan_generation
            or self._scan_cancel.is_set()
            or self._closing
        ):
            return False
        accepted = self._enqueue_path(
            path,
            auto_start=False,
            explicit_input=False,
            config_snapshot=config_snapshot,
            from_scan=True,
            precomputed_candidates=precomputed_candidates,
        )
        if accepted and auto_start:
            self._scan_autostart_generations.add(generation)
        if not accepted:
            self._disable_context_auto_close(abnormal=True)
        return accepted

    def _finish_background_scan(
        self, generation, count, scan_thread, failure=None
    ):
        self._scan_threads.discard(scan_thread)
        if self._scan_thread is scan_thread:
            self._scan_thread = None
        if generation != self._scan_generation:
            self._scan_autostart_generations.discard(generation)
            return
        self._hide_scan_progress(generation)
        cancelled = self._scan_cancel.is_set() or self._closing
        if cancelled:
            self._scan_autostart_generations.discard(generation)
            self._update_pending_intake_display()
            return
        if failure:
            self._disable_context_auto_close(abnormal=True)
            self.log_event("SCAN_FAILED", count=count, detail=failure)
        else:
            self.log_event("SCAN_COMPLETE", count=count)
        should_auto_start = generation in self._scan_autostart_generations
        self._scan_autostart_generations.discard(generation)
        if should_auto_start and self.scheduler:
            self.scheduler.enable_processing()
        self._start_next_pending_scan()
        self._schedule_context_auto_close_check()

    def _start_next_pending_scan(self):
        self._scan_thread = None
        if self._closing or self._scan_cancel.is_set():
            self._update_pending_intake_display()
            return
        self._release_pending_intake()
        if self._pending_intake:
            return
        self._scan_cancel.clear()

    def _enqueue_path(
        self,
        path,
        auto_start=False,
        explicit_input=True,
        config_snapshot=None,
        from_scan=False,
        from_pending=False,
        precomputed_candidates=None,
    ):
        path = os.path.normpath(path)
        logical_key = logical_archive_key(path)
        if not os.path.isfile(path) or logical_key in self.seen_paths:
            return False
        if config_snapshot is None:
            job_config = dict(self.config)
            job_config["cleanup_policy"] = self.var_cleanup_policy.get()
        else:
            job_config = dict(config_snapshot)
        if (
            not from_scan
            and not from_pending
            and (
                self._pending_intake
                or self._scan_thread is not None
            )
        ):
            return self._defer_intake_request(
                "file", [path], auto_start, explicit_input, job_config
            )
        self.seen_paths.add(logical_key)
        job = Job(
            path=path,
            original_path=path,
            original_basename=Path(path).name,
            cleanup_policy_snapshot=str(
                job_config.get("cleanup_policy", "keep") or "keep"
            ),
            extract_to_source_override=bool(
                job_config.get("_extract_to_source_override", False)
            ),
            explicit_input=bool(explicit_input),
            stego_candidates=list(precomputed_candidates or ()),
        )
        if self.scheduler:
            accepted = self.scheduler.submit(job)
            if not accepted:
                self.seen_paths.discard(logical_key)
                self._update_pending_intake_display()
                return False
            if auto_start:
                self.scheduler.enable_processing()
            self._update_pending_intake_display()
            return True
        self.seen_paths.discard(logical_key)
        return False

    def _start_processing(self):
        if not self._sync_config():
            self.log_event("CONFIG_SYNC_FAILED")
            return
        if self.scheduler:
            self.scheduler.resume_intake()
            self._release_pending_intake()
            self.scheduler.enable_processing()
            self._update_pending_intake_display()
        self.log_event("QUEUE_STARTED")

    def _sync_config(self):
        candidate = dict(self.config)
        candidate["extract_to_source"] = self.var_extract_to_source.get()
        candidate["wait_disk_space"] = self.var_wait_space.get()
        candidate["extract_mode"] = "staging" if self.var_staging_mode.get() else "direct"
        scan_mode = self._selected_scan_mode()
        candidate["deep_scan"] = scan_mode == SCAN_MODE_DEEP
        candidate["steganographier_compat_mode"] = (
            scan_mode == SCAN_MODE_STEGANOGRAPHIER
        )
        candidate["nested_extraction"] = self.var_nested.get()
        try:
            candidate["max_nested_depth"] = max(
                0, min(20, int(self.spin_nested_depth.get()))
            )
        except ValueError:
            candidate["max_nested_depth"] = 2
        policy = self.var_cleanup_policy.get()
        candidate["cleanup_policy"] = policy
        candidate["del_archive"] = policy == "permanent"
        candidate["target_dir"] = self.entry_target.get().strip()
        candidate["temp_dir"] = self.entry_temp.get().strip()
        candidate["password_file"] = self.entry_pwd.get().strip()
        main_pwd = self.entry_main_pwd.get()
        candidate["_app_dir"] = get_app_dir()
        try:
            save_config(candidate)
        except (OSError, TypeError, ValueError) as e:
            self._restore_config_controls()
            messagebox.showerror("配置保存失败", str(e))
            return False
        if self.scheduler:
            try:
                self.scheduler.refresh_config(candidate)
            except OSError as e:
                try:
                    save_config(self.config)
                except (OSError, TypeError, ValueError):
                    logger.exception("Could not roll back persisted configuration")
                self._restore_config_controls()
                messagebox.showerror("配置应用失败", str(e))
                return False
            self.scheduler.set_session_main_password(
                main_pwd if main_pwd.strip() else None
            )
        self.config = candidate
        return True

    def _restore_config_controls(self):
        self.var_extract_to_source.set(
            bool(self.config.get("extract_to_source", True))
        )
        self.var_wait_space.set(bool(self.config.get("wait_disk_space", True)))
        self.var_staging_mode.set(
            self.config.get("extract_mode", "staging") == "staging"
        )
        self._select_scan_mode(self._scan_mode_from_config(self.config))
        self.var_nested.set(bool(self.config.get("nested_extraction", False)))
        self.var_cleanup_policy.set(self.config.get("cleanup_policy", "keep"))
        for entry, value in (
            (self.entry_target, self.config.get("target_dir", "")),
            (self.entry_temp, self.config.get("temp_dir", r"C:\Temp_Smart7z")),
            (self.entry_pwd, self.config.get("password_file", "code.txt")),
            (self.spin_nested_depth, self.config.get("max_nested_depth", 2)),
        ):
            entry.delete(0, tk.END)
            entry.insert(0, str(value))

    def _on_cleanup_policy_change(self):
        if self.var_cleanup_policy.get() == "permanent":
            if not messagebox.askyesno("确认永久删除", "永久删除源压缩包不可恢复，且仅在验证通过的 COMPLETE 任务上执行。是否继续？"):
                self.var_cleanup_policy.set(self.config.get("cleanup_policy", "keep"))
                return
        self._sync_config()

    def _update_pending_intake_display(self):
        scheduler_pending = 0
        if self.scheduler and hasattr(self.scheduler, "deferred_intake_size"):
            scheduler_pending = self.scheduler.deferred_intake_size()
        pending = scheduler_pending + len(self._pending_intake)
        self.pending_intake_label.config(text=f"待接纳: {pending}")

    def _defer_intake_request(
        self, kind, paths, auto_start, explicit_input, config_snapshot
    ) -> bool:
        return self._defer_intake_items(
            (
                kind,
                path,
                bool(auto_start),
                bool(explicit_input),
                dict(config_snapshot),
            )
            for path in paths
        )

    def _defer_intake_items(self, items) -> bool:
        accepted_any = False
        additions = []
        proposed_keys = set(self._pending_intake_keys)
        for kind, path, auto_start, explicit_input, config_snapshot in items:
            if kind == "file":
                key = (kind, logical_archive_key(path))
            else:
                key = (
                    kind,
                    os.path.normcase(os.path.realpath(os.path.abspath(path))),
                )
            if key in proposed_keys:
                accepted_any = True
                continue
            proposed_keys.add(key)
            additions.append(
                (
                    kind,
                    path,
                    auto_start,
                    explicit_input,
                    dict(config_snapshot),
                    key,
                )
            )
            accepted_any = True
        if len(self._pending_intake) + len(additions) > PENDING_INTAKE_LIMIT:
            return False
        self._pending_intake.extend(additions)
        self._pending_intake_keys.update(item[-1] for item in additions)
        self._update_pending_intake_display()
        return accepted_any

    def _release_pending_intake(self) -> int:
        released = 0
        start_requested = False
        start_deferred_to_scan = False
        while self._pending_intake:
            (
                kind,
                path,
                auto_start,
                explicit_input,
                config_snapshot,
                key,
            ) = self._pending_intake.pop(0)
            self._pending_intake_keys.discard(key)
            if kind == "scan":
                if self._scan_thread is not None:
                    self._pending_intake.insert(
                        0,
                        (
                            kind,
                            path,
                            auto_start,
                            explicit_input,
                            config_snapshot,
                            key,
                        ),
                    )
                    self._pending_intake_keys.add(key)
                    break
                scan_auto_start = bool(auto_start or start_requested)
                accepted = self._launch_background_scan(
                    [path], scan_auto_start, config_snapshot
                )
                if accepted:
                    released += 1
                    start_deferred_to_scan = scan_auto_start
                break
            else:
                accepted = self._enqueue_path(
                    path,
                    auto_start=False,
                    explicit_input=explicit_input,
                    config_snapshot=config_snapshot,
                    from_pending=True,
                )
            if accepted:
                released += 1
                start_requested = bool(start_requested or auto_start)
        if (
            start_requested
            and not start_deferred_to_scan
            and self.scheduler
        ):
            self.scheduler.enable_processing()
        self._update_pending_intake_display()
        self._schedule_context_auto_close_check()
        return released

    @staticmethod
    def _cleanup_policy_display(job):
        return {
            "keep": "保留",
            "recycle": "回收站",
            "permanent": "永久删除",
        }.get(job.cleanup_policy_snapshot, job.cleanup_policy_snapshot or "-")

    def _cancel_current(self):
        if self.scheduler:
            self.scheduler.cancel_current()
            self.log_event("CANCEL_CURRENT_REQUESTED")

    def _cancel_remaining(self):
        self._scan_cancel.set()
        self._scan_generation += 1
        self._scan_thread = None
        self._scan_autostart_generations.clear()
        self._hide_scan_progress()
        self._pending_intake.clear()
        self._pending_intake_keys.clear()
        self._update_pending_intake_display()
        if self.scheduler:
            self.scheduler.cancel_remaining()
            self.log_event("CANCEL_REMAINING")

    def _clear_finished(self):
        if self.scheduler:
            removed = set(self.scheduler.clear_finished())
        else:
            removed = {
                task_id
                for task_id, job in self.jobs.items()
                if job.state in TERMINAL_STATES
            }
        self._remove_jobs_from_ui(removed)
        self._update_total_progress()

    def _clear_selected(self):
        selected_items = set(self.tree.selection())
        if not selected_items:
            return
        task_ids = {
            task_id
            for task_id, item_id in self.job_tree_ids.items()
            if item_id in selected_items
        }
        self._clear_after_terminal.update(task_ids)
        if self.scheduler and self.scheduler.current_job:
            if self.scheduler.current_job.task_id in task_ids:
                self.scheduler.cancel_current()
        if self.scheduler:
            self.scheduler.cancel_jobs(task_ids)
            removed = set(self.scheduler.clear_finished(task_ids))
            self._remove_jobs_from_ui(removed)
            self._clear_after_terminal.difference_update(removed)
        else:
            terminal = {
                task_id
                for task_id in task_ids
                if self.jobs.get(task_id)
                and self.jobs[task_id].state in TERMINAL_STATES
            }
            self._remove_jobs_from_ui(terminal)
            self._clear_after_terminal.difference_update(terminal)

    def _remove_jobs_from_ui(self, task_ids):
        for task_id in set(task_ids):
            self._suppressed_job_ids.add(task_id)
            item = self.job_tree_ids.pop(task_id, None)
            job = self.jobs.pop(task_id, None)
            self._job_sequence.pop(task_id, None)
            if item is not None:
                try:
                    self.tree.delete(item)
                except tk.TclError:
                    pass
            if job:
                self._dismiss_prompts_for_job(job)
                for source in (job.path, job.original_path):
                    if source:
                        self.seen_paths.discard(logical_archive_key(source))

    def _retry_clear_job(self, task_id):
        if self._closing or task_id not in self._clear_after_terminal:
            return
        removed = [task_id]
        if self.scheduler:
            removed = self.scheduler.clear_finished({task_id})
            if not removed and not self.scheduler.has_job(task_id):
                removed = [task_id]
        if removed:
            self._remove_jobs_from_ui(set(removed))
            self._clear_after_terminal.discard(task_id)
        elif task_id in self.jobs:
            self.root.after(50, self._retry_clear_job, task_id)

    def _sel_target(self):
        d = filedialog.askdirectory()
        if d:
            self.entry_target.delete(0, tk.END)
            self.entry_target.insert(0, d)
            self._sync_config()

    def _sel_temp(self):
        d = filedialog.askdirectory()
        if d:
            self.entry_temp.delete(0, tk.END)
            self.entry_temp.insert(0, d)
            self._sync_config()

    def _sel_pwd(self):
        f = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if f:
            self.entry_pwd.delete(0, tk.END)
            self.entry_pwd.insert(0, f)
            self._sync_config()

    def _register_menu(self):
        if register_context_menu():
            messagebox.showinfo("成功", "右键菜单已添加。")
        else:
            messagebox.showerror("失败", "添加右键菜单失败。")

    def _unregister_menu(self):
        if unregister_context_menu():
            messagebox.showinfo("成功", "右键菜单已删除。")
        else:
            messagebox.showerror("失败", "删除右键菜单失败。")

    def _on_drop(self, event):
        paths = self.root.tk.splitlist(event.data)
        for p in paths:
            if p.startswith("{") and p.endswith("}"):
                p = p[1:-1]
            if os.path.isdir(p):
                self._start_background_scan([p], auto_start=False)
            else:
                # Drag/drop is a queueing gesture; the explicit Start button
                # remains the only way to begin a GUI-created batch.
                self._enqueue_path(p, auto_start=False)

    def _process_external_paths(
        self,
        args,
        auto_start,
        source,
        cleanup_policy=CleanupPolicy.KEEP.value,
        extract_to_source=False,
        context_menu=False,
    ):
        if (
            not isinstance(cleanup_policy, str)
            or cleanup_policy not in EXTERNAL_CLEANUP_POLICIES
        ):
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        if not isinstance(extract_to_source, bool):
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        config_snapshot = dict(self.config)
        config_snapshot["cleanup_policy"] = cleanup_policy
        config_snapshot["del_archive"] = (
            cleanup_policy == CleanupPolicy.PERMANENT.value
        )
        config_snapshot["_extract_to_source_override"] = extract_to_source
        items = []
        file_count = 0
        directory_count = 0
        for path in args:
            if not isinstance(path, str):
                continue
            if os.path.isdir(path):
                items.append(
                    ("scan", path, bool(auto_start), False, config_snapshot)
                )
                directory_count += 1
            elif os.path.isfile(path):
                if logical_archive_key(path) in self.seen_paths:
                    if context_menu:
                        self._disable_context_auto_close(abnormal=True)
                    return False
                items.append(
                    ("file", path, bool(auto_start), True, config_snapshot)
                )
                file_count += 1
        if not items:
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        blocked_before_request = bool(
            self._pending_intake
            or self._scan_thread is not None
        )
        if not self._defer_intake_items(items):
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        if not blocked_before_request:
            self._release_pending_intake()
        if file_count or directory_count:
            self.log_event(
                "EXTERNAL_PATHS_RECEIVED",
                context=source,
                file_count=file_count,
                directory_count=directory_count,
                mode_zh="自动开始" if auto_start else "仅加入队列",
                mode_en="start automatically" if auto_start else "queue only",
            )
        if context_menu:
            self._note_context_menu_request()
        return True

    def process_ipc_args(
        self,
        args,
        auto_start=True,
        cleanup_policy=CleanupPolicy.KEEP.value,
        extract_to_source=False,
        context_menu=False,
    ):
        if not isinstance(context_menu, bool):
            self._disable_context_auto_close(abnormal=True)
            return False
        if not context_menu:
            self._disable_context_auto_close()
        return self._process_external_paths(
            args,
            auto_start=bool(auto_start),
            source="IPC",
            cleanup_policy=cleanup_policy,
            extract_to_source=extract_to_source,
            context_menu=context_menu,
        )

    def activate_window(self):
        self._disable_context_auto_close()
        if self._closing:
            return False
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
            return True
        except (AttributeError, RuntimeError, tk.TclError):
            logger.exception("Could not activate the primary window")
            return False

    def _process_cli_args(self):
        if self.startup_args:
            self._process_external_paths(
                self.startup_args,
                auto_start=self.startup_auto_start,
                source="CLI",
                cleanup_policy=self.startup_cleanup_policy,
                extract_to_source=self.startup_extract_to_source,
                context_menu=self.startup_context_menu,
            )

    def _note_context_menu_request(self) -> None:
        if (
            not self._context_auto_close_armed
            or self._context_auto_close_abnormal
            or self._closing
        ):
            return
        self._context_auto_close_generation += 1
        self._schedule_context_auto_close_check()

    def _schedule_context_auto_close_check(self) -> None:
        if (
            not self._context_auto_close_armed
            or self._context_auto_close_abnormal
            or self._closing
        ):
            return
        generation = self._context_auto_close_generation
        try:
            self.root.after(
                CONTEXT_AUTO_CLOSE_GRACE_MS,
                self._maybe_auto_close_context_window,
                generation,
            )
        except (AttributeError, RuntimeError, tk.TclError):
            self._disable_context_auto_close(abnormal=True)
            logger.exception("Could not schedule context-menu auto-close check")

    def _maybe_auto_close_context_window(self, generation) -> None:
        if (
            generation != self._context_auto_close_generation
            or not self._context_auto_close_armed
            or self._context_auto_close_abnormal
            or self._closing
            or not self.jobs
        ):
            return
        if any(job.state != JobState.COMPLETE for job in self.jobs.values()):
            return
        if self._pending_intake or self._scan_thread is not None:
            return
        if any(thread.is_alive() for thread in self._scan_threads):
            return
        if (
            self.current_pwd_job is not None
            or self.pending_pwd_jobs
            or self.current_stego_job is not None
            or self.pending_stego_jobs
        ):
            return
        if self.scheduler is not None:
            try:
                if self.scheduler.current_job is not None:
                    return
                if self.scheduler.is_io_busy():
                    return
                if self.scheduler.deferred_intake_size() != 0:
                    return
            except Exception:
                self._disable_context_auto_close(abnormal=True)
                logger.exception("Could not verify context-menu completion state")
                return
        try:
            closed = self._on_closing()
        except Exception:
            self._disable_context_auto_close(abnormal=True)
            logger.exception("Context-menu auto-close failed")
            return
        if not closed:
            self._disable_context_auto_close(abnormal=True)

    def _disable_context_auto_close(self, abnormal=False) -> None:
        if abnormal:
            self._context_auto_close_abnormal = True
        if self._context_auto_close_armed:
            self._context_auto_close_armed = False
            self._context_auto_close_generation += 1

    def _on_closing(self, force=False):
        if self._closing:
            return True
        if not self._sync_config() and not force:
            return False
        self._closing = True
        self._scan_cancel.set()
        self._scan_generation += 1
        self._scan_autostart_generations.clear()
        self._hide_scan_progress()
        self._pending_intake.clear()
        self._pending_intake_keys.clear()
        if self.scheduler:
            self.scheduler.pause_intake()
        if self.ipc_server:
            try:
                self.ipc_server.begin_draining()
            except Exception:
                logger.exception("IPC draining transition failed")
        self._disable_for_shutdown()
        self._shutdown_done.clear()
        self._shutdown_started = time.monotonic()
        self._shutdown_extended = False
        self._shutdown_thread = threading.Thread(
            target=self._shutdown_worker,
            name="Smart7zShutdown",
            daemon=True,
        )
        self._shutdown_thread.start()
        try:
            self.root.after(100, self._poll_shutdown)
        except (RuntimeError, tk.TclError):
            return True
        return True

    def _disable_for_shutdown(self) -> None:
        try:
            self.root.title("Smart 7z Ultra - 正在关闭")
        except (RuntimeError, tk.TclError):
            pass
        try:
            pending = list(self.root.winfo_children())
        except (AttributeError, RuntimeError, tk.TclError):
            pending = []
        while pending:
            widget = pending.pop()
            try:
                pending.extend(widget.winfo_children())
            except (AttributeError, RuntimeError, tk.TclError):
                pass
            try:
                widget.configure(state=tk.DISABLED)
            except (AttributeError, RuntimeError, tk.TclError):
                pass

    def _shutdown_worker(self) -> None:
        scheduler_stopped = self.scheduler is None
        while not scheduler_stopped:
            try:
                scheduler_stopped = bool(self.scheduler.stop())
            except Exception:
                logger.exception("Scheduler shutdown retry failed")
            if not scheduler_stopped:
                time.sleep(0.25)
        ipc_stopped = self.ipc_server is None
        while not ipc_stopped:
            try:
                ipc_stopped = bool(self.ipc_server.close())
            except Exception:
                logger.exception("IPC shutdown retry failed")
            if not ipc_stopped:
                time.sleep(0.25)
        scan_deadline = time.monotonic() + 1.0
        for scan_thread in list(self._scan_threads):
            if (
                scan_thread is not threading.current_thread()
                and scan_thread.is_alive()
            ):
                remaining = max(0.0, scan_deadline - time.monotonic())
                if not remaining:
                    break
                scan_thread.join(timeout=remaining)
        self._scan_threads = {
            thread for thread in self._scan_threads if thread.is_alive()
        }
        self._shutdown_done.set()

    def _poll_shutdown(self) -> None:
        if self._shutdown_done.is_set():
            thread = self._shutdown_thread
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=0)
            try:
                self.root.destroy()
            except (RuntimeError, tk.TclError):
                pass
            return
        if (
            not self._shutdown_extended
            and time.monotonic() - self._shutdown_started >= 5.0
        ):
            self._shutdown_extended = True
            try:
                self.root.title("Smart 7z Ultra - 安全停止中")
            except (RuntimeError, tk.TclError):
                pass
        try:
            self.root.after(100, self._poll_shutdown)
        except (RuntimeError, tk.TclError):
            return

    def _wait_for_shutdown_without_mainloop(self) -> None:
        """Finish shutdown synchronously after or before the Tk main loop."""

        thread = self._shutdown_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        try:
            self.root.destroy()
        except (RuntimeError, tk.TclError):
            pass

    @staticmethod
    def _job_size_bytes(job):
        try:
            return os.path.getsize(job.path)
        except OSError:
            return 0

    def _format_size(self, job):
        size = self._job_size_bytes(job)
        if size >= 1024 * 1024 * 1024:
            return f"{size / 1024 / 1024 / 1024:.2f} GB"
        if size:
            return f"{size / 1024 / 1024:.2f} MB"
        else:
            return "0 MB"

    def log_event(self, code: str, **values) -> None:
        self._append_log_line(format_user_message(code, **values))

    def _insert_styled_log_message(self, message: str) -> None:
        whole_line_red, spans = user_message_red_spans(message)
        if not spans:
            self.log_text.insert(tk.END, message)
            return

        tag = LOG_RED_LINE_TAG if whole_line_red else LOG_RED_KEYWORD_TAG
        cursor = 0
        for start, end in spans:
            if start > cursor:
                self.log_text.insert(tk.END, message[cursor:start])
            self.log_text.insert(tk.END, message[start:end], tag)
            cursor = end
        if cursor < len(message):
            self.log_text.insert(tk.END, message[cursor:])

    def _append_log_line(self, msg: str) -> None:
        normalized = re.sub(r"[\x00\r\n\t]+", " ", str(msg)).strip()
        if not normalized:
            return
        if len(normalized) > MAX_UI_LOG_CHARS:
            normalized = normalized[: MAX_UI_LOG_CHARS - 4].rstrip() + " ..."

        def _log():
            if self._closing:
                return
            try:
                self.log_text.config(state="normal")
                if self.log_lines >= self.max_log_lines:
                    self.log_text.delete("1.0", "101.0")
                    self.log_lines = max(0, self.log_lines - 100)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                self.log_text.insert(tk.END, f"[{ts}] ")
                self._insert_styled_log_message(normalized)
                self.log_text.insert(tk.END, "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state="disabled")
                self.log_lines += 1
            except (RuntimeError, tk.TclError):
                return

        self._post_to_tk(_log)


def create_root():
    if DND_AVAILABLE and TkinterDnD is not None:
        return TkinterDnD.Tk()
    return tk.Tk()


def _forward_exit_code(
    result: IPCForwardResult,
    *,
    allow_shutdown_handoff: bool = False,
) -> Optional[int]:
    """Return an exit code when launch must stop, otherwise ``None``."""

    if result.accepted:
        return 0
    if not result.reached_existing:
        return None
    if allow_shutdown_handoff and result.reason == "server_stopping":
        return None
    detail = result.reason or result.status
    try:
        messagebox.showerror(
            "请求未接纳",
            "已有 Smart7z 实例，但本次请求未被确认接纳。"
            f"\n原因: {detail}\n为避免重复处理，未启动第二实例。",
        )
    except (RuntimeError, tk.TclError):
        logger.error("Existing Smart7z instance did not accept request: %s", detail)
    return 1


def _forward_launch_request(request: ExternalIntakeRequest) -> IPCForwardResult:
    return forward_to_existing(
        request.paths,
        auto_start=request.auto_start,
        cleanup_policy=request.cleanup_policy,
        extract_to_source=request.extract_to_source,
        context_menu=request.context_menu,
    )


def _wait_for_existing_or_claim_mutex(request: ExternalIntakeRequest):
    """Wait for a starting primary instance, or take over if it exits."""

    deadline = time.monotonic() + INSTANCE_STARTUP_WAIT_SECONDS
    last_reason = "state_unavailable"
    while True:
        forward_result = _forward_launch_request(request)
        last_reason = forward_result.reason or forward_result.status
        forward_exit_code = _forward_exit_code(
            forward_result,
            allow_shutdown_handoff=True,
        )
        if forward_exit_code is not None:
            raise SystemExit(forward_exit_code)

        instance_mutex = create_mutex()
        if instance_mutex is not None:
            return instance_mutex

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                messagebox.showerror(
                    "启动请求未转交",
                    "检测到另一个 Smart7z 正在启动或关闭，但未能在限定时间内完成请求转交。"
                    "\n本次请求未进入队列，也没有启动第二个实例。"
                    f"\n最后状态: {last_reason}\n请稍后重试。",
                )
            except (RuntimeError, tk.TclError):
                logger.error(
                    "Timed out waiting for the primary Smart7z instance: %s",
                    last_reason,
                )
            raise SystemExit(1)
        time.sleep(min(INSTANCE_STARTUP_POLL_SECONDS, remaining))


def run_app(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    request = parse_launch_args(argv)
    forward_result = _forward_launch_request(request)
    forward_exit_code = _forward_exit_code(
        forward_result,
        allow_shutdown_handoff=sys.platform == "win32",
    )
    if forward_exit_code is not None:
        sys.exit(forward_exit_code)

    instance_mutex = None
    if sys.platform == "win32":
        instance_mutex = create_mutex()
        if instance_mutex is None:
            instance_mutex = _wait_for_existing_or_claim_mutex(request)

    try:
        root = create_root()
        if not DND_AVAILABLE:
            try:
                messagebox.showwarning(
                    "依赖缺失",
                    "未检测到 tkinterdnd2，拖拽不可用。\n文件/文件夹按钮、命令行与 IPC 仍可用。\n可选: pip install tkinterdnd2",
                )
            except (RuntimeError, tk.TclError):
                pass
        app = Smart7zAppModern(
            root,
            startup_args=request.paths,
            startup_auto_start=request.auto_start,
            startup_cleanup_policy=request.cleanup_policy,
            startup_extract_to_source=request.extract_to_source,
            startup_context_menu=request.context_menu,
        )
        if app.startup_blocked or app.scheduler is None:
            app._on_closing(force=True)
            app._wait_for_shutdown_without_mainloop()
            return
        ipc = BoundedIPCServer(app)
        if not ipc.start():
            retry_result = _forward_launch_request(request)
            retry_exit_code = _forward_exit_code(retry_result)
            if retry_exit_code is not None:
                app._on_closing(force=True)
                app._wait_for_shutdown_without_mainloop()
                sys.exit(retry_exit_code)
            messagebox.showerror("启动错误", f"无法绑定 IPC 端口 {IPC_PORT}，可能已有实例在运行。")
            app._on_closing(force=True)
            app._wait_for_shutdown_without_mainloop()
            return
        else:
            app.ipc_server = ipc
        try:
            root.mainloop()
        finally:
            app._on_closing(force=True)
            app._wait_for_shutdown_without_mainloop()
    finally:
        if instance_mutex is not None and not close_mutex(instance_mutex):
            logger.warning("Could not close the Smart7z instance mutex")
