"""UI-independent launch arguments and single-instance IPC for Smart7z."""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import socket
import struct
import tempfile
import threading
from typing import Optional

from launch_ipc import (
    EXTERNAL_CLEANUP_POLICIES,
    ExternalIntakeRequest,
    IPCForwardResult,
    IPC_ACK_TIMEOUT_SECONDS,
    IPC_FORWARD_ACCEPTED,
    IPC_FORWARD_INDETERMINATE,
    IPC_FORWARD_REJECTED,
    IPC_FORWARD_UNAVAILABLE,
    IPC_MAX_BYTES,
    IPC_MAX_PATHS,
    IPC_PORT,
    IPC_STATE_MAX_BYTES,
    IPC_VERSION,
    _forward_launch_request,
    _ipc_state_path,
    _normalize_ipc_path,
    forward_to_existing,
    parse_launch_args,
    try_forward_to_existing,
)
from models import CleanupPolicy, JobState

logger = logging.getLogger(__name__)

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

PROCESSING_STATES = frozenset(
    {
        JobState.DISCOVERING,
        JobState.GROUPED,
        JobState.STANDALONE,
        JobState.LISTING,
        JobState.PASSWORD_ATTEMPT,
        JobState.PLANNED,
        JobState.SPACE_WAIT,
        JobState.EXTRACTING,
        JobState.VERIFYING,
        JobState.COMMITTING,
    }
)

ARCHIVE_EXTS = frozenset(
    {
        ".7z",
        ".rar",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".iso",
        ".cab",
        ".001",
    }
)

INSTANCE_STARTUP_WAIT_SECONDS = 15.0
INSTANCE_STARTUP_POLL_SECONDS = 0.1
CONTEXT_AUTO_CLOSE_GRACE_MS = 1500

SCAN_MODE_DEEP = "deep"
SCAN_MODE_STEGANOGRAPHIER = "steganographier"
SCAN_MODE_NORMAL = "normal"

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


class _IPCDispatchTicket:
    """Make timeout cancellation atomic with UI-thread dispatch start."""

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
        # Bind an ephemeral port by default: the actual port is published
        # through the IPC state file, so a fixed port only created a
        # startup failure mode when 59777 was taken by another program.
        port: int = 0,
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
        self._tickets = set()
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
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
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
        except OSError as exc:
            logger.error("IPC bind failed: %s", exc)
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

    def _listen(self, listener, generation) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lifecycle_lock:
                if self._stop_event.is_set() or generation != self._generation:
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
                    if request is None:
                        self._send_reply(conn, False, "invalid_paths")
                        continue
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
                    with self._lifecycle_lock:
                        self._tickets.add(ticket)
                    post_to_ui = getattr(self.app, "_post_to_ui", None)
                    try:
                        queued = bool(
                            callable(post_to_ui)
                            and post_to_ui(self._dispatch_request, generation, request, ticket)
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
                    finally:
                        with self._lifecycle_lock:
                            self._tickets.discard(ticket)
            except (OSError, RuntimeError):
                logger.exception("IPC connection error")
            finally:
                with self._lifecycle_lock:
                    self._connections.discard(conn)

    def _dispatch_request(self, generation, request, ticket) -> None:
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
            disable_auto_close = getattr(self.app, "_disable_context_auto_close", None)
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
    def _recv_exact(conn, size):
        buffer = b""
        while len(buffer) < size:
            try:
                part = conn.recv(size - len(buffer))
            except OSError:
                return None
            if not part:
                return None
            buffer += part
        return buffer

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
            payload = json.loads(data.decode("utf-8"))
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
        cleanup_policy = payload.get("cleanup_policy", CleanupPolicy.KEEP.value)
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
        if action == "activate" and (raw_paths or context_menu):
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
        self.begin_draining()
        with self._lifecycle_lock:
            self._running = False
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
                self._tickets.clear()
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
        with self._lifecycle_lock:
            self._draining = True
            self._running = False
            tickets = list(self._tickets)
        for ticket in tickets:
            ticket.cancel_pending("server_stopping")


__all__ = [
    "ARCHIVE_EXTS",
    "BoundedIPCServer",
    "CONTEXT_AUTO_CLOSE_GRACE_MS",
    "EXTERNAL_CLEANUP_POLICIES",
    "ExternalIntakeRequest",
    "INSTANCE_STARTUP_POLL_SECONDS",
    "INSTANCE_STARTUP_WAIT_SECONDS",
    "IPCForwardResult",
    "IPC_FORWARD_ACCEPTED",
    "IPC_FORWARD_INDETERMINATE",
    "IPC_FORWARD_REJECTED",
    "IPC_FORWARD_UNAVAILABLE",
    "IPC_MAX_BYTES",
    "IPC_MAX_PATHS",
    "IPC_PORT",
    "IPC_VERSION",
    "PROCESSING_STATES",
    "SCAN_MODE_DEEP",
    "SCAN_MODE_NORMAL",
    "SCAN_MODE_STEGANOGRAPHIER",
    "STATUS_DISPLAY",
    "_forward_launch_request",
    "_ipc_state_path",
    "forward_to_existing",
    "parse_launch_args",
    "try_forward_to_existing",
]
