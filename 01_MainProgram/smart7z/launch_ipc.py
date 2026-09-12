"""Lightweight launch parsing and IPC forwarding for short-lived processes."""

from __future__ import annotations

import os
import sys


IPC_PORT = 59777
IPC_MAX_BYTES = 256 * 1024
IPC_MAX_PATHS = 2000
IPC_VERSION = 3
IPC_STATE_MAX_BYTES = 4096
IPC_ACK_TIMEOUT_SECONDS = 5.0
IPC_CONNECT_TIMEOUT_SECONDS = 0.2
INSTANCE_MUTEX_NAME = "Smart7z_Instance_Mutex"

EXTERNAL_CLEANUP_POLICIES = frozenset({"keep", "permanent"})

IPC_FORWARD_ACCEPTED = "accepted"
IPC_FORWARD_REJECTED = "rejected"
IPC_FORWARD_INDETERMINATE = "indeterminate"
IPC_FORWARD_UNAVAILABLE = "unavailable"


class IPCForwardResult(tuple):
    """Small immutable result without importing dataclasses on the fast path."""

    __slots__ = ()

    def __new__(cls, status: str, reason: str = "", server_reached: bool = False):
        return tuple.__new__(cls, (status, reason, server_reached))

    @property
    def status(self) -> str:
        return self[0]

    @property
    def reason(self) -> str:
        return self[1]

    @property
    def server_reached(self) -> bool:
        return self[2]

    @property
    def accepted(self) -> bool:
        return self.status == IPC_FORWARD_ACCEPTED

    @property
    def reached_existing(self) -> bool:
        return self.server_reached

    def __repr__(self) -> str:
        return (
            f"IPCForwardResult(status={self.status!r}, reason={self.reason!r}, "
            f"server_reached={self.server_reached!r})"
        )


class ExternalIntakeRequest(tuple):
    """Immutable shell request shared by the bootstrap and Qt runtime."""

    __slots__ = ()

    def __new__(
        cls,
        paths=(),
        auto_start: bool = True,
        cleanup_policy: str = "keep",
        extract_to_source: bool = False,
        context_menu: bool = False,
    ):
        return tuple.__new__(
            cls,
            (
                tuple(paths),
                auto_start,
                cleanup_policy,
                extract_to_source,
                context_menu,
            ),
        )

    @property
    def paths(self):
        return self[0]

    @property
    def auto_start(self) -> bool:
        return self[1]

    @property
    def cleanup_policy(self) -> str:
        return self[2]

    @property
    def extract_to_source(self) -> bool:
        return self[3]

    @property
    def context_menu(self) -> bool:
        return self[4]

    @property
    def action(self) -> str:
        return "enqueue" if self.paths else "activate"

    def __repr__(self) -> str:
        return (
            f"ExternalIntakeRequest(paths={self.paths!r}, "
            f"auto_start={self.auto_start!r}, "
            f"cleanup_policy={self.cleanup_policy!r}, "
            f"extract_to_source={self.extract_to_source!r}, "
            f"context_menu={self.context_menu!r})"
        )


def parse_launch_args(args) -> ExternalIntakeRequest:
    """Parse shell flags without consuming path-like values after ``--``."""

    paths = []
    auto_start = True
    cleanup_policy = "keep"
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
            cleanup_policy = "keep"
        elif parse_options and value == "--delete-source":
            cleanup_policy = "permanent"
        elif parse_options and value == "--extract-here":
            extract_to_source = True
        elif parse_options and value == "--context-menu":
            context_menu = True
        else:
            paths.append(value)
    return ExternalIntakeRequest(
        paths,
        auto_start,
        cleanup_policy,
        extract_to_source,
        context_menu,
    )


def _ipc_state_path() -> str:
    # All copies use the same instance lock, so discovery must be copy-independent.
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.environ.get("TMP")
    if not base:
        import tempfile

        base = tempfile.gettempdir()
    state_root = os.path.join(os.path.abspath(base), "Smart7z")
    return os.path.join(state_root, f"ipc-v{IPC_VERSION}.json")


def _instance_mutex_exists(name: str = INSTANCE_MUTEX_NAME):
    """Return False only when Windows confirms that no app mutex exists."""

    if sys.platform != "win32":
        return None
    try:
        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_mutex = kernel32.OpenMutexW
        open_mutex.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
        open_mutex.restype = ctypes.wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.wintypes.HANDLE]
        close_handle.restype = ctypes.wintypes.BOOL
        ctypes.set_last_error(0)
        handle = open_mutex(0x00100000, False, name)
        if handle:
            close_handle(handle)
            return True
        error = ctypes.get_last_error()
        if error == 2:
            return False
        if error == 5:
            return True
    except (AttributeError, OSError, ValueError):
        pass
    return None


def _read_ipc_state(path=None):
    state_path = path or _ipc_state_path()
    try:
        with open(state_path, "rb") as stream:
            raw = stream.read(IPC_STATE_MAX_BYTES + 1)
        if len(raw) > IPC_STATE_MAX_BYTES:
            return None
        import json

        state = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(state, dict) or state.get("version") != IPC_VERSION:
        return None
    token = state.get("token")
    port = state.get("port")
    pid = state.get("pid")
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    return state


def _normalize_ipc_path(path: str):
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        return None
    try:
        from local_paths import is_local_filesystem_path

        normalized = os.path.abspath(os.path.normpath(path))
        if not is_local_filesystem_path(normalized):
            return None
        resolved = os.path.realpath(normalized)
        if not is_local_filesystem_path(resolved) or not os.path.exists(normalized):
            return None
    except (OSError, ValueError):
        return None
    return normalized


def _recv_exact(sock, count: int):
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def forward_to_existing(
    args,
    port=None,
    auto_start=True,
    cleanup_policy="keep",
    extract_to_source=False,
    context_menu=False,
    token=None,
    state_path=None,
) -> IPCForwardResult:
    if not isinstance(auto_start, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_auto_start")
    if not isinstance(cleanup_policy, str) or cleanup_policy not in EXTERNAL_CLEANUP_POLICIES:
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_cleanup_policy")
    if not isinstance(extract_to_source, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_destination_mode")
    if not isinstance(context_menu, bool):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_context_menu")

    raw_paths = list(args)
    if len(raw_paths) > IPC_MAX_PATHS:
        return IPCForwardResult(IPC_FORWARD_REJECTED, "too_many_paths")
    if context_menu and not raw_paths:
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_context_menu")
    if any(not isinstance(value, str) or not value or "\x00" in value for value in raw_paths):
        return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_paths")

    if token is None:
        if state_path is None and _instance_mutex_exists() is False:
            return IPCForwardResult(IPC_FORWARD_UNAVAILABLE, "instance_unavailable")
        state = _read_ipc_state(state_path)
        if state is None:
            return IPCForwardResult(IPC_FORWARD_UNAVAILABLE, "state_unavailable")
        token = state["token"]
        if port is None:
            port = state["port"]
    if port is None:
        port = IPC_PORT

    normalized = []
    for value in raw_paths:
        path = _normalize_ipc_path(os.path.abspath(value))
        if path is None:
            return IPCForwardResult(IPC_FORWARD_REJECTED, "invalid_paths")
        normalized.append(path)

    import json
    import socket
    import struct

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(IPC_CONNECT_TIMEOUT_SECONDS)
            client.connect(("127.0.0.1", port))
            client.settimeout(IPC_ACK_TIMEOUT_SECONDS + 1.0)
            dispatch_attempted = True
            client.sendall(struct.pack("!I", len(payload)) + payload)
            client.shutdown(socket.SHUT_WR)
            header = _recv_exact(client, 4)
            if header is None:
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "reply_header_unavailable",
                    True,
                )
            (reply_length,) = struct.unpack("!I", header)
            if reply_length <= 0 or reply_length > 4096:
                return IPCForwardResult(IPC_FORWARD_INDETERMINATE, "invalid_reply", True)
            reply = _recv_exact(client, reply_length)
            if reply is None:
                return IPCForwardResult(
                    IPC_FORWARD_INDETERMINATE,
                    "reply_body_unavailable",
                    True,
                )
            try:
                response = json.loads(reply.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                return IPCForwardResult(IPC_FORWARD_INDETERMINATE, "invalid_reply", True)
            if not isinstance(response, dict):
                return IPCForwardResult(IPC_FORWARD_INDETERMINATE, "invalid_reply", True)
            reason = str(response.get("reason") or "not_accepted")
            if response.get("accepted") is True:
                return IPCForwardResult(IPC_FORWARD_ACCEPTED, reason, True)
            if reason == "dispatch_in_progress":
                return IPCForwardResult(IPC_FORWARD_INDETERMINATE, reason, True)
            return IPCForwardResult(IPC_FORWARD_REJECTED, reason, True)
    except socket.timeout:
        status = IPC_FORWARD_INDETERMINATE if dispatch_attempted else IPC_FORWARD_UNAVAILABLE
        return IPCForwardResult(status, "socket_timeout", dispatch_attempted)
    except (ConnectionRefusedError, OSError):
        status = IPC_FORWARD_INDETERMINATE if dispatch_attempted else IPC_FORWARD_UNAVAILABLE
        reason = "connection_lost" if dispatch_attempted else "connection_unavailable"
        return IPCForwardResult(status, reason, dispatch_attempted)


def try_forward_to_existing(
    args,
    port=None,
    auto_start=True,
    cleanup_policy="keep",
    extract_to_source=False,
    context_menu=False,
    token=None,
    state_path=None,
) -> bool:
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


def _forward_launch_request(request: ExternalIntakeRequest) -> IPCForwardResult:
    return forward_to_existing(
        request.paths,
        auto_start=request.auto_start,
        cleanup_policy=request.cleanup_policy,
        extract_to_source=request.extract_to_source,
        context_menu=request.context_menu,
    )


__all__ = [
    "EXTERNAL_CLEANUP_POLICIES",
    "ExternalIntakeRequest",
    "INSTANCE_MUTEX_NAME",
    "IPCForwardResult",
    "IPC_ACK_TIMEOUT_SECONDS",
    "IPC_CONNECT_TIMEOUT_SECONDS",
    "IPC_FORWARD_ACCEPTED",
    "IPC_FORWARD_INDETERMINATE",
    "IPC_FORWARD_REJECTED",
    "IPC_FORWARD_UNAVAILABLE",
    "IPC_MAX_BYTES",
    "IPC_MAX_PATHS",
    "IPC_PORT",
    "IPC_STATE_MAX_BYTES",
    "IPC_VERSION",
    "_forward_launch_request",
    "forward_to_existing",
    "parse_launch_args",
    "try_forward_to_existing",
]
