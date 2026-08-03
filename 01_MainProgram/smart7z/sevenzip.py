"""Serialized 7-Zip runner: one process-wide operation slot."""

from __future__ import annotations

import locale
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from models import ArchiveManifest, ArchiveMember, ErrorCategory

logger = logging.getLogger(__name__)

EXIT_SUCCESS = 0
EXIT_WARNING = 1
EXIT_FATAL = 2
EXIT_CMD_ERROR = 7
EXIT_MEMORY_ERROR = 8
EXIT_USER_CANCEL = 255

SWITCHES = ["", "-tzip", "-trar", "-t7z"]

# Process-wide single-operation gate (all runners share this).
_GLOBAL_OP_GATE = threading.Semaphore(1)
_GLOBAL_CURRENT_LOCK = threading.Lock()
_GLOBAL_CURRENT_PROC: Optional[subprocess.Popen] = None
_GLOBAL_CURRENT_OWNER: Optional[int] = None
_FORMAT_CACHE_LOCK = threading.Lock()
_FORMAT_CACHE: Dict[str, Set[str]] = {}

MAX_DIAG_LINES = 50
MAX_DIAG_BYTES = 64 * 1024
MAX_COMMAND_CAPTURE_BYTES = 1024 * 1024
MAX_PARSED_MEMBERS = 200_000
MAX_STREAM_LINE_BYTES = 256 * 1024

_SINGLE_STREAM_FORMATS = frozenset(
    {
        "brotli",
        "bzip2",
        "gzip",
        "lz4",
        "lzip",
        "lzma",
        "xz",
        "z",
        "zstd",
    }
)
_SINGLE_STREAM_SUFFIXES = (
    (".tbz2", ".tar"),
    (".tbz", ".tar"),
    (".txz", ".tar"),
    (".tlz", ".tar"),
    (".tgz", ".tar"),
    (".bzip2", ""),
    (".brotli", ""),
    (".lzma", ""),
    (".zstd", ""),
    (".bz2", ""),
    (".gzip", ""),
    (".lz4", ""),
    (".lzip", ""),
    (".xz", ""),
    (".gz", ""),
    (".lz", ""),
    (".zst", ""),
    (".br", ""),
    (".z", ""),
)


class SevenZipError(Exception):
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
        return_code: int = -1,
        *,
        listing_wall_ms: float = 0.0,
        parse_cpu_ms: float = 0.0,
        listing_attempts: int = 0,
        early_abort_reason: str = "",
    ):
        super().__init__(message)
        self.category = category
        self.return_code = return_code
        self.listing_wall_ms = max(0.0, float(listing_wall_ms))
        self.parse_cpu_ms = max(0.0, float(parse_cpu_ms))
        self.listing_attempts = max(0, int(listing_attempts))
        self.early_abort_reason = str(early_abort_reason or "")


@dataclass
class SevenZipResult:
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    cancelled: bool = False
    timed_out: bool = False
    output_truncated: bool = False
    line_truncated: bool = False
    monitor_stopped: bool = False
    consumer_stopped: bool = False
    consumer_failed: bool = False
    warning_detected: bool = False
    bad_password_detected: bool = False
    diagnostic_tail: str = ""
    raw_sample: bytes = field(default=b"", repr=False)


class _BoundedLineSplitter:
    """Split byte chunks into lines while bounding an unterminated tail."""

    def __init__(self, max_pending_bytes: int = MAX_STREAM_LINE_BYTES):
        self.max_pending_bytes = max(1, int(max_pending_bytes))
        self.pending = b""
        self.truncated = False

    def feed(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        data = self.pending + chunk
        lines = data.splitlines(keepends=True)
        if lines and not lines[-1].endswith((b"\n", b"\r")):
            self.pending = lines.pop()
        else:
            self.pending = b""
        if len(self.pending) > self.max_pending_bytes:
            self.pending = self.pending[-self.max_pending_bytes :]
            self.truncated = True
        return lines

    def finish(self) -> bytes:
        pending = self.pending
        self.pending = b""
        return pending


def classify_return_code(code: int) -> Tuple[bool, Optional[ErrorCategory]]:
    if code == EXIT_SUCCESS:
        return True, None
    if code == EXIT_WARNING:
        return True, ErrorCategory.VERIFY_FAILED
    if code == EXIT_FATAL:
        return False, ErrorCategory.INTERNAL_ERROR
    if code == EXIT_CMD_ERROR:
        return False, ErrorCategory.UNSUPPORTED_FORMAT
    if code == EXIT_MEMORY_ERROR:
        return False, ErrorCategory.INTERNAL_ERROR
    if code == EXIT_USER_CANCEL:
        return False, ErrorCategory.CANCELLED
    return False, ErrorCategory.INTERNAL_ERROR


def is_clean_success(code: int) -> bool:
    return code == EXIT_SUCCESS


def is_warning(code: int) -> bool:
    return code == EXIT_WARNING


def is_failure(code: int) -> bool:
    return code not in (EXIT_SUCCESS, EXIT_WARNING)


def format_command(cmd: List[str]) -> str:
    return " ".join(redact_command(cmd))


def redact_command(cmd: List[str]) -> List[str]:
    """Return shell-formatted arguments without exposing 7-Zip passwords."""

    safe = []
    for value in cmd:
        text = str(value)
        if text.startswith("-p") and text != "-p-":
            text = "-p******"
        safe.append(subprocess.list2cmdline([text]))
    return safe


def redact_text(text: str) -> str:
    return re.sub(r"(?<!\S)-p(?!-)(?:\"[^\"]*\"|'[^']*'|\S+)", "-p******", text)


def decode_output(raw: bytes, encoding_order: Optional[List[str]] = None) -> str:
    if encoding_order is None:
        encoding_order = ["utf-8"]
        try:
            encoding_order.append(locale.getpreferredencoding(False))
        except Exception:
            pass
        encoding_order.append("cp1252")
        encoding_order.append("gbk")

    for enc in encoding_order:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _make_startupinfo():
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return si
    return None


def _english_env() -> dict:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["LANGUAGE"] = "C"
    return env


def _set_global_process(
    proc: Optional[subprocess.Popen], owner: Optional[int] = None
) -> None:
    global _GLOBAL_CURRENT_PROC, _GLOBAL_CURRENT_OWNER
    with _GLOBAL_CURRENT_LOCK:
        _GLOBAL_CURRENT_PROC = proc
        _GLOBAL_CURRENT_OWNER = owner if proc is not None else None


def terminate_process_tree(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            # Kill the whole process tree.  ``taskkill`` itself is bounded and
            # its return code is advisory; the Popen handle below remains the
            # source of truth.
            try:
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                    capture_output=True,
                    startupinfo=_make_startupinfo(),
                    timeout=3,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                proc.terminate()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning("Failed to terminate 7z process tree: %s", e)
        try:
            proc.kill()
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            logger.error("7z process did not terminate: pid=%s", proc.pid)


def cancel_any_current() -> None:
    with _GLOBAL_CURRENT_LOCK:
        proc = _GLOBAL_CURRENT_PROC
    if proc is not None:
        terminate_process_tree(proc)


def _targeted_type_switch(path: str) -> str:
    """Return at most one defensible fallback switch for *path*."""
    lower = path.lower()
    try:
        with open(path, "rb") as stream:
            signature = stream.read(8)
    except OSError:
        signature = b""
    if signature.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "-tzip"
    if signature.startswith(b"Rar!\x1a\x07"):
        return "-trar"
    if signature.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "-t7z"
    if lower.endswith((".zip", ".z01", ".z02", ".z03")):
        return "-tzip"
    if lower.endswith((".rar", ".r00", ".r01", ".r02")) or re.search(
        r"\.part\d+\.rar$", lower
    ):
        return "-trar"
    if lower.endswith(".7z"):
        return "-t7z"
    return ""


class SltStreamParser:
    """Incrementally parse UTF-8 ``7z l -slt`` output with bounded lines."""

    def __init__(
        self,
        max_members: int = MAX_PARSED_MEMBERS,
        *,
        stop_after_entries: Optional[int] = None,
        max_line_bytes: int = MAX_STREAM_LINE_BYTES,
    ):
        self.max_members = max(1, int(max_members))
        self.stop_after_entries = (
            None
            if stop_after_entries is None
            else max(1, int(stop_after_entries))
        )
        self.max_line_bytes = max(1, int(max_line_bytes))
        self.manifest = ArchiveManifest()
        self.saw_files_separator = False
        self.limit_exceeded = False
        self.line_limit_exceeded = False
        self._current_file: Dict[str, str] = {}
        self._archive_headers: Dict[str, str] = {}
        self._pending = b""
        self._parse_cpu_ns = 0
        self._finished = False

    @property
    def should_stop(self) -> bool:
        return self.limit_exceeded or self.line_limit_exceeded

    @property
    def parse_cpu_ms(self) -> float:
        return max(0.0, self._parse_cpu_ns / 1_000_000.0)

    def feed_bytes(self, chunk: bytes) -> None:
        if not chunk or self._finished or self.should_stop:
            return
        started_ns = time.perf_counter_ns()
        try:
            self._consume_bytes(bytes(chunk))
        finally:
            self._parse_cpu_ns += time.perf_counter_ns() - started_ns

    def _consume_bytes(self, chunk: bytes) -> None:
        data = self._pending + chunk
        cursor = 0
        data_length = len(data)

        while cursor < data_length:
            lf_index = data.find(b"\n", cursor)
            cr_index = data.find(b"\r", cursor)
            indexes = [index for index in (lf_index, cr_index) if index >= 0]
            if not indexes:
                break
            separator = min(indexes)
            if data[separator:separator + 1] == b"\r":
                if separator + 1 >= data_length:
                    break
                line_end = separator + (
                    2 if data[separator + 1:separator + 2] == b"\n" else 1
                )
            else:
                line_end = separator + 1
            raw_line = data[cursor:line_end]
            if len(raw_line) > self.max_line_bytes:
                self._mark_line_limit()
                self._pending = b""
                return
            self._feed_line(raw_line.decode("utf-8", errors="replace"))
            cursor = line_end
            if self.should_stop:
                self._pending = b""
                return

        self._pending = data[cursor:]
        if len(self._pending) > self.max_line_bytes:
            self._mark_line_limit()
            self._pending = b""

    def _mark_line_limit(self) -> None:
        self.line_limit_exceeded = True
        self.manifest.summary_mode = True
        self.manifest.early_abort_reason = "manifest_line_limit_exceeded"
        self.manifest.diagnostics.append(
            f"Manifest line exceeded {self.max_line_bytes} bytes"
        )

    def _flush_current(self) -> None:
        if not self._current_file:
            return
        _flush_member(self._current_file, self.manifest, self.max_members)
        self._current_file = {}
        if (
            self.stop_after_entries is not None
            and self.manifest.entry_count > self.stop_after_entries
        ):
            self.limit_exceeded = True
            self.manifest.summary_mode = True
            self.manifest.early_abort_reason = "manifest_limit_exceeded"
            self.manifest.diagnostics.append(
                "Manifest entry limit exceeded "
                f"({self.stop_after_entries})"
            )

    def _feed_line(self, line: str) -> None:
        raw = line.rstrip("\r\n")
        stripped = raw.strip()

        if stripped == "----------":
            self._flush_current()
            self.saw_files_separator = True
            self._current_file = {}
            return

        if not self.saw_files_separator:
            if "=" in raw:
                key, val = raw.split("=", 1)
                key = key.strip()
                val = val[1:] if val.startswith(" ") else val
                if key not in {"Path", "Symbolic Link", "Hard Link", "Link"}:
                    val = val.strip()
                self._archive_headers[key] = val
                if key == "Type" and not self.manifest.format:
                    self.manifest.format = val.lower()
            return

        if not stripped:
            self._flush_current()
            return

        if "=" in raw:
            key, val = raw.split("=", 1)
            key = key.strip()
            val = val[1:] if val.startswith(" ") else val
            if key not in {"Path", "Symbolic Link", "Hard Link", "Link"}:
                val = val.strip()
            self._current_file[key] = val

    def finish(self) -> ArchiveManifest:
        if self._finished:
            return self.manifest
        started_ns = time.perf_counter_ns()
        try:
            if not self.should_stop and self._pending:
                if len(self._pending) > self.max_line_bytes:
                    self._mark_line_limit()
                else:
                    self._feed_line(
                        self._pending.decode("utf-8", errors="replace")
                    )
            self._pending = b""
            if not self.should_stop:
                self._flush_current()
            if self._archive_headers.get("Encrypted") == "+":
                self.manifest.is_encrypted = True
            self.manifest.raw_fields = {
                key: value
                for key, value in self._archive_headers.items()
                if key
                in (
                    "Type",
                    "Physical Size",
                    "Encrypted",
                    "Volumes",
                    "Volume Index",
                )
            }
            self._finished = True
            return self.manifest
        finally:
            self._parse_cpu_ns += time.perf_counter_ns() - started_ns


def parse_slt(
    stdout: str, max_members: int = MAX_PARSED_MEMBERS
) -> ArchiveManifest:
    """Compatibility wrapper for parsing complete ``7z l -slt`` text."""
    parser = SltStreamParser(max_members=max_members)
    parser.feed_bytes(stdout.encode("utf-8", errors="replace"))
    return parser.finish()


def parse_supported_format_extensions(stdout: str) -> Set[str]:
    """Parse extension tokens from the ``7z i`` Formats table.

    The table is column-oriented and some rows include an optional secondary
    capability field.  Parsing arbitrary ``.token`` text from the whole output
    mistakes capability flags and codec identifiers for extensions, so only
    rows between ``Formats:`` and ``Codecs:`` are considered.
    """
    extensions: Set[str] = set()
    in_formats = False
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if line.strip() == "Formats:":
            in_formats = True
            continue
        if line.strip() == "Codecs:":
            break
        if not in_formats or not re.match(r"^\s*0\s", line):
            continue

        tokens = line.split()
        if len(tokens) < 4 or tokens[0] != "0":
            continue
        # tokens[1] is the main capability bitmap.  A five-character field
        # containing a dot may follow it (for example ``wud.0``).
        index = 2
        if (
            index < len(tokens)
            and len(tokens[index]) == 5
            and "." in tokens[index]
            and re.fullmatch(r"[A-Za-z0-9.+-]{5}", tokens[index])
        ):
            index += 1
        if index >= len(tokens):
            continue
        format_name = tokens[index].casefold()
        index += 1

        for token in tokens[index:]:
            if token.startswith("(") and token.endswith(")"):
                # A stream format annotation such as ``(.tar)`` is not a
                # separate extension advertised by this row.
                continue
            if token.startswith("offset=") or token == "||":
                break
            if any(char.isupper() for char in token):
                break
            if token.isdigit() or not re.fullmatch(r"[a-z0-9][a-z0-9+_-]*", token):
                break
            if len(token) == 1 and (format_name, token) not in {
                ("ar", "a"),
                ("z", "z"),
            }:
                # Most one-letter tokens after the extension column are a
                # textual signature (``k o l y`` etc.).
                break
            extensions.add("." + token.casefold())
    return extensions


def _flush_member(
    record: dict, manifest: ArchiveManifest, max_members: int
) -> None:
    path = record.get("Path") or record.get("path")
    if path is None and not record:
        return
    path = path or ""
    attrs = record.get("Attributes", "")
    folder_marker = record.get("Folder", "")
    is_dir = (
        (bool(attrs) and "D" in attrs.upper())
        or folder_marker == "+"
        or path.endswith("/")
        or path.endswith("\\")
    )
    raw_size = record.get("Size", record.get("size"))
    size = _safe_int(raw_size)
    link_target = (
        record.get("Symbolic Link", "")
        or record.get("Hard Link", "")
        or record.get("Link", "")
    )
    unix_link = attrs.lstrip().startswith("l")
    manifest.entry_count += 1
    if len(manifest.members) >= max_members:
        manifest.summary_mode = True
        if not manifest.diagnostics:
            manifest.diagnostics.append(
                f"Manifest member limit reached ({max_members})"
            )
        return
    member = ArchiveMember(
        path=path,
        attributes=attrs,
        size=size,
        packed_size=_safe_int(record.get("Packed Size", record.get("PackedSize", "0"))),
        method=record.get("Method", ""),
        encrypted=record.get("Encrypted", "") == "+",
        crc=record.get("CRC", ""),
        timestamp=record.get("Modified", record.get("Modified Time", "")),
        is_dir=is_dir,
        size_known=raw_size is not None and str(raw_size).strip() != "",
        is_link=bool(link_target) or unix_link,
        link_target=link_target,
        is_anti=record.get("Anti", "") == "+",
        is_alt_stream=record.get("Alternate Stream", "") == "+",
    )
    manifest.members.append(member)
    if not is_dir:
        manifest.total_size += member.size
    if member.encrypted:
        manifest.is_encrypted = True


def _safe_int(val: str) -> int:
    if val is None:
        return 0
    s = str(val).strip().replace(",", "").replace(" ", "")
    # Tolerate locale thousands separators like 1.234.567
    if s.count(".") > 1 and s.replace(".", "").isdigit():
        s = s.replace(".", "")
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def assert_manifest_fields(manifest: ArchiveManifest) -> None:
    """Raise if critical listing fields are missing after parse."""
    if not manifest.members:
        raise SevenZipError(
            "Listing produced no members (missing Path fields?)",
            ErrorCategory.INTERNAL_ERROR,
        )
    for m in manifest.members:
        if not m.path:
            raise SevenZipError(
                "Member missing Path field",
                ErrorCategory.INTERNAL_ERROR,
            )


def _populate_single_stream_member_path(
    manifest: ArchiveManifest, archive_path: str
) -> None:
    """Fill the output name omitted by SLT for nameless stream formats.

    7-Zip 26.02 emits a real member record for bzip2/xz/lzma streams but no
    ``Path`` field.  Extraction still creates one file derived from the input
    filename, so verification must use that same deterministic name.
    """

    if (
        len(manifest.members) != 1
        or manifest.members[0].path
        or manifest.format.casefold() not in _SINGLE_STREAM_FORMATS
    ):
        return

    archive_name = os.path.basename(archive_path)
    lower_name = archive_name.casefold()
    output_name = ""
    for suffix, replacement in _SINGLE_STREAM_SUFFIXES:
        if lower_name.endswith(suffix):
            output_name = archive_name[: -len(suffix)] + replacement
            break
    if not output_name:
        stem, extension = os.path.splitext(archive_name)
        output_name = stem if extension and stem else archive_name + ".out"
    manifest.members[0].path = output_name


def _detect_encryption_from_output(stdout: str, stderr: str) -> bool:
    combined = (stdout + stderr).lower()
    return "encrypted" in combined or "密码" in combined


def _detect_bad_password(stdout: str, stderr: str) -> bool:
    """Recognize actual 7-Zip password diagnostics, not member filenames."""

    combined = stdout + "\n" + stderr
    error_keywords = (
        "password is required",
        "wrong password",
        "cannot open encrypted",
        "data error in encrypted file",
        "crc failed in encrypted",
        "密码错误",
        "加密文件中数据错误",
        "加密文件中 crc 失败",
    )
    for raw_line in combined.splitlines():
        line = raw_line.strip()
        lower = line.casefold()
        if lower.startswith("enter password"):
            return True
        if lower.startswith(("wrong password", "password is required")):
            return True
        if lower.startswith(("error:", "errors:", "错误:", "错误：")) and any(
            keyword in lower for keyword in error_keywords
        ):
            return True
    return False


def _detect_fatal(stdout: str, stderr: str) -> Optional[str]:
    keywords = [
        "missing volume",
        "unexpected end of archive",
        "headers error",
        "is not archive",
        "cannot open the file as archive",
        "意外的归档结尾",
        "头错误",
        "不可预知的末端",
        "缺少卷",
        "不可预料的压缩文件末端",
    ]
    combined = stdout + stderr
    lower = combined.lower()
    for kw in keywords:
        if kw.lower() in lower or kw in combined:
            return kw
    return None


def _detect_warning_output(stdout: str, stderr: str = "") -> bool:
    combined = stdout + "\n" + stderr
    summary = re.compile(
        r"(?im)^\s*(?:warnings?|archives with warnings)\s*:\s*(?:[1-9]\d*)?\s*$"
    )
    localized_summary = re.compile(
        r"(?im)^\s*(?:警告|有警告的压缩包)\s*[：:]\s*(?:[1-9]\d*)?\s*$"
    )
    return bool(
        summary.search(combined)
        or localized_summary.search(combined)
        or "there are data after the end of archive" in combined.casefold()
        or "压缩包末尾有数据" in combined
        or "压缩包末尾存在数据" in combined
    )


def _bound_diag(text: str) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) > MAX_DIAG_LINES:
        lines = lines[-MAX_DIAG_LINES:]
    out = "\n".join(lines)
    if len(out.encode("utf-8", errors="replace")) > MAX_DIAG_BYTES:
        out = out.encode("utf-8", errors="replace")[-MAX_DIAG_BYTES:].decode(
            "utf-8", errors="replace"
        )
    return out


class SevenZipRunner:
    def __init__(
        self,
        sevenzip_path: str,
        cancel_check: Optional[Callable[[], bool]] = None,
        encoding_order: Optional[List[str]] = None,
    ):
        self.sevenzip_path = sevenzip_path
        self.cancel_check = cancel_check or (lambda: False)
        self.encoding_order = encoding_order
        self._local_proc: Optional[subprocess.Popen] = None
        self._local_lock = threading.Lock()

    def _build_cmd(
        self,
        action: str,
        target: str,
        output_dir: str = None,
        password: str = None,
        type_switch: str = "",
    ) -> List[str]:
        cmd = [self.sevenzip_path, action]
        if action == "l":
            cmd.append("-slt")
        cmd.append(target)
        if output_dir:
            cmd.append(f"-o{output_dir}")
        if type_switch:
            cmd.append(type_switch)
        if action in ("x", "e"):
            cmd.append("-y")
            cmd.append("-bsp1")
            cmd.append("-bse1")
        cmd.append("-sccUTF-8")
        if password is not None:
            cmd.append(f"-p{password}")
        return cmd

    def list(
        self,
        path: str,
        password: str = None,
        type_switch: str = "",
        timeout: int = 30,
        manifest_entry_limit: int = MAX_PARSED_MEMBERS,
    ) -> ArchiveManifest:
        listing_started_ns = time.perf_counter_ns()
        parse_cpu_ms = 0.0
        entry_limit = max(
            1,
            min(int(manifest_entry_limit), MAX_PARSED_MEMBERS),
        )
        parser = SltStreamParser(
            max_members=entry_limit,
            stop_after_entries=entry_limit,
        )

        def listing_error(
            message: str,
            category: ErrorCategory,
            return_code: int,
            *,
            early_abort_reason: str = "",
        ) -> SevenZipError:
            return SevenZipError(
                message,
                category,
                return_code,
                listing_wall_ms=(time.perf_counter_ns() - listing_started_ns)
                / 1_000_000.0,
                parse_cpu_ms=parse_cpu_ms,
                listing_attempts=1,
                early_abort_reason=early_abort_reason,
            )

        cmd = self._build_cmd("l", path, password=password, type_switch=type_switch)
        file_size = os.path.getsize(path) if os.path.exists(path) else 0
        effective_timeout = 120 if file_size > 5 * 1024**3 else timeout

        result = self._run_popen(
            cmd,
            effective_timeout,
            capture_limit=MAX_COMMAND_CAPTURE_BYTES,
            stdout_consumer=parser.feed_bytes,
            stop_check=lambda: parser.should_stop,
            capture_stdout=False,
        )
        if result.stdout:
            parser.feed_bytes(result.stdout.encode("utf-8", errors="replace"))
        manifest = parser.finish()
        parse_cpu_ms = parser.parse_cpu_ms
        _populate_single_stream_member_path(manifest, path)
        manifest.used_switch = type_switch
        manifest.listing_return_code = result.return_code

        if result.consumer_failed:
            raise listing_error(
                "Streaming manifest parser failed",
                ErrorCategory.INTERNAL_ERROR,
                result.return_code,
                early_abort_reason="manifest_parser_failed",
            )
        if parser.line_limit_exceeded:
            raise listing_error(
                "Archive manifest contains an overlong field line",
                ErrorCategory.VERIFY_FAILED,
                result.return_code,
                early_abort_reason="manifest_line_limit_exceeded",
            )
        if parser.limit_exceeded:
            manifest.listing_wall_ms = (
                time.perf_counter_ns() - listing_started_ns
            ) / 1_000_000.0
            manifest.parse_cpu_ms = parse_cpu_ms
            manifest.listing_attempts = 1
            return manifest

        if result.cancelled:
            raise listing_error("Operation cancelled", ErrorCategory.CANCELLED, -1)
        if result.timed_out:
            raise listing_error(
                f"Timeout ({effective_timeout}s)", ErrorCategory.TIMEOUT, -1
            )

        diagnostic = result.diagnostic_tail
        if result.bad_password_detected:
            raise listing_error(
                "Bad password", ErrorCategory.BAD_PASSWORD, result.return_code
            )

        fatal_kw = _detect_fatal(result.stdout + diagnostic, result.stderr)
        if fatal_kw and result.return_code not in (EXIT_SUCCESS, EXIT_WARNING):
            cat = (
                ErrorCategory.MISSING_VOLUME
                if "volume" in fatal_kw.lower() or "卷" in fatal_kw
                else ErrorCategory.CORRUPT_HEADER
            )
            raise listing_error(f"Fatal: {fatal_kw}", cat, result.return_code)

        if result.return_code in (EXIT_SUCCESS, EXIT_WARNING):
            manifest.listing_return_code = (
                EXIT_WARNING
                if result.return_code == EXIT_SUCCESS and result.warning_detected
                else result.return_code
            )
            if result.warning_detected:
                manifest.diagnostics.append("7-Zip reported warnings during listing")
            if not manifest.format:
                manifest.format = type_switch.lstrip("-t") if type_switch else "unknown"
            # A successful SLT listing with a parsed archive type and an
            # explicit file-record separator but no records is an empty
            # archive.  This is locale-independent; current 7-Zip versions do
            # not necessarily print a ``Files = 0`` summary for it.
            valid_empty = bool(manifest.format) and parser.saw_files_separator
            if not manifest.members and not valid_empty:
                raise listing_error(
                    "Listing produced no archive members",
                    ErrorCategory.NOT_ARCHIVE,
                    result.return_code,
                )
            if manifest.members:
                assert_manifest_fields(manifest)
            manifest.listing_wall_ms = (
                time.perf_counter_ns() - listing_started_ns
            ) / 1_000_000.0
            manifest.parse_cpu_ms = parse_cpu_ms
            manifest.listing_attempts = 1
            return manifest

        raise listing_error(
            _bound_diag(result.stderr) or f"Read failed Code {result.return_code}",
            ErrorCategory.NOT_ARCHIVE,
            result.return_code,
        )

    def list_with_fallback(
        self,
        path: str,
        password: str = None,
        timeout: int = 30,
        manifest_entry_limit: int = MAX_PARSED_MEMBERS,
    ) -> ArchiveManifest:
        try:
            manifest = self.list(
                path,
                password=password,
                timeout=timeout,
                manifest_entry_limit=manifest_entry_limit,
            )
            manifest.listing_attempts = max(1, manifest.listing_attempts)
            return manifest
        except SevenZipError as first_error:
            first_error.listing_attempts = max(1, first_error.listing_attempts)
            if first_error.category not in (
                ErrorCategory.NOT_ARCHIVE,
                ErrorCategory.CORRUPT_HEADER,
            ):
                raise
            switch = _targeted_type_switch(path)
            if not switch:
                raise
            try:
                manifest = self.list(
                    path,
                    password=password,
                    type_switch=switch,
                    timeout=timeout,
                    manifest_entry_limit=manifest_entry_limit,
                )
                manifest.listing_wall_ms += first_error.listing_wall_ms
                manifest.parse_cpu_ms += first_error.parse_cpu_ms
                manifest.listing_attempts = (
                    max(1, manifest.listing_attempts)
                    + first_error.listing_attempts
                )
                return manifest
            except SevenZipError as fallback_error:
                fallback_error.listing_wall_ms += first_error.listing_wall_ms
                fallback_error.parse_cpu_ms += first_error.parse_cpu_ms
                fallback_error.listing_attempts = (
                    max(1, fallback_error.listing_attempts)
                    + first_error.listing_attempts
                )
                if not fallback_error.early_abort_reason:
                    fallback_error.early_abort_reason = first_error.early_abort_reason
                raise fallback_error from first_error

    def supported_formats(self, timeout: int = 30) -> Set[str]:
        """Query ``7z i`` once per executable and return advertised extensions."""
        cache_key = os.path.normcase(os.path.abspath(self.sevenzip_path))
        with _FORMAT_CACHE_LOCK:
            cached = _FORMAT_CACHE.get(cache_key)
            if cached is not None:
                return set(cached)
        result = self.raw(["i"], timeout=timeout)
        formats: Set[str] = set()
        if result.return_code == EXIT_SUCCESS:
            formats = parse_supported_format_extensions(result.stdout)
        if result.return_code == EXIT_SUCCESS:
            with _FORMAT_CACHE_LOCK:
                _FORMAT_CACHE[cache_key] = set(formats)
        return formats

    def extract(
        self,
        archive_path: str,
        output_dir: str,
        password: str = None,
        type_switch: str = "",
        progress_cb: Optional[Callable[[int], None]] = None,
        monitor_cb: Optional[Callable[[], bool]] = None,
        timeout: int = 0,
    ) -> SevenZipResult:
        os.makedirs(output_dir, exist_ok=True)
        cmd = self._build_cmd(
            "x",
            archive_path,
            output_dir=output_dir,
            password=password,
            type_switch=type_switch,
        )
        return self._run_popen(
            cmd,
            timeout,
            progress_cb=progress_cb,
            monitor_cb=monitor_cb,
            merge_stderr=True,
        )

    def test(
        self, path: str, password: str = None, timeout: int = 60
    ) -> SevenZipResult:
        cmd = self._build_cmd("t", path, password=password)
        return self._run_popen(cmd, timeout)

    def raw(self, args: List[str], timeout: int = 0) -> SevenZipResult:
        cmd = [self.sevenzip_path] + args
        return self._run_popen(cmd, timeout)

    def cancel_current(self) -> None:
        with self._local_lock:
            proc = self._local_proc
        if proc is not None:
            terminate_process_tree(proc)

    def _run_popen(
        self,
        cmd: List[str],
        timeout: int,
        progress_cb: Optional[Callable[[int], None]] = None,
        monitor_cb: Optional[Callable[[], bool]] = None,
        merge_stderr: bool = False,
        capture_limit: int = MAX_COMMAND_CAPTURE_BYTES,
        stdout_consumer: Optional[Callable[[bytes], None]] = None,
        stop_check: Optional[Callable[[], bool]] = None,
        capture_stdout: bool = True,
    ) -> SevenZipResult:
        result = SevenZipResult()
        si = _make_startupinfo()
        env = _english_env()
        logger.debug("CMD: %s", format_command(cmd))

        acquired = False
        # Always wait in bounded intervals.  Cancellation must remain
        # responsive even when another runner instance owns the process-wide
        # operation slot.
        while not acquired:
            if self.cancel_check():
                result.cancelled = True
                return result
            acquired = _GLOBAL_OP_GATE.acquire(timeout=0.2)

        try:
            if self.cancel_check():
                result.cancelled = True
                return result

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    startupinfo=si,
                    env=env,
                    bufsize=0,
                )
            except Exception as e:
                result.return_code = -1
                result.stderr = str(e)
                logger.error("7z spawn error: %s", result.stderr)
                return result

            with self._local_lock:
                self._local_proc = proc
            _set_global_process(proc, id(self))

            stdout_chunks: List[bytes] = []
            stderr_chunks: List[bytes] = []
            stdout_tail = deque(maxlen=MAX_DIAG_LINES)
            stderr_tail = deque(maxlen=MAX_DIAG_LINES)
            capture_lock = threading.Lock()
            consumer_failed = threading.Event()
            start = time.monotonic()

            def _read_stream(
                stream,
                bucket: List[bytes],
                tail,
                *,
                consumer: Optional[Callable[[bytes], None]] = None,
                capture_enabled: bool = True,
            ) -> None:
                captured = 0
                splitter = _BoundedLineSplitter()
                try:
                    while True:
                        chunk = stream.read(4096)
                        if not chunk:
                            break
                        if consumer is not None and not consumer_failed.is_set():
                            try:
                                consumer(chunk)
                            except Exception:
                                logger.exception("7z stdout consumer failed")
                                result.consumer_failed = True
                                consumer_failed.set()
                        if capture_enabled:
                            with capture_lock:
                                room = max(0, capture_limit - captured)
                                if room:
                                    piece = chunk[:room]
                                    bucket.append(piece)
                                    captured += len(piece)
                                if len(chunk) > room:
                                    result.output_truncated = True
                        for line in splitter.feed(chunk):
                            tail.append(line[-4096:])
                    pending = splitter.finish()
                    if pending:
                        tail.append(pending[-4096:])
                    if splitter.truncated:
                        result.line_truncated = True
                except (OSError, ValueError):
                    return

            readers = []
            if proc.stdout:
                t = threading.Thread(
                    target=_read_stream,
                    args=(proc.stdout, stdout_chunks, stdout_tail),
                    kwargs={
                        "consumer": stdout_consumer,
                        "capture_enabled": capture_stdout,
                    },
                    daemon=True,
                )
                t.start()
                readers.append(t)
            if proc.stderr and not merge_stderr:
                t = threading.Thread(
                    target=_read_stream,
                    args=(proc.stderr, stderr_chunks, stderr_tail),
                    daemon=True,
                )
                t.start()
                readers.append(t)

            # Progress polling from accumulated stdout
            last_pct = -1
            while proc.poll() is None:
                if self.cancel_check():
                    terminate_process_tree(proc)
                    result.cancelled = True
                    break
                if timeout and timeout > 0 and (time.monotonic() - start) > timeout:
                    terminate_process_tree(proc)
                    result.timed_out = True
                    break
                should_stop = consumer_failed.is_set()
                if not should_stop and stop_check is not None:
                    try:
                        should_stop = bool(stop_check())
                    except Exception:
                        logger.exception("7z stdout stop check failed")
                        result.consumer_failed = True
                        consumer_failed.set()
                        should_stop = True
                if should_stop:
                    terminate_process_tree(proc)
                    result.consumer_stopped = True
                    break
                if monitor_cb:
                    try:
                        keep_running = monitor_cb()
                    except (OSError, ValueError):
                        keep_running = False
                    if not keep_running:
                        terminate_process_tree(proc)
                        result.monitor_stopped = True
                        break
                if progress_cb and stdout_tail:
                    sample = b"".join(list(stdout_tail)[-4:])
                    text = decode_output(sample, self.encoding_order)
                    percentages = re.findall(r"(\d+)%", text)
                    if percentages:
                        pct = int(percentages[-1])
                        if pct != last_pct:
                            last_pct = pct
                            try:
                                progress_cb(pct)
                            except Exception:
                                pass
                time.sleep(0.05)

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_process_tree(proc)
                result.timed_out = True
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)

            for t in readers:
                t.join(timeout=2)

            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

            raw_out = b"".join(stdout_chunks)
            raw_err = b"".join(stderr_chunks)
            diagnostic_raw = b"".join(stdout_tail) + b"".join(stderr_tail)
            diagnostic = decode_output(diagnostic_raw, self.encoding_order)
            result.raw_sample = diagnostic.encode(
                "utf-8", errors="replace"
            )[-MAX_DIAG_BYTES:]
            # Streaming listing consumers own their structured data.  The
            # retained stdout/stderr text remains bounded diagnostic material.
            result.stdout = decode_output(raw_out, self.encoding_order)
            result.stderr = decode_output(raw_err, self.encoding_order)
            result.diagnostic_tail = _bound_diag(diagnostic)
            result.warning_detected = _detect_warning_output(
                result.stdout + "\n" + result.diagnostic_tail,
                result.stderr,
            )
            result.bad_password_detected = _detect_bad_password(
                result.stdout + "\n" + result.diagnostic_tail,
                result.stderr,
            )
            if (
                not result.cancelled
                and not result.timed_out
                and not result.monitor_stopped
                and not result.consumer_stopped
            ):
                result.return_code = proc.returncode if proc.returncode is not None else -1
            elif result.cancelled:
                result.return_code = EXIT_USER_CANCEL

            # Final progress scan
            if progress_cb and result.stdout:
                percentages = re.findall(r"(\d+)%", result.stdout)
                if percentages:
                    try:
                        progress_cb(int(percentages[-1]))
                    except Exception:
                        pass

            return result
        finally:
            with self._local_lock:
                self._local_proc = None
            with _GLOBAL_CURRENT_LOCK:
                is_owner = _GLOBAL_CURRENT_OWNER == id(self)
            if is_owner:
                _set_global_process(None)
            if acquired:
                _GLOBAL_OP_GATE.release()
