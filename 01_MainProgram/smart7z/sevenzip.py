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
MAX_LIST_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_CAPTURE_BYTES = 1024 * 1024
MAX_PARSED_MEMBERS = 200_000

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
    ):
        super().__init__(message)
        self.category = category
        self.return_code = return_code


@dataclass
class SevenZipResult:
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    cancelled: bool = False
    timed_out: bool = False
    output_truncated: bool = False
    monitor_stopped: bool = False
    warning_detected: bool = False
    bad_password_detected: bool = False
    diagnostic_tail: str = ""
    raw_sample: bytes = field(default=b"", repr=False)


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


def parse_slt(
    stdout: str, max_members: int = MAX_PARSED_MEMBERS
) -> ArchiveManifest:
    """Parse 7z -slt output. Tolerates field order and '=' in filenames."""
    manifest = ArchiveManifest()
    current_file: dict = {}
    in_files = False
    archive_headers: dict = {}

    for line in stdout.splitlines():
        raw = line.rstrip("\r\n")
        stripped = raw.strip()

        if stripped == "----------":
            if current_file:
                _flush_member(current_file, manifest, max_members)
            in_files = True
            current_file = {}
            continue

        if not in_files:
            if "=" in raw:
                key, val = raw.split("=", 1)
                key = key.strip()
                val = val[1:] if val.startswith(" ") else val
                if key not in {"Path", "Symbolic Link", "Hard Link", "Link"}:
                    val = val.strip()
                archive_headers[key] = val
                if key == "Type" and not manifest.format:
                    manifest.format = val.lower()
            continue

        if not stripped:
            if current_file:
                _flush_member(current_file, manifest, max_members)
                current_file = {}
            continue

        if "=" in raw:
            # First '=' only — values may contain '='
            key, val = raw.split("=", 1)
            key = key.strip()
            val = val[1:] if val.startswith(" ") else val
            if key not in {"Path", "Symbolic Link", "Hard Link", "Link"}:
                val = val.strip()
            current_file[key] = val

    if current_file:
        _flush_member(current_file, manifest, max_members)

    if archive_headers.get("Encrypted") == "+":
        manifest.is_encrypted = True
    manifest.raw_fields = {
        k: v
        for k, v in archive_headers.items()
        if k in ("Type", "Physical Size", "Encrypted", "Volumes", "Volume Index")
    }
    return manifest


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
    ) -> ArchiveManifest:
        cmd = self._build_cmd("l", path, password=password, type_switch=type_switch)
        file_size = os.path.getsize(path) if os.path.exists(path) else 0
        effective_timeout = 120 if file_size > 5 * 1024**3 else timeout

        result = self._run_popen(
            cmd, effective_timeout, capture_limit=MAX_LIST_CAPTURE_BYTES
        )

        if result.cancelled:
            raise SevenZipError("Operation cancelled", ErrorCategory.CANCELLED, -1)
        if result.timed_out:
            raise SevenZipError(
                f"Timeout ({effective_timeout}s)", ErrorCategory.TIMEOUT, -1
            )

        diagnostic = result.diagnostic_tail
        if result.bad_password_detected:
            raise SevenZipError(
                "Bad password", ErrorCategory.BAD_PASSWORD, result.return_code
            )

        fatal_kw = _detect_fatal(result.stdout + diagnostic, result.stderr)
        if fatal_kw and result.return_code not in (EXIT_SUCCESS, EXIT_WARNING):
            cat = (
                ErrorCategory.MISSING_VOLUME
                if "volume" in fatal_kw.lower() or "卷" in fatal_kw
                else ErrorCategory.CORRUPT_HEADER
            )
            raise SevenZipError(f"Fatal: {fatal_kw}", cat, result.return_code)

        if result.return_code in (EXIT_SUCCESS, EXIT_WARNING):
            manifest = parse_slt(result.stdout)
            _populate_single_stream_member_path(manifest, path)
            manifest.used_switch = type_switch
            manifest.listing_return_code = (
                EXIT_WARNING
                if result.return_code == EXIT_SUCCESS and result.warning_detected
                else result.return_code
            )
            if result.warning_detected:
                manifest.diagnostics.append("7-Zip reported warnings during listing")
            if result.output_truncated:
                manifest.summary_mode = True
                manifest.diagnostics.append(
                    "7-Zip listing exceeded the bounded capture limit"
                )
            if not manifest.format:
                manifest.format = type_switch.lstrip("-t") if type_switch else "unknown"
            # A successful SLT listing with a parsed archive type and an
            # explicit file-record separator but no records is an empty
            # archive.  This is locale-independent; current 7-Zip versions do
            # not necessarily print a ``Files = 0`` summary for it.
            valid_empty = bool(manifest.format) and "----------" in result.stdout
            if not manifest.members and not valid_empty:
                raise SevenZipError(
                    "Listing produced no archive members",
                    ErrorCategory.NOT_ARCHIVE,
                    result.return_code,
                )
            if manifest.is_encrypted and not password:
                raise SevenZipError(
                    "Encrypted archive",
                    ErrorCategory.BAD_PASSWORD,
                    result.return_code,
                )
            if manifest.members:
                assert_manifest_fields(manifest)
            return manifest

        raise SevenZipError(
            _bound_diag(result.stderr) or f"Read failed Code {result.return_code}",
            ErrorCategory.NOT_ARCHIVE,
            result.return_code,
        )

    def list_with_fallback(
        self, path: str, password: str = None, timeout: int = 30
    ) -> ArchiveManifest:
        try:
            return self.list(path, password=password, timeout=timeout)
        except SevenZipError as first_error:
            if first_error.category in (
                ErrorCategory.BAD_PASSWORD,
                ErrorCategory.CANCELLED,
                ErrorCategory.TIMEOUT,
            ):
                raise
            switch = _targeted_type_switch(path)
            if not switch:
                raise
            try:
                return self.list(
                    path,
                    password=password,
                    type_switch=switch,
                    timeout=timeout,
                )
            except SevenZipError as fallback_error:
                if fallback_error.category in (
                    ErrorCategory.BAD_PASSWORD,
                    ErrorCategory.CANCELLED,
                    ErrorCategory.TIMEOUT,
                ):
                    raise
                last_error = fallback_error
        if last_error:
            raise last_error
        raise SevenZipError("All format probes failed", ErrorCategory.NOT_ARCHIVE)

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
            start = time.monotonic()

            def _read_stream(stream, bucket: List[bytes], tail) -> None:
                captured = 0
                pending = b""
                try:
                    while True:
                        chunk = stream.read(4096)
                        if not chunk:
                            break
                        with capture_lock:
                            room = max(0, capture_limit - captured)
                            if room:
                                piece = chunk[:room]
                                bucket.append(piece)
                                captured += len(piece)
                            if len(chunk) > room:
                                result.output_truncated = True
                        pending += chunk
                        lines = pending.splitlines(keepends=True)
                        if lines and not lines[-1].endswith((b"\n", b"\r")):
                            pending = lines.pop()
                        else:
                            pending = b""
                        for line in lines:
                            tail.append(line[-4096:])
                    if pending:
                        tail.append(pending[-4096:])
                except (OSError, ValueError):
                    return

            readers = []
            if proc.stdout:
                t = threading.Thread(
                    target=_read_stream,
                    args=(proc.stdout, stdout_chunks, stdout_tail),
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
            # Listing needs the full bounded manifest.  Diagnostics remain a
            # separate, bounded tail so callers do not accidentally log it all.
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
            if not result.cancelled and not result.timed_out and not result.monitor_stopped:
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
