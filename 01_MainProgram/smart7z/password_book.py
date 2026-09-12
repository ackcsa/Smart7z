"""Bounded password candidates and lossless, conflict-checked book updates."""

import codecs
import io
import locale
import logging
import os
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


logger = logging.getLogger(__name__)
PASSWORD_FILE_MAX_BYTES = 4 * 1024 * 1024
PASSWORD_MAX_CANDIDATES = 10_000
PASSWORD_MAX_CHARS = 4096
_BOOK_LOCK = threading.RLock()


@dataclass(frozen=True)
class _Snapshot:
    raw: bytes = field(repr=False)
    identity: Optional[Tuple[int, ...]]


def _identity(info: os.stat_result) -> Tuple[int, ...]:
    # Windows path and handle stat APIs can disagree about ctime.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_snapshot(path: str) -> _Snapshot:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return _Snapshot(b"", None)
    if (
        not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        or before.st_size > PASSWORD_FILE_MAX_BYTES
    ):
        raise OSError("Password book is not a bounded regular file")
    with open(path, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(PASSWORD_FILE_MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (
        len(raw) > PASSWORD_FILE_MAX_BYTES
        or len(raw) != after.st_size
        or _identity(before) != _identity(opened)
        or _identity(opened) != _identity(after)
    ):
        raise OSError("Password book changed during reading")
    return _Snapshot(raw, _identity(after))


def _decode(raw: bytes) -> Tuple[str, str, bytes]:
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if raw.startswith(bom):
            return raw[len(bom):].decode(encoding), encoding, bom
    for encoding in dict.fromkeys(("utf-8", locale.getpreferredencoding(False), "cp1252", "gbk")):
        try:
            text = raw.decode(encoding)
            if text.encode(encoding) == raw:
                return text, encoding, b""
        except (UnicodeError, LookupError):
            continue
    raise ValueError("Password book encoding cannot be preserved")


def _lines(text: str) -> List[str]:
    with io.StringIO(text, newline="") as stream:
        return stream.readlines()


def read_password_candidates(path: str) -> List[str]:
    with _BOOK_LOCK:
        try:
            text, _encoding, _bom = _decode(_read_snapshot(path).raw)
        except (OSError, ValueError):
            logger.warning("Password book could not be read completely; candidates were skipped")
            return []
    values = []
    for line in _lines(text):
        value = line.rstrip("\r\n")
        if value and len(value) <= PASSWORD_MAX_CHARS and "\x00" not in value:
            values.append(value)
            if len(values) >= PASSWORD_MAX_CANDIDATES:
                break
    return values


def promote_password(path: str, password: str) -> bool:
    if not password or len(password) > PASSWORD_MAX_CHARS or any(c in password for c in "\r\n\x00"):
        return False
    with _BOOK_LOCK:
        fd = -1
        temporary = ""
        try:
            original = _read_snapshot(path)
            text, encoding, bom = _decode(original.raw)
            lines = _lines(text)
            newline = next(
                (line[len(line.rstrip("\r\n")):] for line in lines if line.endswith(("\r", "\n"))),
                "\n",
            )
            remaining = "".join(line for line in lines if line.rstrip("\r\n") != password)
            updated = bom + (password + newline + remaining).encode(encoding)
            if updated == original.raw:
                return True
            if len(updated) > PASSWORD_FILE_MAX_BYTES:
                raise OSError("Password book update would exceed the read limit")
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix="smart7z_passwords_", suffix=".tmp", dir=parent)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(updated)
                stream.flush()
                os.fsync(stream.fileno())
            # Candidate limits never apply to persistence. Recheck the complete
            # snapshot after flushing so an external edit is not overwritten.
            if _read_snapshot(path) != original:
                raise OSError("Password book changed before replacement")
            if original.identity is None:
                if os.name == "nt":
                    os.rename(temporary, path)
                else:
                    os.link(temporary, path)
            else:
                os.replace(temporary, path)
            return True
        except (OSError, ValueError):
            logger.warning("Password promotion was skipped; the existing book was not replaced")
            return False
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except OSError:
                    logger.warning("Could not remove a temporary password book")
