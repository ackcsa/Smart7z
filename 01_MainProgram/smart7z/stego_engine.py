"""Compatibility facade for the structural steganography scanner.

The modern runtime uses :func:`stego_candidates.find_candidates` directly and
performs carving plus 7-Zip validation inside ``Executor``.  Older Smart7z
callers imported ``StegoDetector`` and ``StegoExtractor`` from this module, so
the names remain available without retaining the former, weaker ZIP parser.

Only one uniquely high-confidence, structurally complete ZIP candidate is
exposed through the legacy mode API.  Ambiguous, provisional, signature-only,
or non-ZIP candidates deliberately produce ``None`` and must be handled by the
modern candidate-review workflow.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

from models import ArchiveCandidate, Confidence
from stego_candidates import find_candidates


logger = logging.getLogger(__name__)

_COPY_BUFFER_SIZE = 1024 * 1024
_REQUIRED_ZIP_FLAGS = frozenset({"central_directory_valid", "local_header_valid"})


@dataclass(frozen=True)
class _FileSnapshot:
    """Identity fields used to reject a host changed during detection/copy."""

    device: int
    inode: int
    size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "_FileSnapshot":
        return cls(
            device=int(value.st_dev),
            inode=int(value.st_ino),
            size=int(value.st_size),
            mtime_ns=int(value.st_mtime_ns),
        )


def _snapshot(path: str) -> Optional[_FileSnapshot]:
    try:
        value = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError, TypeError):
        return None
    if not os.path.isfile(path):
        return None
    return _FileSnapshot.from_stat(value)


def _legacy_mode(candidate: ArchiveCandidate) -> Optional[str]:
    """Map a safe modern candidate to the historical mode identifiers."""

    if candidate.embedded_format.lower() != "zip":
        return None
    if candidate.mode == "za":
        return "za"
    if candidate.mode == "append" and candidate.start_offset > 0:
        return "append"
    return None


def _has_complete_zip_flags(candidate: ArchiveCandidate) -> bool:
    flags = {str(flag).lower() for flag in candidate.validation_flags}
    return (
        _REQUIRED_ZIP_FLAGS.issubset(flags)
        or {"empty_archive", "central_directory_valid"}.issubset(flags)
    )


def _is_complete_zip(candidate: ArchiveCandidate, file_size: int) -> bool:
    return (
        candidate.confidence is Confidence.HIGH
        and _legacy_mode(candidate) is not None
        and _has_complete_zip_flags(candidate)
        and 0 <= candidate.start_offset < candidate.end_offset <= file_size
    )


def _safe_candidates(path: str) -> Tuple[_FileSnapshot, list[ArchiveCandidate]]:
    before = _snapshot(path)
    if before is None:
        return _FileSnapshot(0, 0, 0, 0), []
    try:
        candidates = find_candidates(path)
    except (OSError, ValueError, EOFError, OverflowError):
        logger.exception("Structural candidate scan failed")
        return before, []
    after = _snapshot(path)
    if after != before:
        logger.warning("Structural host changed while it was being scanned")
        return before, []
    return before, [candidate for candidate in candidates if _is_complete_zip(candidate, before.size)]


def _unique_candidate(path: str, mode: Optional[str] = None) -> Optional[ArchiveCandidate]:
    _host, candidates = _safe_candidates(path)
    if mode is not None:
        candidates = [candidate for candidate in candidates if _legacy_mode(candidate) == mode]
    return candidates[0] if len(candidates) == 1 else None


def _candidate_bounds(path: str, mode: str) -> Optional[Tuple[int, int]]:
    candidate = _unique_candidate(path, mode)
    if candidate is None:
        return None
    return candidate.start_offset, candidate.end_offset


def _copy_exact_span(
    source_path: str,
    destination_path: str,
    candidate: ArchiveCandidate,
    expected_snapshot: _FileSnapshot,
) -> None:
    """Stream one immutable candidate span to a newly created file."""

    remaining = candidate.end_offset - candidate.start_offset
    with open(source_path, "rb") as source:
        if _FileSnapshot.from_stat(os.fstat(source.fileno())) != expected_snapshot:
            raise OSError("Structural host changed before carving")
        source.seek(candidate.start_offset)
        with open(destination_path, "xb") as destination:
            while remaining:
                block = source.read(min(_COPY_BUFFER_SIZE, remaining))
                if not block:
                    raise OSError("Structural host ended before the candidate boundary")
                destination.write(block)
                remaining -= len(block)
        if _FileSnapshot.from_stat(os.fstat(source.fileno())) != expected_snapshot:
            raise OSError("Structural host changed while carving")


def _carved_copy_is_exact(path: str, expected_size: int) -> bool:
    """Independently re-run structural validation against the carved result."""

    try:
        if os.path.getsize(path) != expected_size:
            return False
        matches = [
            candidate
            for candidate in find_candidates(path)
            if candidate.embedded_format.lower() == "zip"
            and candidate.start_offset == 0
            and candidate.end_offset == expected_size
            and candidate.confidence is Confidence.HIGH
            and _has_complete_zip_flags(candidate)
        ]
        return len(matches) == 1
    except (OSError, ValueError, EOFError, OverflowError):
        logger.exception("Carved ZIP structural revalidation failed")
        return False


class StegoDetector:
    """Legacy detector backed by the modern structural candidate API."""

    @staticmethod
    def quick_detect(file_path: str) -> Optional[str]:
        """Return ``append``/``za`` only for one safe, unambiguous candidate."""

        candidate = _unique_candidate(file_path)
        return _legacy_mode(candidate) if candidate is not None else None

    @staticmethod
    def _has_tail_eocd(path: str) -> bool:
        return _unique_candidate(path, "append") is not None

    @staticmethod
    def _has_za_signature(path: str) -> bool:
        return _unique_candidate(path, "za") is not None


class StegoExtractor:
    """Legacy exact-span copier for already validated ZIP candidates.

    The compatibility API does not know the application's configured 7-Zip
    executable.  It therefore performs an independent structural validation of
    the carved copy; callers must still list it through the serialized
    ``SevenZipRunner`` before password attempts or extraction, as the modern
    executor does.
    """

    @staticmethod
    def extract_embedded_zip(file_path: str, temp_dir: str, mode: str) -> Optional[str]:
        if mode not in {"append", "za"}:
            return None
        if not isinstance(temp_dir, (str, os.PathLike)):
            return None

        expected_snapshot, candidates = _safe_candidates(file_path)
        matching = [candidate for candidate in candidates if _legacy_mode(candidate) == mode]
        if len(matching) != 1:
            return None
        candidate = matching[0]

        try:
            os.makedirs(temp_dir, exist_ok=True)
            if not os.path.isdir(temp_dir):
                return None
            destination = os.path.join(os.fspath(temp_dir), f"stego_{uuid.uuid4().hex}.zip")
            _copy_exact_span(file_path, destination, candidate, expected_snapshot)
            if not _carved_copy_is_exact(destination, candidate.size):
                raise OSError("Carved ZIP failed independent structural validation")
            return destination
        except (OSError, ValueError, TypeError):
            logger.exception("Legacy structural ZIP extraction failed")
            try:
                if "destination" in locals() and os.path.isfile(destination):
                    os.unlink(destination)
            except OSError:
                logger.warning("Unable to remove rejected carved ZIP", exc_info=True)
            return None

    @staticmethod
    def _locate_zip_boundaries_append(file_path: str) -> Optional[Tuple[int, int]]:
        return _candidate_bounds(file_path, "append")

    @staticmethod
    def _locate_zip_boundaries_za(file_path: str) -> Optional[Tuple[int, int]]:
        return _candidate_bounds(file_path, "za")
