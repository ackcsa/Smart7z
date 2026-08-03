"""
Steganography candidate enumeration engine.

Replaces ``StegoDetector.quick_detect()`` with a structured,
extension-independent scanner that returns :class:`ArchiveCandidate`
instances with confidence, validation flags, and diagnostics.

Detection plugins:
- **ZIP/ZIP64** -- full boundary validation via local headers, central
  directory, EOCD/ZIP64 locator and record.
- **BMFF/ISO boxes** -- bounds-checked iterator with ``free``/``skip``/
  ``wide`` scanning and embedded-archive validation inside those boxes.
- **7z / RAR** -- bounded signature detection (low confidence).

The function does not rely on file extension. It supports both appended
archives (scan from end) and prepended containers. Candidates are scored:
complete structural validation > signature-only, shortest span preferred.
"""

import os
import stat
import struct
import logging
from typing import Callable, Iterator, List, Optional, Tuple

from models import ArchiveCandidate, Confidence

logger = logging.getLogger(__name__)

CancelCheck = Optional[Callable[[], bool]]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIG_LOCAL = b'PK\x03\x04'
SIG_CENTRAL = b'PK\x01\x02'
SIG_EOCD = b'PK\x05\x06'
SIG_ZIP64_RECORD = b'PK\x06\x06'
SIG_ZIP64_LOCATOR = b'PK\x06\x07'

SIG_RAR4 = b'Rar!\x1a\x07\x00'
SIG_RAR5 = b'Rar!\x1a\x07\x01\x00'
SIG_7Z = b'7z\xbc\xaf\x27\x1c'

EOCD_MIN_SIZE = 22
EOCD_MAX_COMMENT = 65557  # 22 + 65535

ZIP_LOCAL_HEADER_SIZE = 30
ZIP_CENTRAL_HEADER_SIZE = 46

BMFF_BOX_SIZE = 8
SCAN_CHUNK_BYTES = 1024 * 1024


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _read_at(path: str, offset: int, size: int) -> Optional[bytes]:
    """Read *size* bytes at *offset*; return None on failure."""
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read(size)
            if len(data) < size:
                return None
            return data
    except (IOError, OSError):
        return None


def _read_u16(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]


def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def _read_u64(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]


def _scan_occurrences(path: str, needle: bytes, start: int, end: int,
                      chunk_size: int = SCAN_CHUNK_BYTES,
                      max_results: int = 10_000,
                      cancel_check: CancelCheck = None) -> List[int]:
    """Find all occurrences of *needle* within [start, end)."""
    occurrences: List[int] = []
    try:
        with open(path, 'rb') as f:
            search_pos = start
            f.seek(start)
            overlap = len(needle) - 1
            prev_tail = b''
            while search_pos < end:
                if cancel_check is not None and cancel_check():
                    return occurrences
                read_size = min(chunk_size, end - search_pos)
                chunk = f.read(read_size)
                if not chunk:
                    break
                prefix = prev_tail[-overlap:] if overlap and prev_tail else b''
                scan = prefix + chunk
                scan_start = search_pos - len(prefix)
                local = scan.find(needle)
                while local != -1:
                    abs_off = scan_start + local
                    if abs_off >= start:
                        occurrences.append(abs_off)
                        if len(occurrences) >= max_results:
                            return occurrences
                    local = scan.find(needle, local + 1)
                search_pos += len(chunk)
                prev_tail = chunk
    except (IOError, OSError):
        pass
    return occurrences


# ---------------------------------------------------------------------------
# ZIP/ZIP64 structural validator
# ---------------------------------------------------------------------------

class _ZipGeometry:
    """Validated ZIP geometry computed from structural records."""

    def __init__(self):
        self.absolute_start: Optional[int] = None
        self.absolute_end: Optional[int] = None
        self.local_header_offsets: List[int] = []
        self.central_directory_offset: Optional[int] = None
        self.central_directory_size: int = 0
        self.entry_count: int = 0
        self.disk_number: int = 0
        self.cd_start_disk: int = 0
        self.total_entries: int = 0
        self.comment_length: int = 0
        self.is_zip64: bool = False
        self.zip64_record_offset: Optional[int] = None
        self.eocd_offset: Optional[int] = None
        self.flags: List[str] = []


def _validate_eocd_at(path: str, file_size: int,
                     eocd_offset: int) -> Optional[_ZipGeometry]:
    """Validate an EOCD record and build ZIP geometry. Returns None on failure."""
    raw = _read_at(path, eocd_offset, EOCD_MIN_SIZE)
    if raw is None:
        return None

    sig = _read_u32(raw, 0)
    if sig != 0x06054B50:
        return None

    disk = _read_u16(raw, 4)
    cd_start_disk = _read_u16(raw, 6)
    num_rec = _read_u16(raw, 8)
    total_rec = _read_u16(raw, 10)
    cd_size = _read_u32(raw, 12)
    cd_offset = _read_u32(raw, 16)
    comment_len = _read_u16(raw, 20)

    geom = _ZipGeometry()
    geom.eocd_offset = eocd_offset
    geom.disk_number = disk
    geom.cd_start_disk = cd_start_disk
    geom.entry_count = total_rec
    geom.total_entries = total_rec
    geom.cd_size = cd_size
    geom.comment_length = comment_len

    eocd_end = eocd_offset + EOCD_MIN_SIZE + comment_len
    if eocd_end > file_size:
        logger.debug("EOCD end exceeds file size at %d", eocd_offset)
        return None

    zip_end = eocd_end

    # Determine ZIP64
    is_zip64 = (cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF or
                num_rec == 0xFFFF or total_rec == 0xFFFF)
    geom.is_zip64 = is_zip64

    rel_cd_offset: Optional[int] = None
    abs_cd_offset: Optional[int] = None
    cd_size_final = cd_size

    if is_zip64:
        loc_result = _find_zip64_locator(path, file_size, eocd_offset)
        if loc_result is not None:
            rec_offset, locator_ok = loc_result
            geom.zip64_record_offset = rec_offset
            geom.flags.append("zip64_record_found")
            if locator_ok:
                geom.flags.append("zip64_locator_found")

            # ZIP64 end of central directory record layout (56 bytes minimum):
            # 0: sig (4), 4: record_size (8), 12: version_made (2),
            # 14: version_needed (2), 16: disk_number (4), 20: cd_start_disk (4),
            # 24: num_rec_this_disk (8), 32: total_rec (8), 40: cd_size (8),
            # 48: cd_offset (8)
            rec_raw = _read_at(path, rec_offset, 56)
            if rec_raw is not None:
                if _read_u32(rec_raw, 0) == 0x06064B50:
                    rec_disk = _read_u32(rec_raw, 16)
                    rec_cd_disk = _read_u32(rec_raw, 20)
                    rec_entries_disk = _read_u64(rec_raw, 24)
                    rec_entries_total = _read_u64(rec_raw, 32)
                    cd_size_64 = _read_u64(rec_raw, 40)
                    cd_offset_64 = _read_u64(rec_raw, 48)

                    # Validate consistency
                    geom.flags.append("zip64_record_valid")
                    if rec_entries_disk == rec_entries_total:
                        geom.flags.append("zip64_entry_count_valid")
                        geom.entry_count = rec_entries_total
                        geom.total_entries = rec_entries_total
                    cd_size_final = cd_size_64
                    rel_cd_offset = cd_offset_64

                    # Validate disk fields
                    if rec_disk == 0:
                        geom.flags.append("zip64_disk_valid")
                    if rec_cd_disk == 0:
                        geom.flags.append("zip64_cd_disk_valid")

                    geom.cd_size = cd_size_64
                    geom.central_directory_size = cd_size_64

                    # Absolute CD offset = rec_abs - cd_size (adjacent)
                    abs_cd_offset = rec_offset - cd_size_64

    empty_archive = (
        not is_zip64
        and disk == 0
        and cd_start_disk == 0
        and num_rec == 0
        and total_rec == 0
        and cd_size == 0
        and cd_offset == 0
    )

    if abs_cd_offset is None and empty_archive:
        # A valid empty ZIP consists only of its EOCD (plus an optional
        # comment), so there is no central-directory or local-header signature
        # to inspect.  Its origin is the EOCD itself.
        rel_cd_offset = 0
        abs_cd_offset = eocd_offset
        geom.central_directory_size = 0
        geom.flags.extend(
            ["empty_archive", "central_directory_valid", "local_header_not_required"]
        )
    elif abs_cd_offset is None:
        # Traditional ZIP fallback
        if cd_offset != 0xFFFFFFFF and cd_offset < eocd_offset and cd_size_final > 0:
            rel_cd_offset = cd_offset
            abs_cd_offset = eocd_offset - cd_size_final
        else:
            logger.debug("Cannot determine CD offset at EOCD %d", eocd_offset)
            return None

    if not is_zip64:
        geom.central_directory_size = cd_size_final

    if abs_cd_offset < 0 or (
        abs_cd_offset >= eocd_offset and not empty_archive
    ):
        logger.debug("Invalid abs_cd_offset: %d", abs_cd_offset)
        return None

    # Validate central directory signature
    if not empty_archive:
        cd_raw = _read_at(path, abs_cd_offset, 4)
        if cd_raw != SIG_CENTRAL:
            logger.debug("CD signature mismatch at %d", abs_cd_offset)
            return None
        geom.flags.append("central_directory_valid")

    geom.central_directory_offset = abs_cd_offset

    # Validate entry count bounds
    if total_rec == 0:
        if "empty_archive" not in geom.flags:
            geom.flags.append("empty_archive")
    elif total_rec < 65536:
        geom.flags.append("entry_count_reasonable")
    else:
        geom.flags.append("entry_count_large")

    # Compute ZIP container origin from geometry
    if rel_cd_offset is None:
        return None
    zip_start = abs_cd_offset - rel_cd_offset

    if zip_start < 0 or (
        zip_start >= abs_cd_offset and not empty_archive
    ):
        logger.debug("Invalid zip_start: %d", zip_start)
        return None

    geom.absolute_start = zip_start
    geom.absolute_end = zip_end

    if not empty_archive:
        # Validate first local header
        first_local_offset = _get_first_local_offset(
            path, abs_cd_offset, file_size, total_rec, cd_offset, cd_size, eocd_offset
        )
        if first_local_offset is None:
            logger.debug("Cannot determine first local header offset")
            return None
        first_local_abs = zip_start + first_local_offset

        if first_local_abs < zip_start or first_local_abs >= file_size:
            logger.debug("First local header out of bounds: %d", first_local_abs)
            return None

        lh_raw = _read_at(path, first_local_abs, 4)
        if lh_raw != SIG_LOCAL:
            logger.debug("Local header signature mismatch at %d", first_local_abs)
            return None
        geom.flags.append("local_header_valid")
        geom.local_header_offsets.append(first_local_abs)

    # Validate comment bounds
    if comment_len <= 65535:
        geom.flags.append("comment_bounds_valid")

    # Validate disk fields
    if disk == 0:
        geom.flags.append("disk_number_valid")
    if cd_start_disk == 0:
        geom.flags.append("cd_start_disk_valid")

    return geom


def _find_zip64_locator(path: str, file_size: int,
                        eocd_offset: int) -> Optional[Tuple[int, bool]]:
    """Find ZIP64 locator and record. Returns (record_offset, locator_found)."""
    search_window = min(eocd_offset, 4096)
    if search_window < 4:
        return None

    chunk = _read_at(path, eocd_offset - search_window, search_window)
    if chunk is None:
        return None

    loc_idx = chunk.rfind(SIG_ZIP64_LOCATOR)
    locator_found = loc_idx != -1

    if locator_found:
        loc_abs = eocd_offset - search_window + loc_idx
        # Record before locator
        rec_window = min(loc_abs, 2048)
        if rec_window < 4:
            return None
        rec_chunk = _read_at(path, loc_abs - rec_window, rec_window)
        if rec_chunk is None:
            return None
        rec_idx = rec_chunk.rfind(SIG_ZIP64_RECORD)
        if rec_idx != -1:
            return (loc_abs - rec_window + rec_idx, True)
        return None

    # Fallback: search for record directly
    rec_window = min(eocd_offset, 2048)
    if rec_window < 4:
        return None
    rec_chunk = _read_at(path, eocd_offset - rec_window, rec_window)
    if rec_chunk is None:
        return None
    rec_idx = rec_chunk.rfind(SIG_ZIP64_RECORD)
    if rec_idx != -1:
        return (eocd_offset - rec_window + rec_idx, False)
    return None


def _get_first_local_offset(path: str, cd_offset: int, file_size: int,
                            total_rec: int, cd_offset_field: int,
                            cd_size_field: int, eocd_offset: int) -> Optional[int]:
    """Extract the first local header offset from the central directory."""
    first_entry = _read_at(path, cd_offset, ZIP_CENTRAL_HEADER_SIZE)
    if first_entry is None:
        return None

    if _read_u32(first_entry, 0) != 0x02014B50:
        return None

    comp_size = _read_u32(first_entry, 20)
    uncomp_size = _read_u32(first_entry, 24)
    filename_len = _read_u16(first_entry, 28)
    extra_len = _read_u16(first_entry, 30)
    local_offset = _read_u32(first_entry, 42)

    # ZIP64 extra field extension
    if local_offset == 0xFFFFFFFF and extra_len > 0:
        extra_start = cd_offset + ZIP_CENTRAL_HEADER_SIZE + filename_len
        extra_data = _read_at(path, extra_start, extra_len)
        if extra_data is not None:
            pos = 0
            while pos + 4 <= len(extra_data):
                header_id, data_size = struct.unpack_from('<HH', extra_data, pos)
                if header_id == 0x0001:  # ZIP64 extension
                    inner = pos + 4
                    if uncomp_size == 0xFFFFFFFF:
                        inner += 8
                    if comp_size == 0xFFFFFFFF:
                        inner += 8
                    if inner + 8 <= pos + 4 + data_size:
                        return struct.unpack_from('<Q', extra_data, inner)[0]
                    break
                pos += 4 + data_size

    return local_offset


def _enumerate_local_headers(path: str, zip_start: int, zip_end: int,
                             geom: _ZipGeometry,
                             cancel_check: CancelCheck = None) -> List[int]:
    """Enumerate all local header offsets within ZIP bounds."""
    offsets = _scan_occurrences(
        path,
        SIG_LOCAL,
        zip_start,
        zip_end,
        cancel_check=cancel_check,
    )
    geom.local_header_offsets.extend(offsets)
    if offsets:
        geom.flags.append("multiple_local_headers" if len(offsets) > 1 else "single_local_header")
    return offsets


def _zip64_local_offset(extra: bytes, uncomp_size: int, comp_size: int,
                        local_offset: int, disk_start: int) -> Optional[Tuple[int, int]]:
    pos = 0
    while pos + 4 <= len(extra):
        header_id, data_size = struct.unpack_from('<HH', extra, pos)
        data_start = pos + 4
        data_end = data_start + data_size
        if data_end > len(extra):
            return None
        if header_id == 0x0001:
            cursor = data_start
            if uncomp_size == 0xFFFFFFFF:
                cursor += 8
            if comp_size == 0xFFFFFFFF:
                cursor += 8
            if local_offset == 0xFFFFFFFF:
                if cursor + 8 > data_end:
                    return None
                local_offset = _read_u64(extra, cursor)
                cursor += 8
            if disk_start == 0xFFFF:
                if cursor + 4 > data_end:
                    return None
                disk_start = _read_u32(extra, cursor)
            return local_offset, disk_start
        pos = data_end
    return None


def _validate_all_zip_entries(path: str, file_size: int,
                              geom: _ZipGeometry,
                              cancel_check: CancelCheck = None) -> bool:
    """Validate every central record and its referenced local header."""

    start = geom.central_directory_offset
    zip_start = geom.absolute_start
    if start is None or zip_start is None:
        return False
    end = start + geom.central_directory_size
    if end > file_size or end > (geom.eocd_offset or file_size):
        return False
    if geom.entry_count == 0:
        valid = geom.central_directory_size == 0 and start == end
        if valid:
            geom.flags.extend(
                [
                    "all_central_entries_valid",
                    "all_local_headers_valid",
                    "entry_count_matches",
                ]
            )
        return valid

    cursor = start
    parsed = 0
    local_offsets = set()
    while cursor < end:
        if cancel_check is not None and cancel_check():
            return False
        header = _read_at(path, cursor, ZIP_CENTRAL_HEADER_SIZE)
        if header is None or _read_u32(header, 0) != 0x02014B50:
            return False
        comp_size = _read_u32(header, 20)
        uncomp_size = _read_u32(header, 24)
        filename_len = _read_u16(header, 28)
        extra_len = _read_u16(header, 30)
        comment_len = _read_u16(header, 32)
        disk_start = _read_u16(header, 34)
        local_offset = _read_u32(header, 42)
        record_end = (
            cursor + ZIP_CENTRAL_HEADER_SIZE + filename_len + extra_len + comment_len
        )
        if record_end > end:
            return False
        filename = _read_at(path, cursor + ZIP_CENTRAL_HEADER_SIZE, filename_len)
        extra = _read_at(
            path, cursor + ZIP_CENTRAL_HEADER_SIZE + filename_len, extra_len
        )
        if filename is None or extra is None:
            return False
        if local_offset == 0xFFFFFFFF or disk_start == 0xFFFF:
            resolved = _zip64_local_offset(
                extra, uncomp_size, comp_size, local_offset, disk_start
            )
            if resolved is None:
                return False
            local_offset, disk_start = resolved
        if disk_start != 0:
            return False
        local_absolute = zip_start + local_offset
        if local_absolute in local_offsets or not zip_start <= local_absolute < start:
            return False
        local = _read_at(path, local_absolute, ZIP_LOCAL_HEADER_SIZE)
        if local is None or _read_u32(local, 0) != 0x04034B50:
            return False
        local_filename_len = _read_u16(local, 26)
        local_extra_len = _read_u16(local, 28)
        local_header_end = (
            local_absolute + ZIP_LOCAL_HEADER_SIZE + local_filename_len + local_extra_len
        )
        if local_header_end > start:
            return False
        local_filename = _read_at(
            path, local_absolute + ZIP_LOCAL_HEADER_SIZE, local_filename_len
        )
        if local_filename != filename:
            return False
        local_offsets.add(local_absolute)
        parsed += 1
        if parsed > geom.entry_count:
            return False
        cursor = record_end

    if cursor != end or parsed != geom.entry_count:
        return False
    geom.flags.extend(
        [
            "all_central_entries_valid",
            "all_local_headers_valid",
            "entry_count_matches",
        ]
    )
    return True


def _detect_zip_candidates(
    path: str,
    file_size: int,
    cancel_check: CancelCheck = None,
    enumerate_local_headers: bool = True,
) -> List[ArchiveCandidate]:
    """Detect and validate ZIP/ZIP64 candidates in a file."""
    candidates: List[ArchiveCandidate] = []

    if file_size < EOCD_MIN_SIZE:
        return candidates

    # Scan for all EOCD signatures with bounded memory.  Tail candidates are
    # collected first so a hostile file containing many false signatures near
    # its head cannot hide a normal appended archive from the result limit.
    eocd_offsets: List[int] = []
    seen_offsets = set()
    tail_region = min(file_size, EOCD_MAX_COMMENT * 4)
    tail_start = file_size - tail_region
    tail_scan_start = max(0, tail_start - (len(SIG_EOCD) - 1))
    tail_offsets = _scan_occurrences(
        path,
        SIG_EOCD,
        tail_scan_start,
        file_size,
        cancel_check=cancel_check,
    )
    for offset in tail_offsets:
        if offset not in seen_offsets:
            seen_offsets.add(offset)
            eocd_offsets.append(offset)
    if cancel_check is not None and cancel_check():
        return []

    # The prefix scan stops where the overlapping tail scan begins, avoiding
    # a second read of the normal EOCD region while retaining middle ZIPs.
    all_offsets = (
        _scan_occurrences(
            path,
            SIG_EOCD,
            0,
            tail_start,
            max_results=10_000,
            cancel_check=cancel_check,
        )
        if tail_start > 0
        else []
    )
    for offset in all_offsets:
        if offset not in seen_offsets:
            seen_offsets.add(offset)
            eocd_offsets.append(offset)
    if cancel_check is not None and cancel_check():
        return []

    for eocd_off in eocd_offsets:
        if cancel_check is not None and cancel_check():
            return []
        geom = _validate_eocd_at(path, file_size, eocd_off)
        if geom is None or geom.absolute_start is None:
            continue

        if enumerate_local_headers:
            # The complete candidate API retains richer diagnostics.  The
            # exact-only path validates local headers from central records and
            # does not need this additional full-span signature pass.
            _enumerate_local_headers(
                path,
                geom.absolute_start,
                geom.absolute_end,
                geom,
                cancel_check=cancel_check,
            )
            if cancel_check is not None and cancel_check():
                return []
        _validate_all_zip_entries(
            path, file_size, geom, cancel_check=cancel_check
        )

        # Determine confidence
        high_confidence_flags = {"local_header_valid", "central_directory_valid",
                                 "disk_number_valid", "comment_bounds_valid"}
        has_high_flags = sum(1 for f in geom.flags if f in high_confidence_flags)

        if "empty_archive" in geom.flags and has_high_flags >= 2:
            confidence = Confidence.HIGH
        elif has_high_flags >= 3 and geom.entry_count > 0:
            confidence = Confidence.HIGH
        elif has_high_flags >= 2:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        candidate = ArchiveCandidate(
            host_format=_detect_host_format(path, file_size),
            embedded_format="zip",
            start_offset=geom.absolute_start,
            end_offset=geom.absolute_end,
            mode="append" if geom.absolute_start > 0 else "inline",
            confidence=confidence,
            validation_flags=geom.flags,
            diagnostics=[
                f"EOCD@{eocd_off}",
                f"CD@{geom.central_directory_offset}",
                f"entries={geom.entry_count}",
                f"zip64={geom.is_zip64}",
                f"local_headers={len(geom.local_header_offsets)}",
                f"comment_len={geom.comment_length}",
            ]
        )
        candidates.append(candidate)

    return candidates


# ---------------------------------------------------------------------------
# BMFF/ISO Box iterator
# ---------------------------------------------------------------------------

def _iterate_boxes(path: str, offset: int, file_size: int,
                   parent_end: Optional[int] = None,
                   cancel_check: CancelCheck = None) -> Iterator[Tuple[int, int, bytes, bool]]:
    """Yield (box_offset, box_size, box_type, is_largesize) for BMFF boxes.

    Bounds-checked: aborts on malformed size but continues scanning siblings.
    Supports standard 32-bit size, largesize (size=1), size=0 (to parent end).
    """
    end = parent_end if parent_end is not None else file_size
    pos = offset

    while pos + BMFF_BOX_SIZE <= end:
        if cancel_check is not None and cancel_check():
            return
        raw = _read_at(path, pos, BMFF_BOX_SIZE)
        if raw is None:
            break

        size_32 = struct.unpack_from('>I', raw, 0)[0]
        box_type = raw[4:8]

        header_size = BMFF_BOX_SIZE
        is_large = False

        if size_32 == 1:
            # 64-bit largesize
            large_raw = _read_at(path, pos + 8, 8)
            if large_raw is None:
                break
            size = struct.unpack('>Q', large_raw)[0]
            header_size = 16
            is_large = True
        elif size_32 == 0:
            # Box extends to end of parent
            size = end - pos
        else:
            size = size_32

        if size < header_size:
            # Malformed box; skip this branch
            break

        actual_end = pos + size
        if actual_end > end:
            # Truncated box
            yield (pos, end - pos, box_type, is_large)
            break

        yield (pos, size, box_type, is_large)
        pos += size


def _detect_bmff_candidates(path: str, file_size: int,
                            cancel_check: CancelCheck = None) -> List[ArchiveCandidate]:
    """Detect archive candidates inside BMFF/ISO boxes."""
    candidates: List[ArchiveCandidate] = []

    if file_size < BMFF_BOX_SIZE:
        return candidates

    container_types = {
        b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts",
        b"udta", b"meta", b"ilst", b"dinf", b"mvex", b"moof",
        b"traf", b"mfra",
    }
    eligible_types = {b"free", b"skip", b"wide"}

    def walk(start: int, end: int, depth: int = 0) -> None:
        if (
            depth > 16
            or start >= end
            or (cancel_check is not None and cancel_check())
        ):
            return
        for box_offset, box_size, box_type, is_large in _iterate_boxes(
            path,
            start,
            file_size,
            parent_end=end,
            cancel_check=cancel_check,
        ):
            if cancel_check is not None and cancel_check():
                return
            header_size = 16 if is_large else BMFF_BOX_SIZE
            data_start = box_offset + header_size
            data_end = min(box_offset + box_size, end, file_size)
            if data_start > data_end:
                continue

            if box_type in eligible_types and data_end - data_start >= EOCD_MIN_SIZE:
                for eocd_off in _scan_occurrences(
                    path,
                    SIG_EOCD,
                    data_start,
                    data_end,
                    max_results=256,
                    cancel_check=cancel_check,
                ):
                    if cancel_check is not None and cancel_check():
                        return
                    geom = _validate_eocd_at(path, file_size, eocd_off)
                    if (
                        geom is None
                        or geom.absolute_start is None
                        or geom.absolute_end is None
                        or geom.absolute_start < data_start
                        or geom.absolute_end > data_end
                    ):
                        continue
                    flags = list(geom.flags)
                    if not _validate_all_zip_entries(
                        path, file_size, geom, cancel_check=cancel_check
                    ):
                        continue
                    flags = list(geom.flags)
                    flags.extend(
                        [
                            f"bmff_box_{box_type.decode('latin-1')}",
                            "bmff_box_bounds_valid",
                            "bmff_zip_complete",
                        ]
                    )
                    candidates.append(
                        ArchiveCandidate(
                            host_format="bmff",
                            embedded_format="zip",
                            start_offset=geom.absolute_start,
                            end_offset=geom.absolute_end,
                            mode="za",
                            confidence=Confidence.HIGH,
                            validation_flags=flags,
                            diagnostics=[
                                f"box@{box_offset} size={box_size}",
                                f"data_start={data_start}",
                                f"EOCD@{eocd_off}",
                            ],
                        )
                    )

            if box_type in container_types:
                child_start = data_start + (4 if box_type == b"meta" else 0)
                walk(child_start, data_end, depth + 1)

    walk(0, file_size)

    return candidates


# ---------------------------------------------------------------------------
# Signature-only detectors (7z, RAR)
# ---------------------------------------------------------------------------

def _detect_signature_candidates(path: str, file_size: int,
                                 cancel_check: CancelCheck = None) -> List[ArchiveCandidate]:
    """Detect 7z and RAR signatures as low-confidence candidates."""
    candidates: List[ArchiveCandidate] = []

    if file_size < 8:
        return candidates

    # 7z signature: 7z BC AF 27 1C
    sz_offsets = _scan_occurrences(
        path, SIG_7Z, 0, file_size, cancel_check=cancel_check
    )
    for off in sz_offsets:
        if cancel_check is not None and cancel_check():
            return []
        # Read version bytes for minimal validation
        ver_raw = _read_at(path, off + 6, 2)
        if ver_raw is not None:
            candidate = ArchiveCandidate(
                host_format=_detect_host_format(path, file_size),
                embedded_format="7z",
                start_offset=off,
                end_offset=file_size,
                mode="signature_only",
                confidence=Confidence.LOW,
                validation_flags=["7z_signature_match"],
                diagnostics=[
                    f"7z_sig@{off}",
                    f"version={ver_raw[0]}.{ver_raw[1]}",
                ]
            )
            candidates.append(candidate)

    # RAR4 and RAR5 signatures
    for sig, fmt in ((SIG_RAR4, "rar4"), (SIG_RAR5, "rar5")):
        rar_offsets = _scan_occurrences(
            path, sig, 0, file_size, cancel_check=cancel_check
        )
        for off in rar_offsets:
            if cancel_check is not None and cancel_check():
                return []
            candidate = ArchiveCandidate(
                host_format=_detect_host_format(path, file_size),
                embedded_format=fmt,
                start_offset=off,
                end_offset=file_size,
                mode="signature_only",
                confidence=Confidence.LOW,
                validation_flags=[f"{fmt}_signature_match"],
                diagnostics=[f"{fmt}_sig@{off}"]
            )
            candidates.append(candidate)

    return candidates


# ---------------------------------------------------------------------------
# Host format detection (structural, not extension-based)
# ---------------------------------------------------------------------------

def _detect_host_format(path: str, file_size: int) -> str:
    """Determine host file format from structural magic, not extension."""
    if file_size < 12:
        return "unknown"

    head = _read_at(path, 0, 16)
    if head is None:
        return "unknown"

    # BMFF/ISO
    if head[4:8] in (b'ftyp', b'moov', b'mdat', b'skids', b'wide'):
        return "bmff"

    # ZIP
    if head[:4] in (SIG_LOCAL, SIG_CENTRAL, SIG_EOCD):
        return "zip"

    # 7z
    if head[:6] == SIG_7Z:
        return "7z"

    # RAR
    if head[:7] == SIG_RAR4 or head[:8] == SIG_RAR5:
        return "rar"

    # ELF
    if head[:4] == b'\x7fELF':
        return "elf"

    # PE/MZ
    if head[:2] == b'MZ':
        return "pe"

    return "unknown"


# ---------------------------------------------------------------------------
# Candidate scoring and deduplication
# ---------------------------------------------------------------------------

def _score_candidate(cand: ArchiveCandidate) -> Tuple[int, int, int]:
    """Score a candidate for sorting. Higher is better.

    Returns (confidence_rank, -span_penalty, validation_depth).
    """
    conf_rank = {"high": 3, "medium": 2, "low": 1}.get(cand.confidence.value, 0)
    span = cand.end_offset - cand.start_offset
    val_depth = len(cand.validation_flags)
    return (conf_rank, -span, val_depth)


def _deduplicate_candidates(candidates: List[ArchiveCandidate]) -> List[ArchiveCandidate]:
    """Remove duplicate candidates keeping the highest-confidence/scored one."""
    by_key: dict = {}
    for cand in candidates:
        key = (cand.start_offset, cand.end_offset, cand.embedded_format)
        if key not in by_key or _score_candidate(cand) > _score_candidate(by_key[key]):
            by_key[key] = cand
    return sorted(by_key.values(), key=_score_candidate, reverse=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_candidates(path: str, cancel_check: CancelCheck = None) -> List[ArchiveCandidate]:
    """
    Scan *path* for embedded archive candidates.

    Returns a deduplicated, scored list of ArchiveCandidate instances sorted
    by confidence and completeness. Does not rely on file extension.

    Detection plugins:
    - ZIP/ZIP64 full structural validation
    - BMFF/ISO box walking with free/skip/wide scanning
    - 7z and RAR signature detection (low confidence)
    """
    candidates: List[ArchiveCandidate] = []

    if cancel_check is not None and cancel_check():
        return candidates

    try:
        file_size = _regular_file_size(path)
    except (OSError, ValueError):
        return candidates
    if file_size is None:
        return candidates
    if file_size < EOCD_MIN_SIZE:
        return candidates

    # ZIP/ZIP64 full structural validation
    candidates.extend(
        _detect_zip_candidates(path, file_size, cancel_check=cancel_check)
    )
    if cancel_check is not None and cancel_check():
        return []

    # BMFF box walking
    candidates.extend(
        _detect_bmff_candidates(path, file_size, cancel_check=cancel_check)
    )
    if cancel_check is not None and cancel_check():
        return []

    # Signature-only: 7z, RAR (bounded)
    candidates.extend(
        _detect_signature_candidates(path, file_size, cancel_check=cancel_check)
    )
    if cancel_check is not None and cancel_check():
        return []

    # Deduplicate and sort
    candidates = _deduplicate_candidates(candidates)

    return candidates


def is_exact_high_confidence_candidate(candidate: ArchiveCandidate) -> bool:
    """Return whether a candidate may drive unattended archive handling."""

    if (
        candidate.confidence != Confidence.HIGH
        or candidate.embedded_format.casefold() not in {"zip", "zip64"}
        or candidate.end_offset <= candidate.start_offset
        or candidate.mode == "signature_only"
    ):
        return False
    flags = {flag.casefold() for flag in candidate.validation_flags}
    if {"boundary_provisional", "end_provisional"} & flags:
        return False
    required = {
        "central_directory_valid",
        "comment_bounds_valid",
        "all_central_entries_valid",
        "all_local_headers_valid",
        "entry_count_matches",
    }
    if not required.issubset(flags):
        return False
    return "local_header_valid" in flags or "empty_archive" in flags


def find_exact_high_confidence_candidates(
    path: str, cancel_check: CancelCheck = None
) -> List[ArchiveCandidate]:
    """Find unattended ZIP candidates with one host-file signature pass."""

    if cancel_check is not None and cancel_check():
        return []
    try:
        file_size = _regular_file_size(path)
    except (OSError, ValueError):
        return []
    if file_size is None or file_size < EOCD_MIN_SIZE:
        return []
    candidates = _detect_zip_candidates(
        path,
        file_size,
        cancel_check=cancel_check,
        enumerate_local_headers=False,
    )
    return [
        candidate
        for candidate in _deduplicate_candidates(candidates)
        if is_exact_high_confidence_candidate(candidate)
    ]


def _regular_file_size(path: str) -> Optional[int]:
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        return None
    return max(0, int(info.st_size))
