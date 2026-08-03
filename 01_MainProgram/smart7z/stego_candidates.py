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

import bisect
import os
import stat
import struct
import logging
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from models import ArchiveCandidate, Confidence

logger = logging.getLogger(__name__)

CancelCheck = Optional[Callable[[], bool]]
ProgressCallback = Optional[Callable[[int, int], None]]

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
ZIP64_RECORD_MIN_SIZE = 56
ZIP64_LOCATOR_SIZE = 20
ZIP64_RECORD_SEARCH_BYTES = 64 * 1024

ZIP_LOCAL_HEADER_SIZE = 30
ZIP_CENTRAL_HEADER_SIZE = 46

BMFF_BOX_SIZE = 8
SCAN_CHUNK_BYTES = 1024 * 1024
SCAN_SIGNATURES = (SIG_EOCD, SIG_7Z, SIG_RAR4, SIG_RAR5)


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


def _scan_signatures_once(
    path: str,
    needles: Iterable[bytes],
    start: int,
    end: int,
    *,
    chunk_size: int = SCAN_CHUNK_BYTES,
    max_results: int = 10_000,
    priority_tail_needle: Optional[bytes] = SIG_EOCD,
    progress_cb: ProgressCallback = None,
    cancel_check: CancelCheck = None,
) -> Dict[bytes, List[int]]:
    """Find several signatures in one sequential file read.

    EOCD results retain tail priority so a hostile prefix containing many
    false signatures cannot crowd out a normal appended archive.
    """

    unique_needles = tuple(dict.fromkeys(needles))
    results: Dict[bytes, List[int]] = {
        needle: [] for needle in unique_needles
    }
    if not unique_needles or start >= end:
        return results

    priority_prefix: List[int] = []
    priority_tail: List[int] = []
    priority_tail_start = max(start, end - (EOCD_MAX_COMMENT * 4))
    overlap = max(len(needle) for needle in unique_needles) - 1
    total = end - start

    try:
        with open(path, 'rb') as stream:
            search_pos = start
            stream.seek(start)
            previous_tail = b''
            while search_pos < end:
                if cancel_check is not None and cancel_check():
                    return results
                read_size = min(chunk_size, end - search_pos)
                chunk = stream.read(read_size)
                if not chunk:
                    break
                prefix = (
                    previous_tail[-overlap:]
                    if overlap and previous_tail
                    else b''
                )
                scan = prefix + chunk
                scan_start = search_pos - len(prefix)

                for needle in unique_needles:
                    local = scan.find(needle)
                    while local != -1:
                        absolute = scan_start + local
                        if absolute >= start:
                            if needle == priority_tail_needle:
                                target = (
                                    priority_tail
                                    if absolute >= priority_tail_start
                                    else priority_prefix
                                )
                                if len(target) < max_results:
                                    target.append(absolute)
                            elif len(results[needle]) < max_results:
                                results[needle].append(absolute)
                        local = scan.find(needle, local + 1)

                search_pos += len(chunk)
                previous_tail = chunk
                if progress_cb is not None:
                    try:
                        progress_cb(min(search_pos, end) - start, total)
                    except Exception:
                        logger.debug(
                            "Signature scan progress callback failed",
                            exc_info=True,
                        )
    except (IOError, OSError):
        return results

    if priority_tail_needle in results:
        tail = priority_tail[:max_results]
        remaining = max(0, max_results - len(tail))
        results[priority_tail_needle] = tail + priority_prefix[:remaining]
    return results


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


class _Zip64Geometry:
    """Strictly validated adjacent ZIP64 end-record geometry."""

    def __init__(
        self,
        record_offset: int,
        relative_record_offset: int,
        entries: int,
        central_directory_size: int,
        central_directory_offset: int,
    ):
        self.record_offset = record_offset
        self.relative_record_offset = relative_record_offset
        self.entries = entries
        self.central_directory_size = central_directory_size
        self.central_directory_offset = central_directory_offset


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

    classic_requires_zip64 = (
        disk == 0xFFFF
        or cd_start_disk == 0xFFFF
        or cd_offset == 0xFFFFFFFF
        or cd_size == 0xFFFFFFFF
        or num_rec == 0xFFFF
        or total_rec == 0xFFFF
    )
    zip64 = _find_adjacent_zip64_geometry(
        path,
        eocd_offset,
        disk=disk,
        cd_start_disk=cd_start_disk,
        num_rec=num_rec,
        total_rec=total_rec,
        cd_size=cd_size,
        cd_offset=cd_offset,
    )
    if classic_requires_zip64 and zip64 is None:
        logger.debug("Required ZIP64 geometry is invalid at EOCD %d", eocd_offset)
        return None
    is_zip64 = zip64 is not None
    geom.is_zip64 = is_zip64

    rel_cd_offset: Optional[int] = None
    abs_cd_offset: Optional[int] = None
    cd_size_final = cd_size

    if zip64 is not None:
        geom.zip64_record_offset = zip64.record_offset
        geom.entry_count = zip64.entries
        geom.total_entries = zip64.entries
        cd_size_final = zip64.central_directory_size
        rel_cd_offset = zip64.central_directory_offset
        geom.cd_size = cd_size_final
        geom.central_directory_size = cd_size_final
        abs_cd_offset = zip64.record_offset - cd_size_final
        geom.flags.extend(
            [
                "zip64_record_found",
                "zip64_locator_found",
                "zip64_record_valid",
                "zip64_entry_count_valid",
                "zip64_disk_valid",
                "zip64_cd_disk_valid",
                "zip64_geometry_valid",
                "zip64_classic_fields_consistent",
                "zip64_locator_offset_valid",
            ]
        )

    empty_archive = (
        geom.entry_count == 0
        and cd_size_final == 0
        and (
            (zip64 is not None and rel_cd_offset == 0)
            or (zip64 is None and cd_offset == 0)
        )
        and disk in (0, 0xFFFF)
        and cd_start_disk in (0, 0xFFFF)
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
    if geom.entry_count == 0:
        if "empty_archive" not in geom.flags:
            geom.flags.append("empty_archive")
    elif geom.entry_count < 65536:
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
            path,
            abs_cd_offset,
            file_size,
            geom.entry_count,
            rel_cd_offset,
            cd_size_final,
            eocd_offset,
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


def _find_adjacent_zip64_geometry(
    path: str,
    eocd_offset: int,
    *,
    disk: int,
    cd_start_disk: int,
    num_rec: int,
    total_rec: int,
    cd_size: int,
    cd_offset: int,
) -> Optional[_Zip64Geometry]:
    """Validate a ZIP64 record and locator immediately before an EOCD.

    Steganographier-compatible files can retain usable classic EOCD values
    while also carrying ZIP64 end records.  Accept that layout only when every
    redundant field and relative offset describes the same single-disk ZIP.
    """

    locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE
    if locator_offset < ZIP64_RECORD_MIN_SIZE:
        return None
    locator = _read_at(path, locator_offset, ZIP64_LOCATOR_SIZE)
    if locator is None or locator[:4] != SIG_ZIP64_LOCATOR:
        return None

    locator_disk = _read_u32(locator, 4)
    relative_record_offset = _read_u64(locator, 8)
    total_disks = _read_u32(locator, 16)
    if locator_disk != 0 or total_disks != 1:
        return None

    search_start = max(0, locator_offset - ZIP64_RECORD_SEARCH_BYTES)
    chunk = _read_at(path, search_start, locator_offset - search_start)
    if chunk is None:
        return None

    record_index = chunk.rfind(SIG_ZIP64_RECORD)
    while record_index != -1:
        record_offset = search_start + record_index
        record = _read_at(path, record_offset, ZIP64_RECORD_MIN_SIZE)
        if record is not None:
            record_size = _read_u64(record, 4)
            record_end = record_offset + 12 + record_size
            if record_size >= 44 and record_end == locator_offset:
                record_disk = _read_u32(record, 16)
                record_cd_disk = _read_u32(record, 20)
                record_entries_disk = _read_u64(record, 24)
                record_entries_total = _read_u64(record, 32)
                record_cd_size = _read_u64(record, 40)
                record_cd_offset = _read_u64(record, 48)

                classic_consistent = (
                    disk in (0, 0xFFFF)
                    and cd_start_disk in (0, 0xFFFF)
                    and record_disk == 0
                    and record_cd_disk == 0
                    and record_entries_disk == record_entries_total
                    and num_rec in (0xFFFF, record_entries_disk)
                    and total_rec in (0xFFFF, record_entries_total)
                    and cd_size in (0xFFFFFFFF, record_cd_size)
                    and cd_offset in (0xFFFFFFFF, record_cd_offset)
                )
                archive_start = record_offset - relative_record_offset
                absolute_cd_offset = archive_start + record_cd_offset
                geometry_consistent = (
                    archive_start >= 0
                    and absolute_cd_offset >= archive_start
                    and absolute_cd_offset + record_cd_size == record_offset
                    and relative_record_offset
                    == record_cd_offset + record_cd_size
                    and (
                        (record_entries_total == 0 and record_cd_size == 0)
                        or (
                            record_entries_total > 0
                            and record_cd_size >= ZIP_CENTRAL_HEADER_SIZE
                        )
                    )
                )
                if classic_consistent and geometry_consistent:
                    return _Zip64Geometry(
                        record_offset,
                        relative_record_offset,
                        record_entries_total,
                        record_cd_size,
                        record_cd_offset,
                    )
        record_index = chunk.rfind(SIG_ZIP64_RECORD, 0, record_index)
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
        if local_absolute not in geom.local_header_offsets:
            geom.local_header_offsets.append(local_absolute)
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
    if geom.local_header_offsets:
        geom.flags.append(
            "multiple_local_headers"
            if len(geom.local_header_offsets) > 1
            else "single_local_header"
        )
    return True


def _detect_zip_candidates(
    path: str,
    file_size: int,
    cancel_check: CancelCheck = None,
    enumerate_local_headers: bool = True,
    eocd_offsets: Optional[Iterable[int]] = None,
) -> List[ArchiveCandidate]:
    """Detect and validate ZIP/ZIP64 candidates in a file."""
    candidates: List[ArchiveCandidate] = []

    if file_size < EOCD_MIN_SIZE:
        return candidates

    # Scan for all EOCD signatures with bounded memory.  Tail candidates are
    # collected first so a hostile file containing many false signatures near
    # its head cannot hide a normal appended archive from the result limit.
    if eocd_offsets is None:
        discovered_offsets: List[int] = []
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
                discovered_offsets.append(offset)
        if cancel_check is not None and cancel_check():
            return []

        # The prefix scan stops where the overlapping tail scan begins,
        # avoiding a second read of the normal EOCD region while retaining
        # middle ZIPs.
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
                discovered_offsets.append(offset)
        if cancel_check is not None and cancel_check():
            return []
    else:
        discovered_offsets = list(dict.fromkeys(eocd_offsets))

    for eocd_off in discovered_offsets:
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


def _detect_bmff_candidates(
    path: str,
    file_size: int,
    cancel_check: CancelCheck = None,
    eocd_offsets: Optional[Iterable[int]] = None,
) -> List[ArchiveCandidate]:
    """Detect archive candidates inside BMFF/ISO boxes."""
    candidates: List[ArchiveCandidate] = []

    if file_size < BMFF_BOX_SIZE:
        return candidates

    known_eocd_offsets = (
        sorted(set(eocd_offsets)) if eocd_offsets is not None else None
    )

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
                if known_eocd_offsets is None:
                    box_eocd_offsets = _scan_occurrences(
                        path,
                        SIG_EOCD,
                        data_start,
                        data_end,
                        max_results=256,
                        cancel_check=cancel_check,
                    )
                else:
                    first = bisect.bisect_left(
                        known_eocd_offsets, data_start
                    )
                    last = bisect.bisect_left(
                        known_eocd_offsets, data_end
                    )
                    box_eocd_offsets = known_eocd_offsets[first:last]
                for eocd_off in box_eocd_offsets:
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

def _detect_signature_candidates(
    path: str,
    file_size: int,
    cancel_check: CancelCheck = None,
    signature_offsets: Optional[Dict[bytes, List[int]]] = None,
) -> List[ArchiveCandidate]:
    """Detect 7z and RAR signatures as low-confidence candidates."""
    candidates: List[ArchiveCandidate] = []

    if file_size < 8:
        return candidates

    # 7z signature: 7z BC AF 27 1C
    sz_offsets = (
        list(signature_offsets.get(SIG_7Z, ()))
        if signature_offsets is not None
        else _scan_occurrences(
            path, SIG_7Z, 0, file_size, cancel_check=cancel_check
        )
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
        rar_offsets = (
            list(signature_offsets.get(sig, ()))
            if signature_offsets is not None
            else _scan_occurrences(
                path, sig, 0, file_size, cancel_check=cancel_check
            )
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

def find_candidates(
    path: str,
    cancel_check: CancelCheck = None,
    progress_cb: ProgressCallback = None,
) -> List[ArchiveCandidate]:
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

    signature_offsets = _scan_signatures_once(
        path,
        SCAN_SIGNATURES,
        0,
        file_size,
        progress_cb=progress_cb,
        cancel_check=cancel_check,
    )
    if cancel_check is not None and cancel_check():
        return []

    # ZIP/ZIP64 full structural validation. Central records already validate
    # every referenced local header, so no extra full-span local-header pass
    # is needed here.
    candidates.extend(
        _detect_zip_candidates(
            path,
            file_size,
            cancel_check=cancel_check,
            enumerate_local_headers=False,
            eocd_offsets=signature_offsets.get(SIG_EOCD, ()),
        )
    )
    if cancel_check is not None and cancel_check():
        return []

    # BMFF box walking
    candidates.extend(
        _detect_bmff_candidates(
            path,
            file_size,
            cancel_check=cancel_check,
            eocd_offsets=signature_offsets.get(SIG_EOCD, ()),
        )
    )
    if cancel_check is not None and cancel_check():
        return []

    # Signature-only: 7z, RAR (bounded)
    candidates.extend(
        _detect_signature_candidates(
            path,
            file_size,
            cancel_check=cancel_check,
            signature_offsets=signature_offsets,
        )
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
    path: str,
    cancel_check: CancelCheck = None,
    progress_cb: ProgressCallback = None,
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
    signature_offsets = _scan_signatures_once(
        path,
        (SIG_EOCD,),
        0,
        file_size,
        progress_cb=progress_cb,
        cancel_check=cancel_check,
    )
    if cancel_check is not None and cancel_check():
        return []
    candidates = _detect_zip_candidates(
        path,
        file_size,
        cancel_check=cancel_check,
        enumerate_local_headers=False,
        eocd_offsets=signature_offsets.get(SIG_EOCD, ()),
    )
    return [
        candidate
        for candidate in _deduplicate_candidates(candidates)
        if is_exact_high_confidence_candidate(candidate)
    ]


def find_exact_appended_zip_candidates(
    path: str,
    minimum_start: int,
    max_prefix_bytes: int,
    cancel_check: CancelCheck = None,
) -> List[ArchiveCandidate]:
    """Validate complete tail ZIPs without scanning the whole host file."""

    if cancel_check is not None and cancel_check():
        return []
    try:
        file_size = _regular_file_size(path)
    except (OSError, ValueError):
        return []
    if file_size is None or file_size < EOCD_MIN_SIZE:
        return []
    minimum_start = max(0, min(int(minimum_start), file_size))
    tail_start = max(minimum_start, file_size - EOCD_MAX_COMMENT)
    eocd_offsets = _scan_occurrences(
        path,
        SIG_EOCD,
        tail_start,
        file_size,
        cancel_check=cancel_check,
    )
    candidates = _detect_zip_candidates(
        path,
        file_size,
        cancel_check=cancel_check,
        enumerate_local_headers=False,
        eocd_offsets=eocd_offsets,
    )
    return [
        candidate
        for candidate in _deduplicate_candidates(candidates)
        if candidate.start_offset >= minimum_start
        and candidate.start_offset - minimum_start <= max_prefix_bytes
        and candidate.end_offset == file_size
        and is_exact_high_confidence_candidate(candidate)
    ]


def find_exact_zip_candidates_in_span(
    path: str,
    span_start: int,
    span_end: int,
    trailing_search_bytes: int = 0,
    cancel_check: CancelCheck = None,
) -> List[ArchiveCandidate]:
    """Validate ZIPs ending near a known payload boundary without full scans.

    ``span_start`` and ``span_end`` describe the container payload that may
    hold a ZIP. ``trailing_search_bytes`` permits a small, bounded suffix after
    the ZIP, as used by Steganographier's MP4 hash-randomization trailer.
    """

    if cancel_check is not None and cancel_check():
        return []
    try:
        file_size = _regular_file_size(path)
    except (OSError, ValueError):
        return []
    if file_size is None:
        return []

    start = max(0, min(int(span_start), file_size))
    end = max(start, min(int(span_end), file_size))
    trailing = max(0, min(int(trailing_search_bytes), end - start))
    if end - start < EOCD_MIN_SIZE:
        return []

    search_start = max(start, end - EOCD_MAX_COMMENT - trailing)
    eocd_offsets = _scan_occurrences(
        path,
        SIG_EOCD,
        search_start,
        end,
        cancel_check=cancel_check,
    )
    if cancel_check is not None and cancel_check():
        return []
    candidates = _detect_zip_candidates(
        path,
        file_size,
        cancel_check=cancel_check,
        enumerate_local_headers=False,
        eocd_offsets=eocd_offsets,
    )
    return [
        candidate
        for candidate in _deduplicate_candidates(candidates)
        if candidate.start_offset >= start
        and candidate.end_offset <= end
        and end - candidate.end_offset <= trailing
        and is_exact_high_confidence_candidate(candidate)
    ]


def _regular_file_size(path: str) -> Optional[int]:
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        return None
    return max(0, int(info.st_size))
