"""Fast, bounded detection for files compatible with SteganographierGUI.

The detector deliberately avoids scanning media payloads. It reads BMFF box
headers or Matroska EBML metadata, then validates only the ZIP EOCD, central
directory, and referenced local headers at known payload boundaries.
"""

from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator, List, Optional, Tuple

from models import ArchiveCandidate
from stego_candidates import find_exact_zip_candidates_in_span


CancelCheck = Optional[Callable[[], bool]]

EMPTY_MDAT = b"\x00\x00\x00\x08mdat"
ARCHIVE_DECOY_SIGNATURES = (
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
)
MAX_RANDOMIZED_SUFFIX = 24 * 1024
MAX_EBML_ELEMENTS = 100_000

EBML_ID = 0x1A45DFA3
SEGMENT_ID = 0x18538067
SEEK_HEAD_ID = 0x114D9B74
SEEK_ID = 0x4DBB
SEEK_TARGET_ID = 0x53AB
SEEK_POSITION_ID = 0x53AC
ATTACHMENTS_ID = 0x1941A469
ATTACHED_FILE_ID = 0x61A7
FILE_NAME_ID = 0x466E
FILE_MIME_ID = 0x4660
FILE_DATA_ID = 0x465C
CLUSTER_ID = 0x1F43B675


@dataclass(frozen=True)
class _BmffBox:
    offset: int
    data_start: int
    end: int
    box_type: bytes


@dataclass(frozen=True)
class _EbmlElement:
    element_id: int
    offset: int
    data_start: int
    end: int
    unknown_size: bool = False


def find_steganographier_candidates(
    path: str,
    cancel_check: CancelCheck = None,
) -> List[ArchiveCandidate]:
    """Return exact ZIP candidates using only bounded container reads."""

    if cancel_check is not None and cancel_check():
        return []
    try:
        file_size = _regular_file_size(path)
        if file_size is None or file_size < 12:
            return []
        with open(path, "rb") as stream:
            magic = stream.read(12)
            if len(magic) < 4:
                return []
            if magic[:4] == b"\x1aE\xdf\xa3":
                candidates = _find_matroska_candidates(
                    path, stream, file_size, cancel_check
                )
            elif len(magic) >= 8 and magic[4:8] == b"ftyp":
                candidates = _find_bmff_candidates(
                    path, stream, file_size, cancel_check
                )
            else:
                return []
    except (OSError, ValueError, EOFError, struct.error):
        return []

    by_span = {}
    for candidate in candidates:
        key = (
            candidate.start_offset,
            candidate.end_offset,
            candidate.embedded_format,
        )
        by_span.setdefault(key, candidate)
    return sorted(
        by_span.values(),
        key=lambda item: (item.start_offset, item.end_offset),
    )


def _find_bmff_candidates(
    path: str,
    stream: BinaryIO,
    file_size: int,
    cancel_check: CancelCheck,
) -> List[ArchiveCandidate]:
    first = _read_bmff_box(stream, 0, file_size)
    if first is None or first.box_type != b"ftyp":
        return []
    candidates: List[ArchiveCandidate] = []

    second = _read_bmff_box(stream, first.end, file_size)
    if second is not None and second.box_type == b"free":
        if _payload_may_be_zip(stream, second.data_start, second.end):
            exact = find_exact_zip_candidates_in_span(
                path,
                second.data_start,
                second.end,
                cancel_check=cancel_check,
            )
            for candidate in exact:
                if (
                    candidate.start_offset == second.data_start
                    and candidate.end_offset == second.end
                ):
                    candidates.append(
                        _decorate_candidate(
                            candidate,
                            host_format="bmff",
                            mode="steganographier_free_atom",
                            flags=(
                                "steganographier_compatible",
                                "bmff_ftyp_valid",
                                "free_atom_exact_payload",
                            ),
                        )
                    )

    if cancel_check is not None and cancel_check():
        return []
    trailing = find_exact_zip_candidates_in_span(
        path,
        first.end,
        file_size,
        trailing_search_bytes=MAX_RANDOMIZED_SUFFIX,
        cancel_check=cancel_check,
    )
    for candidate in trailing:
        if candidate.start_offset <= first.end:
            continue
        if candidate.end_offset == file_size:
            flags = (
                "steganographier_compatible",
                "bmff_ftyp_valid",
                "zip_appended_to_media",
            )
        elif _has_steganographier_suffix(
            stream, candidate.end_offset, file_size
        ):
            flags = (
                "steganographier_compatible",
                "bmff_ftyp_valid",
                "steganographier_randomized_suffix",
            )
        else:
            continue
        candidates.append(
            _decorate_candidate(
                candidate,
                host_format="bmff",
                mode="steganographier_mp4_trailing",
                flags=flags,
            )
        )
    return candidates


def _read_bmff_box(
    stream: BinaryIO, offset: int, limit: int
) -> Optional[_BmffBox]:
    if offset < 0 or offset + 8 > limit:
        return None
    stream.seek(offset)
    header = stream.read(16)
    if len(header) < 8:
        return None
    size32 = struct.unpack_from(">I", header, 0)[0]
    box_type = header[4:8]
    header_size = 8
    if size32 == 1:
        if len(header) < 16:
            return None
        size = struct.unpack_from(">Q", header, 8)[0]
        header_size = 16
    elif size32 == 0:
        size = limit - offset
    else:
        size = size32
    if size < header_size or offset + size > limit:
        return None
    return _BmffBox(offset, offset + header_size, offset + size, box_type)


def _payload_may_be_zip(stream: BinaryIO, start: int, end: int) -> bool:
    if end - start < 22:
        return False
    stream.seek(start)
    return stream.read(4) in {b"PK\x03\x04", b"PK\x05\x06"}


def _has_steganographier_suffix(
    stream: BinaryIO, start: int, file_size: int
) -> bool:
    suffix_size = file_size - start
    if suffix_size <= len(EMPTY_MDAT) or suffix_size > MAX_RANDOMIZED_SUFFIX:
        return False
    stream.seek(start)
    suffix = stream.read(suffix_size)
    if len(suffix) != suffix_size or not suffix.endswith(EMPTY_MDAT):
        return False
    body = suffix[: -len(EMPTY_MDAT)]
    for first in ARCHIVE_DECOY_SIGNATURES:
        if not body.startswith(first):
            continue
        for first_kib in range(5, 11):
            second_offset = len(first) + first_kib * 1024
            for second in ARCHIVE_DECOY_SIGNATURES:
                if not body.startswith(second, second_offset):
                    continue
                random_tail = len(body) - second_offset - len(second)
                if random_tail in {size * 1024 for size in range(5, 11)}:
                    return True
    return False


def _find_matroska_candidates(
    path: str,
    stream: BinaryIO,
    file_size: int,
    cancel_check: CancelCheck,
) -> List[ArchiveCandidate]:
    header = _read_ebml_element(stream, 0, file_size)
    if header is None or header.element_id != EBML_ID or header.unknown_size:
        return []

    segment = None
    cursor = header.end
    for _ in range(32):
        element = _read_ebml_element(stream, cursor, file_size)
        if element is None:
            break
        if element.element_id == SEGMENT_ID:
            segment = element
            break
        if element.unknown_size or element.end <= cursor:
            break
        cursor = element.end
    if segment is None:
        return []

    attachment_offsets = []
    cursor = segment.data_start
    segment_end = segment.end
    for _ in range(MAX_EBML_ELEMENTS):
        if cancel_check is not None and cancel_check():
            return []
        element = _read_ebml_element(stream, cursor, segment_end)
        if element is None:
            break
        if element.element_id == ATTACHMENTS_ID:
            attachment_offsets.append(element.offset)
        elif element.element_id == SEEK_HEAD_ID and not element.unknown_size:
            target = _attachments_from_seek_head(
                stream, element, segment, segment_end
            )
            if target is not None:
                attachment_offsets.append(target)
        if element.unknown_size:
            if element.element_id == CLUSTER_ID:
                break
            break
        if element.end <= cursor:
            break
        cursor = element.end
        if cursor >= segment_end:
            break

    candidates: List[ArchiveCandidate] = []
    for offset in dict.fromkeys(attachment_offsets):
        if cancel_check is not None and cancel_check():
            return []
        attachments = _read_ebml_element(stream, offset, segment_end)
        if (
            attachments is None
            or attachments.element_id != ATTACHMENTS_ID
            or attachments.unknown_size
        ):
            continue
        candidates.extend(
            _candidates_from_attachments(
                path, stream, attachments, cancel_check
            )
        )
    return candidates


def _attachments_from_seek_head(
    stream: BinaryIO,
    seek_head: _EbmlElement,
    segment: _EbmlElement,
    segment_end: int,
) -> Optional[int]:
    for seek in _iter_ebml_children(stream, seek_head):
        if seek.element_id != SEEK_ID or seek.unknown_size:
            continue
        target_id = None
        position = None
        for child in _iter_ebml_children(stream, seek):
            size = child.end - child.data_start
            if child.unknown_size or size < 1 or size > 8:
                continue
            stream.seek(child.data_start)
            raw = stream.read(size)
            if len(raw) != size:
                continue
            if child.element_id == SEEK_TARGET_ID:
                target_id = int.from_bytes(raw, "big")
            elif child.element_id == SEEK_POSITION_ID:
                position = int.from_bytes(raw, "big")
        if target_id != ATTACHMENTS_ID or position is None:
            continue
        target = segment.data_start + position
        if segment.data_start <= target < segment_end:
            return target
    return None


def _candidates_from_attachments(
    path: str,
    stream: BinaryIO,
    attachments: _EbmlElement,
    cancel_check: CancelCheck,
) -> List[ArchiveCandidate]:
    candidates: List[ArchiveCandidate] = []
    for attached in _iter_ebml_children(stream, attachments):
        if cancel_check is not None and cancel_check():
            return []
        if attached.element_id != ATTACHED_FILE_ID or attached.unknown_size:
            continue
        filename = ""
        mime = ""
        data_span: Optional[Tuple[int, int]] = None
        for child in _iter_ebml_children(stream, attached):
            if child.unknown_size:
                continue
            size = child.end - child.data_start
            if child.element_id == FILE_NAME_ID and size <= 16 * 1024:
                filename = _read_text(stream, child.data_start, size)
            elif child.element_id == FILE_MIME_ID and size <= 4 * 1024:
                mime = _read_text(stream, child.data_start, size)
            elif child.element_id == FILE_DATA_ID:
                data_span = (child.data_start, child.end)
        if data_span is None:
            continue
        data_start, data_end = data_span
        suffix = os.path.splitext(filename)[1].casefold()
        zip_hint = suffix == ".zip" or "zip" in mime.casefold()
        if not zip_hint and not _payload_may_be_zip(stream, data_start, data_end):
            continue
        exact = find_exact_zip_candidates_in_span(
            path,
            data_start,
            data_end,
            cancel_check=cancel_check,
        )
        for candidate in exact:
            if (
                candidate.start_offset != data_start
                or candidate.end_offset != data_end
            ):
                continue
            hint_flags = []
            if suffix == ".zip":
                hint_flags.append("attachment_zip_filename")
            if "zip" in mime.casefold():
                hint_flags.append("attachment_zip_mime")
            candidates.append(
                _decorate_candidate(
                    candidate,
                    host_format="matroska",
                    mode="steganographier_mkv_attachment",
                    flags=(
                        "steganographier_compatible",
                        "matroska_ebml_valid",
                        "attachment_exact_payload",
                        *hint_flags,
                    ),
                    diagnostics=(
                        f"attachment_name={filename}",
                        f"attachment_mime={mime}",
                    ),
                )
            )
    return candidates


def _read_text(
    stream: BinaryIO, offset: int, size: int
) -> str:
    stream.seek(offset)
    return stream.read(size).rstrip(b"\x00").decode("utf-8", "replace")


def _iter_ebml_children(
    stream: BinaryIO, parent: _EbmlElement
) -> Iterator[_EbmlElement]:
    cursor = parent.data_start
    for _ in range(MAX_EBML_ELEMENTS):
        if cursor >= parent.end:
            return
        child = _read_ebml_element(stream, cursor, parent.end)
        if child is None:
            return
        yield child
        if child.unknown_size or child.end <= cursor:
            return
        cursor = child.end


def _read_ebml_element(
    stream: BinaryIO, offset: int, limit: int
) -> Optional[_EbmlElement]:
    if offset < 0 or offset >= limit:
        return None
    stream.seek(offset)
    first = stream.read(1)
    if not first or first == b"\x00":
        return None
    id_length = _vint_length(first[0], 4)
    if id_length is None:
        return None
    raw_id = first + stream.read(id_length - 1)
    if len(raw_id) != id_length:
        return None

    size_first = stream.read(1)
    if not size_first or size_first == b"\x00":
        return None
    size_length = _vint_length(size_first[0], 8)
    if size_length is None:
        return None
    raw_size = size_first + stream.read(size_length - 1)
    if len(raw_size) != size_length:
        return None
    marker = 1 << (8 - size_length)
    value = raw_size[0] & (marker - 1)
    for byte in raw_size[1:]:
        value = (value << 8) | byte
    unknown = value == (1 << (7 * size_length)) - 1
    data_start = offset + id_length + size_length
    end = limit if unknown else data_start + value
    if data_start > limit or end < data_start or end > limit:
        return None
    return _EbmlElement(
        int.from_bytes(raw_id, "big"),
        offset,
        data_start,
        end,
        unknown,
    )


def _vint_length(first_byte: int, maximum: int) -> Optional[int]:
    mask = 0x80
    for length in range(1, maximum + 1):
        if first_byte & mask:
            return length
        mask >>= 1
    return None


def _decorate_candidate(
    candidate: ArchiveCandidate,
    *,
    host_format: str,
    mode: str,
    flags: Tuple[str, ...],
    diagnostics: Tuple[str, ...] = (),
) -> ArchiveCandidate:
    candidate.host_format = host_format
    candidate.embedded_format = "zip"
    candidate.mode = mode
    for flag in flags:
        if flag not in candidate.validation_flags:
            candidate.validation_flags.append(flag)
    candidate.diagnostics.extend(diagnostics)
    return candidate


def _regular_file_size(path: str) -> Optional[int]:
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        return None
    return max(0, int(info.st_size))
