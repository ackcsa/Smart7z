"""Content-first filtering for automatically discovered archive candidates."""

from __future__ import annotations

import os
import stat
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Set, Tuple

from models import ArchiveCandidate


CancelCheck = Optional[Callable[[], bool]]
ProgressCallback = Optional[Callable[[int, int], None]]


HEAD_SCAN_BYTES = 1024 * 1024
TAIL_SCAN_BYTES = 1024 * 1024
QUICK_EDGE_SCAN_BYTES = 64 * 1024
MAX_ZIP_CLASSIFY_ENTRIES = 250_000
MAX_ZIP_CENTRAL_BYTES = 32 * 1024 * 1024
MAX_PE_HEADER_OFFSET = 1024 * 1024
MAX_SFX_PREFIX_BYTES = 1024 * 1024
MAX_7Z_NEXT_HEADER_BYTES = 32 * 1024 * 1024

ZIP_LOCAL = b"PK\x03\x04"
ZIP_CENTRAL = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
ZIP64_EOCD = b"PK\x06\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
RAR4 = b"Rar!\x1a\x07\x00"
RAR5 = b"Rar!\x1a\x07\x01\x00"
SEVEN_ZIP = b"7z\xbc\xaf\x27\x1c"


SEMANTIC_EXTENSION_HINTS = frozenset(
    {
        ".doc",
        ".docm",
        ".docx",
        ".dotm",
        ".dotx",
        ".b64",
        ".dll",
        ".epub",
        ".exe",
        ".flv",
        ".hxi",
        ".hxr",
        ".hxs",
        ".hxq",
        ".hxw",
        ".ihex",
        ".jar",
        ".lit",
        ".msi",
        ".msp",
        ".obj",
        ".odp",
        ".ods",
        ".odt",
        ".pdf",
        ".potm",
        ".potx",
        ".ppam",
        ".ppsm",
        ".ppsx",
        ".pptm",
        ".pptx",
        ".rpm",
        ".swf",
        ".sys",
        ".vsdx",
        ".vsdm",
        ".xls",
        ".xlsb",
        ".xlsm",
        ".xlsx",
        ".xltm",
        ".xltx",
        ".apk",
        ".aab",
        ".appx",
        ".msix",
        ".ipa",
        ".whl",
        ".nupkg",
        ".vsix",
        ".xpi",
    }
)

COMPOUND_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.7z",
)


@dataclass(frozen=True)
class AutoDiscoveryDecision:
    should_queue: bool
    reason: str
    semantic_kind: str = ""
    archive_evidence: Tuple[str, ...] = ()
    candidates: Tuple[ArchiveCandidate, ...] = ()

    @property
    def is_semantic(self) -> bool:
        return bool(self.semantic_kind)


@dataclass(frozen=True)
class _ZipCentralInfo:
    start: int
    size: int
    entries: int


def has_independent_archive_structure(path: str) -> bool:
    """Return whether *path* contains a complete archive, not just volume bytes."""

    try:
        file_size = _regular_file_size(path)
        if file_size is None:
            return False
        head, tail, tail_start = _read_edges(path, file_size)
    except (OSError, ValueError):
        return False

    if head.startswith((SEVEN_ZIP, RAR4, RAR5, b"MSCF", b"MSWIM\x00\x00\x00", b"!<arch>\n")):
        return True
    if _has_compressed_stream_header(head[:32]):
        return True
    if _has_valid_tar_header(head) or _has_iso_descriptor(head):
        return True
    if tail.endswith(b"koly") or b"conectix" in tail[-1024:]:
        return True
    if any(
        signature in head or signature in tail
        for signature in (ZIP_LOCAL, ZIP_CENTRAL, ZIP_EOCD, ZIP64_EOCD)
    ):
        return _zip_central_info(path, file_size, tail, tail_start) is not None
    return False


def classify_automatic_candidate(
    path: str,
    archive_extensions: Optional[Iterable[str]] = None,
    cancel_check: CancelCheck = None,
    progress_cb: ProgressCallback = None,
    allow_full_embedded_scan: bool = True,
) -> AutoDiscoveryDecision:
    """Classify a file found by a folder or nested-output scan.

    A complete, boundary-validated embedded ZIP may override media semantics.
    Explicit user inputs intentionally bypass this function in the UI layer.
    """

    if cancel_check is not None and cancel_check():
        return AutoDiscoveryDecision(False, "cancelled")
    try:
        file_size = _regular_file_size(path)
        if file_size is None:
            return AutoDiscoveryDecision(False, "not_a_file")
        quick_head, quick_tail, quick_tail_start = _read_quick_edges(
            path, file_size
        )
    except (OSError, ValueError):
        return AutoDiscoveryDecision(False, "unreadable")

    if cancel_check is not None and cancel_check():
        return AutoDiscoveryDecision(False, "cancelled")
    quick_semantic = _semantic_magic(quick_head, quick_tail, path)
    quick_evidence = _quick_archive_evidence(quick_head, quick_tail)
    needs_full_pdf_check = (
        b"%PDF-" in quick_head[:1024] and b"%%EOF" not in quick_tail
    )
    if not quick_semantic and not needs_full_pdf_check and quick_evidence:
        return AutoDiscoveryDecision(
            True,
            "content_archive",
            archive_evidence=tuple(sorted(quick_evidence)),
        )

    try:
        head, tail, tail_start = _read_edges(
            path,
            file_size,
            initial_head=quick_head,
            initial_tail=quick_tail,
            initial_tail_start=quick_tail_start,
        )
    except (OSError, ValueError):
        return AutoDiscoveryDecision(False, "unreadable")

    advertised = _normalize_archive_extensions(archive_extensions)
    semantic = _semantic_magic(head, tail, path)
    archive_evidence = set(_archive_magic_evidence(head, tail))
    exact_embedded = []

    if _looks_zip_like(head, tail, path, advertised):
        zip_info = _zip_central_info(
            path,
            file_size,
            tail,
            tail_start,
            cancel_check=cancel_check,
        )
        if allow_full_embedded_scan and (
            zip_info is None
            or (semantic and _is_media_semantic(semantic) and archive_evidence)
        ):
            try:
                from stego_candidates import find_exact_high_confidence_candidates

                exact_embedded = [
                    candidate
                    for candidate in find_exact_high_confidence_candidates(
                        path,
                        cancel_check=cancel_check,
                        progress_cb=progress_cb,
                    )
                    if candidate.start_offset > 0 or candidate.end_offset < file_size
                ]
            except (OSError, ValueError, EOFError):
                exact_embedded = []
            if cancel_check is not None and cancel_check():
                return AutoDiscoveryDecision(False, "cancelled")
            if zip_info is None and len(exact_embedded) == 1:
                candidate = exact_embedded[0]
                zip_info = _zip_central_info_for_span(
                    path,
                    file_size,
                    candidate.start_offset,
                    candidate.end_offset,
                    cancel_check=cancel_check,
                )
        if zip_info is not None:
            archive_evidence.add("zip_central_directory")
            zip_semantic = _read_zip_semantic_kind(
                path, zip_info, cancel_check=cancel_check
            )
            if cancel_check is not None and cancel_check():
                return AutoDiscoveryDecision(False, "cancelled")
            if zip_semantic:
                semantic = semantic or zip_semantic
            elif (
                zip_semantic is None
                and os.path.splitext(path)[1].casefold() in SEMANTIC_EXTENSION_HINTS
            ):
                semantic = semantic or "large_semantic_zip_extension"

    if semantic and _is_media_semantic(semantic):
        if exact_embedded:
            return AutoDiscoveryDecision(
                True,
                "confirmed_embedded_archive",
                semantic_kind=semantic,
                archive_evidence=tuple(sorted(archive_evidence)),
                candidates=tuple(exact_embedded),
            )

    if semantic:
        return AutoDiscoveryDecision(
            False,
            "semantic_container",
            semantic_kind=semantic,
            archive_evidence=tuple(sorted(archive_evidence)),
        )

    if archive_evidence:
        return AutoDiscoveryDecision(
            True,
            "content_archive",
            archive_evidence=tuple(sorted(archive_evidence)),
        )

    suffix = os.path.splitext(path)[1].casefold()
    lower = path.casefold()
    if lower.endswith(COMPOUND_ARCHIVE_SUFFIXES):
        return AutoDiscoveryDecision(True, "compound_extension_hint")
    if suffix in advertised and suffix not in SEMANTIC_EXTENSION_HINTS:
        return AutoDiscoveryDecision(True, "extension_hint")
    return AutoDiscoveryDecision(False, "no_archive_structure")


def classify_nested_candidate(
    path: str,
    archive_extensions: Optional[Iterable[str]] = None,
    cancel_check: CancelCheck = None,
) -> AutoDiscoveryDecision:
    """Classify nested output while protecting ordinary Windows programs.

    A structurally valid PE is considered a protection anchor unless its
    overlay contains one complete, boundary-validated ZIP or 7z payload.
    Files merely named ``.exe`` continue through normal content detection.
    """

    if os.path.splitext(path)[1].casefold() != ".exe":
        return classify_automatic_candidate(
            path,
            archive_extensions,
            cancel_check=cancel_check,
        )
    if cancel_check is not None and cancel_check():
        return AutoDiscoveryDecision(False, "cancelled")

    pe_image_end = windows_pe_image_end(path)
    if pe_image_end is None:
        return classify_automatic_candidate(
            path,
            archive_extensions,
            cancel_check=cancel_check,
        )
    try:
        file_size = os.path.getsize(path)
    except OSError:
        return AutoDiscoveryDecision(False, "unreadable")

    if pe_image_end < file_size:
        try:
            from stego_candidates import find_exact_appended_zip_candidates

            zip_candidates = find_exact_appended_zip_candidates(
                path,
                pe_image_end,
                MAX_SFX_PREFIX_BYTES,
                cancel_check=cancel_check,
            )
        except (OSError, ValueError, EOFError):
            zip_candidates = []
        if cancel_check is not None and cancel_check():
            return AutoDiscoveryDecision(False, "cancelled")
        if len(zip_candidates) == 1:
            return AutoDiscoveryDecision(
                True,
                "self_extracting_archive",
                semantic_kind="windows_executable",
                archive_evidence=("zip_sfx_overlay",),
                candidates=tuple(zip_candidates),
            )
        if _has_valid_7z_sfx_overlay(path, pe_image_end, file_size):
            return AutoDiscoveryDecision(
                True,
                "self_extracting_archive",
                semantic_kind="windows_executable",
                archive_evidence=("7z_sfx_overlay",),
            )

    return AutoDiscoveryDecision(
        False,
        "protected_executable",
        semantic_kind="windows_executable",
    )


def windows_pe_image_end(path: str) -> Optional[int]:
    """Return the first byte after a validated PE image, or ``None``."""

    try:
        file_size = _regular_file_size(path)
        if file_size is None or file_size < 64:
            return None
        with open(path, "rb") as stream:
            dos_header = stream.read(64)
            if len(dos_header) != 64 or not dos_header.startswith(b"MZ"):
                return None
            pe_offset = struct.unpack_from("<L", dos_header, 0x3C)[0]
            if pe_offset < 64 or pe_offset > MAX_PE_HEADER_OFFSET:
                return None
            stream.seek(pe_offset)
            pe_header = stream.read(24)
            if len(pe_header) != 24 or pe_header[:4] != b"PE\x00\x00":
                return None
            machine, section_count = struct.unpack_from("<HH", pe_header, 4)
            optional_size = struct.unpack_from("<H", pe_header, 20)[0]
            if (
                machine not in _PE_MACHINES
                or not 1 <= section_count <= 96
                or optional_size < 64
            ):
                return None
            optional = stream.read(optional_size)
            sections = stream.read(section_count * 40)
    except (OSError, struct.error):
        return None

    if len(optional) != optional_size or len(sections) != section_count * 40:
        return None
    try:
        magic = struct.unpack_from("<H", optional, 0)[0]
        if magic == 0x10B:
            directory_count_offset = 92
            directory_offset = 96
        elif magic == 0x20B:
            directory_count_offset = 108
            directory_offset = 112
        else:
            return None
        image_end = struct.unpack_from("<L", optional, 60)[0]
        if image_end <= 0 or image_end > file_size:
            return None
        for index in range(section_count):
            section = sections[index * 40 : (index + 1) * 40]
            raw_size, raw_offset = struct.unpack_from("<LL", section, 16)
            if raw_size:
                section_end = raw_offset + raw_size
                if raw_offset <= 0 or section_end > file_size:
                    return None
                image_end = max(image_end, section_end)
        if optional_size >= directory_count_offset + 4:
            directory_count = struct.unpack_from(
                "<L", optional, directory_count_offset
            )[0]
            certificate_offset = directory_offset + (4 * 8)
            if directory_count > 4 and optional_size >= certificate_offset + 8:
                cert_start, cert_size = struct.unpack_from(
                    "<LL", optional, certificate_offset
                )
                if cert_size:
                    cert_end = cert_start + cert_size
                    if cert_start <= 0 or cert_end > file_size:
                        return None
                    image_end = max(image_end, cert_end)
    except struct.error:
        return None
    return image_end


_PE_MACHINES = frozenset(
    {
        0x014C,
        0x01C0,
        0x01C2,
        0x01C4,
        0x01F0,
        0x01F1,
        0x0200,
        0x8664,
        0xAA64,
    }
)


def _has_valid_7z_sfx_overlay(
    path: str, pe_image_end: int, file_size: int
) -> bool:
    search_size = min(MAX_SFX_PREFIX_BYTES, file_size - pe_image_end)
    if search_size < 32:
        return False
    try:
        with open(path, "rb") as stream:
            stream.seek(pe_image_end)
            prefix = stream.read(search_size)
            search_from = 0
            while True:
                local_offset = prefix.find(SEVEN_ZIP, search_from)
                if local_offset < 0:
                    return False
                search_from = local_offset + 1
                archive_start = pe_image_end + local_offset
                stream.seek(archive_start)
                header = stream.read(32)
                if len(header) != 32 or header[:6] != SEVEN_ZIP:
                    continue
                expected_start_crc = struct.unpack_from("<L", header, 8)[0]
                if zlib.crc32(header[12:32]) & 0xFFFFFFFF != expected_start_crc:
                    continue
                next_offset, next_size, expected_next_crc = struct.unpack_from(
                    "<QQL", header, 12
                )
                if next_size > MAX_7Z_NEXT_HEADER_BYTES:
                    continue
                next_start = archive_start + 32 + next_offset
                next_end = next_start + next_size
                if next_start < archive_start + 32 or next_end != file_size:
                    continue
                stream.seek(next_start)
                next_header = stream.read(next_size)
                if len(next_header) != next_size:
                    continue
                if (
                    next_header[:1] in {b"\x01", b"\x17"}
                    and zlib.crc32(next_header) & 0xFFFFFFFF
                    == expected_next_crc
                ):
                    return True
    except (OSError, struct.error):
        return False


def _is_media_semantic(kind: str) -> bool:
    return kind.endswith(("_image", "_media", "_audio")) or kind in {
        "flash_video",
    }


def _regular_file_size(path: str) -> Optional[int]:
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        return None
    return max(0, int(info.st_size))


def _read_quick_edges(path: str, file_size: int) -> Tuple[bytes, bytes, int]:
    if file_size <= HEAD_SCAN_BYTES:
        with open(path, "rb") as stream:
            data = stream.read(file_size)
        return data, data, 0

    edge_size = min(file_size, QUICK_EDGE_SCAN_BYTES)
    tail_start = file_size - edge_size
    with open(path, "rb") as stream:
        head = stream.read(edge_size)
        stream.seek(tail_start)
        tail = stream.read(edge_size)
    return head, tail, tail_start


def _read_edges(
    path: str,
    file_size: int,
    initial_head: bytes = b"",
    initial_tail: bytes = b"",
    initial_tail_start: Optional[int] = None,
) -> Tuple[bytes, bytes, int]:
    head_size = min(file_size, HEAD_SCAN_BYTES)
    tail_size = min(file_size, TAIL_SCAN_BYTES)
    tail_start = max(0, file_size - tail_size)
    with open(path, "rb") as stream:
        if initial_head and len(initial_head) <= head_size:
            stream.seek(len(initial_head))
            head = initial_head + stream.read(head_size - len(initial_head))
        else:
            head = stream.read(head_size)
        if tail_start == 0:
            tail = head
        elif (
            initial_tail
            and initial_tail_start is not None
            and tail_start <= initial_tail_start
            and initial_tail_start + len(initial_tail) == file_size
        ):
            stream.seek(tail_start)
            tail = stream.read(initial_tail_start - tail_start) + initial_tail
        else:
            stream.seek(tail_start)
            tail = stream.read(tail_size)
    return head, tail, tail_start


def _quick_archive_evidence(head: bytes, tail: bytes) -> Set[str]:
    """Return archive evidence that is conclusive from small edge reads."""

    evidence: Set[str] = set()
    if head.startswith(SEVEN_ZIP):
        evidence.add("7z_header")
    if head.startswith((RAR4, RAR5)):
        evidence.add("rar_header")
    if head.startswith(b"MSCF"):
        evidence.add("cab_header")
    if head.startswith(b"MSWIM\x00\x00\x00"):
        evidence.add("wim_header")
    if head.startswith(b"!<arch>\n"):
        evidence.add("ar_header")
    if _has_compressed_stream_header(head[:32]):
        evidence.add("compressed_stream_header")
    if _has_valid_tar_header(head[:512]):
        evidence.add("tar_header")
    if _has_iso_descriptor(head):
        evidence.add("iso9660_header")
    if tail.endswith(b"koly"):
        evidence.add("dmg_tail")
    if b"conectix" in tail[-1024:]:
        evidence.add("vhd_tail")
    return evidence


def _normalize_archive_extensions(
    archive_extensions: Optional[Iterable[str]],
) -> frozenset[str]:
    if isinstance(archive_extensions, frozenset):
        return archive_extensions
    return frozenset(
        value.casefold()
        for value in (archive_extensions or ())
        if isinstance(value, str) and value.startswith(".")
    )


def _semantic_magic(head: bytes, tail: bytes, path: str) -> str:
    suffix = os.path.splitext(path)[1].casefold()
    if head.startswith(b"MZ"):
        return "windows_executable"
    if head.startswith(b"\x7fELF"):
        return "elf_executable"
    if head[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "mach_or_java_binary"
    if head.startswith(b"%PDF-") or (
        b"%PDF-" in head[:1024] and b"%%EOF" in tail
    ):
        return "pdf_document"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole_compound_document"
    if head.startswith(b"{\\rtf"):
        return "rtf_document"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite_database"
    if head.startswith(b"ITSF"):
        return "compiled_help_document"
    if head.startswith(b"ITOLITLS"):
        return "help_or_ebook_container"
    if head.startswith(b"regf"):
        return "windows_registry_hive"
    if head.startswith(b"\xed\xab\xee\xdb"):
        return "rpm_package"

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png_image"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif_image"
    if head.startswith(b"BM"):
        return "bitmap_image"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff_image"
    if head.startswith(b"\x00\x00\x01\x00"):
        return "icon_image"
    if head.startswith(b"RIFF") and head[8:12] in {b"WAVE", b"AVI ", b"WEBP"}:
        return "riff_media"

    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "bmff_media"
    if head.startswith(b"\x1aE\xdf\xa3"):
        return "matroska_media"
    if head.startswith(b"OggS"):
        return "ogg_media"
    if head.startswith(b"fLaC"):
        return "flac_audio"
    if head.startswith(b"ID3"):
        return "mp3_audio"
    if _looks_like_flv(head):
        return "flash_video"
    if _looks_like_swf(head):
        return "flash_media"

    if head.startswith((b"\x00\x01\x00\x00", b"OTTO", b"wOFF", b"wOF2")):
        return "font_file"
    if _looks_like_intel_hex(head):
        return "intel_hex_firmware"
    if suffix == ".b64" and _looks_like_base64(head):
        return "base64_text"
    if suffix == ".obj" and _looks_like_coff_object(head):
        return "coff_object"
    return ""


def _looks_like_flv(data: bytes) -> bool:
    if len(data) < 9 or data[:4] != b"FLV\x01":
        return False
    flags = data[4]
    data_offset = struct.unpack_from(">L", data, 5)[0]
    return not flags & ~0x05 and data_offset >= 9


def _looks_like_swf(data: bytes) -> bool:
    if len(data) < 8 or data[:3] not in {b"FWS", b"CWS", b"ZWS"}:
        return False
    version = data[3]
    declared_size = struct.unpack_from("<L", data, 4)[0]
    return 1 <= version <= 50 and declared_size >= 8


def _looks_like_intel_hex(data: bytes) -> bool:
    first_line = data.lstrip(b"\xef\xbb\xbf\r\n \t").splitlines()[0:1]
    if not first_line or not first_line[0].startswith(b":"):
        return False
    encoded = first_line[0][1:].strip()
    if len(encoded) < 10 or len(encoded) % 2:
        return False
    try:
        record = bytes.fromhex(encoded.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return len(record) == record[0] + 5 and sum(record) % 256 == 0


def _looks_like_base64(data: bytes) -> bool:
    sample = b"".join(data[:64 * 1024].split())
    if len(sample) < 16:
        return False
    padding = len(sample) - len(sample.rstrip(b"="))
    if padding > 2 or b"=" in sample[:-padding or None]:
        return False
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return all(value in alphabet for value in sample.rstrip(b"="))


def _looks_like_coff_object(data: bytes) -> bool:
    if len(data) < 20:
        return False
    machine, section_count = struct.unpack_from("<2H", data)
    known_machines = {
        0x014C,
        0x0166,
        0x0169,
        0x01C0,
        0x01C2,
        0x01C4,
        0x01F0,
        0x01F1,
        0x0200,
        0x0266,
        0x0284,
        0x0366,
        0x0466,
        0x0520,
        0x0EBC,
        0x8664,
        0x9041,
        0xAA64,
    }
    optional_header_size = struct.unpack_from("<H", data, 16)[0]
    return machine in known_machines and 0 < section_count <= 96 and optional_header_size == 0


def _archive_magic_evidence(head: bytes, tail: bytes) -> Set[str]:
    evidence: Set[str] = set()
    edges = (head, tail)
    if any(
        signature in edge
        for edge in edges
        for signature in (ZIP_LOCAL, ZIP_CENTRAL, ZIP64_EOCD)
    ):
        evidence.add("zip_header")
    if ZIP_EOCD in tail or ZIP64_LOCATOR in tail:
        evidence.add("zip_tail")
    if any(SEVEN_ZIP in edge for edge in edges):
        evidence.add("7z_header")
    if any(RAR4 in edge or RAR5 in edge for edge in edges):
        evidence.add("rar_header")
    if any(b"MSCF" in edge for edge in edges):
        evidence.add("cab_header")
    if any(b"MSWIM\x00\x00\x00" in edge for edge in edges):
        evidence.add("wim_header")
    if any(b"!<arch>\n" in edge for edge in edges):
        evidence.add("ar_header")
    if any(_has_compressed_stream_header(edge) for edge in edges):
        evidence.add("compressed_stream_header")
    if any(_has_valid_tar_header(edge) for edge in edges):
        evidence.add("tar_header")
    if any(_has_iso_descriptor(edge) for edge in edges):
        evidence.add("iso9660_header")
    if b"koly" in tail:
        evidence.add("dmg_tail")
    if b"conectix" in tail:
        evidence.add("vhd_tail")
    return evidence


def _has_compressed_stream_header(data: bytes) -> bool:
    if b"\xfd7zXZ\x00" in data or b"(\xb5/\xfd" in data:
        return True

    search_from = 0
    while True:
        offset = data.find(b"\x1f\x8b\x08", search_from)
        if offset < 0:
            break
        search_from = offset + 1
        if offset + 10 <= len(data) and not data[offset + 3] & 0xE0:
            return True

    search_from = 0
    while True:
        offset = data.find(b"BZh", search_from)
        if offset < 0:
            return False
        search_from = offset + 1
        if (
            offset + 10 <= len(data)
            and data[offset + 3 : offset + 4] in b"123456789"
            and data[offset + 4 : offset + 10] == b"1AY&SY"
        ):
            return True


def _has_valid_tar_header(data: bytes) -> bool:
    search_from = 0
    while True:
        magic_offset = data.find(b"ustar", search_from)
        if magic_offset < 0:
            return False
        search_from = magic_offset + 1
        header_start = magic_offset - 257
        header_end = header_start + 512
        if header_start < 0 or header_end > len(data):
            continue
        header = data[header_start:header_end]
        raw_checksum = header[148:156].strip(b" \x00")
        try:
            expected = int(raw_checksum or b"0", 8)
        except ValueError:
            continue
        actual = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
        if expected == actual:
            return True


def _has_iso_descriptor(data: bytes) -> bool:
    search_from = 0
    while True:
        marker = data.find(b"CD001", search_from)
        if marker < 0:
            return False
        search_from = marker + 1
        if marker > 0 and marker + 5 < len(data):
            descriptor_type = data[marker - 1]
            descriptor_version = data[marker + 5]
            if descriptor_type <= 3 and descriptor_version == 1:
                return True


def _looks_zip_like(
    head: bytes,
    tail: bytes,
    path: str,
    advertised_extensions: frozenset[str],
) -> bool:
    if any(
        signature in head or signature in tail
        for signature in (ZIP_LOCAL, ZIP_CENTRAL, ZIP_EOCD, ZIP64_EOCD, ZIP64_LOCATOR)
    ):
        return True
    suffix = os.path.splitext(path)[1].casefold()
    return (
        suffix in SEMANTIC_EXTENSION_HINTS
        or suffix == ".zip"
        or suffix in advertised_extensions
    )


def _zip_central_info(
    path: str,
    file_size: int,
    tail: bytes,
    tail_start: int,
    logical_end: Optional[int] = None,
    cancel_check: CancelCheck = None,
) -> Optional[_ZipCentralInfo]:
    if logical_end is None:
        logical_end = file_size
    candidates = []
    search_from = 0
    while True:
        if cancel_check is not None and cancel_check():
            return None
        offset = tail.find(ZIP_EOCD, search_from)
        if offset < 0:
            break
        search_from = offset + 1
        if offset + 22 <= len(tail):
            comment_length = struct.unpack_from("<H", tail, offset + 20)[0]
            if tail_start + offset + 22 + comment_length == logical_end:
                candidates.append(offset)

    for offset in reversed(candidates):
        if cancel_check is not None and cancel_check():
            return None
        (
            _signature,
            disk_number,
            cd_disk,
            entries_on_disk,
            total_entries,
            cd_size,
            cd_relative,
            _comment_length,
        ) = struct.unpack_from("<4s4H2LH", tail, offset)
        if disk_number or cd_disk or entries_on_disk != total_entries:
            continue
        absolute_eocd = tail_start + offset
        if (
            total_entries == 0xFFFF
            or cd_size == 0xFFFFFFFF
            or cd_relative == 0xFFFFFFFF
        ):
            info = _zip64_central_info(tail, tail_start, offset, absolute_eocd)
        else:
            central_start = absolute_eocd - cd_size
            info = _ZipCentralInfo(central_start, cd_size, total_entries)
        if info is not None and _validate_zip_central_start(path, file_size, info):
            return info
    return None


def _zip_central_info_for_span(
    path: str,
    file_size: int,
    span_start: int,
    span_end: int,
    cancel_check: CancelCheck = None,
) -> Optional[_ZipCentralInfo]:
    if not 0 <= span_start < span_end <= file_size:
        return None
    tail_start = max(span_start, span_end - TAIL_SCAN_BYTES)
    try:
        with open(path, "rb") as stream:
            stream.seek(tail_start)
            tail = stream.read(span_end - tail_start)
    except OSError:
        return None
    info = _zip_central_info(
        path,
        file_size,
        tail,
        tail_start,
        logical_end=span_end,
        cancel_check=cancel_check,
    )
    if info is None or info.start < span_start or info.start + info.size > span_end:
        return None
    return info


def _zip64_central_info(
    tail: bytes, tail_start: int, eocd_offset: int, absolute_eocd: int
) -> Optional[_ZipCentralInfo]:
    locator_offset = eocd_offset - 20
    if (
        locator_offset < 0
        or tail[locator_offset : locator_offset + 4] != ZIP64_LOCATOR
    ):
        return None
    try:
        (
            _locator_signature,
            zip64_disk,
            zip64_relative,
            disk_count,
        ) = struct.unpack_from("<4sLQL", tail, locator_offset)
    except struct.error:
        return None
    if zip64_disk or disk_count != 1:
        return None

    zip64_offset = tail.rfind(ZIP64_EOCD, 0, locator_offset)
    if zip64_offset < 0 or zip64_offset + 56 > locator_offset:
        return None
    try:
        fields = struct.unpack_from("<4sQ2H2L4Q", tail, zip64_offset)
    except struct.error:
        return None
    (
        _signature,
        record_size,
        _version_made,
        _version_needed,
        disk_number,
        cd_disk,
        entries_on_disk,
        total_entries,
        cd_size,
        cd_relative,
    ) = fields
    if (
        record_size < 44
        or zip64_offset + 12 + record_size != locator_offset
        or disk_number
        or cd_disk
        or entries_on_disk != total_entries
    ):
        return None
    absolute_zip64 = tail_start + zip64_offset
    archive_prefix = absolute_zip64 - zip64_relative
    central_start = archive_prefix + cd_relative
    if central_start + cd_size > absolute_zip64 or absolute_eocd > tail_start + len(tail):
        return None
    return _ZipCentralInfo(central_start, cd_size, total_entries)


def _validate_zip_central_start(
    path: str, file_size: int, info: _ZipCentralInfo
) -> bool:
    if (
        info.start < 0
        or info.size < 0
        or info.entries < 0
        or info.start + info.size > file_size
    ):
        return False
    if info.entries == 0:
        return info.size == 0
    try:
        with open(path, "rb") as stream:
            stream.seek(info.start)
            return stream.read(4) == ZIP_CENTRAL
    except OSError:
        return False


_ZIP_SEMANTIC_EXACT_NAMES = frozenset(
    {
        "[content_types].xml",
        "_rels/.rels",
        "word/document.xml",
        "xl/workbook.xml",
        "ppt/presentation.xml",
        "visio/document.xml",
        "fixeddocumentsequence.fdseq",
        "appxmanifest.xml",
        "appxblockmap.xml",
        "appxsignature.p7x",
        "extension.vsixmanifest",
        "meta-inf/manifest.xml",
        "content.xml",
        "styles.xml",
        "mimetype",
        "meta-inf/container.xml",
        "meta-inf/manifest.mf",
        "androidmanifest.xml",
        "classes.dex",
        "resources.arsc",
        "base/manifest/androidmanifest.xml",
        "install.rdf",
        "meta-inf/mozilla.rsa",
        "doc.kml",
    }
)


def _read_zip_semantic_kind(
    path: str,
    info: _ZipCentralInfo,
    cancel_check: CancelCheck = None,
) -> Optional[str]:
    if (
        info.entries > MAX_ZIP_CLASSIFY_ENTRIES
        or info.size > MAX_ZIP_CENTRAL_BYTES
    ):
        return None

    signals: Set[str] = set()
    consumed = 0
    try:
        with open(path, "rb", buffering=1024 * 1024) as stream:
            stream.seek(info.start)
            for _index in range(info.entries):
                if cancel_check is not None and cancel_check():
                    return None
                header = stream.read(46)
                if len(header) != 46 or header[:4] != ZIP_CENTRAL:
                    return None
                name_length, extra_length, comment_length = struct.unpack_from(
                    "<3H", header, 28
                )
                record_size = 46 + name_length + extra_length + comment_length
                if consumed + record_size > info.size:
                    return None
                raw_name = stream.read(name_length)
                if len(raw_name) != name_length:
                    return None
                stream.seek(extra_length + comment_length, os.SEEK_CUR)
                consumed += record_size
                if _observe_zip_semantic_name(raw_name, signals):
                    kind = _semantic_zip_kind(signals)
                    if kind:
                        return kind
    except (OSError, struct.error):
        return None
    return ""


def _observe_zip_semantic_name(raw_name: bytes, signals: Set[str]) -> bool:
    normalized = raw_name.replace(b"\\", b"/").strip(b"/").lower()
    try:
        name = normalized.decode("ascii")
    except UnicodeDecodeError:
        name = ""
    before = len(signals)
    if name in _ZIP_SEMANTIC_EXACT_NAMES:
        signals.add(name)
    if normalized.endswith(b".fpage"):
        signals.add("signal.fpage")
    if normalized.endswith(b".nuspec"):
        signals.add("signal.nuspec")
    if normalized.startswith(b"base/dex/"):
        signals.add("base/dex/signal")
    if normalized.startswith(b"payload/") and normalized.endswith(b".app/info.plist"):
        signals.add("payload/signal.app/info.plist")
    if normalized.endswith(b".dist-info/wheel"):
        signals.add("signal.dist-info/wheel")
    if normalized.endswith(b".dist-info/metadata"):
        signals.add("signal.dist-info/metadata")
    return len(signals) != before


def _parse_central_names(data: bytes, expected_entries: int) -> Optional[Set[str]]:
    """Compatibility parser retained for focused callers and diagnostics."""

    names: Set[str] = set()
    offset = 0
    for _index in range(expected_entries):
        if offset + 46 > len(data) or data[offset : offset + 4] != ZIP_CENTRAL:
            return None
        flags = struct.unpack_from("<H", data, offset + 8)[0]
        name_length, extra_length, comment_length = struct.unpack_from(
            "<3H", data, offset + 28
        )
        record_end = offset + 46 + name_length + extra_length + comment_length
        if record_end > len(data):
            return None
        raw_name = data[offset + 46 : offset + 46 + name_length]
        encoding = "utf-8" if flags & 0x800 else "cp437"
        try:
            name = raw_name.decode(encoding)
        except UnicodeDecodeError:
            name = raw_name.decode(encoding, errors="replace")
        normalized = name.replace("\\", "/").strip("/").casefold()
        if normalized:
            names.add(normalized)
        offset = record_end
    return names


def _semantic_zip_kind(names: Set[str]) -> str:
    if not names:
        return ""

    content_types = "[content_types].xml" in names
    package_rels = "_rels/.rels" in names
    if content_types and package_rels:
        if "word/document.xml" in names:
            return "ooxml_word_document"
        if "xl/workbook.xml" in names:
            return "ooxml_spreadsheet"
        if "ppt/presentation.xml" in names:
            return "ooxml_presentation"
        if "visio/document.xml" in names:
            return "ooxml_visio_document"
        if "fixeddocumentsequence.fdseq" in names or any(
            name.endswith(".fpage") for name in names
        ):
            return "xps_document"
    if content_types and (
        "appxmanifest.xml" in names
        or "appxblockmap.xml" in names
        or "appxsignature.p7x" in names
    ):
        return "windows_app_package"
    if content_types and "extension.vsixmanifest" in names:
        return "visual_studio_extension"
    if content_types and any(name.endswith(".nuspec") for name in names):
        return "nuget_package"

    if (
        "meta-inf/manifest.xml" in names
        and "content.xml" in names
        and ("styles.xml" in names or "mimetype" in names)
    ):
        return "open_document"
    if "meta-inf/container.xml" in names and "mimetype" in names:
        return "epub_document"
    if "meta-inf/manifest.mf" in names:
        return "java_application_package"
    if "androidmanifest.xml" in names and (
        "classes.dex" in names or "resources.arsc" in names
    ):
        return "android_application_package"
    if (
        "base/manifest/androidmanifest.xml" in names
        and any(name.startswith("base/dex/") for name in names)
    ):
        return "android_app_bundle"
    if any(
        name.startswith("payload/") and name.endswith(".app/info.plist")
        for name in names
    ):
        return "ios_application_package"
    if any(name.endswith(".dist-info/wheel") for name in names) and any(
        name.endswith(".dist-info/metadata") for name in names
    ):
        return "python_wheel"
    if "install.rdf" in names or "meta-inf/mozilla.rsa" in names:
        return "browser_extension"
    if "doc.kml" in names:
        return "kmz_document"
    return ""
