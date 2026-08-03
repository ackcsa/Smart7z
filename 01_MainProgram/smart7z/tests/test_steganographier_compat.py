import builtins
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import steganographier_compat


def _zip_bytes(name="payload.txt", content=b"payload"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return output.getvalue()


def _bmff_box(box_type, payload=b""):
    return (8 + len(payload)).to_bytes(4, "big") + box_type + payload


def _ebml_id(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _ebml_size(value):
    for length in range(1, 9):
        if value <= (1 << (7 * length)) - 2:
            raw = bytearray(value.to_bytes(length, "big"))
            raw[0] |= 1 << (8 - length)
            return bytes(raw)
    raise ValueError("EBML payload too large")


def _ebml_element(element_id, payload=b""):
    return _ebml_id(element_id) + _ebml_size(len(payload)) + payload


def _ebml_uint(value):
    size = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(size, "big")


def _matroska_with_attachment(zip_data, cluster_size=0, seek_head=False):
    attached = _ebml_element(
        steganographier_compat.ATTACHED_FILE_ID,
        _ebml_element(
            steganographier_compat.FILE_NAME_ID, b"hidden.zip"
        )
        + _ebml_element(
            steganographier_compat.FILE_MIME_ID, b"application/zip"
        )
        + _ebml_element(steganographier_compat.FILE_DATA_ID, zip_data),
    )
    attachments = _ebml_element(
        steganographier_compat.ATTACHMENTS_ID, attached
    )
    cluster = _ebml_element(
        steganographier_compat.CLUSTER_ID, b"V" * cluster_size
    )
    seek = b""
    if seek_head:
        for _ in range(8):
            position = len(seek) + len(cluster)
            entry = _ebml_element(
                steganographier_compat.SEEK_ID,
                _ebml_element(
                    steganographier_compat.SEEK_TARGET_ID,
                    _ebml_id(steganographier_compat.ATTACHMENTS_ID),
                )
                + _ebml_element(
                    steganographier_compat.SEEK_POSITION_ID,
                    _ebml_uint(position),
                ),
            )
            updated = _ebml_element(
                steganographier_compat.SEEK_HEAD_ID, entry
            )
            if updated == seek:
                break
            seek = updated
    ebml = _ebml_element(steganographier_compat.EBML_ID, b"")
    segment = _ebml_element(
        steganographier_compat.SEGMENT_ID,
        seek + cluster + attachments,
    )
    return ebml + segment


class TestSteganographierCompat(unittest.TestCase):
    def test_trailing_mp4_with_current_randomized_suffix(self):
        zip_data = _zip_bytes()
        suffix = (
            b"Rar!\x1a\x07\x01\x00"
            + b"A" * (5 * 1024)
            + b"7z\xbc\xaf\x27\x1c"
            + b"B" * (10 * 1024)
            + steganographier_compat.EMPTY_MDAT
        )
        content = (
            _bmff_box(b"ftyp", b"isom\x00\x00\x00\x00isom")
            + _bmff_box(b"mdat", b"video-data")
            + zip_data
            + suffix
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hidden.mp4"
            path.write_bytes(content)

            candidates = steganographier_compat.find_steganographier_candidates(
                str(path)
            )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.mode, "steganographier_mp4_trailing")
        self.assertEqual(content[candidate.start_offset : candidate.end_offset], zip_data)
        self.assertIn(
            "steganographier_randomized_suffix", candidate.validation_flags
        )

    def test_classic_mp4_plus_zip_at_eof_is_compatible(self):
        zip_data = _zip_bytes()
        prefix = _bmff_box(b"ftyp", b"isom") + _bmff_box(b"mdat", b"cover")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "classic.mov"
            path.write_bytes(prefix + zip_data)
            candidates = steganographier_compat.find_steganographier_candidates(
                str(path)
            )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].start_offset, len(prefix))
        self.assertEqual(candidates[0].end_offset, len(prefix) + len(zip_data))

    def test_zarchiver_free_atom_payload_is_exact(self):
        zip_data = _zip_bytes()
        ftyp = _bmff_box(b"ftyp", b"isom")
        free = _bmff_box(b"free", zip_data)
        content = ftyp + free + _bmff_box(b"mdat", b"V" * (2 * 1024 * 1024))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "zarchiver.mp4"
            path.write_bytes(content)
            candidates = steganographier_compat.find_steganographier_candidates(
                str(path)
            )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.mode, "steganographier_free_atom")
        self.assertEqual(candidate.start_offset, len(ftyp) + 8)
        self.assertEqual(candidate.end_offset, len(ftyp) + len(free))

    def test_matroska_seek_head_skips_large_cluster(self):
        zip_data = _zip_bytes(content=b"x" * 4096)
        content = _matroska_with_attachment(
            zip_data, cluster_size=8 * 1024 * 1024, seek_head=True
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hidden.mkv"
            path.write_bytes(content)
            real_open = builtins.open
            bytes_read = 0

            class CountingReader:
                def __init__(self, handle):
                    self.handle = handle

                def read(self, size=-1):
                    nonlocal bytes_read
                    data = self.handle.read(size)
                    bytes_read += len(data)
                    return data

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def __getattr__(self, name):
                    return getattr(self.handle, name)

            def counting_open(target, mode="r", *args, **kwargs):
                handle = real_open(target, mode, *args, **kwargs)
                if "b" in mode and os.path.abspath(target) == os.path.abspath(path):
                    return CountingReader(handle)
                return handle

            with mock.patch("builtins.open", side_effect=counting_open):
                candidates = (
                    steganographier_compat.find_steganographier_candidates(
                        str(path)
                    )
                )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].mode, "steganographier_mkv_attachment"
        )
        self.assertLess(bytes_read, 256 * 1024)

    def test_regular_media_and_non_zip_attachment_are_not_reported(self):
        mp4 = _bmff_box(b"ftyp", b"isom") + _bmff_box(
            b"mdat", b"ordinary PK\x03\x04 bytes"
        )
        mkv = _matroska_with_attachment(b"not-a-zip")
        with tempfile.TemporaryDirectory() as temp:
            mp4_path = Path(temp) / "ordinary.mp4"
            mkv_path = Path(temp) / "ordinary.mkv"
            mp4_path.write_bytes(mp4)
            mkv_path.write_bytes(mkv)
            self.assertEqual(
                steganographier_compat.find_steganographier_candidates(
                    str(mp4_path)
                ),
                [],
            )
            self.assertEqual(
                steganographier_compat.find_steganographier_candidates(
                    str(mkv_path)
                ),
                [],
            )

    def test_unknown_size_cluster_without_seek_head_exits_bounded(self):
        zip_data = _zip_bytes()
        attached = _ebml_element(
            steganographier_compat.ATTACHMENTS_ID,
            _ebml_element(
                steganographier_compat.ATTACHED_FILE_ID,
                _ebml_element(
                    steganographier_compat.FILE_NAME_ID, b"hidden.zip"
                )
                + _ebml_element(
                    steganographier_compat.FILE_DATA_ID, zip_data
                ),
            ),
        )
        unknown_cluster = (
            _ebml_id(steganographier_compat.CLUSTER_ID) + b"\xff" + b"media"
        )
        content = _ebml_element(steganographier_compat.EBML_ID) + _ebml_element(
            steganographier_compat.SEGMENT_ID, unknown_cluster + attached
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unknown-size.mkv"
            path.write_bytes(content)
            self.assertEqual(
                steganographier_compat.find_steganographier_candidates(
                    str(path)
                ),
                [],
            )

    def test_cancelled_scan_does_not_open_file(self):
        with mock.patch(
            "steganographier_compat.open",
            side_effect=AssertionError("cancelled detection must not read"),
        ):
            self.assertEqual(
                steganographier_compat.find_steganographier_candidates(
                    "ignored.mp4", cancel_check=lambda: True
                ),
                [],
            )


if __name__ == "__main__":
    unittest.main()
