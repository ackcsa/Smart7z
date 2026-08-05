import gzip
import io
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

import archive_classifier
from archive_classifier import classify_automatic_candidate
from executor import Executor
from models import Job
from nested import NestedExtractor


def _zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return stream.getvalue()


def _ooxml_bytes():
    return _zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "_rels/.rels": b"<Relationships/>",
            "word/document.xml": b"<document/>",
        }
    )


def _pe_bytes(overlay=b""):
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<L", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHLLLHH",
        image,
        0x84,
        0x8664,
        1,
        0,
        0,
        0,
        0xF0,
        0x0022,
    )
    optional_offset = 0x98
    struct.pack_into("<H", image, optional_offset, 0x20B)
    struct.pack_into("<L", image, optional_offset + 60, 0x200)
    struct.pack_into("<L", image, optional_offset + 108, 16)
    section_offset = optional_offset + 0xF0
    image[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<L", image, section_offset + 8, 0x200)
    struct.pack_into("<L", image, section_offset + 12, 0x1000)
    struct.pack_into("<L", image, section_offset + 16, 0x200)
    struct.pack_into("<L", image, section_offset + 20, 0x200)
    struct.pack_into("<L", image, section_offset + 36, 0x60000020)
    return bytes(image) + overlay


def _7z_bytes():
    next_header = b"\x01\x00"
    next_crc = zlib.crc32(next_header) & 0xFFFFFFFF
    start_header = struct.pack("<QQL", 0, len(next_header), next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return (
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<L", start_crc)
        + start_header
        + next_header
    )


class TestContentFirstClassifier(unittest.TestCase):
    def test_leading_archive_header_uses_quick_edge_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "large.7z"
            with path.open("wb") as stream:
                stream.write(b"7z\xbc\xaf\x27\x1c\x00\x04")
                stream.truncate(8 * 1024 * 1024)

            with mock.patch.object(
                archive_classifier,
                "_read_edges",
                side_effect=AssertionError("full edge read must be skipped"),
            ):
                decision = classify_automatic_candidate(
                    str(path), frozenset({".7z"})
                )

            self.assertTrue(decision.should_queue)
            self.assertEqual(decision.reason, "content_archive")
            self.assertIn("7z_header", decision.archive_evidence)

    def test_classifier_uses_one_metadata_query_per_plain_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plain.bin"
            path.write_bytes(b"plain data")
            original_stat = archive_classifier.os.stat

            with mock.patch.object(
                archive_classifier.os,
                "stat",
                wraps=original_stat,
            ) as stat_call:
                decision = classify_automatic_candidate(str(path))

            self.assertFalse(decision.should_queue)
            self.assertEqual(stat_call.call_count, 1)

    def test_quick_header_does_not_override_tail_validated_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "polyglot.bin"
            payload = bytearray(2 * 1024 * 1024)
            payload[:6] = b"7z\xbc\xaf\x27\x1c"
            payload[32:37] = b"%PDF-"
            payload[-128 * 1024 : -128 * 1024 + 5] = b"%%EOF"
            path.write_bytes(payload)

            decision = classify_automatic_candidate(str(path))

            self.assertFalse(decision.should_queue)
            self.assertEqual(decision.semantic_kind, "pdf_document")

    def test_cancelled_automatic_classification_has_no_queue_side_effect(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "candidate.zip"
            path.write_bytes(_zip_bytes({"inside.txt": b"payload"}))

            decision = classify_automatic_candidate(
                str(path),
                {".zip"},
                cancel_check=lambda: True,
            )

            self.assertFalse(decision.should_queue)
            self.assertEqual(decision.reason, "cancelled")

    def test_ooxml_structure_is_skipped_even_when_renamed_zip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for name in ("report.docx", "report.zip"):
                path = Path(temp_dir) / name
                path.write_bytes(_ooxml_bytes())
                with self.subTest(name=name):
                    decision = classify_automatic_candidate(
                        str(path), {".zip", ".docx"}
                    )
                    self.assertFalse(decision.should_queue)
                    self.assertEqual(decision.reason, "semantic_container")
                    self.assertEqual(
                        decision.semantic_kind,
                        "ooxml_word_document",
                    )
                    self.assertIn(
                        "zip_central_directory",
                        decision.archive_evidence,
                    )

    def test_generic_zip_renamed_docx_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.docx"
            path.write_bytes(_zip_bytes({"payload.txt": b"payload"}))
            decision = classify_automatic_candidate(str(path), {".docx"})
            self.assertTrue(decision.should_queue)
            self.assertEqual(decision.reason, "content_archive")
            self.assertFalse(decision.is_semantic)

    def test_7z_and_rar_signatures_override_semantic_extension_hint(self):
        samples = {
            "renamed-7z.docx": b"preamble" + b"7z\xbc\xaf\x27\x1c" + b"payload",
            "renamed-rar.docx": b"preamble" + b"Rar!\x1a\x07\x01\x00" + b"payload",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, payload in samples.items():
                path = Path(temp_dir) / name
                path.write_bytes(payload)
                with self.subTest(name=name):
                    decision = classify_automatic_candidate(
                        str(path), {".docx"}
                    )
                    self.assertTrue(decision.should_queue)
                    self.assertFalse(decision.is_semantic)

    def test_exact_media_zip_queues_but_executable_host_stays_skipped(self):
        zip_data = _zip_bytes({"payload.txt": b"payload"})
        samples = {
            "program.bin": b"MZ" + (b"\x00" * 64) + zip_data,
            "image.bin": b"\x89PNG\r\n\x1a\n" + (b"\x00" * 64) + zip_data,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            decisions = {}
            for name, payload in samples.items():
                path = Path(temp_dir) / name
                path.write_bytes(payload)
                decisions[name] = classify_automatic_candidate(str(path), {".zip"})
            self.assertFalse(decisions["program.bin"].should_queue)
            self.assertTrue(decisions["image.bin"].should_queue)
            self.assertEqual(
                decisions["image.bin"].reason, "confirmed_embedded_archive"
            )

    def test_mkv_host_with_one_complete_middle_zip_is_confirmed(self):
        zip_data = _zip_bytes({"payload.txt": b"payload"})
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "movie.mkv"
            path.write_bytes(
                b"\x1a\x45\xdf\xa3"
                + (b"m" * (1024 * 1024))
                + zip_data
                + (b"t" * (1024 * 1024))
            )

            decision = classify_automatic_candidate(str(path), {".mkv", ".zip"})

            self.assertTrue(decision.should_queue)
            self.assertEqual(decision.reason, "confirmed_embedded_archive")
            self.assertIn("zip_central_directory", decision.archive_evidence)

    def test_media_with_weak_archive_magic_stays_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "image.bin"
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 32 + b"7z\xbc\xaf\x27\x1c")
            decision = classify_automatic_candidate(str(path), {".7z"})
            self.assertFalse(decision.should_queue)
            self.assertEqual(decision.reason, "semantic_container")

    def test_zip_structure_tolerates_preamble_and_trailing_data(self):
        generic = _zip_bytes({"payload.txt": b"payload"})
        semantic = _ooxml_bytes()
        with tempfile.TemporaryDirectory() as temp_dir:
            generic_path = Path(temp_dir) / "renamed.bin"
            semantic_path = Path(temp_dir) / "document.7z"
            generic_path.write_bytes(b"prefix-data" + generic + b"trailing-data")
            semantic_path.write_bytes(b"prefix-data" + semantic + b"trailing-data")

            accepted = classify_automatic_candidate(str(generic_path), {".7z"})
            skipped = classify_automatic_candidate(str(semantic_path), {".7z"})
            self.assertTrue(accepted.should_queue)
            self.assertIn("zip_central_directory", accepted.archive_evidence)
            self.assertFalse(skipped.should_queue)
            self.assertEqual(skipped.semantic_kind, "ooxml_word_document")

    def test_tar_and_gzip_signatures_tolerate_preamble_and_trailing_data(self):
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as archive:
            info = tarfile.TarInfo("payload.txt")
            payload = b"payload"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        samples = {
            "renamed-tar.bin": b"prefix" + tar_stream.getvalue() + b"tail",
            "renamed-gzip.bin": b"prefix" + gzip.compress(b"payload") + b"tail",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, payload in samples.items():
                path = Path(temp_dir) / name
                path.write_bytes(payload)
                with self.subTest(name=name):
                    self.assertTrue(
                        classify_automatic_candidate(str(path)).should_queue
                    )

    def test_short_gzip_magic_alone_is_not_archive_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "random.bin"
            path.write_bytes(b"plain-data\x1f\x8bnot-a-gzip-stream")
            decision = classify_automatic_candidate(str(path))
            self.assertFalse(decision.should_queue)
            self.assertEqual(decision.reason, "no_archive_structure")

    def test_other_7z_readable_semantic_formats_are_skipped(self):
        samples = {
            "package.rpm": b"\xed\xab\xee\xdb" + (b"\x00" * 92),
            "movie.flv": b"FLV\x01\x05\x00\x00\x00\x09",
            "movie.swf": b"FWS\x0a\x08\x00\x00\x00",
            "help.hxs": b"ITOLITLS\x01\x00\x00\x00" + (b"\x00" * 32),
            "settings.bin": b"regf" + (b"\x00" * 64),
            "firmware.ihex": b":00000001FF\r\n",
            "encoded.b64": b"VGhpcyBpcyBiYXNlNjQu",
            "module.obj": struct.pack(
                "<HHLLLHH",
                0x8664,
                1,
                0,
                0,
                0,
                0,
                0,
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, payload in samples.items():
                path = Path(temp_dir) / name
                path.write_bytes(payload)
                with self.subTest(name=name):
                    decision = classify_automatic_candidate(
                        str(path), {path.suffix}
                    )
                    self.assertFalse(decision.should_queue)
                    self.assertTrue(decision.is_semantic)

    def test_archives_renamed_to_semantic_extensions_are_still_accepted(self):
        payload = _zip_bytes({"payload.txt": b"payload"})
        with tempfile.TemporaryDirectory() as temp_dir:
            for name in ("archive.b64", "archive.obj", "archive.rpm"):
                path = Path(temp_dir) / name
                path.write_bytes(payload)
                with self.subTest(name=name):
                    decision = classify_automatic_candidate(
                        str(path), {path.suffix}
                    )
                    self.assertTrue(decision.should_queue)
                    self.assertFalse(decision.is_semantic)


class TestAutomaticDiscoveryIntegration(unittest.TestCase):
    def test_nested_scan_skips_semantic_zip_and_marks_child_automatic(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            semantic = Path(temp_dir) / "report.zip"
            archive = Path(temp_dir) / "payload.docx"
            semantic.write_bytes(_ooxml_bytes())
            archive.write_bytes(_zip_bytes({"payload.txt": b"payload"}))
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
                archive_extensions={".zip", ".docx"},
            )

            count = extractor.scan_and_submit(
                Job(path="parent.zip", extract_to_source_override=True), temp_dir
            )

        self.assertEqual(count, 1)
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0].original_basename, "payload.docx")
        self.assertFalse(submitted[0].explicit_input)
        self.assertEqual(submitted[0].nested_depth, 1)
        self.assertTrue(submitted[0].extract_to_source_override)

    def test_nested_scan_submits_only_main_volume_for_common_schemes(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            samples = {
                "numeric.001": b"7z\xbc\xaf\x27\x1cmain",
                "numeric.002": b"7z\xbc\xaf\x27\x1cchild",
                "parts.part01.rar": b"Rar!\x1a\x07\x01\x00main",
                "parts.part02.rar": b"Rar!\x1a\x07\x01\x00child",
                "classic.rar": b"Rar!\x1a\x07\x01\x00main",
                "classic.r00": b"Rar!\x1a\x07\x01\x00child",
                "split.z01": b"PK\x03\x04child",
                "split.zip": b"PK\x05\x06" + (b"\x00" * 18),
                "legacy.arj": b"`\xeamain",
                "legacy.a01": b"`\xeachild",
                "image.swm": b"MSWIM\x00\x00\x00main",
                "image2.swm": b"MSWIM\x00\x00\x00child",
            }
            for name, payload in samples.items():
                (Path(temp_dir) / name).write_bytes(payload)
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                max_children=20,
                submit_cb=submitted.append,
                archive_extensions={
                    ".001",
                    ".a01",
                    ".arj",
                    ".r00",
                    ".rar",
                    ".swm",
                    ".z01",
                    ".zip",
                },
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

            self.assertEqual(count, 7)
        self.assertEqual(
            {job.original_basename for job in submitted},
            {
                "numeric.001",
                "numeric.002",
                "parts.part01.rar",
                "classic.rar",
                "split.zip",
                "legacy.arj",
                "image.swm",
            },
        )

    def test_root_executable_protects_the_whole_extraction_root(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "game.exe").write_bytes(_pe_bytes())
            (Path(temp_dir) / "resources.pak").write_bytes(
                _zip_bytes({"asset.bin": b"payload"})
            )
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
                archive_extensions={".pak"},
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 0)
        self.assertEqual(submitted, [])

    def test_executable_protects_its_directory_and_parent_only(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            executable_dir = root / "game" / "bin"
            executable_dir.mkdir(parents=True)
            (executable_dir / "game.exe").write_bytes(_pe_bytes())
            (root / "game" / "assets.pak").write_bytes(
                _zip_bytes({"asset.bin": b"payload"})
            )
            other = root / "other"
            other.mkdir()
            (other / "archive.zip").write_bytes(
                _zip_bytes({"data.txt": b"nested"})
            )
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
                archive_extensions={".pak", ".zip"},
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 1)
        self.assertEqual(submitted[0].original_basename, "archive.zip")

    def test_executable_protection_never_crosses_the_extraction_root(self):
        extractor = NestedExtractor(enabled=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "output"
            root.mkdir()
            executable = root / "game.exe"
            executable.write_bytes(_pe_bytes())
            decisions = {}

            protected = extractor._find_protected_directories(
                str(root), decisions
            )

            canonical_root = extractor._canonical(str(root))
            self.assertEqual(protected, {canonical_root})
            self.assertNotIn(
                extractor._canonical(str(root.parent)), protected
            )

    def test_zip_sfx_executable_remains_a_nested_candidate(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            sfx = Path(temp_dir) / "setup.exe"
            sfx.write_bytes(
                _pe_bytes(_zip_bytes({"payload.txt": b"payload"}))
            )
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 1)
        self.assertEqual(submitted[0].original_basename, "setup.exe")

    def test_7z_sfx_executable_remains_a_nested_candidate(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            sfx = Path(temp_dir) / "installer.exe"
            sfx.write_bytes(_pe_bytes(_7z_bytes()))
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 1)
        self.assertEqual(submitted[0].original_basename, "installer.exe")

    def test_archive_renamed_exe_does_not_enable_directory_protection(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "renamed.exe").write_bytes(
                _zip_bytes({"renamed.txt": b"payload"})
            )
            (root / "sibling.zip").write_bytes(
                _zip_bytes({"sibling.txt": b"payload"})
            )
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 2)
        self.assertEqual(
            {job.original_basename for job in submitted},
            {"renamed.exe", "sibling.zip"},
        )

    def test_non_pe_exe_name_does_not_enable_directory_protection(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "game.exe").write_bytes(b"MZ-not-a-valid-pe")
            (root / "sibling.zip").write_bytes(
                _zip_bytes({"sibling.txt": b"payload"})
            )
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
            )

            count = extractor.scan_and_submit(Job(path="parent.zip"), temp_dir)

        self.assertEqual(count, 1)
        self.assertEqual(submitted[0].original_basename, "sibling.zip")

    def test_nested_jobs_never_use_structural_deep_scan(self):
        deep_executor = Executor(object(), {"deep_scan": True})
        shallow_executor = Executor(object(), {"deep_scan": False})
        scanned_job = Job(path="compatible.mp4", explicit_input=False)
        scanned_job.stego_candidates = [mock.sentinel.compatible_candidate]

        self.assertTrue(
            deep_executor._may_scan_structure(
                Job(path="folder-candidate.bin", explicit_input=False)
            )
        )
        self.assertTrue(
            shallow_executor._may_scan_structure(
                Job(path="dragged.bin", explicit_input=True)
            )
        )
        self.assertTrue(shallow_executor._may_scan_structure(scanned_job))
        self.assertFalse(
            deep_executor._may_scan_structure(
                Job(
                    path="nested.bin",
                    nested_depth=1,
                    explicit_input=True,
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
