import unittest
import os
import sys
import struct
import tempfile
import zipfile
import zlib
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from discovery import (
    MAX_VOLUME_INDEX,
    is_multipart_child,
    detect_archive_set,
    group_into_sets,
    get_archive_volumes,
    logical_archive_key,
)
from models import ArchiveSet


class TestIsMultipartChild(unittest.TestCase):
    def test_part2_rar(self):
        self.assertTrue(is_multipart_child("test.part2.rar"))

    def test_part1_rar(self):
        self.assertFalse(is_multipart_child("test.part1.rar"))

    def test_002(self):
        self.assertTrue(is_multipart_child("test.002"))

    def test_001(self):
        self.assertFalse(is_multipart_child("test.001"))

    def test_r01_without_main_rar_is_not_a_child(self):
        # 没有同族 .rar 主卷时，.r01 是独立包而不是续卷；若判为子卷，
        # 扫描会永久跳过它（实测：这种文件里的 ZIP 可被 7-Zip 正常解压）。
        self.assertFalse(is_multipart_child("test.r01"))

    def test_r01_with_main_rar_is_a_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "test.rar"), "wb") as handle:
                handle.write(b"Rar!\x1a\x07\x00" + b"0" * 64)
            self.assertTrue(is_multipart_child(os.path.join(tmp, "test.r01")))

    def test_z01_no_zip(self):
        self.assertFalse(is_multipart_child("test.z01"))

    def test_single_file(self):
        with mock.patch(
            "discovery.os.path.exists",
            side_effect=AssertionError("ordinary names need no existence probe"),
        ):
            self.assertFalse(is_multipart_child("archive.zip"))

    def test_main_volume_name_needs_no_existence_probe(self):
        with mock.patch(
            "discovery.os.path.exists",
            side_effect=AssertionError("main volume needs no existence probe"),
        ):
            self.assertFalse(is_multipart_child("archive.part01.rar"))

    def test_rar_main(self):
        self.assertFalse(is_multipart_child("archive.rar"))

    def test_extended_volume_schemes_with_main_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = (
                "old.rar",
                "old.r00",
                "old.s00",
                "wide.zip",
                "wide.z100",
                "legacy.arj",
                "legacy.a01",
                "image.swm",
                "image2.swm",
            )
            for name in names:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            self.assertTrue(is_multipart_child(os.path.join(tmp, "old.s00")))
            self.assertTrue(is_multipart_child(os.path.join(tmp, "wide.z100")))
            self.assertTrue(is_multipart_child(os.path.join(tmp, "legacy.a01")))
            self.assertTrue(is_multipart_child(os.path.join(tmp, "image2.swm")))


class TestDetectArchiveSet(unittest.TestCase):
    def test_numeric_split(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.001", "a.002", "a.003"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "a.001"))
            self.assertEqual(s.format_family, "numeric_split")
            self.assertEqual(len(s.volumes), 3)
            self.assertTrue(s.is_complete)

    def test_numeric_split_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.001", "a.003"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "a.001"))
            self.assertFalse(s.is_complete)
            self.assertIn(2, s.missing_indexes)

    def test_numeric_split_large_gap_and_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["A.001", "a.010"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "A.001"))
            self.assertFalse(s.is_complete)
            self.assertEqual(s.missing_indexes, list(range(2, 10)))

    def test_numeric_width_is_not_mixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.001", "a.0002"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "a.001"))
            self.assertEqual(len(s.volumes), 1)

    def test_extreme_volume_index_is_not_grouped(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = os.path.join(tmp, "a.000001")
            extreme = os.path.join(tmp, f"a.{MAX_VOLUME_INDEX + 1:06d}")
            for path in (main, extreme):
                with open(path, "w") as stream:
                    stream.write("x")

            archive_set = detect_archive_set(main)
            self.assertEqual(archive_set.volumes, [main])
            self.assertTrue(archive_set.is_complete)
            self.assertFalse(is_multipart_child(extreme))

    def test_part_rar(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["b.part1.rar", "b.part2.rar"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "b.part1.rar"))
            self.assertEqual(s.format_family, "part_rar")
            self.assertEqual(len(s.volumes), 2)

    def test_classic_rar(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["c.rar", "c.r00", "c.r01"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "c.rar"))
            self.assertEqual(s.format_family, "classic_rar")
            self.assertEqual(len(s.volumes), 3)

    def test_zip_split(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["d.zip", "d.z01", "d.z02"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            s = detect_archive_set(os.path.join(tmp, "d.zip"))
            self.assertEqual(s.format_family, "zip_split")
            self.assertEqual(len(s.volumes), 3)

    def test_extended_classic_rar_and_zip_volume_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["old.rar", "old.r00", "old.s00"]:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            rar_set = detect_archive_set(os.path.join(tmp, "old.s00"))
            self.assertEqual(rar_set.format_family, "classic_rar")
            self.assertEqual(len(rar_set.volumes), 3)
            self.assertIn(100, rar_set.missing_indexes)

            for name in ["wide.zip", "wide.z100"]:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            zip_set = detect_archive_set(os.path.join(tmp, "wide.z100"))
            self.assertEqual(zip_set.format_family, "zip_split")
            self.assertEqual(len(zip_set.volumes), 2)
            self.assertEqual(zip_set.missing_indexes, list(range(1, 100)))

    def test_arj_split(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["legacy.arj", "legacy.a01", "legacy.a02"]:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            archive_set = detect_archive_set(os.path.join(tmp, "legacy.a02"))
            self.assertEqual(archive_set.format_family, "arj_split")
            self.assertEqual(len(archive_set.volumes), 3)
            self.assertTrue(archive_set.is_complete)
            self.assertTrue(archive_set.main_path.lower().endswith("legacy.arj"))

    def test_split_wim(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["install.swm", "install2.swm", "install3.swm", "install10.swm"]:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            archive_set = detect_archive_set(os.path.join(tmp, "install2.swm"))
            self.assertEqual(archive_set.format_family, "wim_split")
            self.assertEqual(len(archive_set.volumes), 4)
            self.assertEqual(archive_set.missing_indexes, list(range(4, 10)))
            self.assertTrue(archive_set.main_path.lower().endswith("install.swm"))

    def test_split_wim_missing_middle_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["install.swm", "install3.swm"]:
                with open(os.path.join(tmp, name), "w") as stream:
                    stream.write("x")
            archive_set = detect_archive_set(os.path.join(tmp, "install.swm"))
            self.assertFalse(archive_set.is_complete)
            self.assertEqual(archive_set.missing_indexes, [2])

    def test_standalone_wim_name_ending_in_digits_is_not_rebased(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "windows11.swm")
            with open(path, "w") as stream:
                stream.write("x")
            archive_set = detect_archive_set(path)
            self.assertEqual(archive_set.volumes, [path])
            self.assertTrue(archive_set.is_complete)

    def test_standalone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "single.mp4")
            with open(path, "w") as f:
                f.write("x")
            s = detect_archive_set(path)
            self.assertEqual(s.format_family, "standalone")
            self.assertEqual(len(s.volumes), 1)


class TestGroupIntoSets(unittest.TestCase):
    def test_groups_and_standalone(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for name in ["a.001", "a.002", "b.mp4", "c.part1.rar", "c.part2.rar"]:
                p = os.path.join(tmp, name)
                with open(p, "w") as f:
                    f.write("x")
                files.append(p)

            sets, standalone = group_into_sets(files)
            self.assertEqual(len(sets), 2)
            self.assertEqual(len(standalone), 1)
            self.assertEqual(os.path.basename(standalone[0]), "b.mp4")

    def test_dedup_same_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for name in ["a.001", "a.002", "a.003"]:
                p = os.path.join(tmp, name)
                with open(p, "w") as f:
                    f.write("x")
                files.append(p)

            sets, standalone = group_into_sets(files)
            self.assertEqual(len(sets), 1)
            self.assertEqual(len(sets[0].volumes), 3)


class TestGetArchiveVolumes(unittest.TestCase):
    def test_single(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "single.zip")
            with open(path, "w") as f:
                f.write("x")
            vols = get_archive_volumes(path)
            self.assertEqual(len(vols), 1)

    def test_multi(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.001", "a.002"]:
                with open(os.path.join(tmp, name), "w") as f:
                    f.write("x")
            vols = get_archive_volumes(os.path.join(tmp, "a.001"))
            self.assertEqual(len(vols), 2)


class TestContinuationNamedPackages(unittest.TestCase):
    """A complete archive keeps its own identity even with a continuation name."""

    @staticmethod
    def _write_zip(path):
        with zipfile.ZipFile(path, "w") as writer:
            writer.writestr("payload.txt", b"package")

    @staticmethod
    def _write_fragment(path):
        with open(path, "wb") as stream:
            stream.write(b"\x00" * 64)

    def test_zip_package_named_r20_is_standalone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.r20")
            self._write_zip(path)
            archive_set = detect_archive_set(path)
        self.assertEqual(archive_set.format_family, "standalone")
        self.assertTrue(archive_set.is_complete)
        self.assertEqual(list(archive_set.volumes), [os.path.abspath(path)])

    def test_zip_package_named_z20_is_standalone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "data.z20")
            self._write_zip(path)
            archive_set = detect_archive_set(path)
        self.assertEqual(archive_set.format_family, "standalone")
        self.assertTrue(archive_set.is_complete)

    def test_package_is_not_a_child_of_a_same_named_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_zip(os.path.join(tmp, "data.zip"))
            package = os.path.join(tmp, "data.z20")
            self._write_zip(package)
            self.assertFalse(is_multipart_child(package))

    def test_r_package_is_not_a_child_of_a_same_named_rar(self):
        # .r99 携带完整归档时是独立包，即使同族 .rar 存在也不能被跳过，
        # 去重键同样不能与 .rar 合并（否则会被静默丢弃）。
        with tempfile.TemporaryDirectory() as tmp:
            rar_main = os.path.join(tmp, "mix.rar")
            with open(rar_main, "wb") as stream:
                stream.write(b"Rar!\x1a\x07\x00" + b"0" * 64)
            package = os.path.join(tmp, "mix.r99")
            self._write_zip(package)
            self.assertFalse(is_multipart_child(package))
            self.assertNotEqual(
                logical_archive_key(package), logical_archive_key(rar_main)
            )

    def test_r_continuation_of_a_rar_set_is_still_a_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "book.rar"), "wb") as stream:
                stream.write(b"Rar!\x1a\x07\x00" + b"0" * 64)
            fragment = os.path.join(tmp, "book.r01")
            self._write_fragment(fragment)
            self.assertTrue(is_multipart_child(fragment))

    def test_structureless_sidecar_of_complete_zip_is_not_a_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_zip(os.path.join(tmp, "report.zip"))
            fragment = os.path.join(tmp, "report.z01")
            self._write_fragment(fragment)
            self.assertFalse(is_multipart_child(fragment))
            self.assertNotEqual(logical_archive_key(fragment), logical_archive_key(
                os.path.join(tmp, "report.zip")
            ))
            self.assertEqual(detect_archive_set(fragment).main_path, fragment)

    def test_genuine_missing_volume_is_still_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_fragment(os.path.join(tmp, "report.zip"))
            fragment = os.path.join(tmp, "report.z03")
            self._write_fragment(fragment)
            archive_set = detect_archive_set(fragment)
        self.assertFalse(archive_set.is_complete)
        self.assertEqual(archive_set.format_family, "zip_split")

    def test_numbered_fragment_without_structure_still_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("archive.001", "archive.002"):
                self._write_fragment(os.path.join(tmp, name))
            archive_set = detect_archive_set(os.path.join(tmp, "archive.001"))
        self.assertEqual(archive_set.format_family, "numeric_split")
        self.assertTrue(archive_set.is_complete)

    def test_complete_package_wins_even_with_contiguous_same_named_siblings(self):
        for suffix in (".z01", ".r00", ".r01", ".002", ".part2.rar", ".a01", "2.swm"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                main_suffix = (
                    ".zip" if suffix == ".z01" else
                    ".001" if suffix == ".002" else
                    ".part1.rar" if suffix == ".part2.rar" else
                    ".arj" if suffix == ".a01" else
                    ".swm" if suffix == "2.swm" else ".rar"
                )
                main = os.path.join(tmp, "package" + main_suffix)
                selected = os.path.join(tmp, "package" + suffix)
                self._write_zip(main)
                self._write_zip(selected)
                archive_set = detect_archive_set(selected)
                self.assertEqual(archive_set.main_path, selected)
                self.assertEqual(archive_set.volumes, [selected])
                self.assertFalse(is_multipart_child(selected))
                self.assertNotEqual(logical_archive_key(selected), logical_archive_key(main))

    def test_real_rar_main_volume_flags_prevent_standalone_override(self):
        for version in (4, 5):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                if version == 4:
                    body = struct.pack("<BHHHI", 0x73, 1, 13, 0, 0)
                    header = b"Rar!\x1a\x07\x00" + struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body
                else:
                    body = b"\x03\x01\x00\x01"
                    header = b"Rar!\x1a\x07\x01\x00" + struct.pack("<L", zlib.crc32(body)) + body
                main = os.path.join(tmp, "volumes.part1.rar")
                child = os.path.join(tmp, "volumes.part2.rar")
                for path in (main, child):
                    with open(path, "wb") as stream:
                        stream.write(header)
                self.assertTrue(is_multipart_child(child))
                self.assertEqual(logical_archive_key(main), logical_archive_key(child))
                self.assertEqual(detect_archive_set(child).volumes, [main, child])

    def test_incomplete_7z_header_does_not_override_missing_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = struct.pack("<QQL", 4096, 20, 0)
            header = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<L", zlib.crc32(body)) + body
            main = os.path.join(tmp, "archive.7z.001")
            with open(main, "wb") as stream:
                stream.write(header + b"payload")
            self._write_fragment(os.path.join(tmp, "archive.7z.003"))
            archive_set = detect_archive_set(main)
            self.assertFalse(archive_set.is_complete)
            self.assertEqual(archive_set.missing_indexes, [2])


if __name__ == '__main__':
    unittest.main()
