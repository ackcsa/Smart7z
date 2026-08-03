import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from stego_engine import StegoDetector, StegoExtractor


def _zip_bytes(name: str = "payload.txt", content: bytes = b"payload") -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        path = handle.name
    try:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, content)
        return Path(path).read_bytes()
    finally:
        os.unlink(path)


class TestStegoEngineCompatibility(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_extensionless_appended_zip_is_detected_and_copied_exactly(self):
        archive = _zip_bytes()
        host = self.root / "host.without-supported-extension"
        prefix = b"arbitrary-host-prefix\x00" * 13
        host.write_bytes(prefix + archive + b"trailing-host-data")

        self.assertEqual(StegoDetector.quick_detect(str(host)), "append")
        self.assertEqual(
            StegoExtractor._locate_zip_boundaries_append(str(host)),
            (len(prefix), len(prefix) + len(archive)),
        )

        carved = StegoExtractor.extract_embedded_zip(
            str(host), str(self.root / "carved"), "append"
        )
        self.assertIsNotNone(carved)
        self.assertEqual(Path(carved).read_bytes(), archive)
        with zipfile.ZipFile(carved) as extracted:
            self.assertEqual(extracted.read("payload.txt"), b"payload")

    def test_plain_zip_is_not_reported_as_hidden(self):
        archive = self.root / "ordinary.zip"
        archive.write_bytes(_zip_bytes())

        self.assertIsNone(StegoDetector.quick_detect(str(archive)))
        self.assertIsNone(
            StegoExtractor.extract_embedded_zip(
                str(archive), str(self.root / "carved"), "append"
            )
        )

    def test_appended_empty_zip_has_exact_safe_span(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
            archive_path = handle.name
        try:
            with zipfile.ZipFile(archive_path, "w"):
                pass
            archive = Path(archive_path).read_bytes()
        finally:
            os.unlink(archive_path)
        prefix = b"empty-archive-host"
        host = self.root / "empty-host.bin"
        host.write_bytes(prefix + archive + b"tail")

        self.assertEqual(StegoDetector.quick_detect(str(host)), "append")
        carved = StegoExtractor.extract_embedded_zip(
            str(host), str(self.root / "empty-carved"), "append"
        )
        self.assertIsNotNone(carved)
        self.assertEqual(Path(carved).read_bytes(), archive)
        with zipfile.ZipFile(carved) as extracted:
            self.assertEqual(extracted.namelist(), [])

    def test_ambiguous_candidates_require_modern_review(self):
        first = _zip_bytes("first.txt", b"one")
        second = _zip_bytes("second.txt", b"two")
        host = self.root / "ambiguous.bin"
        host.write_bytes(b"host-prefix" + first + b"separator" + second)

        self.assertIsNone(StegoDetector.quick_detect(str(host)))
        self.assertIsNone(
            StegoExtractor.extract_embedded_zip(
                str(host), str(self.root / "carved"), "append"
            )
        )

    def test_rejected_copy_is_removed(self):
        archive = _zip_bytes()
        host = self.root / "host.bin"
        host.write_bytes(b"prefix" + archive)
        output = self.root / "carved"

        with (
            mock.patch("stego_engine._carved_copy_is_exact", return_value=False),
            self.assertLogs("stego_engine", level="ERROR"),
        ):
            result = StegoExtractor.extract_embedded_zip(
                str(host), str(output), "append"
            )

        self.assertIsNone(result)
        self.assertEqual(list(output.iterdir()), [])

    def test_invalid_mode_or_missing_source_has_no_side_effect(self):
        output = self.root / "carved"
        self.assertIsNone(
            StegoExtractor.extract_embedded_zip(
                str(self.root / "missing.bin"), str(output), "append"
            )
        )
        self.assertIsNone(
            StegoExtractor.extract_embedded_zip(
                str(self.root / "missing.bin"), str(output), "signature_only"
            )
        )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
