import unittest
import os
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sevenzip import (
    SevenZipError, SevenZipResult, SevenZipRunner, SltStreamParser,
    classify_return_code, is_clean_success, is_warning,
    is_failure, redact_command, parse_slt, _detect_warning_output,
    EXIT_SUCCESS, EXIT_WARNING, EXIT_FATAL, EXIT_CMD_ERROR,
    EXIT_MEMORY_ERROR, EXIT_USER_CANCEL, _BoundedLineSplitter,
    _targeted_type_switch,
)
from models import ArchiveManifest, ArchiveMember, ErrorCategory


class TestExitCodeClassification(unittest.TestCase):
    def test_success(self):
        ok, cat = classify_return_code(0)
        self.assertTrue(ok)

    def test_warning(self):
        ok, cat = classify_return_code(1)
        self.assertTrue(ok)

    def test_fatal(self):
        ok, cat = classify_return_code(2)
        self.assertFalse(ok)

    def test_cmd_error(self):
        ok, cat = classify_return_code(7)
        self.assertFalse(ok)

    def test_memory_error(self):
        ok, cat = classify_return_code(8)
        self.assertFalse(ok)

    def test_user_cancel(self):
        ok, cat = classify_return_code(255)
        self.assertFalse(ok)
        self.assertEqual(cat, ErrorCategory.CANCELLED)

    def test_unknown_code(self):
        ok, cat = classify_return_code(99)
        self.assertFalse(ok)


class TestReturnCodeHelpers(unittest.TestCase):
    def test_is_clean_success(self):
        self.assertTrue(is_clean_success(0))
        self.assertFalse(is_clean_success(1))
        self.assertFalse(is_clean_success(2))

    def test_is_warning(self):
        self.assertTrue(is_warning(1))
        self.assertFalse(is_warning(0))
        self.assertFalse(is_warning(2))

    def test_is_failure(self):
        self.assertTrue(is_failure(2))
        self.assertTrue(is_failure(7))
        self.assertFalse(is_failure(0))
        self.assertFalse(is_failure(1))


class TestWarningOutputDetection(unittest.TestCase):
    def test_detects_warning_block_even_when_process_code_is_zero(self):
        self.assertTrue(
            _detect_warning_output(
                "WARNINGS:\nThere are data after the end of archive\nWarnings: 1"
            )
        )

    def test_does_not_treat_zero_or_member_name_as_warning(self):
        self.assertFalse(_detect_warning_output("Warnings: 0"))
        self.assertFalse(_detect_warning_output("Path = WARNINGS:"))


class TestRedaction(unittest.TestCase):
    def test_redact_password(self):
        cmd = ['7z', 'x', 'test.zip', '-psecret', '-oC:\\out']
        safe = redact_command(cmd)
        self.assertEqual(safe[3], '-p******')
        self.assertEqual(safe[0], '7z')

    def test_redact_no_password(self):
        cmd = ['7z', 'l', '-slt', 'test.zip']
        safe = redact_command(cmd)
        self.assertEqual(safe, cmd)

    def test_redact_spaces(self):
        cmd = ['7z', 'x', 'test file.zip', '-psecret']
        safe = redact_command(cmd)
        self.assertEqual(safe[2], '"test file.zip"')
        self.assertEqual(safe[3], '-p******')


class TestBoundedLineSplitter(unittest.TestCase):
    def test_preserves_lines_across_chunk_boundaries(self):
        splitter = _BoundedLineSplitter(max_pending_bytes=32)

        self.assertEqual(splitter.feed(b"first\r"), [b"first\r"])
        self.assertEqual(splitter.feed(b"\nsecond"), [b"\n"])
        self.assertEqual(splitter.feed(b" line\nthird"), [b"second line\n"])
        self.assertEqual(splitter.finish(), b"third")
        self.assertFalse(splitter.truncated)

    def test_bounds_unterminated_line_and_keeps_tail(self):
        splitter = _BoundedLineSplitter(max_pending_bytes=8)

        self.assertEqual(splitter.feed(b"012345"), [])
        self.assertEqual(splitter.feed(b"6789abcdef"), [])
        self.assertEqual(splitter.finish(), b"89abcdef")
        self.assertTrue(splitter.truncated)


class TestSltParser(unittest.TestCase):
    def test_basic_output(self):
        sample = """----------

Path = file1.txt
Size = 1024
Packed Size = 512
Method = LZMA2
Encrypted = -
CRC = AABBCCDD

Path = file2.txt
Size = 2048
Packed Size = 1024
Method = LZMA2
Encrypted = +
CCDDEEFF
"""
        m = parse_slt(sample)
        self.assertEqual(len(m.members), 2)
        self.assertEqual(m.members[0].path, "file1.txt")
        self.assertEqual(m.members[0].size, 1024)
        self.assertFalse(m.members[0].encrypted)
        self.assertTrue(m.members[1].encrypted)

    def test_archive_format(self):
        sample = """----------
Path = test.txt
Size = 100
Encrypted = -
"""
        m = parse_slt(sample)
        self.assertEqual(len(m.members), 1)

    def test_filename_with_equals(self):
        sample = """----------
Path = file=name.txt
Size = 100
Encrypted = -
"""
        m = parse_slt(sample)
        self.assertEqual(len(m.members), 1)
        self.assertEqual(m.members[0].path, "file=name.txt")

    def test_regular_unix_attributes_are_not_misread_as_links(self):
        sample = """----------
Path = regular.sh
Size = 12
Attributes = -rwxr-xr-x
Encrypted = -
"""
        manifest = parse_slt(sample)

        self.assertEqual(len(manifest.members), 1)
        self.assertFalse(manifest.members[0].is_link)

    def test_empty_archive(self):
        sample = """----------
"""
        m = parse_slt(sample)
        self.assertEqual(len(m.members), 0)

    def test_total_size_accumulation(self):
        sample = """----------
Path = a.txt
Size = 100
Encrypted = -

Path = b.txt
Size = 200
Encrypted = -
"""
        m = parse_slt(sample)
        self.assertEqual(m.total_size, 300)

    def test_encrypted_detection(self):
        sample = """----------
Path = secret.txt
Size = 100
Encrypted = +
Method = AES-256
"""
        m = parse_slt(sample)
        self.assertTrue(m.is_encrypted)
        self.assertTrue(m.members[0].encrypted)

    def test_stream_parser_handles_utf8_and_chunk_boundaries(self):
        parser = SltStreamParser()
        payload = (
            "Type = zip\r\n----------\r\n"
            "Path = 资料/file=name.txt\r\n"
            "Size = 7\r\nEncrypted = +\r\n"
        ).encode("utf-8")
        split_at = payload.index("资".encode("utf-8")) + 1

        parser.feed_bytes(payload[:split_at])
        parser.feed_bytes(payload[split_at:split_at + 5])
        parser.feed_bytes(payload[split_at + 5:])
        manifest = parser.finish()

        self.assertTrue(parser.saw_files_separator)
        self.assertFalse(parser.should_stop)
        self.assertEqual(manifest.format, "zip")
        self.assertEqual(manifest.entry_count, 1)
        self.assertEqual(manifest.members[0].path, "资料/file=name.txt")
        self.assertTrue(manifest.is_encrypted)

    def test_stream_parser_stops_at_limit_plus_one(self):
        parser = SltStreamParser(max_members=2, stop_after_entries=2)
        parser.feed_bytes(
            b"Type = zip\n----------\n"
            b"Path = a.txt\nSize = 1\n\n"
            b"Path = b.txt\nSize = 1\n\n"
            b"Path = c.txt\nSize = 1\n\n"
            b"Path = ignored.txt\nSize = 1\n\n"
        )
        manifest = parser.finish()

        self.assertTrue(parser.limit_exceeded)
        self.assertTrue(parser.should_stop)
        self.assertEqual(manifest.entry_count, 3)
        self.assertEqual([member.path for member in manifest.members], ["a.txt", "b.txt"])
        self.assertEqual(manifest.early_abort_reason, "manifest_limit_exceeded")

    def test_stream_parser_rejects_overlong_manifest_line(self):
        parser = SltStreamParser(max_line_bytes=16)

        parser.feed_bytes(b"Type = zip\n----------\nPath = " + b"x" * 32)
        manifest = parser.finish()

        self.assertTrue(parser.line_limit_exceeded)
        self.assertTrue(parser.should_stop)
        self.assertEqual(
            manifest.early_abort_reason,
            "manifest_line_limit_exceeded",
        )


class TestListingBehavior(unittest.TestCase):
    @staticmethod
    def _visible_header_encrypted_result():
        return SevenZipResult(
            return_code=EXIT_SUCCESS,
            stdout=(
                "Type = zip\nEncrypted = -\n----------\n"
                "Path = secret.txt\nSize = 4\nEncrypted = +\n"
            ),
        )

    def test_complete_visible_header_encrypted_manifest_needs_no_relisting(self):
        runner = SevenZipRunner("7z.exe")
        with mock.patch.object(
            runner,
            "_run_popen",
            return_value=self._visible_header_encrypted_result(),
        ):
            manifest = runner.list("visible-header.zip")

        self.assertTrue(manifest.is_encrypted)
        self.assertEqual(manifest.entry_count, 1)
        self.assertEqual(manifest.members[0].path, "secret.txt")

    def test_fallback_metrics_include_both_process_attempts(self):
        runner = SevenZipRunner("7z.exe")
        first = SevenZipError(
            "auto failed",
            ErrorCategory.NOT_ARCHIVE,
            listing_wall_ms=3.0,
            parse_cpu_ms=1.0,
            listing_attempts=1,
        )
        fallback = ArchiveManifest(
            format="zip",
            listing_wall_ms=4.0,
            parse_cpu_ms=2.0,
            listing_attempts=1,
        )
        with mock.patch.object(runner, "list", side_effect=[first, fallback]):
            manifest = runner.list_with_fallback("renamed.zip")

        self.assertEqual(manifest.listing_attempts, 2)
        self.assertEqual(manifest.listing_wall_ms, 7.0)
        self.assertEqual(manifest.parse_cpu_ms, 3.0)

    def test_signature_takes_priority_over_misleading_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as stream:
            path = stream.name
            stream.write(b"PK\x03\x04payload")
        try:
            self.assertEqual(_targeted_type_switch(path), "-tzip")
        finally:
            os.remove(path)

    def test_listing_returns_bounded_manifest_when_stream_limit_fires(self):
        runner = SevenZipRunner("7z.exe")

        def fake_run(_cmd, _timeout, **kwargs):
            consumer = kwargs["stdout_consumer"]
            stop_check = kwargs["stop_check"]
            consumer(
                b"Type = zip\n----------\n"
                b"Path = a.txt\nSize = 1\n\n"
                b"Path = b.txt\nSize = 1\n\n"
                b"Path = c.txt\nSize = 1\n\n"
            )
            self.assertTrue(stop_check())
            return SevenZipResult(return_code=-1, consumer_stopped=True)

        with mock.patch.object(runner, "_run_popen", side_effect=fake_run):
            manifest = runner.list("too-many.zip", manifest_entry_limit=2)

        self.assertEqual(manifest.entry_count, 3)
        self.assertTrue(manifest.summary_mode)
        self.assertEqual(manifest.early_abort_reason, "manifest_limit_exceeded")

    def test_run_popen_terminates_process_after_stream_limit(self):
        runner = SevenZipRunner("unused")
        parser = SltStreamParser(max_members=1, stop_after_entries=1)
        script = (
            "import sys,time;"
            "sys.stdout.write('Type = zip\\n----------\\n'"
            "+'Path = a.txt\\nSize = 1\\n\\n'"
            "+'Path = b.txt\\nSize = 1\\n\\n');"
            "sys.stdout.flush();time.sleep(10)"
        )
        started = time.monotonic()

        result = runner._run_popen(
            [sys.executable, "-c", script],
            timeout=5,
            stdout_consumer=parser.feed_bytes,
            stop_check=lambda: parser.should_stop,
            capture_stdout=False,
        )

        self.assertTrue(result.consumer_stopped)
        self.assertTrue(parser.limit_exceeded)
        self.assertLess(time.monotonic() - started, 8.0)


class TestSevenZipResult(unittest.TestCase):
    def test_defaults(self):
        r = SevenZipResult()
        self.assertEqual(r.return_code, -1)
        self.assertFalse(r.cancelled)
        self.assertFalse(r.timed_out)

    def test_with_values(self):
        r = SevenZipResult(return_code=0, stdout="test")
        self.assertEqual(r.return_code, 0)
        self.assertEqual(r.stdout, "test")


if __name__ == '__main__':
    unittest.main()
