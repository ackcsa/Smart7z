import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sevenzip import (
    SevenZipResult, classify_return_code, is_clean_success, is_warning,
    is_failure, redact_command, parse_slt, _detect_warning_output,
    EXIT_SUCCESS, EXIT_WARNING, EXIT_FATAL, EXIT_CMD_ERROR,
    EXIT_MEMORY_ERROR, EXIT_USER_CANCEL
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
