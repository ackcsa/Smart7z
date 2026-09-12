import codecs
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import password_book


class TestPasswordBook(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="smart7z-password-book-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.book = self.root / "code.txt"

    def assert_no_temporary_books(self):
        self.assertEqual(list(self.root.glob("smart7z_passwords_*.tmp")), [])

    def test_oversized_book_is_never_replaced_by_successful_password(self):
        original = b"x" * (password_book.PASSWORD_FILE_MAX_BYTES + 1)
        self.book.write_bytes(original)
        self.assertEqual(password_book.read_password_candidates(str(self.book)), [])
        self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), original)
        self.assert_no_temporary_books()

    def test_candidate_limit_does_not_truncate_persistence(self):
        lines = [f"candidate-{index}" for index in range(password_book.PASSWORD_MAX_CANDIDATES + 5)]
        original = "\n".join(lines) + "\n"
        self.book.write_bytes(original.encode("utf-8"))
        self.assertEqual(
            len(password_book.read_password_candidates(str(self.book))),
            password_book.PASSWORD_MAX_CANDIDATES,
        )
        self.assertTrue(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), ("successful\n" + original).encode("utf-8"))
        self.assert_no_temporary_books()

    def test_spaces_bom_newlines_blank_lines_and_long_entries_are_preserved(self):
        text = " first \r\n\r\nsecond\r\n" + "x" * (password_book.PASSWORD_MAX_CHARS + 1)
        for bom, encoding in (
            (codecs.BOM_UTF8, "utf-8"),
            (codecs.BOM_UTF16_LE, "utf-16-le"),
            (codecs.BOM_UTF16_BE, "utf-16-be"),
        ):
            with self.subTest(encoding=encoding):
                self.book.write_bytes(bom + text.encode(encoding))
                self.assertEqual(
                    password_book.read_password_candidates(str(self.book)),
                    [" first ", "second"],
                )
                self.assertTrue(password_book.promote_password(str(self.book), "second"))
                expected = "second\r\n first \r\n\r\n" + "x" * (password_book.PASSWORD_MAX_CHARS + 1)
                self.assertEqual(self.book.read_bytes(), bom + expected.encode(encoding))

    def test_legacy_encoding_is_preserved(self):
        original = "caf\u00e9\r\nother"
        self.book.write_bytes(original.encode("cp1252"))
        with mock.patch.object(password_book.locale, "getpreferredencoding", return_value="cp1252"):
            self.assertTrue(password_book.promote_password(str(self.book), "other"))
        self.assertEqual(self.book.read_bytes(), "other\r\ncaf\u00e9\r\n".encode("cp1252"))

    def test_unencodable_promotion_keeps_original_book(self):
        original = b"caf\xe9\n"
        self.book.write_bytes(original)
        with mock.patch.object(password_book.locale, "getpreferredencoding", return_value="cp1252"):
            self.assertFalse(password_book.promote_password(str(self.book), "\u4e2d\u6587"))
        self.assertEqual(self.book.read_bytes(), original)

    def test_read_failure_does_not_mean_empty_book(self):
        original = b"existing\n"
        self.book.write_bytes(original)
        with mock.patch.object(password_book, "_read_snapshot", side_effect=PermissionError):
            self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), original)
        self.assert_no_temporary_books()

    def test_invalid_encoding_is_not_lossily_rewritten(self):
        original = codecs.BOM_UTF8 + b"invalid\xff\n"
        self.book.write_bytes(original)
        self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), original)

    def test_external_edit_before_replacement_wins(self):
        self.book.write_bytes(b"original\n")
        external = b"external\n"
        real_fsync = os.fsync

        def edit_during_flush(fd):
            real_fsync(fd)
            self.book.write_bytes(external)

        with mock.patch.object(password_book.os, "fsync", side_effect=edit_during_flush):
            self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), external)
        self.assert_no_temporary_books()

    def test_external_creation_before_first_publish_wins(self):
        external = b"external\n"
        real_read = password_book._read_snapshot
        reads = 0

        def create_after_check(path):
            nonlocal reads
            snapshot = real_read(path)
            reads += 1
            if reads == 2:
                self.book.write_bytes(external)
            return snapshot

        with mock.patch.object(password_book, "_read_snapshot", side_effect=create_after_check):
            self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), external)
        self.assert_no_temporary_books()

    def test_replace_failure_keeps_book_and_removes_temporary(self):
        original = b"existing\n"
        self.book.write_bytes(original)
        with mock.patch.object(password_book.os, "replace", side_effect=PermissionError):
            self.assertFalse(password_book.promote_password(str(self.book), "successful"))
        self.assertEqual(self.book.read_bytes(), original)
        self.assert_no_temporary_books()

    def test_new_book_and_exact_duplicate_promotion(self):
        self.assertTrue(password_book.promote_password(str(self.book), " value "))
        self.assertEqual(self.book.read_bytes(), b" value \n")
        self.book.write_bytes(b"value\n value \nlast")
        self.assertTrue(password_book.promote_password(str(self.book), " value "))
        self.assertEqual(self.book.read_bytes(), b" value \nvalue\nlast")
        self.assert_no_temporary_books()

    def test_multiline_password_is_never_injected_into_book(self):
        self.book.write_bytes(b"existing\n")
        for value in ("first\nsecond", "first\rsecond", "first\x00second"):
            with self.subTest(value=value):
                self.assertFalse(password_book.promote_password(str(self.book), value))
        self.assertEqual(self.book.read_bytes(), b"existing\n")


if __name__ == "__main__":
    unittest.main()
