import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import verify_project


class TestVerificationGate(unittest.TestCase):
    def test_source_and_test_edits_invalidate_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "workspace" / "program"
            source.mkdir(parents=True)
            (source / "tests").mkdir()
            code = source / "app.py"
            code.write_text("before", encoding="utf-8")
            before = verify_project.input_fingerprint(source)
            code.write_text("after", encoding="utf-8")
            after = verify_project.input_fingerprint(source)
            self.assertNotEqual(before, after)
            (source / "tests" / "test_app.py").write_text("test", encoding="utf-8")
            self.assertNotEqual(after, verify_project.input_fingerprint(source))

    def test_reuse_requires_matching_fresh_success(self):
        report = {
            "passed": True, "tests_run": 2, "input_fingerprint": "source",
            "environment": {"qt": "v"}, "patterns": ["test_*.py"], "finished_at": time.time(),
        }
        self.assertTrue(verify_project.reusable(report, "source", {"qt": "v"}, ("test_*.py",)))
        for updates in (
            {"passed": False}, {"tests_run": 0}, {"input_fingerprint": "changed"},
            {"environment": {"qt": "new"}}, {"patterns": ["test_ui.py"]}, {"finished_at": 0},
        ):
            with self.subTest(updates=updates):
                self.assertFalse(verify_project.reusable(
                    {**report, **updates}, "source", {"qt": "v"}, ("test_*.py",)
                ))

    def test_partial_or_skipped_tests_never_authorize_build(self):
        complete = {"passed": True, "tests_run": 2, "patterns": ["test_*.py"], "skipped": []}
        self.assertTrue(verify_project.release_gate(complete))
        for updates in (
            {"passed": False}, {"tests_run": 0},
            {"patterns": ["test_config.py"]}, {"skipped": [["qt", "missing"]]},
        ):
            self.assertFalse(verify_project.release_gate({**complete, **updates}))

    def test_pattern_cannot_escape_tests_directory(self):
        self.assertEqual(verify_project.select_patterns("ui", None), verify_project.SUITES["ui"])
        with self.assertRaises(ValueError):
            verify_project.select_patterns("full", ["../test_secret.py"])

    def test_empty_selection_is_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "tests").mkdir()
            with mock.patch.object(verify_project, "SOURCE", source):
                with self.assertRaisesRegex(ValueError, "No tests selected"):
                    verify_project.run_tests(("test_missing.py",), source / "result.log")


if __name__ == "__main__":
    unittest.main()
