import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import path_safety


@unittest.skipUnless(os.name == "nt", "Windows reparse-point behavior")
class TestWindowsReparseSafety(unittest.TestCase):
    def test_attribute_check_uses_lexical_path_not_resolved_target(self):
        lexical = os.path.abspath(r"C:\safe-root\junction")
        with mock.patch.object(
            path_safety, "_GetFileAttributesW", return_value=path_safety.FILE_ATTRIBUTE_REPARSE_POINT
        ) as get_attributes:
            self.assertTrue(path_safety.is_reparse_escape(lexical))
        get_attributes.assert_called_once_with(lexical)

    def test_untrusted_path_rejects_existing_internal_reparse_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            junction = root / "junction"
            junction.mkdir()
            with mock.patch.object(
                path_safety,
                "is_reparse_escape",
                side_effect=lambda value: os.path.normcase(os.path.abspath(value))
                == os.path.normcase(os.path.abspath(junction)),
            ):
                safe, reason = path_safety.is_safe_output_path(
                    os.path.join("junction", "payload.txt"), str(root)
                )
        self.assertFalse(safe)
        self.assertIn("Reparse point", reason)

    def test_reparse_path_has_no_user_bypass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            junction = root / "junction"
            junction.mkdir()
            with mock.patch.object(
                path_safety,
                "is_reparse_escape",
                side_effect=lambda value: os.path.normcase(os.path.abspath(value))
                == os.path.normcase(os.path.abspath(junction)),
            ):
                safe, reason = path_safety.is_safe_output_path(
                    os.path.join("junction", "payload.txt"),
                    str(root),
                )
        self.assertFalse(safe)
        self.assertIn("Reparse point", reason)


if __name__ == "__main__":
    unittest.main()
