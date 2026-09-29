import unittest
from pathlib import Path

from author_info import ATTRIBUTION, LICENSE_ID, SOURCE_MARK, contact_details


class TestAuthorInfo(unittest.TestCase):
    def test_attribution_and_contact(self):
        self.assertEqual(ATTRIBUTION, "by Kurpphy")
        self.assertEqual(LICENSE_ID, "GPL-3.0-only")
        email, qq = contact_details().splitlines()
        self.assertEqual(email.split("@")[1], "outlook.com")
        self.assertTrue(qq.startswith("QQ: "))
        self.assertTrue(qq[4:].isdigit())

    def test_source_marker_is_static_metadata(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn(SOURCE_MARK, (root / "smart7z_version_info.txt.in").read_text("utf-8"))
        code = (root / "author_info.py").read_text("utf-8")
        for forbidden in ("socket", "requests", "uuid", "getenv", "subprocess"):
            self.assertNotIn(forbidden, code)

    def test_project_license_is_shipped(self):
        root = Path(__file__).resolve().parents[1]
        license_file = root / "LICENSE"
        if not license_file.exists():
            license_file = root.parents[1] / "LICENSE"
        self.assertIn("Version 3, 29 June 2007", license_file.read_text("utf-8"))
        build = (root / "build_release.ps1").read_text("utf-8")
        for target in ("BaseAppDir", "SourcePackageDir"):
            self.assertIn(f"(Join-Path ${target} 'LICENSE')", build)

    def test_root_license_changes_invalidate_verification(self):
        from verify_project import input_fingerprint
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "program" / "smart7z"
            source.mkdir(parents=True)
            (root / "LICENSE").write_text("before", encoding="utf-8")
            before = input_fingerprint(source)
            (root / "LICENSE").write_text("after", encoding="utf-8")
            self.assertNotEqual(before, input_fingerprint(source))
