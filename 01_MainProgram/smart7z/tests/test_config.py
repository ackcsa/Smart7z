import unittest
import os
import sys
import tempfile
import json
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_mod
import recovery
from runtime_ipc import _ipc_state_path
from config import (
    DEFAULT_CONFIG, load_config, save_config,
    find_sevenzip, get_password_file_path,
    get_app_dir, get_config_path, get_state_path, get_state_root,
    set_config_path, set_app_dir
)
from models import CleanupPolicy


class TestDefaultConfig(unittest.TestCase):
    def test_has_required_keys(self):
        required = ['7z_path', 'target_dir', 'extract_to_source',
                     'wait_disk_space', 'del_archive', 'deep_scan',
                     'steganographier_compat_mode',
                     'temp_dir', 'password_file', 'extract_mode']
        for k in required:
            self.assertIn(k, DEFAULT_CONFIG)
        self.assertTrue(DEFAULT_CONFIG['steganographier_compat_mode'])

    def test_has_new_keys(self):
        self.assertIn('config_version', DEFAULT_CONFIG)
        self.assertIn('cleanup_policy', DEFAULT_CONFIG)

    def test_fresh_defaults_to_keep(self):
        self.assertEqual(DEFAULT_CONFIG['cleanup_policy'], 'keep')
        self.assertFalse(DEFAULT_CONFIG['del_archive'])

    def test_fresh_defaults_auto_discover_sevenzip(self):
        self.assertEqual(DEFAULT_CONFIG['7z_path'], '')

    def test_space_wait_defaults_to_two_hours(self):
        self.assertEqual(DEFAULT_CONFIG['space_wait_timeout'], 7200)

    def test_trusted_input_is_not_a_supported_setting(self):
        self.assertNotIn('trusted_input', DEFAULT_CONFIG)


class TestConfigSaveLoad(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'smart7z_config.json')
            set_config_path(config_path)
            set_app_dir(tmp)
            cfg = DEFAULT_CONFIG.copy()
            cfg['target_dir'] = tmp
            try:
                save_config(cfg)
                loaded = load_config()
                self.assertEqual(loaded['target_dir'], tmp)
                self.assertIn('config_version', loaded)
            finally:
                set_config_path(None)
                set_app_dir(None)

    def test_load_merges_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'smart7z_config.json')
            set_config_path(config_path)
            set_app_dir(tmp)
            partial = {'target_dir': tmp}
            try:
                save_config(partial)
                loaded = load_config()
                self.assertIn('config_version', loaded)
                self.assertIn('cleanup_policy', loaded)
            finally:
                set_config_path(None)
                set_app_dir(None)

    def test_load_removes_retired_trusted_input_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'smart7z_config.json')
            payload = {
                'config_version': 1,
                'cleanup_policy': 'keep',
                'trusted_input': True,
            }
            Path(config_path).write_text(
                json.dumps(payload), encoding='utf-8'
            )
            set_config_path(config_path)
            set_app_dir(tmp)
            try:
                loaded = load_config()
                persisted = json.loads(Path(config_path).read_text(encoding='utf-8'))
                self.assertNotIn('trusted_input', loaded)
                self.assertNotIn('trusted_input', persisted)
            finally:
                set_config_path(None)
                set_app_dir(None)


class TestFrozenStateLayout(unittest.TestCase):
    def setUp(self):
        set_config_path(None)
        set_app_dir(None)

    def tearDown(self):
        set_config_path(None)
        set_app_dir(None)

    def test_installed_and_portable_state_roots_are_frozen_once(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp) / "app"
            local = Path(temp) / "local"
            app_dir.mkdir()
            local.mkdir()
            with (
                mock.patch.object(config_mod, "get_app_dir", return_value=str(app_dir)),
                mock.patch.object(config_mod.sys, "frozen", True, create=True),
                mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}),
            ):
                installed_root = local / "Smart7z"
                self.assertEqual(get_state_root(), str(installed_root))
                self.assertEqual(
                    get_config_path(), str(installed_root / "smart7z_config.json")
                )
                self.assertEqual(
                    recovery.default_recovery_journal_path(),
                    str(installed_root / "recovery-v1.json"),
                )
                self.assertEqual(
                    _ipc_state_path(), str(installed_root / "ipc-v3.json")
                )

                (app_dir / config_mod.PORTABLE_MARKER_NAME).touch()
                self.assertEqual(get_state_root(), str(app_dir))
                self.assertEqual(
                    get_state_path("recovery-v1.json"),
                    str(app_dir / "recovery-v1.json"),
                )

    def test_installed_mode_reuses_legacy_relative_password_in_place(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp) / "app"
            local = Path(temp) / "local"
            app_dir.mkdir()
            local.mkdir()
            legacy_config = app_dir / "smart7z_config.json"
            legacy_password = app_dir / "code.txt"
            legacy_payload = {
                **DEFAULT_CONFIG,
                "cleanup_policy": "keep",
                "password_file": "code.txt",
            }
            legacy_config.write_text(
                json.dumps(legacy_payload), encoding="utf-8"
            )
            legacy_password.write_text("secret", encoding="utf-8")
            original_config = legacy_config.read_bytes()
            original_password = legacy_password.read_bytes()

            with (
                mock.patch.object(config_mod, "get_app_dir", return_value=str(app_dir)),
                mock.patch.object(config_mod.sys, "frozen", True, create=True),
                mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}),
            ):
                loaded = load_config()
                password_path = Path(get_password_file_path(loaded))
                state_root = local / "Smart7z"
                self.assertTrue((state_root / "smart7z_config.json").is_file())
                self.assertEqual(password_path, legacy_password)
                self.assertEqual(password_path.read_text(encoding="utf-8"), "secret")
                self.assertFalse((state_root / "code.txt").exists())

            self.assertEqual(legacy_config.read_bytes(), original_config)
            self.assertEqual(legacy_password.read_bytes(), original_password)

    def test_installed_mode_ignores_empty_state_placeholder_for_legacy_book(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp) / "app"
            state_root = Path(temp) / "local" / "Smart7z"
            app_dir.mkdir()
            state_root.mkdir(parents=True)
            legacy_password = app_dir / "code.txt"
            state_password = state_root / "code.txt"
            legacy_password.write_text("legacy-secret\n", encoding="utf-8")
            state_password.write_bytes(b"")

            with (
                mock.patch.object(config_mod, "get_app_dir", return_value=str(app_dir)),
                mock.patch.object(config_mod.sys, "frozen", True, create=True),
                mock.patch.dict(
                    os.environ,
                    {"LOCALAPPDATA": str(Path(temp) / "local")},
                ),
            ):
                self.assertEqual(
                    Path(get_password_file_path(dict(DEFAULT_CONFIG))),
                    legacy_password,
                )

    def test_installed_mode_keeps_existing_state_password_book(self):
        with tempfile.TemporaryDirectory() as temp:
            app_dir = Path(temp) / "app"
            state_root = Path(temp) / "local" / "Smart7z"
            app_dir.mkdir()
            state_root.mkdir(parents=True)
            (app_dir / "code.txt").write_text(
                "legacy-secret\n", encoding="utf-8"
            )
            state_password = state_root / "code.txt"
            state_password.write_text("state-secret\n", encoding="utf-8")

            with (
                mock.patch.object(config_mod, "get_app_dir", return_value=str(app_dir)),
                mock.patch.object(config_mod.sys, "frozen", True, create=True),
                mock.patch.dict(
                    os.environ,
                    {"LOCALAPPDATA": str(Path(temp) / "local")},
                ),
            ):
                self.assertEqual(
                    Path(get_password_file_path(dict(DEFAULT_CONFIG))),
                    state_password,
                )

class TestFindSevenzip(unittest.TestCase):
    def test_empty_config_prefers_app_local_sevenzip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_7z = Path(temp_dir, "7z.exe")
            local_7z.touch()
            set_app_dir(temp_dir)
            try:
                self.assertEqual(find_sevenzip({"7z_path": ""}), str(local_7z))
            finally:
                set_app_dir(None)

    def test_configured_path_wins(self):
        result = find_sevenzip({"7z_path": r"C:\Program Files\7-Zip\7z.exe"})
        if os.path.exists(r"C:\Program Files\7-Zip\7z.exe"):
            self.assertEqual(result, r"C:\Program Files\7-Zip\7z.exe")

    def test_invalid_configured_falls_back(self):
        result = find_sevenzip({"7z_path": r"C:\nonexistent\7z.exe"})
        if os.path.exists(r"C:\Program Files\7-Zip\7z.exe"):
            self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
