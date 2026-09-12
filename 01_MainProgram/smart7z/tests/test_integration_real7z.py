"""Capability-gated integration tests against the installed 7-Zip."""

import json
import os
import struct
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

from archive_classifier import classify_automatic_candidate
from config import DEFAULT_CONFIG, find_sevenzip
from executor import Executor
from models import Job, JobState
from nested import NestedExtractor
from sevenzip import SevenZipRunner
from stego_candidates import find_candidates
from steganographier_compat import EMPTY_MDAT, find_steganographier_candidates


SEVENZIP_PATH = find_sevenzip(DEFAULT_CONFIG)


@unittest.skipUnless(SEVENZIP_PATH, "7-Zip is not installed")
class TestRealSevenZipPipeline(unittest.TestCase):
    def _make_zip(self, path, files):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)

    @staticmethod
    def _add_unsaturated_zip64(zip_data):
        eocd_offset = zip_data.rfind(b"PK\x05\x06")
        if eocd_offset < 0 or eocd_offset + 22 != len(zip_data):
            raise ValueError("test ZIP must end with an uncommented EOCD")
        eocd = zip_data[eocd_offset:]
        disk, cd_disk, entries_disk, entries, cd_size, cd_offset = (
            struct.unpack_from("<HHHHII", eocd, 4)
        )
        record = struct.pack(
            "<4sQHHIIQQQQ",
            b"PK\x06\x06",
            44,
            45,
            45,
            disk,
            cd_disk,
            entries_disk,
            entries,
            cd_size,
            cd_offset,
        )
        locator = struct.pack(
            "<4sIQI",
            b"PK\x06\x07",
            0,
            eocd_offset,
            1,
        )
        return zip_data[:eocd_offset] + record + locator + eocd

    def _execute(self, archive, destination, mode, **config_overrides):
        config = dict(DEFAULT_CONFIG)
        config.update(
            {
                "7z_path": SEVENZIP_PATH,
                "extract_to_source": False,
                "target_dir": destination,
                "temp_dir": os.path.join(destination, "staging"),
                "extract_mode": mode,
                "wait_disk_space": False,
                "cleanup_policy": "keep",
                "deep_scan": False,
                "nested_extraction": False,
            }
        )
        config.update(config_overrides)
        runner = SevenZipRunner(SEVENZIP_PATH)
        executor = Executor(runner, config)
        job = Job(
            path=archive,
            original_path=archive,
            original_basename=Path(archive).stem,
            explicit_input=True,
        )
        state, promoted = executor.execute(job)
        executor.cleanup_job_artifacts(job, terminal=True)
        return state, promoted, job

    def test_clean_zip_staging_and_direct_keep_source(self):
        for mode in ("staging", "direct"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp_dir:
                archive = os.path.join(temp_dir, "sample.zip")
                destination = os.path.join(temp_dir, "output")
                self._make_zip(
                    archive,
                    {"hello.txt": "hello", "folder/world.txt": "world"},
                )
                state, promoted, job = self._execute(
                    archive, destination, mode
                )
                self.assertEqual(state, JobState.COMPLETE, job.error_message)
                self.assertIsNone(promoted)
                self.assertTrue(job.commit_verified)
                self.assertTrue(all(record.verified for record in job.commit_records))
                self.assertTrue(os.path.isfile(archive))
                self.assertEqual(job.source_retention_reason, "policy_keep")
                self.assertEqual(
                    Path(job.final_destination, "hello.txt").read_text(encoding="utf-8"),
                    "hello",
                )
                self.assertEqual(
                    Path(job.final_destination, "folder", "world.txt").read_text(
                        encoding="utf-8"
                    ),
                    "world",
                )

    def test_zip_with_empty_root_directory_record_extracts_normally(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "- Latest Video -.zip")
            destination = os.path.join(temp_dir, "output")
            with zipfile.ZipFile(archive, "w") as output:
                root = zipfile.ZipInfo("")
                root.external_attr = (0o40775 << 16) | 0x10
                output.writestr(root, b"")
                output.writestr("first.mp4", b"first")
                output.writestr("second.mp4", b"second")

            state, promoted, job = self._execute(
                archive,
                destination,
                "staging",
            )

            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertIsNone(promoted)
            self.assertTrue(job.commit_verified)
            self.assertEqual(
                Path(job.final_destination, "first.mp4").read_bytes(),
                b"first",
            )
            self.assertEqual(
                Path(job.final_destination, "second.mp4").read_bytes(),
                b"second",
            )

    def test_independent_rar_named_zip_files_complete_and_clean_only_their_own_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first, second = root / "report.r20", root / "report.r21"
            self._make_zip(first, {"payload.txt": "FIRST", "marker.txt": "one"})
            self._make_zip(second, {"payload.txt": "SECOND", "marker.txt": "two"})
            second_before = second.read_bytes()
            config = {
                **DEFAULT_CONFIG,
                "extract_to_source": False, "target_dir": str(root / "output"),
                "temp_dir": str(root / "staging"), "wait_disk_space": False,
                "cleanup_policy": "permanent",
            }
            executor = Executor(SevenZipRunner(SEVENZIP_PATH), config)
            for path, payload in ((first, b"FIRST"), (second, b"SECOND")):
                job = Job(
                    path=str(path), original_path=str(path), explicit_input=True,
                    cleanup_policy_snapshot="permanent",
                )
                try:
                    state, _ = executor.execute(job)
                    self.assertEqual(state, JobState.COMPLETE, job.error_message)
                    self.assertTrue(job.commit_verified)
                    self.assertEqual(job.manifest.used_switch, "-tzip")
                    self.assertEqual(job.manifest.listing_return_code, 0)
                    self.assertEqual(job.extraction_result.return_code, 0)
                    self.assertEqual(Path(job.final_destination, "payload.txt").read_bytes(), payload)
                    self.assertFalse(path.exists())
                    if path == first:
                        self.assertEqual(second.read_bytes(), second_before)
                finally:
                    executor.cleanup_job_artifacts(job, terminal=True)

    def test_mislabeled_zip_with_trailing_data_still_has_a_listing_warning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.r20"
            self._make_zip(path, {"payload.txt": "payload"})
            with path.open("ab") as stream:
                stream.write(b"TAIL" * 4096)
            manifest = SevenZipRunner(SEVENZIP_PATH).list_with_fallback(str(path))
            self.assertEqual(manifest.used_switch, "-tzip")
            self.assertEqual(manifest.listing_attempts, 2)
            self.assertEqual(manifest.listing_return_code, 1)

    def test_empty_zip_commits_verified_empty_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "empty.zip")
            self._make_zip(archive, {})
            output = os.path.join(temp_dir, "output")
            os.makedirs(output)
            executor = Executor(
                SevenZipRunner(SEVENZIP_PATH),
                {
                    **DEFAULT_CONFIG,
                    "extract_to_source": False,
                    "target_dir": output,
                    "temp_dir": os.path.join(temp_dir, "staging"),
                    "cleanup_policy": "keep",
                    "wait_disk_space": False,
                },
            )
            job = Job(
                path=archive,
                original_path=archive,
                original_basename="empty.zip",
            )
            state, promoted = executor.execute(job)
            self.assertEqual(state, JobState.COMPLETE)
            self.assertIsNone(promoted)
            self.assertTrue(job.commit_verified)
            self.assertTrue(os.path.isdir(job.final_destination))
            self.assertEqual(os.listdir(job.final_destination), [])
            self.assertTrue(os.path.isfile(archive))
            self.assertEqual(job.source_retention_reason, "policy_keep")

    def test_renamed_zip_opens_without_structural_carving(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "renamed.bin")
            destination = os.path.join(temp_dir, "output")
            self._make_zip(archive, {"renamed.txt": "recognized"})
            state, _promoted, job = self._execute(
                archive, destination, "direct", deep_scan=True
            )
            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertFalse(job.stego_candidates)
            self.assertEqual(Path(job.final_destination).read_text(), "recognized")

    def test_real_7z_renamed_docx_is_automatic_archive_candidate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "payload.txt")
            archive = os.path.join(temp_dir, "renamed.docx")
            Path(source).write_text("payload", encoding="utf-8")
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-t7z", archive, source, "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)

            decision = classify_automatic_candidate(
                archive,
                runner.supported_formats(timeout=15),
            )
            self.assertTrue(decision.should_queue)
            self.assertIn("7z_header", decision.archive_evidence)

    def test_encrypted_zip_manual_password_and_redaction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "secret.txt")
            archive = os.path.join(temp_dir, "encrypted.zip")
            destination = os.path.join(temp_dir, "output")
            password_file = os.path.join(temp_dir, "code.txt")
            password = "integration-secret-42"
            Path(source).write_text("private", encoding="utf-8")
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-tzip", archive, source, f"-p{password}", "-mem=AES256", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)

            config = dict(DEFAULT_CONFIG)
            config.update(
                {
                    "7z_path": SEVENZIP_PATH,
                    "extract_to_source": False,
                    "target_dir": destination,
                    "temp_dir": os.path.join(temp_dir, "staging"),
                    "extract_mode": "staging",
                    "wait_disk_space": False,
                    "cleanup_policy": "keep",
                    "password_file": password_file,
                }
            )
            job = Job(path=archive, original_path=archive, explicit_input=True)
            executor = Executor(runner, config)
            state, promoted = executor.execute(job, manual_password=password)
            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertEqual(promoted, password)
            self.assertFalse(hasattr(job, "manual_password"))
            self.assertNotIn(password, repr(job))
            self.assertNotIn(password, json.dumps(job.to_task_dict(), default=list))
            self.assertNotIn(password, "\n".join(job.terminal_diagnostics))
            self.assertEqual(Path(password_file).read_text(encoding="utf-8").strip(), password)
            executor.cleanup_job_artifacts(job, terminal=True)

    def test_visible_header_encrypted_zip_reuses_no_password_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "secret.txt")
            archive = os.path.join(temp_dir, "visible-header.zip")
            destination = os.path.join(temp_dir, "output")
            password_file = os.path.join(temp_dir, "code.txt")
            password = "visible-secret"
            Path(source).write_text("private", encoding="utf-8")
            Path(password_file).write_text(
                f"wrong-password\n{password}\n",
                encoding="utf-8",
            )
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-tzip", archive, source, f"-p{password}", "-mem=AES256", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)

            config = {
                **DEFAULT_CONFIG,
                "7z_path": SEVENZIP_PATH,
                "extract_to_source": False,
                "target_dir": destination,
                "temp_dir": os.path.join(temp_dir, "staging"),
                "extract_mode": "staging",
                "wait_disk_space": False,
                "cleanup_policy": "keep",
                "password_file": password_file,
            }
            job = Job(path=archive, original_path=archive, explicit_input=True)
            executor = Executor(runner, config)

            state, promoted = executor.execute(job)

            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertEqual(promoted, password)
            self.assertEqual(job.phase_metrics.listing_attempts, 1)
            self.assertEqual(job.phase_metrics.extraction_attempts, 2)
            self.assertEqual(
                Path(password_file).read_text(encoding="utf-8").splitlines()[0],
                password,
            )
            self.assertTrue(
                any(
                    item.startswith("[TIMING]")
                    for item in job.terminal_diagnostics
                )
            )
            executor.cleanup_job_artifacts(job, terminal=True)

    def test_manual_password_retry_does_not_replay_automatic_candidates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "secret.txt")
            archive = os.path.join(temp_dir, "prompt-retry.zip")
            destination = os.path.join(temp_dir, "output")
            password_file = os.path.join(temp_dir, "retry-code.txt")
            password = "prompt-secret"
            Path(source).write_text("private", encoding="utf-8")
            Path(password_file).write_text(
                "book-wrong-one\nbook-wrong-two\n",
                encoding="utf-8",
            )
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-tzip", archive, source, f"-p{password}", "-mem=AES256", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)

            config = {
                **DEFAULT_CONFIG,
                "7z_path": SEVENZIP_PATH,
                "extract_to_source": False,
                "target_dir": destination,
                "temp_dir": os.path.join(temp_dir, "staging"),
                "extract_mode": "staging",
                "wait_disk_space": False,
                "cleanup_policy": "keep",
                "password_file": password_file,
            }
            job = Job(path=archive, original_path=archive, explicit_input=True)
            executor = Executor(runner, config)

            first_state, first_promoted = executor.execute(job)
            self.assertEqual(first_state, JobState.PASSWORD_REQUIRED)
            self.assertIsNone(first_promoted)
            self.assertEqual(job.phase_metrics.listing_attempts, 1)
            self.assertEqual(job.phase_metrics.extraction_attempts, 2)

            second_state, second_promoted = executor.execute(
                job,
                manual_password="manual-wrong",
            )

            self.assertEqual(second_state, JobState.PASSWORD_REQUIRED)
            self.assertIsNone(second_promoted)
            self.assertEqual(job.phase_metrics.listing_attempts, 1)
            self.assertEqual(job.phase_metrics.extraction_attempts, 3)

            third_state, third_promoted = executor.execute(
                job,
                manual_password=password,
            )

            self.assertEqual(third_state, JobState.COMPLETE, job.error_message)
            self.assertEqual(third_promoted, password)
            self.assertEqual(job.phase_metrics.listing_attempts, 1)
            self.assertEqual(job.phase_metrics.extraction_attempts, 4)
            executor.cleanup_job_artifacts(job, terminal=True)

    def test_password_retry_relists_when_archive_changed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "secret.txt")
            archive = os.path.join(temp_dir, "changed-before-retry.zip")
            destination = os.path.join(temp_dir, "output")
            first_password = "first-secret"
            second_password = "second-secret"
            Path(source).write_text("first", encoding="utf-8")
            runner = SevenZipRunner(SEVENZIP_PATH)
            first_created = runner.raw(
                [
                    "a",
                    "-tzip",
                    archive,
                    source,
                    f"-p{first_password}",
                    "-mem=AES256",
                    "-y",
                ],
                timeout=30,
            )
            self.assertEqual(first_created.return_code, 0, first_created.diagnostic_tail)

            config = {
                **DEFAULT_CONFIG,
                "7z_path": SEVENZIP_PATH,
                "extract_to_source": False,
                "target_dir": destination,
                "temp_dir": os.path.join(temp_dir, "staging"),
                "extract_mode": "staging",
                "wait_disk_space": False,
                "cleanup_policy": "keep",
                "password_file": os.path.join(temp_dir, "empty-code.txt"),
            }
            job = Job(path=archive, original_path=archive, explicit_input=True)
            executor = Executor(runner, config)
            first_state, _first_promoted = executor.execute(job)
            self.assertEqual(first_state, JobState.PASSWORD_REQUIRED)
            self.assertEqual(job.phase_metrics.listing_attempts, 1)

            os.remove(archive)
            Path(source).write_text("second payload is longer", encoding="utf-8")
            second_created = runner.raw(
                [
                    "a",
                    "-tzip",
                    archive,
                    source,
                    f"-p{second_password}",
                    "-mem=AES256",
                    "-y",
                ],
                timeout=30,
            )
            self.assertEqual(second_created.return_code, 0, second_created.diagnostic_tail)

            second_state, second_promoted = executor.execute(
                job,
                manual_password=second_password,
            )

            self.assertEqual(second_state, JobState.COMPLETE, job.error_message)
            self.assertEqual(second_promoted, second_password)
            self.assertEqual(job.phase_metrics.listing_attempts, 2)
            self.assertEqual(
                Path(job.final_destination).read_text(encoding="utf-8"),
                "second payload is longer",
            )
            executor.cleanup_job_artifacts(job, terminal=True)

    def test_manifest_entry_limit_blocks_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "too-many.zip")
            destination = os.path.join(temp_dir, "output")
            self._make_zip(
                archive,
                {
                    "one.txt": "1",
                    "two.txt": "2",
                    "three.txt": "3",
                },
            )

            state, _promoted, job = self._execute(
                archive,
                destination,
                "staging",
                max_manifest_entries=2,
            )

            self.assertEqual(state, JobState.FAILED)
            self.assertEqual(job.source_retention_reason, "manifest_limit")
            self.assertEqual(job.phase_metrics.early_abort_reason, "manifest_limit_exceeded")
            self.assertEqual(job.phase_metrics.extraction_attempts, 0)
            self.assertEqual(job.manifest.entry_count, 3)
            self.assertIn("at least 3", job.error_message)

    def test_output_file_limit_also_stops_listing_early(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "too-many-outputs.zip")
            destination = os.path.join(temp_dir, "output")
            self._make_zip(
                archive,
                {
                    "one.txt": "1",
                    "two.txt": "2",
                    "three.txt": "3",
                },
            )

            state, _promoted, job = self._execute(
                archive,
                destination,
                "staging",
                max_manifest_entries=100,
                max_output_files=2,
            )

            self.assertEqual(state, JobState.FAILED)
            self.assertEqual(job.source_retention_reason, "output_file_quota")
            self.assertEqual(job.phase_metrics.early_abort_reason, "manifest_limit_exceeded")
            self.assertEqual(job.phase_metrics.extraction_attempts, 0)
            self.assertIn("max_output_files=2", job.error_message)

    def test_structural_zip_candidate_has_exact_validated_span(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "payload.zip")
            host = os.path.join(temp_dir, "host.dat")
            self._make_zip(archive, {"inside.txt": "inside"})
            prefix = b"SMART7Z-HOST-PREFIX" * 8
            suffix = b"SMART7Z-HOST-SUFFIX" * 4
            archive_bytes = Path(archive).read_bytes()
            Path(host).write_bytes(prefix + archive_bytes + suffix)
            candidates = find_candidates(host)
            exact = [
                candidate
                for candidate in candidates
                if candidate.embedded_format in ("zip", "zip64")
                and candidate.start_offset == len(prefix)
                and candidate.end_offset == len(prefix) + len(archive_bytes)
            ]
            self.assertTrue(exact, candidates)

    def test_steganographier_zip64_runs_in_compat_and_deep_scan_modes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir, "payload.zip")
            self._make_zip(archive, {"inside.txt": "zip64-compatible"})
            zip64_data = self._add_unsaturated_zip64(archive.read_bytes())
            prefix = (
                (16).to_bytes(4, "big")
                + b"ftyp"
                + b"isom\x00\x00\x00\x00"
                + (13).to_bytes(4, "big")
                + b"mdat"
                + b"cover"
            )
            suffix = (
                b"Rar!\x1a\x07\x01\x00"
                + b"A" * (5 * 1024)
                + b"7z\xbc\xaf\x27\x1c"
                + b"B" * (10 * 1024)
                + EMPTY_MDAT
            )
            host = Path(temp_dir, "hidden-zip64.mp4")
            host.write_bytes(prefix + zip64_data + suffix)
            candidates = find_steganographier_candidates(str(host))
            self.assertEqual(len(candidates), 1)
            self.assertIn("zip64_geometry_valid", candidates[0].validation_flags)

            for scan_mode in ("compat", "deep"):
                with self.subTest(scan_mode=scan_mode):
                    destination = Path(temp_dir, f"output-{scan_mode}")
                    config = {
                        **DEFAULT_CONFIG,
                        "7z_path": SEVENZIP_PATH,
                        "extract_to_source": False,
                        "target_dir": str(destination),
                        "temp_dir": str(Path(temp_dir, f"staging-{scan_mode}")),
                        "extract_mode": "staging",
                        "wait_disk_space": False,
                        "cleanup_policy": "keep",
                        "deep_scan": scan_mode == "deep",
                        "steganographier_compat_mode": scan_mode == "compat",
                        "nested_extraction": False,
                    }
                    job = Job(
                        path=str(host),
                        original_path=str(host),
                        original_basename=host.name,
                        explicit_input=False,
                        stego_candidates=(
                            list(candidates) if scan_mode == "compat" else []
                        ),
                    )
                    executor = Executor(SevenZipRunner(SEVENZIP_PATH), config)

                    state, promoted = executor.execute(job)

                    self.assertEqual(state, JobState.COMPLETE, job.error_message)
                    self.assertIsNone(promoted)
                    self.assertEqual(
                        Path(job.final_destination).read_text(encoding="utf-8"),
                        "zip64-compatible",
                    )
                    self.assertEqual(
                        job.selected_candidate.mode,
                        "steganographier_mp4_trailing",
                    )
                    executor.cleanup_job_artifacts(job, terminal=True)

    def test_warning_host_is_replaced_by_one_exact_zip_candidate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "payload.zip")
            host = os.path.join(temp_dir, "host.mkv")
            destination = os.path.join(temp_dir, "output")
            self._make_zip(archive, {"inside.txt": "one complete archive"})
            Path(host).write_bytes(
                b"\x1a\x45\xdf\xa3"
                + (b"m" * 4096)
                + Path(archive).read_bytes()
                + (b"t" * 4096)
            )
            runner = SevenZipRunner(SEVENZIP_PATH)
            direct = runner.list(host)
            self.assertEqual(direct.listing_return_code, 1)

            state, _promoted, job = self._execute(
                host, destination, "staging"
            )

            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertEqual(len(job.stego_candidates), 1)
            self.assertIsNotNone(job.selected_candidate)
            self.assertEqual(job.manifest.listing_return_code, 0)
            self.assertEqual(job.extraction_result.return_code, 0)
            self.assertTrue(job.verification_result.verified)
            self.assertIsNone(job.error_category)
            self.assertEqual(job.error_message, "")
            self.assertTrue(os.path.isfile(host))
            self.assertEqual(
                Path(destination, "inside.txt").read_text(encoding="utf-8"),
                "one complete archive",
            )

    def test_clean_and_encrypted_7z(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "seven.txt")
            Path(source).write_text("seven", encoding="utf-8")
            destination = os.path.join(temp_dir, "output")
            runner = SevenZipRunner(SEVENZIP_PATH)
            for encrypted in (False, True):
                with self.subTest(encrypted=encrypted):
                    archive = os.path.join(
                        temp_dir, "encrypted.7z" if encrypted else "clean.7z"
                    )
                    password = "seven-secret" if encrypted else None
                    args = ["a", "-t7z", archive, source, "-y"]
                    if password:
                        args.extend([f"-p{password}", "-mhe=on"])
                    created = runner.raw(args, timeout=30)
                    self.assertEqual(created.return_code, 0, created.diagnostic_tail)

                    config = dict(DEFAULT_CONFIG)
                    config.update(
                        {
                            "7z_path": SEVENZIP_PATH,
                            "extract_to_source": False,
                            "target_dir": destination,
                            "temp_dir": os.path.join(temp_dir, "staging"),
                            "wait_disk_space": False,
                            "cleanup_policy": "keep",
                            "password_file": os.path.join(
                                temp_dir, "session-passwords.txt"
                            ),
                        }
                    )
                    job = Job(path=archive, original_path=archive, explicit_input=True)
                    executor = Executor(runner, config)
                    state, _promoted = executor.execute(
                        job, manual_password=password
                    )
                    self.assertEqual(state, JobState.COMPLETE, job.error_message)
                    self.assertTrue(job.commit_verified)
                    if encrypted:
                        promoted_file = os.path.join(
                            temp_dir, "session-passwords.txt"
                        )
                        self.assertEqual(
                            Path(promoted_file).read_text(encoding="utf-8").strip(),
                            password,
                        )
                    executor.cleanup_job_artifacts(job, terminal=True)

    def test_split_7z_missing_volume_retains_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "large.bin")
            # Deterministic incompressible-enough data creates several volumes.
            Path(source).write_bytes(bytes(range(256)) * 4096)
            archive_base = os.path.join(temp_dir, "split.7z")
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-t7z", archive_base, source, "-v128k", "-mx=0", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)
            volumes = sorted(Path(temp_dir).glob("split.7z.*"))
            self.assertGreaterEqual(len(volumes), 3)
            submitted = []
            nested = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
                archive_extensions=runner.supported_formats(timeout=15),
            )
            self.assertEqual(
                nested.scan_and_submit(Job(path="parent.zip"), temp_dir),
                1,
            )
            self.assertEqual(
                Path(submitted[0].path).name,
                "split.7z.001",
            )
            volumes[1].unlink()
            destination = os.path.join(temp_dir, "output")
            state, _promoted, job = self._execute(
                str(volumes[0]), destination, "direct"
            )
            self.assertNotEqual(state, JobState.COMPLETE)
            self.assertFalse(job.cleanup_eligible)
            self.assertTrue(volumes[0].exists())

    def test_complete_split_7z_cleans_every_volume_after_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "complete-source.bin")
            Path(source).write_bytes(bytes(range(256)) * 4096)
            archive_base = os.path.join(temp_dir, "complete.7z")
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-t7z", archive_base, source, "-v128k", "-mx=0", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)
            volumes = sorted(Path(temp_dir).glob("complete.7z.*"))
            self.assertGreaterEqual(len(volumes), 3)

            state, _promoted, job = self._execute(
                str(volumes[0]),
                os.path.join(temp_dir, "output"),
                "direct",
                cleanup_policy="permanent",
                del_archive=True,
            )

            self.assertEqual(state, JobState.COMPLETE, job.error_message)
            self.assertTrue(job.archive_set.cleanup_safe)
            self.assertTrue(all(not volume.exists() for volume in volumes))

    def test_extra_numbered_file_turns_zero_exit_warning_into_retention(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "warning-source.bin")
            Path(source).write_bytes(bytes(range(256)) * 4096)
            archive_base = os.path.join(temp_dir, "warning.7z")
            runner = SevenZipRunner(SEVENZIP_PATH)
            created = runner.raw(
                ["a", "-t7z", archive_base, source, "-v128k", "-mx=0", "-y"],
                timeout=30,
            )
            self.assertEqual(created.return_code, 0, created.diagnostic_tail)
            volumes = sorted(Path(temp_dir).glob("warning.7z.*"))
            extra = Path(temp_dir) / f"warning.7z.{len(volumes) + 1:03d}"
            extra.write_text("unrelated-data", encoding="utf-8")
            all_candidates = volumes + [extra]

            state, _promoted, job = self._execute(
                str(volumes[0]),
                os.path.join(temp_dir, "output"),
                "direct",
                cleanup_policy="permanent",
                del_archive=True,
            )

            self.assertEqual(state, JobState.PARTIAL_RECOVERY, job.error_message)
            self.assertTrue(all(candidate.exists() for candidate in all_candidates))
            self.assertEqual(job.extraction_result.return_code, 1)

    def test_cancellable_real_process(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "cancel-source.bin")
            archive = os.path.join(temp_dir, "cancel.7z")
            # Sparse zero content is quick to create but long enough to enter
            # the compressor with an intentionally expensive setting.
            with open(source, "wb") as stream:
                stream.truncate(256 * 1024 * 1024)
            cancel = threading.Event()
            runner = SevenZipRunner(SEVENZIP_PATH, cancel_check=cancel.is_set)
            result_holder = []

            def run_command():
                result_holder.append(
                    runner.raw(
                        [
                            "a", "-t7z", archive, source, "-mx=9", "-mmt=1",
                            "-md=64m", "-y",
                        ],
                        timeout=60,
                    )
                )

            thread = threading.Thread(target=run_command)
            thread.start()
            time.sleep(0.15)
            cancel.set()
            runner.cancel_current()
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
            self.assertTrue(result_holder)
            self.assertTrue(result_holder[0].cancelled)


if __name__ == "__main__":
    unittest.main()
