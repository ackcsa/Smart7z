"""Capability-gated integration tests against the installed 7-Zip."""

import json
import os
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


SEVENZIP_PATH = find_sevenzip(DEFAULT_CONFIG)


@unittest.skipUnless(SEVENZIP_PATH, "7-Zip is not installed")
class TestRealSevenZipPipeline(unittest.TestCase):
    def _make_zip(self, path, files):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)

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
