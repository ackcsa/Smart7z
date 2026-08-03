import json
import io
import os
import struct
import tempfile
import threading
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

import sevenzip
import stego_candidates
import windows_adapters
from config import DEFAULT_CONFIG, save_config
from executor import Executor
from models import (
    ArchiveCandidate,
    ArchiveManifest,
    ArchiveMember,
    ArchiveSet,
    CleanupPolicy,
    ErrorCategory,
    ExtractionResult,
    Job,
    JobState,
    Confidence,
    VerificationResult,
)
from scheduler import Scheduler
from sevenzip import (
    SevenZipError,
    SevenZipRunner,
    parse_supported_format_extensions,
)
from nested import NestedExtractor
from recovery import RecoveryJournal
from stego_candidates import find_candidates
from discovery import logical_archive_key
from ui_app import BoundedIPCServer, IPC_VERSION


class DummyRunner:
    def __init__(self):
        self.cancel_check = lambda: False


def _scheduler_config(temp_dir):
    config = dict(DEFAULT_CONFIG)
    config["temp_dir"] = temp_dir
    config["_recovery_journal_path"] = os.path.join(
        temp_dir, "recovery-v1.json"
    )
    return config


class TestSecretBoundaries(unittest.TestCase):
    def test_save_config_drops_runtime_secrets_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "config.json")
            config = dict(DEFAULT_CONFIG)
            config["_main_password"] = "never-write-me"
            config["unknown_field"] = "not-schema"
            save_config(config, path=path)
            text = Path(path).read_text(encoding="utf-8")
            self.assertNotIn("never-write-me", text)
            payload = json.loads(text)
            self.assertNotIn("_main_password", payload)
            self.assertNotIn("unknown_field", payload)

    def test_scheduler_keeps_password_off_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scheduler = Scheduler("7z.exe", _scheduler_config(temp_dir))
            try:
                job = Job(path="encrypted.zip")
                job.record_state(JobState.PASSWORD_REQUIRED)
                scheduler.password_pending[job.task_id] = job
                scheduler.submit_password_response(job, "top-secret")
                self.assertFalse(hasattr(job, "manual_password"))
                self.assertNotIn("top-secret", repr(job))
                password, main = scheduler._password_inputs_for(job)
                self.assertEqual(password, "top-secret")
                self.assertIsNone(main)
                self.assertNotIn(job.task_id, scheduler._manual_passwords)
            finally:
                scheduler.stop()


class TestFallbackPolicy(unittest.TestCase):
    def test_only_one_targeted_fallback(self):
        runner = SevenZipRunner("7z.exe")
        calls = []

        def fake_list(
            path,
            password=None,
            type_switch="",
            timeout=30,
            manifest_entry_limit=sevenzip.MAX_PARSED_MEMBERS,
        ):
            del path, password, timeout, manifest_entry_limit
            calls.append(type_switch)
            if not type_switch:
                raise SevenZipError(
                    "not archive",
                    ErrorCategory.NOT_ARCHIVE,
                )
            return ArchiveManifest(format="zip")

        with mock.patch.object(runner, "list", side_effect=fake_list):
            manifest = runner.list_with_fallback("renamed.zip")
        self.assertEqual(manifest.format, "zip")
        self.assertEqual(calls, ["", "-tzip"])

    def test_unknown_extension_has_no_blind_probe(self):
        runner = SevenZipRunner("7z.exe")
        with mock.patch.object(
            runner, "list", side_effect=SevenZipError("not archive")
        ) as listing:
            with self.assertRaises(SevenZipError):
                runner.list_with_fallback("not-an-archive.bin")
        self.assertEqual(listing.call_count, 1)

    def test_internal_listing_failure_is_not_retried_as_a_format_probe(self):
        runner = SevenZipRunner("7z.exe")
        with mock.patch.object(
            runner,
            "list",
            side_effect=SevenZipError(
                "parser failed",
                ErrorCategory.INTERNAL_ERROR,
            ),
        ) as listing:
            with self.assertRaises(SevenZipError):
                runner.list_with_fallback("archive.zip")

        self.assertEqual(listing.call_count, 1)


class TestExecutorPasswordsAndMetrics(unittest.TestCase):
    @staticmethod
    def _executor(temp_dir, runner=None):
        config = dict(DEFAULT_CONFIG)
        config["temp_dir"] = temp_dir
        config["password_file"] = os.path.join(temp_dir, "code.txt")
        return Executor(runner or DummyRunner(), config)

    def test_password_candidates_prioritize_batch_success_before_no_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "code.txt").write_text(
                "file-first\nfile-second\n",
                encoding="utf-8",
            )
            executor = self._executor(temp_dir)

            self.assertEqual(
                executor._password_candidates("manual", "batch-success"),
                [
                    "manual",
                    "batch-success",
                    None,
                    "file-first",
                    "file-second",
                ],
            )
            self.assertEqual(
                executor._password_candidates(
                    "manual",
                    "batch-success",
                    include_no_password=False,
                ),
                ["manual", "batch-success", "file-first", "file-second"],
            )

    def test_encrypted_extraction_skips_guaranteed_no_password_attempt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "code.txt").write_text("file-password\n", encoding="utf-8")
            executor = self._executor(temp_dir)
            job = Job(path=os.path.join(temp_dir, "encrypted.zip"))
            job.manifest = ArchiveManifest(is_encrypted=True)
            attempted = []

            def fake_extract(_job, password):
                attempted.append(password)
                if password == "batch-success":
                    return ExtractionResult(success=True, return_code=0)
                return ExtractionResult(error_category=ErrorCategory.BAD_PASSWORD)

            with (
                mock.patch.object(executor, "_extract", side_effect=fake_extract),
                mock.patch.object(executor, "_cleanup_temp_root", return_value=True),
            ):
                extraction, promoted = executor._extract_with_password_candidates(
                    job,
                    listing_password=None,
                    manual_password="manual-wrong",
                    session_main_password="batch-success",
                )

            self.assertTrue(extraction.success)
            self.assertEqual(promoted, "batch-success")
            self.assertEqual(attempted, ["manual-wrong", "batch-success"])
            self.assertNotIn(None, attempted)
            self.assertEqual(job.phase_metrics.extraction_attempts, 2)

    def test_password_that_unlocked_headers_is_extracted_first(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            executor = self._executor(temp_dir)
            job = Job(path=os.path.join(temp_dir, "header-encrypted.7z"))
            job.manifest = ArchiveManifest(is_encrypted=True)
            attempted = []

            def fake_extract(_job, password):
                attempted.append(password)
                return ExtractionResult(success=True, return_code=0)

            with mock.patch.object(executor, "_extract", side_effect=fake_extract):
                extraction, promoted = executor._extract_with_password_candidates(
                    job,
                    listing_password="known-good",
                    manual_password="manual-wrong",
                    session_main_password="batch-wrong",
                )

            self.assertTrue(extraction.success)
            self.assertEqual(promoted, "known-good")
            self.assertEqual(attempted, ["known-good"])

    def test_terminal_execution_publishes_bounded_timing_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            executor = self._executor(temp_dir)
            job = Job(path=os.path.join(temp_dir, "missing.zip"))

            state, promoted = executor.execute(job)

            self.assertEqual(state, JobState.FAILED)
            self.assertIsNone(promoted)
            self.assertGreaterEqual(job.phase_metrics.total_wall_ms, 0.0)
            timing = [
                item
                for item in job.terminal_diagnostics
                if item.startswith("[TIMING]")
            ]
            self.assertEqual(len(timing), 1)
            self.assertIn("list=0.0ms/0", timing[0])
            self.assertIn("total=", timing[0])


class TestSupportedFormats(unittest.TestCase):
    def test_parses_extensions_without_capability_noise(self):
        sample = """Formats:
 0 C...F..........c.a.m+.. w...0  7z       7z            7 z BC AF
 0  ...F..................  Rar      rar r00       R a r !
 0 C...FMG........c.a.m+.. wud.0  zip      zip z01 zipx jar xpi odt docx appx P K 03 04

Codecs:
 0  EDF  3030103 BCJ
"""
        extensions = parse_supported_format_extensions(sample)
        self.assertTrue({".7z", ".rar", ".r00", ".zip", ".zipx"} <= extensions)
        self.assertFalse({".fm", ".m+", ".wud", ".0"} & extensions)


class TestStegoCandidates(unittest.TestCase):
    @staticmethod
    def _zip_bytes(name="inside.txt", payload=b"payload"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name, payload)
        return stream.getvalue()

    def test_bmff_free_box_uses_exact_zip_geometry(self):
        zip_data = self._zip_bytes()
        prefix = struct.pack(">I4s", 16, b"ftyp") + b"isom0000"
        free_payload = b"pad!" + zip_data + b"tail"
        free_box = struct.pack(">I4s", 8 + len(free_payload), b"free") + free_payload
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(prefix + free_box)
        try:
            candidates = [c for c in find_candidates(path) if c.mode == "za"]
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            expected_start = len(prefix) + 8 + 4
            self.assertEqual(candidate.start_offset, expected_start)
            self.assertEqual(candidate.end_offset, expected_start + len(zip_data))
        finally:
            os.remove(path)

    def test_scan_occurrences_honors_nonzero_start(self):
        # A valid ZIP after a prefix exercises the file seek in bounded scans.
        zip_data = self._zip_bytes()
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(b"host-prefix" + zip_data)
        try:
            candidates = find_candidates(path)
            self.assertTrue(any(c.start_offset == len(b"host-prefix") for c in candidates))
        finally:
            os.remove(path)

    def test_large_prepended_zip_eocd_in_middle_is_discovered(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("large.bin", b"x" * (600 * 1024))
        zip_data = stream.getvalue()
        prefix = b"host-prefix"
        suffix = b"host-tail" * (34 * 1024)
        with tempfile.NamedTemporaryFile(delete=False) as host:
            path = host.name
            host.write(prefix + zip_data + suffix)
        try:
            candidates = find_candidates(path)
            exact = [
                candidate
                for candidate in candidates
                if candidate.embedded_format == "zip"
                and candidate.start_offset == len(prefix)
                and candidate.end_offset == len(prefix) + len(zip_data)
            ]
            self.assertEqual(len(exact), 1)
            self.assertEqual(exact[0].confidence, Confidence.HIGH)
        finally:
            os.remove(path)

    def test_chunked_signature_scan_honors_cancellation(self):
        checks = 0

        def cancelled():
            nonlocal checks
            checks += 1
            return checks >= 2

        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(b"x" * (2 * 1024 * 1024))
        try:
            offsets = stego_candidates._scan_occurrences(
                path,
                b"never-present",
                0,
                os.path.getsize(path),
                chunk_size=64 * 1024,
                cancel_check=cancelled,
            )
            self.assertEqual(offsets, [])
            self.assertEqual(checks, 2)
        finally:
            os.remove(path)

    def test_find_candidates_can_cancel_before_file_scan(self):
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(self._zip_bytes())
        try:
            with mock.patch.object(
                stego_candidates,
                "_detect_zip_candidates",
                side_effect=AssertionError("cancelled scan must not start"),
            ):
                self.assertEqual(
                    find_candidates(path, cancel_check=lambda: True),
                    [],
                )
        finally:
            os.remove(path)

    def test_exact_scan_uses_only_zip_signature_pass(self):
        zip_data = self._zip_bytes()
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(b"media-prefix" + zip_data + b"media-tail")
        scanned_needles = []
        original_scan = stego_candidates._scan_occurrences

        def record_scan(*args, **kwargs):
            scanned_needles.append(args[1])
            return original_scan(*args, **kwargs)

        try:
            with (
                mock.patch.object(
                    stego_candidates,
                    "_detect_signature_candidates",
                    side_effect=AssertionError("irrelevant signature scan"),
                ),
                mock.patch.object(
                    stego_candidates,
                    "_detect_bmff_candidates",
                    side_effect=AssertionError("duplicate BMFF scan"),
                ),
                mock.patch.object(
                    stego_candidates,
                    "_scan_occurrences",
                    side_effect=record_scan,
                ),
            ):
                candidates = (
                    stego_candidates.find_exact_high_confidence_candidates(path)
                )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(set(scanned_needles), {stego_candidates.SIG_EOCD})
        finally:
            os.remove(path)

    def test_exact_scan_keeps_bmff_free_box_geometry(self):
        zip_data = self._zip_bytes()
        prefix = struct.pack(">I4s", 16, b"ftyp") + b"isom0000"
        free_payload = b"pad!" + zip_data + b"tail"
        free_box = struct.pack(">I4s", 8 + len(free_payload), b"free") + free_payload
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            path = stream.name
            stream.write(prefix + free_box)
        try:
            candidates = stego_candidates.find_exact_high_confidence_candidates(
                path
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0].start_offset,
                len(prefix) + 8 + len(b"pad!"),
            )
            self.assertEqual(
                candidates[0].end_offset,
                len(prefix) + 8 + len(b"pad!") + len(zip_data),
            )
        finally:
            os.remove(path)


class TestNestedSingleFile(unittest.TestCase):
    def test_committed_single_archive_is_submitted_as_child(self):
        submitted = []
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = os.path.join(temp_dir, "child.zip")
            with zipfile.ZipFile(nested_path, "w") as archive:
                archive.writestr("data.txt", "nested")
            parent = Job(path=os.path.join(temp_dir, "parent.zip"))
            extractor = NestedExtractor(
                enabled=True,
                max_depth=2,
                submit_cb=submitted.append,
            )
            self.assertEqual(extractor.scan_and_submit(parent, nested_path), 1)
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0].original_basename, "child.zip")

    def test_child_quota_is_shared_within_root_batch(self):
        submitted = []
        extractor = NestedExtractor(
            enabled=True,
            max_depth=2,
            max_children=1,
            submit_cb=submitted.append,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = []
            for index in range(2):
                path = os.path.join(temp_dir, f"child{index}.zip")
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("data.txt", "nested")
                paths.append(path)
            first_parent = Job(path="p1.zip", nested_budget_id="root-batch")
            second_parent = Job(path="p2.zip", nested_budget_id="root-batch")
            self.assertEqual(extractor.scan_and_submit(first_parent, paths[0]), 1)
            self.assertEqual(extractor.scan_and_submit(second_parent, paths[1]), 0)
        self.assertEqual(len(submitted), 1)

    def test_byte_quota_is_shared_within_root_batch(self):
        submitted = []
        extractor = NestedExtractor(
            enabled=True,
            max_depth=2,
            max_children=10,
            max_output_bytes=20,
            submit_cb=submitted.append,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            first = os.path.join(temp_dir, "first.zip")
            second = os.path.join(temp_dir, "second.zip")
            with open(first, "wb") as stream:
                stream.write(b"a" * 12)
            with open(second, "wb") as stream:
                stream.write(b"b" * 12)
            with mock.patch.object(extractor, "_is_archive", return_value=True):
                first_parent = Job(path="p1.zip", nested_budget_id="root-batch")
                second_parent = Job(path="p2.zip", nested_budget_id="root-batch")
                self.assertEqual(extractor.scan_and_submit(first_parent, first), 1)
                with self.assertLogs("nested", level="WARNING"):
                    self.assertEqual(
                        extractor.scan_and_submit(second_parent, second), 0
                    )
        self.assertEqual(len(submitted), 1)
        self.assertEqual(
            extractor._batch_states["root-batch"].scanned_bytes, 12
        )


class TestStegoSelectionScheduling(unittest.TestCase):
    def test_review_selection_does_not_carve_on_caller_thread(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scheduler = Scheduler("7z.exe", _scheduler_config(temp_dir))
            try:
                job = Job(path="host.bin")
                job.stego_candidates = [
                    ArchiveCandidate(
                        embedded_format="zip",
                        start_offset=10,
                        end_offset=20,
                        confidence=Confidence.HIGH,
                    )
                ]
                scheduler.stego_pending[job.task_id] = job
                with mock.patch.object(
                    scheduler.executor,
                    "_carve_candidate",
                    side_effect=AssertionError("must run in worker"),
                ):
                    scheduler.submit_stego_selection(job, 0)
                self.assertTrue(job.stego_selection_pending)
                self.assertIs(scheduler.task_queue.get_nowait(), job)
            finally:
                scheduler.stop()


class TestLogicalArchiveKeys(unittest.TestCase):
    def test_selected_child_volumes_share_main_key_even_before_discovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = os.path.join(temp_dir, "Movie.PART01.RAR")
            later = os.path.join(temp_dir, "movie.part03.rar")
            Path(first).touch()
            Path(later).touch()
            self.assertEqual(logical_archive_key(first), logical_archive_key(later))

    def test_scheduler_deduplicates_multiple_selected_volumes(self):
        events = []
        with tempfile.TemporaryDirectory() as temp_dir:
            first_path = os.path.join(temp_dir, "bundle.001")
            later_path = os.path.join(temp_dir, "bundle.003")
            Path(first_path).touch()
            Path(later_path).touch()
            scheduler = Scheduler(
                "7z.exe",
                _scheduler_config(temp_dir),
                event_cb=lambda event, *_args: events.append(event),
            )
            try:
                scheduler.submit(Job(path=first_path))
                scheduler.submit(Job(path=later_path))
                self.assertEqual(scheduler.stats()["submitted"], 1)
                self.assertEqual(scheduler.queue_size(), 1)
                self.assertIn("job_duplicate", events)
            finally:
                scheduler.stop()


class TestSchedulerIntakePolicy(unittest.TestCase):
    def test_submit_freezes_cleanup_policy_before_config_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scheduler = Scheduler(
                "7z.exe",
                {
                    **_scheduler_config(temp_dir),
                    "cleanup_policy": CleanupPolicy.PERMANENT.value,
                },
            )
            try:
                job = Job(path=os.path.join(temp_dir, "archive.zip"))
                self.assertTrue(scheduler.submit(job))
                scheduler.refresh_config(
                    {
                        **_scheduler_config(temp_dir),
                        "cleanup_policy": CleanupPolicy.KEEP.value,
                    }
                )
                self.assertEqual(
                    job.cleanup_policy_snapshot, CleanupPolicy.PERMANENT.value
                )
            finally:
                scheduler.stop()

    def test_paused_intake_releases_jobs_in_fifo_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scheduler = Scheduler("7z.exe", _scheduler_config(temp_dir))
            try:
                jobs = []
                scheduler.pause_intake()
                for index in range(3):
                    path = os.path.join(temp_dir, f"archive-{index}.zip")
                    Path(path).touch()
                    job = Job(path=path)
                    jobs.append(job)
                    self.assertTrue(scheduler.submit(job))

                self.assertEqual(scheduler.deferred_intake_size(), 3)
                self.assertTrue(all(job.state == JobState.QUEUED for job in jobs))
                self.assertEqual(scheduler.resume_intake(), 3)
                with scheduler.task_queue.mutex:
                    queued = list(scheduler.task_queue.queue)
                self.assertEqual(queued, jobs)
            finally:
                scheduler.stop()


class TestPreflightAndCommit(unittest.TestCase):
    def make_executor(self, **overrides):
        config = dict(DEFAULT_CONFIG)
        config.update(overrides)
        return Executor(DummyRunner(), config)

    def test_extract_to_source_override_wins_over_configured_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "source", "archive.zip")
            target = os.path.join(temp_dir, "configured-target")
            executor = self.make_executor(
                extract_to_source=False,
                target_dir=target,
            )
            job = Job(path=archive, extract_to_source_override=True)

            self.assertEqual(
                executor._get_dest_root(job), os.path.dirname(archive)
            )

    def test_manifest_limit_has_no_user_bypass(self):
        executor = self.make_executor(max_manifest_entries=1)
        manifest = ArchiveManifest(
            members=[
                ArchiveMember(path="a.txt", size=1, size_known=True),
                ArchiveMember(path="b.txt", size=1, size_known=True),
            ],
            entry_count=2,
            total_size=2,
            listing_return_code=0,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            job = Job(path=os.path.join(temp_dir, "a.zip"))
            state = executor._preflight(job, manifest)
        self.assertEqual(state, JobState.FAILED)
        self.assertEqual(job.source_retention_reason, "manifest_limit")
        self.assertIn("超过 max_manifest_entries=1", job.error_message)
        self.assertIn("skipped without extraction", job.error_message)

    def test_internal_manifest_cap_is_reported_when_config_is_higher(self):
        executor = self.make_executor(
            max_manifest_entries=sevenzip.MAX_PARSED_MEMBERS * 2,
            max_output_files=sevenzip.MAX_PARSED_MEMBERS * 3,
        )
        manifest = ArchiveManifest(
            entry_count=sevenzip.MAX_PARSED_MEMBERS + 1,
            early_abort_reason="manifest_limit_exceeded",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            job = Job(path=os.path.join(temp_dir, "huge.zip"))
            state = executor._preflight(job, manifest)

        self.assertEqual(state, JobState.FAILED)
        self.assertEqual(job.source_retention_reason, "manifest_parser_limit")
        self.assertIn(
            f"内部清单解析安全上限 {sevenzip.MAX_PARSED_MEMBERS}",
            job.error_message,
        )
        self.assertNotIn("max_manifest_entries=400000", job.error_message)

    def test_normal_windows_compatible_manifest_is_not_blocked(self):
        executor = self.make_executor()
        members = [
            ArchiveMember(path="资料", is_dir=True),
            ArchiveMember(
                path="资料/项目 01/readme.txt", size=4, size_known=True
            ),
            ArchiveMember(
                path="资料/.gitignore", size=3, size_known=True
            ),
            ArchiveMember(
                path="folder.with.dots/report=final.txt",
                size=5,
                size_known=True,
                encrypted=True,
            ),
        ]
        manifest = ArchiveManifest(
            members=members,
            entry_count=len(members),
            total_size=12,
            listing_return_code=0,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            job = Job(path=os.path.join(temp_dir, "normal.zip"))
            state = executor._preflight(job, manifest)

        self.assertIsNone(state)
        self.assertGreater(job.approved_output_bytes, manifest.total_size)
        self.assertEqual(job.error_message, "")

    def test_unsafe_manifest_errors_identify_the_blocked_case(self):
        cases = (
            (
                ArchiveMember(path="../outside.exe", size=1, size_known=True),
                "unsafe_path_traversal",
                "路径穿越",
            ),
            (
                ArchiveMember(path="CON.txt", size=1, size_known=True),
                "unsafe_device_name",
                "Windows 保留设备名",
            ),
            (
                ArchiveMember(path="note.txt:secret", size=1, size_known=True),
                "unsafe_alternate_stream",
                "NTFS 备用数据流",
            ),
            (
                ArchiveMember(
                    path="linked.bin", size=1, size_known=True, is_link=True
                ),
                "unsafe_link_entry",
                "符号链接或硬链接",
            ),
            (
                ArchiveMember(
                    path="deleted.bin", size=1, size_known=True, is_anti=True
                ),
                "unsafe_anti_entry",
                "反向删除条目",
            ),
            (
                ArchiveMember(path="trailing.", size=1, size_known=True),
                "unsafe_invalid_windows_path",
                "Windows 不兼容路径",
            ),
        )

        for member, expected_reason, expected_label in cases:
            with self.subTest(path=member.path):
                executor = self.make_executor()
                manifest = ArchiveManifest(
                    members=[member],
                    entry_count=1,
                    total_size=1,
                    listing_return_code=0,
                )
                with tempfile.TemporaryDirectory() as temp_dir:
                    job = Job(path=os.path.join(temp_dir, "unsafe.zip"))
                    state = executor._preflight(job, manifest)

                self.assertEqual(state, JobState.FAILED)
                self.assertEqual(job.error_category, ErrorCategory.UNSAFE_PATH)
                self.assertEqual(job.source_retention_reason, expected_reason)
                self.assertIn(expected_label, job.error_message)
                self.assertIn("已跳过且未解压", job.error_message)

    def test_windows_normalized_duplicate_has_specific_error(self):
        executor = self.make_executor()
        manifest = ArchiveManifest(
            members=[
                ArchiveMember(
                    path="Folder/Report.txt", size=1, size_known=True
                ),
                ArchiveMember(
                    path="folder/report.TXT", size=1, size_known=True
                ),
            ],
            entry_count=2,
            total_size=2,
            listing_return_code=0,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            job = Job(path=os.path.join(temp_dir, "collision.zip"))
            state = executor._preflight(job, manifest)

        self.assertEqual(state, JobState.FAILED)
        self.assertEqual(job.source_retention_reason, "unsafe_normalized_collision")
        self.assertIn("Windows 路径冲突", job.error_message)

    def test_single_file_commit_is_verified_and_journaled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            os.makedirs(source)
            os.makedirs(destination)
            Path(source, "hello.txt").write_bytes(b"hello")
            executor = self.make_executor(
                extract_to_source=False,
                target_dir=destination,
                cleanup_policy=CleanupPolicy.KEEP.value,
            )
            job = Job(path=os.path.join(temp_dir, "archive.zip"))
            job.temp_root = source
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[os.path.join(source, "hello.txt")],
            )
            job.verification_result = VerificationResult(verified=True)
            job.error_category = ErrorCategory.BAD_PASSWORD
            job.error_message = "old password failure"
            with mock.patch("executor.zlib.crc32", side_effect=AssertionError):
                state = executor._commit(job)
            self.assertEqual(state, JobState.COMPLETE)
            self.assertTrue(job.commit_verified)
            self.assertTrue(job.commit_records)
            self.assertTrue(all(record.verified for record in job.commit_records))
            self.assertIsNone(job.error_category)
            self.assertEqual(job.error_message, "")
            self.assertEqual(Path(destination, "hello.txt").read_bytes(), b"hello")

    def test_incomplete_volume_set_fails_before_candidate_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = os.path.join(temp_dir, "archive.001")
            third = os.path.join(temp_dir, "archive.003")
            Path(first).write_bytes(b"first")
            Path(third).write_bytes(b"third")
            executor = self.make_executor()
            job = Job(path=first, original_path=first, explicit_input=True)

            with mock.patch.object(
                executor,
                "_prepare_stego_candidate",
                side_effect=AssertionError("incomplete sets must not scan"),
            ):
                state, promoted = executor.execute(job)

            self.assertEqual(state, JobState.FAILED)
            self.assertIsNone(promoted)
            self.assertEqual(job.error_category, ErrorCategory.MISSING_VOLUME)
            self.assertEqual(job.source_retention_reason, "missing_volume")

    def test_conflict_numbers_whole_task(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            os.makedirs(source)
            os.makedirs(destination)
            Path(source, "hello.txt").write_bytes(b"new")
            Path(destination, "hello.txt").write_bytes(b"old")
            executor = self.make_executor(
                extract_to_source=False, target_dir=destination
            )
            job = Job(path=os.path.join(temp_dir, "archive.zip"))
            job.temp_root = source
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[os.path.join(source, "hello.txt")],
            )
            job.verification_result = VerificationResult(verified=True)
            state = executor._commit(job)
            self.assertEqual(state, JobState.COMPLETE)
            self.assertEqual(Path(destination, "hello.txt").read_bytes(), b"old")
            self.assertEqual(Path(job.final_destination, "hello.txt").read_bytes(), b"new")
            self.assertEqual(os.path.basename(job.final_destination), "archive")

    def test_clean_empty_archive_commits_empty_task_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            os.makedirs(source)
            os.makedirs(destination)
            executor = self.make_executor(
                extract_to_source=False, target_dir=destination
            )
            job = Job(
                path=os.path.join(temp_dir, "empty.zip"),
                original_basename="empty.zip",
            )
            job.temp_root = source
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[],
            )
            job.verification_result = VerificationResult(verified=True)
            self.assertEqual(executor._commit(job), JobState.COMPLETE)
            self.assertTrue(os.path.isdir(job.final_destination))
            self.assertEqual(os.listdir(job.final_destination), [])
            self.assertTrue(job.commit_verified)

    def test_cross_volume_flush_failure_retains_extraction_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            os.makedirs(source)
            os.makedirs(destination)
            Path(source, "hello.txt").write_bytes(b"hello")
            executor = self.make_executor(
                extract_to_source=False, target_dir=destination
            )
            job = Job(path=os.path.join(temp_dir, "archive.zip"))
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[os.path.join(source, "hello.txt")],
            )
            job.verification_result = VerificationResult(verified=True)
            with mock.patch.object(
                executor, "_is_same_filesystem", return_value=False
            ), mock.patch(
                "executor.flush_file_to_disk",
                side_effect=OSError("flush failed"),
            ):
                state = executor._commit(job)

            self.assertEqual(state, JobState.PARTIAL_RECOVERY)
            self.assertTrue(os.path.exists(source))
            self.assertTrue(os.path.exists(job.final_destination))

    def test_failed_partial_relocation_keeps_hidden_commit_stage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            os.makedirs(source)
            os.makedirs(destination)
            Path(source, "hello.txt").write_bytes(b"hello")
            executor = self.make_executor(
                extract_to_source=False, target_dir=destination
            )
            job = Job(path=os.path.join(temp_dir, "archive.zip"))
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[os.path.join(source, "hello.txt")],
            )
            job.verification_result = VerificationResult(verified=True)
            with mock.patch.object(
                executor, "_is_same_filesystem", return_value=False
            ), mock.patch(
                "executor.flush_file_to_disk",
                side_effect=OSError("flush failed"),
            ), mock.patch.object(
                executor, "_recover_commit_stage", return_value=None
            ):
                state = executor._commit(job)

            self.assertEqual(state, JobState.FAILED)
            self.assertTrue(os.path.exists(source))
            self.assertIsNotNone(job.temp_root)
            self.assertTrue(os.path.exists(job.temp_root))
            self.assertEqual(job.source_retention_reason, "commit_stage_retained")

    def test_cross_volume_crc_mismatch_publishes_partial_and_keeps_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = os.path.join(temp_dir, "archive.zip")
            source = os.path.join(temp_dir, "source")
            destination = os.path.join(temp_dir, "destination")
            Path(archive).write_bytes(b"archive")
            os.makedirs(source)
            os.makedirs(destination)
            Path(source, "hello.txt").write_bytes(b"hello")
            executor = self.make_executor(
                extract_to_source=False, target_dir=destination
            )
            job = Job(path=archive, original_path=archive)
            job.manifest = ArchiveManifest(
                members=[
                    ArchiveMember(
                        path="hello.txt",
                        size=5,
                        size_known=True,
                        crc="00000000",
                    )
                ]
            )
            job.approved_output_bytes = 1024
            job.approved_file_count = 10
            job.extraction_result = ExtractionResult(
                success=True,
                return_code=0,
                temp_output_dir=source,
                extracted_paths=[os.path.join(source, "hello.txt")],
            )
            job.verification_result = VerificationResult(verified=True)
            with mock.patch.object(
                executor, "_is_same_filesystem", return_value=False
            ):
                state = executor._commit(job)

            self.assertEqual(state, JobState.PARTIAL_RECOVERY)
            self.assertTrue(os.path.exists(archive))
            self.assertFalse(os.path.exists(source))
            self.assertTrue(os.path.exists(job.final_destination))
            self.assertTrue(job.verification_result.crc_mismatches)
            self.assertFalse(job.cleanup_eligible)

    def test_copy_rejects_short_write(self):
        executor = self.make_executor()
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            destination = Path(temp_dir) / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            job = Job()
            job.approved_output_bytes = 1024
            job.approved_file_count = 10

            real_open = open

            class ShortWriter:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def write(self, data):
                    self.handle.write(data[:-1])
                    return max(0, len(data) - 1)

                def __getattr__(self, name):
                    return getattr(self.handle, name)

            def short_open(path, mode="r", *args, **kwargs):
                handle = real_open(path, mode, *args, **kwargs)
                return ShortWriter(handle) if mode == "xb" else handle

            with mock.patch("builtins.open", side_effect=short_open):
                with self.assertRaises(OSError):
                    executor._copy_tree_cancellable(
                        str(source), str(destination), job
                    )


class TestExecutionConfigSnapshot(unittest.TestCase):
    def test_update_does_not_change_active_job_config(self):
        executor = Executor(DummyRunner(), {**DEFAULT_CONFIG, "target_dir": "old"})
        with executor._config_lock:
            executor._active_config = dict(executor._configured)
        try:
            executor.update_config({**DEFAULT_CONFIG, "target_dir": "new"})
            self.assertEqual(executor.config["target_dir"], "old")
        finally:
            with executor._config_lock:
                executor._active_config = None
        self.assertEqual(executor.config["target_dir"], "new")


class TestRecycleBinAssessment(unittest.TestCase):
    def _assess(self, size, settings=(0, 1)):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        source = os.path.join(temp.name, "archive.zip")
        with open(source, "wb") as stream:
            stream.truncate(size)
        volume_guid = "{00000000-0000-0000-0000-000000000001}"
        with (
            mock.patch.object(
                windows_adapters,
                "_get_recycle_volume",
                return_value=("C:\\", windows_adapters.DRIVE_FIXED, volume_guid),
            ),
            mock.patch.object(
                windows_adapters,
                "_read_recycle_bin_settings",
                return_value=settings,
            ),
        ):
            return windows_adapters.assess_recycle_bin(source)

    def test_ready_when_item_fits_enabled_volume(self):
        assessment = self._assess(1024)

        self.assertEqual(assessment.status, windows_adapters.RECYCLE_READY)
        self.assertEqual(assessment.max_capacity_bytes, 1024 * 1024)

    def test_too_large_uses_volume_capacity_in_mebibytes(self):
        assessment = self._assess(1024 * 1024 + 1)

        self.assertEqual(
            assessment.status,
            windows_adapters.RECYCLE_FALLBACK_TOO_LARGE,
        )

    def test_nuke_on_delete_is_explicitly_unavailable(self):
        assessment = self._assess(1024, settings=(1, 100))

        self.assertEqual(
            assessment.status,
            windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE,
        )

    def test_known_unsupported_drive_does_not_read_registry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "archive.zip")
            Path(source).write_bytes(b"source")
            with (
                mock.patch.object(
                    windows_adapters,
                    "_get_recycle_volume",
                    return_value=(
                        "E:\\",
                        windows_adapters.DRIVE_REMOVABLE,
                        "",
                    ),
                ),
                mock.patch.object(
                    windows_adapters, "_read_recycle_bin_settings"
                ) as read_settings,
            ):
                assessment = windows_adapters.assess_recycle_bin(source)

        read_settings.assert_not_called()
        self.assertEqual(
            assessment.status,
            windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE,
        )


class TestCleanupGate(unittest.TestCase):
    @staticmethod
    def _ready_cleanup_job(executor, volumes, policy=CleanupPolicy.RECYCLE.value):
        job = Job(
            path=volumes[0],
            original_path=volumes[0],
            cleanup_policy_snapshot=policy,
        )
        job.archive_set = ArchiveSet(
            main_path=volumes[0], volumes=list(volumes), cleanup_safe=True
        )
        job.record_state(JobState.COMPLETE)
        job.cleanup_eligible = True
        job.commit_verified = True
        executor._remember_source_identities(job)
        return job

    def test_warning_or_unverified_never_cleans(self):
        executor = Executor(
            DummyRunner(),
            {**DEFAULT_CONFIG, "cleanup_policy": CleanupPolicy.PERMANENT.value},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "archive.zip")
            Path(source).write_bytes(b"source")
            job = Job(path=source, original_path=source)
            job.archive_set = ArchiveSet(main_path=source, volumes=[source])
            job.record_state(JobState.COMPLETE)
            job.cleanup_eligible = True
            job.commit_verified = False
            executor._maybe_cleanup_sources(job)
            self.assertTrue(os.path.exists(source))

    def test_unverified_volume_metadata_never_cleans(self):
        executor = Executor(
            DummyRunner(),
            {**DEFAULT_CONFIG, "cleanup_policy": CleanupPolicy.PERMANENT.value},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "archive.001")
            Path(source).write_bytes(b"source")
            job = Job(path=source, original_path=source)
            job.archive_set = ArchiveSet(
                main_path=source,
                volumes=[source],
                cleanup_safe=False,
                cleanup_reason="7z_volumes=2, discovered=1",
            )
            job.record_state(JobState.COMPLETE)
            job.cleanup_eligible = True
            job.commit_verified = True

            executor._maybe_cleanup_sources(job)

            self.assertTrue(os.path.exists(source))
            self.assertIn("volume_cleanup_unverified", job.source_retention_reason)

    def test_manifest_volume_mismatch_only_disables_source_cleanup(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        job = Job(path="archive.cab")
        job.archive_set = ArchiveSet(
            main_path="archive.cab",
            volumes=["archive.cab"],
        )
        manifest = ArchiveManifest(raw_fields={"Volumes": "2"})

        executor._apply_manifest_volume_info(job, manifest)

        self.assertTrue(job.archive_set.is_complete)
        self.assertFalse(job.archive_set.cleanup_safe)
        self.assertIn("7z_volumes=2", job.archive_set.cleanup_reason)

    def test_manifest_extra_discovered_volume_disables_source_cleanup(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        job = Job(path="archive.001")
        job.archive_set = ArchiveSet(
            main_path="archive.001",
            volumes=["archive.001", "archive.002", "archive.003"],
        )
        manifest = ArchiveManifest(raw_fields={"Volumes": "2"})

        executor._apply_manifest_volume_info(job, manifest)

        self.assertFalse(job.archive_set.cleanup_safe)
        self.assertIn("7z_volumes=2, discovered=3", job.archive_set.cleanup_reason)

    def test_nonzero_manifest_volume_index_disables_source_cleanup(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        job = Job(path="archive.002")
        job.archive_set = ArchiveSet(
            main_path="archive.002",
            volumes=["archive.002"],
        )
        manifest = ArchiveManifest(raw_fields={"Volumes": "1", "Volume Index": "1"})

        executor._apply_manifest_volume_info(job, manifest)

        self.assertFalse(job.archive_set.cleanup_safe)
        self.assertIn("7z_volume_index=1", job.archive_set.cleanup_reason)
        self.assertTrue(
            any("cleanup disabled" in item for item in manifest.diagnostics)
        )

    def test_recycle_uses_original_paths_and_stops_after_first_failure(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [
                os.path.join(temp_dir, f"archive.{index:03d}")
                for index in range(1, 4)
            ]
            for volume in volumes:
                Path(volume).write_bytes(volume.encode("utf-8"))
            job = self._ready_cleanup_job(executor, volumes)

            calls = []

            def recycle(path):
                calls.append(path)
                if len(calls) == 1:
                    os.unlink(path)
                    return True
                return False

            ready = windows_adapters.RecycleBinAssessment(
                windows_adapters.RECYCLE_READY
            )
            with (
                mock.patch.object(
                    windows_adapters, "assess_recycle_bin", return_value=ready
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin", side_effect=recycle
                ),
            ):
                executor._maybe_cleanup_sources(job)

            self.assertEqual(calls, volumes[:2])
            self.assertFalse(os.path.exists(volumes[0]))
            self.assertTrue(os.path.exists(volumes[1]))
            self.assertTrue(os.path.exists(volumes[2]))
            self.assertEqual(job.source_retention_reason, "recycle_partial:1:1")
            self.assertIn("[RECYCLE_FAILED]", job.user_notices[-1])

    def test_recycle_rechecks_identity_before_each_shell_operation(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [
                os.path.join(temp_dir, f"archive.{index:03d}")
                for index in (1, 2)
            ]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)
            ready = windows_adapters.RecycleBinAssessment(
                windows_adapters.RECYCLE_READY
            )

            def recycle(path):
                os.unlink(path)
                Path(volumes[1]).write_bytes(b"replacement-is-different")
                return True

            with (
                mock.patch.object(
                    windows_adapters, "assess_recycle_bin", return_value=ready
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin", side_effect=recycle
                ) as recycle_call,
            ):
                executor._maybe_cleanup_sources(job)

            recycle_call.assert_called_once_with(volumes[0])
            self.assertFalse(os.path.exists(volumes[0]))
            self.assertEqual(Path(volumes[1]).read_bytes(), b"replacement-is-different")
            self.assertEqual(
                job.source_retention_reason,
                "recycle_partial:1:source_identity_changed",
            )
            self.assertIn("[RECYCLE_FAILED]", job.user_notices[-1])

    def test_recycle_preflight_failure_keeps_every_volume(self):
        events = []
        executor = Executor(
            DummyRunner(), dict(DEFAULT_CONFIG), event_cb=lambda *args: events.append(args)
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [os.path.join(temp_dir, f"archive.{index:03d}") for index in (1, 2)]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)

            with (
                mock.patch.object(
                    windows_adapters,
                    "assess_recycle_bin",
                    side_effect=OSError("unknown volume policy"),
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin"
                ) as recycle,
                mock.patch.object(
                    windows_adapters, "delete_permanently"
                ) as permanent,
            ):
                executor._maybe_cleanup_sources(job)

            self.assertTrue(all(os.path.exists(volume) for volume in volumes))
            recycle.assert_not_called()
            permanent.assert_not_called()
            self.assertEqual(job.source_retention_reason, "recycle_failed:preflight")
            self.assertIn("[RECYCLE_FAILED]", job.user_notices[-1])
            self.assertTrue(any(event[0] == "user_notice" for event in events))

    def test_missing_source_before_cleanup_keeps_remaining_volumes(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [
                os.path.join(temp_dir, f"archive.{index:03d}")
                for index in (1, 2)
            ]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)
            os.unlink(volumes[0])

            with (
                mock.patch.object(windows_adapters, "assess_recycle_bin") as assess,
                mock.patch.object(windows_adapters, "send_to_recycle_bin") as recycle,
                mock.patch.object(windows_adapters, "delete_permanently") as permanent,
            ):
                executor._maybe_cleanup_sources(job)

            assess.assert_not_called()
            recycle.assert_not_called()
            permanent.assert_not_called()
            self.assertTrue(os.path.exists(volumes[1]))
            self.assertEqual(job.source_retention_reason, "source_missing")
            self.assertTrue(
                any("volume disappeared" in item for item in job.terminal_diagnostics)
            )

    def test_recycle_fallback_uses_journaled_permanent_staging(self):
        events = []
        journal = mock.Mock()
        journal.register_source_stage.return_value = "journal-entry"
        journal.source_stage_ready.return_value = True
        journal.last_error = ""
        executor = Executor(
            DummyRunner(),
            dict(DEFAULT_CONFIG),
            event_cb=lambda *args: events.append(args),
            recovery_journal=journal,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [os.path.join(temp_dir, f"archive.{index:03d}") for index in (1, 2)]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)
            assessments = [
                windows_adapters.RecycleBinAssessment(
                    windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE
                ),
                windows_adapters.RecycleBinAssessment(
                    windows_adapters.RECYCLE_FALLBACK_TOO_LARGE
                ),
            ]

            def remove_staged(path):
                os.unlink(path)
                return True

            with (
                mock.patch.object(
                    windows_adapters,
                    "assess_recycle_bin",
                    side_effect=assessments,
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin"
                ) as recycle,
                mock.patch.object(
                    windows_adapters,
                    "delete_permanently",
                    side_effect=remove_staged,
                ) as permanent,
            ):
                executor._maybe_cleanup_sources(job)

            self.assertFalse(any(os.path.exists(volume) for volume in volumes))
            recycle.assert_not_called()
            self.assertEqual(permanent.call_count, 2)
            self.assertEqual(journal.register_source_stage.call_count, 2)
            for call in journal.register_source_stage.call_args_list:
                self.assertEqual(call.kwargs["cleanup_policy"], "recycle_fallback")
            self.assertIn("cleaned:recycle_with_fallback:2", job.source_retention_reason)
            notices = "\n".join(job.user_notices)
            self.assertIn("[RECYCLE_FALLBACK_UNAVAILABLE]", notices)
            self.assertIn("[RECYCLE_FALLBACK_TOO_LARGE]", notices)
            self.assertEqual(
                sum(event[0] == "user_notice" for event in events),
                2,
            )

    def test_recycle_failure_prevents_planned_permanent_fallback(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [os.path.join(temp_dir, f"archive.{index:03d}") for index in (1, 2)]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)
            assessments = [
                windows_adapters.RecycleBinAssessment(
                    windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE
                ),
                windows_adapters.RecycleBinAssessment(
                    windows_adapters.RECYCLE_READY
                ),
            ]

            with (
                mock.patch.object(
                    windows_adapters,
                    "assess_recycle_bin",
                    side_effect=assessments,
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin", return_value=False
                ) as recycle,
                mock.patch.object(
                    windows_adapters, "delete_permanently"
                ) as permanent,
            ):
                executor._maybe_cleanup_sources(job)

            recycle.assert_called_once_with(volumes[1])
            permanent.assert_not_called()
            self.assertTrue(all(os.path.exists(volume) for volume in volumes))
            self.assertIn("[RECYCLE_FAILED]", job.user_notices[-1])

    def test_recycle_fallback_delete_failure_restores_unprocessed_volumes(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            volumes = [os.path.join(temp_dir, f"archive.{index:03d}") for index in (1, 2)]
            for volume in volumes:
                Path(volume).write_bytes(b"source")
            job = self._ready_cleanup_job(executor, volumes)
            unavailable = windows_adapters.RecycleBinAssessment(
                windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE
            )

            with (
                mock.patch.object(
                    windows_adapters,
                    "assess_recycle_bin",
                    return_value=unavailable,
                ),
                mock.patch.object(
                    windows_adapters, "send_to_recycle_bin"
                ) as recycle,
                mock.patch.object(
                    windows_adapters, "delete_permanently", return_value=False
                ) as permanent,
            ):
                executor._maybe_cleanup_sources(job)

            recycle.assert_not_called()
            permanent.assert_called_once()
            self.assertTrue(all(os.path.exists(volume) for volume in volumes))
            self.assertIn("recycle_fallback_failed", job.source_retention_reason)
            self.assertIn(
                "[RECYCLE_FALLBACK_DELETE_FAILED]", job.user_notices[-1]
            )

    def test_source_identity_uses_metadata_without_content_hash(self):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "archive.zip")
            Path(source).write_bytes(b"original")
            job = Job(
                path=source,
                original_path=source,
                cleanup_policy_snapshot=CleanupPolicy.PERMANENT.value,
            )
            job.archive_set = ArchiveSet(
                main_path=source, volumes=[source], cleanup_safe=True
            )
            job.record_state(JobState.COMPLETE)
            job.cleanup_eligible = True
            job.commit_verified = True
            executor._remember_source_identities(job)
            expected = next(iter(job.source_identities.values()))
            self.assertEqual(
                set(expected.__dataclass_fields__),
                {"device", "inode", "size", "mtime_ns"},
            )


class TestCommitCopyVerification(unittest.TestCase):
    def _copy_payload(self, payload: bytes, expected_crc: str):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "source"
        destination = Path(temp.name) / "destination"
        source.mkdir()
        destination.mkdir()
        (source / "payload.bin").write_bytes(payload)
        job = Job()
        job.manifest = ArchiveManifest(
            members=[
                ArchiveMember(
                    path="payload.bin",
                    size=len(payload),
                    size_known=True,
                    crc=expected_crc,
                )
            ],
            total_size=len(payload),
            listing_return_code=0,
        )
        job.approved_output_bytes = len(payload) + 1
        job.approved_file_count = 1
        mismatches = executor._copy_tree_cancellable(
            str(source), str(destination), job
        )
        return mismatches, destination / "payload.bin"

    def test_matching_member_crc_is_verified_during_copy(self):
        payload = b"verified payload"
        expected_crc = f"{zlib.crc32(payload) & 0xFFFFFFFF:08X}"
        mismatches, copied = self._copy_payload(payload, expected_crc)
        self.assertEqual(mismatches, [])
        self.assertEqual(copied.read_bytes(), payload)

    def test_member_crc_mismatch_is_reported_during_copy(self):
        mismatches, _copied = self._copy_payload(b"changed payload", "00000000")
        self.assertEqual(len(mismatches), 1)
        self.assertIn("expected 00000000", mismatches[0])

    def test_member_without_crc_is_copied_without_crc_work(self):
        with mock.patch("executor.zlib.crc32", side_effect=AssertionError):
            mismatches, copied = self._copy_payload(b"payload", "")
        self.assertEqual(mismatches, [])
        self.assertEqual(copied.read_bytes(), b"payload")


class TestOutputDirectoryVerification(unittest.TestCase):
    def _verify(self, manifest_members, directories):
        executor = Executor(DummyRunner(), dict(DEFAULT_CONFIG))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        files = []
        for relative, payload in (("folder/payload.bin", b"payload"),):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            files.append(str(path))
        directory_paths = [str(root / relative) for relative in directories]
        for directory in directory_paths:
            Path(directory).mkdir(parents=True, exist_ok=True)
        job = Job()
        job.manifest = ArchiveManifest(
            members=manifest_members,
            listing_return_code=0,
        )
        job.extraction_result = ExtractionResult(
            success=True,
            return_code=0,
            temp_output_dir=str(root),
            extracted_paths=files,
            extracted_directories=directory_paths,
        )
        return executor._verify(job)

    def test_explicit_empty_directory_is_required(self):
        result = self._verify(
            [ArchiveMember(path="empty", is_dir=True)],
            [],
        )
        self.assertFalse(result.verified)
        self.assertEqual(result.missing_directories, ["empty"])

    def test_missing_directory_fails(self):
        result = self._verify(
            [ArchiveMember(path="folder", is_dir=True)],
            [],
        )
        self.assertFalse(result.verified)
        self.assertEqual(result.missing_directories, ["folder"])

    def test_unexpected_directory_fails(self):
        result = self._verify(
            [ArchiveMember(path="folder/payload.bin", size=7, size_known=True)],
            ["folder", "unexpected"],
        )
        self.assertFalse(result.verified)
        self.assertEqual(result.extra_directories, ["unexpected"])

    def test_implicit_parent_directory_is_accepted(self):
        result = self._verify(
            [ArchiveMember(path="folder/payload.bin", size=7, size_known=True)],
            ["folder"],
        )
        self.assertTrue(result.verified)

    def test_duplicate_normalized_manifest_path_fails(self):
        result = self._verify(
            [
                ArchiveMember(
                    path="folder/payload.bin", size=7, size_known=True
                ),
                ArchiveMember(
                    path="folder\\payload.bin", size=7, size_known=True
                ),
            ],
            ["folder"],
        )
        self.assertFalse(result.verified)
        self.assertTrue(
            any("Duplicate normalized manifest" in item for item in result.unsafe)
        )


class TestRecoveryMoveDisposition(unittest.TestCase):
    def test_commit_move_is_preserved_until_publication_releases_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_path = os.path.join(temp_dir, "recovery-v1.json")
            source = os.path.join(temp_dir, "task_source")
            stage = os.path.join(temp_dir, ".smart7z_commit_stage")
            os.makedirs(source)
            Path(source, "payload.txt").write_text("payload", encoding="utf-8")
            journal = RecoveryJournal(journal_path)
            try:
                self.assertIsNotNone(
                    journal.register_artifact(
                        source,
                        task_id="task",
                        artifact_kind="session_extract",
                        name_prefix="task_",
                        disposition="delete",
                    )
                )
                self.assertTrue(
                    journal.prepare_artifact_move(
                        source, stage, ".smart7z_commit_"
                    )
                )
                os.replace(source, stage)
                self.assertTrue(journal.commit_artifact_move(source, stage))
            finally:
                journal.close()

            reopened = RecoveryJournal(journal_path)
            try:
                messages = reopened.recover()
                self.assertTrue(os.path.isdir(stage))
                self.assertTrue(
                    any("preserved" in message.lower() for message in messages)
                )
                self.assertTrue(reopened.unregister_artifact(stage))
            finally:
                reopened.close()

    def test_recovery_preserves_artifact_when_new_content_appears(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_path = os.path.join(temp_dir, "recovery-v1.json")
            artifact = os.path.join(temp_dir, "task_artifact")
            os.makedirs(artifact)
            journal = RecoveryJournal(journal_path)
            try:
                self.assertIsNotNone(
                    journal.register_artifact(
                        artifact,
                        task_id="task",
                        artifact_kind="session_extract",
                        name_prefix="task_",
                        disposition="delete",
                    )
                )
            finally:
                journal.close()

            Path(artifact, "sentinel.txt").write_text("later", encoding="utf-8")
            reopened = RecoveryJournal(journal_path)
            try:
                messages = reopened.recover()
                self.assertTrue(os.path.isdir(artifact))
                self.assertTrue(
                    any("content changed" in message.lower() for message in messages)
                )
            finally:
                reopened.close()


class TestIPCValidation(unittest.TestCase):
    def setUp(self):
        class App:
            pass

        self.server = BoundedIPCServer(App())

    def test_rejects_relative_and_nonexistent_paths(self):
        payload = json.dumps(
            {
                "version": IPC_VERSION,
                "token": self.server.token,
                "action": "enqueue",
                "paths": ["relative.zip"],
                "auto_start": True,
            }
        ).encode("utf-8")
        self.assertIsNone(self.server._parse_request(payload))
        payload = json.dumps(
            {
                "version": IPC_VERSION,
                "token": self.server.token,
                "action": "enqueue",
                "paths": [os.path.abspath("definitely-missing.zip")],
                "auto_start": True,
            }
        ).encode("utf-8")
        self.assertIsNone(self.server._parse_request(payload))

    def test_accepts_existing_absolute_path(self):
        with tempfile.NamedTemporaryFile() as stream:
            payload = json.dumps(
                {
                    "version": IPC_VERSION,
                    "token": self.server.token,
                    "action": "enqueue",
                    "paths": [stream.name],
                    "auto_start": True,
                }
            ).encode("utf-8")
            request = self.server._parse_request(payload)
            self.assertEqual(
                request.paths, (os.path.normpath(stream.name),)
            )


class TestGlobalGate(unittest.TestCase):
    def test_two_runners_never_overlap_popen(self):
        active = [0]
        maximum = [0]
        lock = threading.Lock()

        class FakePipe:
            def read(self, _size):
                return b""

            def close(self):
                return None

        class FakeProcess:
            def __init__(self, *args, **kwargs):
                self.stdout = FakePipe()
                self.stderr = FakePipe()
                self.pid = 123
                self.returncode = None
                with lock:
                    active[0] += 1
                    maximum[0] = max(maximum[0], active[0])
                self._polls = 0

            def poll(self):
                self._polls += 1
                if self._polls < 4:
                    return None
                if self.returncode is None:
                    self.returncode = 0
                    with lock:
                        active[0] -= 1
                return self.returncode

            def wait(self, timeout=None):
                while self.poll() is None:
                    pass
                return self.returncode

        runners = [SevenZipRunner("7z.exe"), SevenZipRunner("7z.exe")]
        with mock.patch.object(sevenzip.subprocess, "Popen", side_effect=FakeProcess):
            threads = [
                threading.Thread(target=runner.raw, args=(["i"], 2))
                for runner in runners
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        self.assertEqual(maximum[0], 1)


if __name__ == "__main__":
    unittest.main()
