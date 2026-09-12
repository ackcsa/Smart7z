"""Acceptance tests: config migration, path safety, scheduler cancel, redaction."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_mod
from config import (
    DEFAULT_CONFIG,
    map_del_archive_to_cleanup_policy,
    migrate_legacy_raw,
    is_legacy_raw,
    load_config,
    save_config,
    set_config_path,
    set_app_dir,
    find_sevenzip,
)
from models import (
    Job, JobState, CleanupPolicy, ErrorCategory, Confidence,
    ArchiveCandidate, TERMINAL_STATES,
)
from sevenzip import (
    redact_command, redact_text, parse_slt, classify_return_code,
    is_clean_success, is_warning, is_failure, EXIT_SUCCESS, EXIT_WARNING,
)
from path_safety import is_safe_output_path, has_device_name
from scheduler import Scheduler
from discovery import detect_archive_set, is_multipart_child


class TestDelArchiveMigration(unittest.TestCase):
    def test_false_to_keep(self):
        self.assertEqual(map_del_archive_to_cleanup_policy(False), "keep")

    def test_true_to_permanent(self):
        self.assertEqual(map_del_archive_to_cleanup_policy(True), "permanent")

    def test_missing_none_to_keep(self):
        self.assertEqual(map_del_archive_to_cleanup_policy(None), "keep")

    def test_string_true(self):
        self.assertEqual(map_del_archive_to_cleanup_policy("True"), "permanent")
        self.assertEqual(map_del_archive_to_cleanup_policy("true"), "permanent")
        self.assertEqual(map_del_archive_to_cleanup_policy("1"), "permanent")

    def test_string_false(self):
        self.assertEqual(map_del_archive_to_cleanup_policy("False"), "keep")
        self.assertEqual(map_del_archive_to_cleanup_policy("0"), "keep")

    def test_int_values(self):
        self.assertEqual(map_del_archive_to_cleanup_policy(1), "permanent")
        self.assertEqual(map_del_archive_to_cleanup_policy(0), "keep")

    def test_legacy_raw_migration_false(self):
        raw = {"del_archive": False, "target_dir": "C:\\out"}
        self.assertTrue(is_legacy_raw(raw))
        m = migrate_legacy_raw(raw)
        self.assertEqual(m["cleanup_policy"], "keep")
        self.assertEqual(m["config_version"], 1)

    def test_legacy_raw_migration_true(self):
        m = migrate_legacy_raw({"del_archive": True})
        self.assertEqual(m["cleanup_policy"], "permanent")

    def test_legacy_missing_del_archive(self):
        m = migrate_legacy_raw({})
        self.assertEqual(m["cleanup_policy"], "keep")

    def test_load_legacy_false_preserves_sources_with_keep(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "smart7z_config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"del_archive": False, "target_dir": tmp}, f)
            set_config_path(path)
            set_app_dir(tmp)
            try:
                cfg = load_config()
                self.assertEqual(cfg["cleanup_policy"], "keep")
                self.assertIn("config_version", cfg)
            finally:
                set_config_path(None)
                set_app_dir(None)

    def test_load_legacy_preserves_permanent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "smart7z_config.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"del_archive": True}, f)
            set_config_path(path)
            set_app_dir(tmp)
            try:
                cfg = load_config()
                self.assertEqual(cfg["cleanup_policy"], "permanent")
            finally:
                set_config_path(None)
                set_app_dir(None)

    def test_fresh_defaults_keep(self):
        self.assertEqual(DEFAULT_CONFIG["cleanup_policy"], "keep")

    def test_malformed_falls_back_to_keep(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "smart7z_config.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            set_config_path(path)
            set_app_dir(tmp)
            try:
                with self.assertWarns(RuntimeWarning):
                    cfg = load_config()
                self.assertEqual(cfg["cleanup_policy"], "keep")
            finally:
                set_config_path(None)
                set_app_dir(None)

    def test_versioned_config_not_remigrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "smart7z_config.json")
            raw = {"config_version": 1, "cleanup_policy": "keep", "del_archive": True}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(raw, f)
            set_config_path(path)
            set_app_dir(tmp)
            try:
                cfg = load_config()
                self.assertEqual(cfg["cleanup_policy"], "keep")
            finally:
                set_config_path(None)
                set_app_dir(None)


class TestPathSafety(unittest.TestCase):
    def test_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, reason = is_safe_output_path("../etc/passwd", tmp)
            self.assertFalse(ok)

    def test_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, _ = is_safe_output_path("C:\\Windows\\system32", tmp)
            self.assertFalse(ok)

    def test_safe_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, reason = is_safe_output_path("folder/file.txt", tmp)
            self.assertTrue(ok, reason)

    def test_device_name(self):
        self.assertTrue(has_device_name("CON"))
        self.assertTrue(has_device_name("folder/NUL.txt"))
        self.assertFalse(has_device_name("normal.txt"))

    def test_null_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, _ = is_safe_output_path("a\x00b.txt", tmp)
            self.assertFalse(ok)

    def test_windows_trailing_dot_space_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in ("folder./file.txt", "name ", "NUL .txt"):
                with self.subTest(path=path):
                    ok, _ = is_safe_output_path(path, tmp)
                    self.assertFalse(ok)

    def test_control_character_and_oversized_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(is_safe_output_path("bad\x01name", tmp)[0])
            self.assertFalse(is_safe_output_path("x" * 256, tmp)[0])


class TestRedaction(unittest.TestCase):
    def test_cmd_redact(self):
        safe = redact_command(["7z", "x", "a.zip", "-pSecret123"])
        self.assertIn("-p******", safe)
        self.assertNotIn("Secret123", " ".join(safe))

    def test_text_redact(self):
        t = redact_text("CMD: 7z x -pMyPass file.zip")
        self.assertNotIn("MyPass", t)
        self.assertIn("-p******", t)

    def test_job_to_task_dict_omits_password(self):
        job = Job(path="a.zip")
        d = job.to_task_dict()
        self.assertNotIn("manual_password", d)
        self.assertNotIn("tried_passwords", d)
        blob = json.dumps(d, default=list)
        self.assertNotIn("secret", blob)


class TestSltParsing(unittest.TestCase):
    def test_reordered_and_equals_in_name(self):
        sample = """Type = zip
----------
Size = 10
Path = a=b.txt
Encrypted = -
CRC = AA

Path = dir/
Attributes = D
Size = 0
Encrypted = -
"""
        m = parse_slt(sample)
        self.assertEqual(m.format, "zip")
        self.assertEqual(m.members[0].path, "a=b.txt")
        self.assertEqual(m.members[0].size, 10)
        self.assertTrue(m.members[1].is_dir)
        # dirs should not add to total_size
        self.assertEqual(m.total_size, 10)

    def test_locale_thousands(self):
        sample = """----------
Path = big.bin
Size = 1.234.567
Encrypted = -
"""
        m = parse_slt(sample)
        self.assertEqual(m.members[0].size, 1234567)


class TestExitCodes(unittest.TestCase):
    def test_warning_not_clean(self):
        self.assertTrue(is_warning(1))
        self.assertFalse(is_clean_success(1))
        self.assertFalse(is_failure(1))
        ok, cat = classify_return_code(1)
        self.assertTrue(ok)


class TestMultipart(unittest.TestCase):
    def test_missing_middle(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.001", "a.003"]:
                Path(tmp, name).write_text("x")
            s = detect_archive_set(os.path.join(tmp, "a.001"))
            self.assertEqual(s.format_family, "numeric_split")
            self.assertIn(2, s.missing_indexes)
            self.assertFalse(s.is_complete)

    def test_part_rar_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["x.part1.rar", "x.part2.rar"]:
                Path(tmp, name).write_text("x")
            s = detect_archive_set(os.path.join(tmp, "x.part1.rar"))
            self.assertEqual(len(s.volumes), 2)
            self.assertTrue(s.is_complete)

    def test_child_skip(self):
        self.assertTrue(is_multipart_child("a.part02.rar"))
        self.assertFalse(is_multipart_child("a.part01.rar"))


class TestSchedulerCancel(unittest.TestCase):
    def setUp(self):
        self._scheduler_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._scheduler_temp.cleanup)

    def _make_scheduler(self, event_cb=None):
        config = dict(DEFAULT_CONFIG)
        config["temp_dir"] = self._scheduler_temp.name
        config["_recovery_journal_path"] = os.path.join(
            self._scheduler_temp.name, "recovery-v1.json"
        )
        scheduler = Scheduler("7z.exe", config, event_cb=event_cb)
        self.addCleanup(scheduler.stop)
        return scheduler

    def test_cancel_remaining_marks_interrupted(self):
        events = []

        def cb(etype, job, *a, **k):
            events.append((etype, job.state))

        sched = self._make_scheduler(event_cb=cb)
        # Do not start worker — just drain queue APIs
        jobs = [Job(path=f"f{i}.zip") for i in range(3)]
        for j in jobs:
            j.state = JobState.QUEUED
            sched.task_queue.put(j)
            sched._jobs[j.task_id] = j
        sched.cancel_remaining()
        self.assertEqual(sched.task_queue.qsize(), 0)
        interrupted = [e for e in events if e[0] == "job_interrupted"]
        self.assertEqual(len(interrupted), 3)
        for j in jobs:
            self.assertEqual(j.state, JobState.INTERRUPTED)

    def test_discard_remaining_removes_pending_jobs_without_interruption_events(self):
        events = []
        sched = self._make_scheduler(
            event_cb=lambda event_type, *_args, **_kwargs: events.append(event_type)
        )
        jobs = [Job(path=f"f{index}.zip") for index in range(3)]
        for job in jobs:
            sched.task_queue.put(job)
            sched._jobs[job.task_id] = job

        removed = set(sched.discard_remaining())

        self.assertEqual(removed, {job.task_id for job in jobs})
        self.assertEqual(sched.task_queue.qsize(), 0)
        self.assertFalse(any(event == "job_interrupted" for event in events))
        for job in jobs:
            self.assertFalse(sched.has_job(job.task_id))
            self.assertEqual(job.state, JobState.QUEUED)

    def test_password_pending_cancel(self):
        events = []
        sched = self._make_scheduler(
            event_cb=lambda *a, **k: events.append(a[0])
        )
        job = Job(path="enc.zip")
        job.state = JobState.PASSWORD_REQUIRED
        sched._jobs[job.task_id] = job
        sched.password_pending[job.task_id] = job
        sched.cancel_remaining()
        self.assertEqual(job.state, JobState.INTERRUPTED)
        self.assertEqual(len(sched.password_pending), 0)

    def test_discard_selected_removes_all_pending_kinds_and_keeps_others(self):
        sched = self._make_scheduler()
        queued, deferred, password, stego, keep = [Job(path=f"{n}.zip") for n in range(5)]
        for job in (queued, password, stego, keep):
            sched.submit(job)
        sched.pause_intake()
        sched.submit(deferred)
        sched.password_pending[password.task_id] = password
        sched.stego_pending[stego.task_id] = stego
        sched._manual_passwords[password.task_id] = "secret"
        selected = {job.task_id for job in (queued, deferred, password, stego)}
        with mock.patch.object(sched.executor, "cleanup_job_artifacts") as cleanup:
            self.assertEqual(set(sched.discard_jobs(selected)), selected)
            self.assertEqual(cleanup.call_count, 4)
        self.assertEqual(set(sched._jobs), {keep.task_id})
        self.assertFalse(sched.password_pending)
        self.assertFalse(sched.stego_pending)
        self.assertFalse(sched._manual_passwords)
        self.assertEqual(sched.deferred_intake_size(), 0)
        self.assertEqual(sched.queue_size(), 1)
        sched.submit_password_response(password, "late")
        sched.submit_stego_selection(stego, 0)
        self.assertEqual(sched.queue_size(), 1)

    def test_discard_active_job_cleans_after_worker_and_suppresses_prompt(self):
        events = []
        sched = self._make_scheduler(event_cb=lambda kind, *_a, **_k: events.append(kind))
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def execute(job, **_kwargs):
            started.set()
            release.wait(3)
            return JobState.PASSWORD_REQUIRED, None

        job = Job(path="active.zip")
        with (
            mock.patch.object(sched.executor, "execute", side_effect=execute),
            mock.patch.object(sched.executor, "cleanup_job_artifacts") as cleanup,
            mock.patch.object(sched.runner, "cancel_current") as cancel,
        ):
            sched.submit(job)
            sched.start()
            sched.enable_processing()
            self.assertTrue(started.wait(3))
            self.assertEqual(sched.discard_jobs({job.task_id}), [job.task_id])
            cancel.assert_called_once()
            cleanup.assert_not_called()
            release.set()
            deadline = time.monotonic() + 3
            while sched.current_job is not None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNone(sched.current_job)
            cleanup.assert_called_once_with(job, terminal=True)
        self.assertFalse(sched.has_job(job.task_id))
        self.assertNotIn("password_required", events)
        self.assertNotIn("job_interrupted", events)
        self.assertFalse(sched.password_pending)
        self.assertFalse(sched._closed_nested_batches)
        self.assertFalse(sched._discarded_nested_batches)

    def test_discard_rejects_late_nested_children_without_history_rows(self):
        for selected_only in (False, True):
            with self.subTest(selected_only=selected_only):
                events = []
                sched = self._make_scheduler(
                    event_cb=lambda kind, job, *_a, **_k: events.append((kind, job.task_id))
                )
                parent = Job(path="parent.zip")
                self.assertTrue(sched.submit(parent))
                sched.task_queue.get_nowait()
                sched.task_queue.task_done()
                sched.current_job = parent
                with mock.patch.object(sched.runner, "cancel_current"):
                    if selected_only:
                        sched.discard_jobs({parent.task_id})
                    else:
                        sched.discard_remaining()
                child = Job(path="late-child.zip", nested_depth=1)
                self.assertFalse(sched.submit(child))
                self.assertFalse(sched.has_job(child.task_id))
                self.assertFalse(any(task_id == child.task_id for _, task_id in events))
                self.assertEqual(sched.queue_size(), 0)
                sched.current_job = None
                sched.stop()

    def test_promoted_password_is_used_by_next_job_in_same_batch(self):
        completed = []
        done = threading.Event()

        def published(event_type, job, *_args, **_kwargs):
            if event_type == "job_complete":
                completed.append(job.task_id)
                if len(completed) == 2:
                    done.set()

        sched = self._make_scheduler(event_cb=published)
        book = Path(self._scheduler_temp.name, "code.txt")
        book.write_text("old\nshared\n", encoding="utf-8")
        sched.executor.config["password_file"] = str(book)
        attempts = []

        def execute(job, manual_password=None, session_main_password=None):
            attempts.append(sched.executor._password_candidates(manual_password, session_main_password))
            sched.executor._promote_password("shared")
            job.record_state(JobState.COMPLETE)
            return JobState.COMPLETE, "shared"

        with mock.patch.object(sched.executor, "execute", side_effect=execute):
            sched.submit(Job(path="first.7z"))
            sched.submit(Job(path="second.7z"))
            sched.start()
            sched.enable_processing()
            try:
                self.assertTrue(done.wait(3))
            finally:
                self.assertTrue(sched.stop())
        self.assertEqual(attempts, [[None, "old", "shared"], ["shared", None, "old"]])
        self.assertEqual(book.read_text(encoding="utf-8").splitlines(), ["shared", "old"])

    def test_repeated_success_password_emits_one_promotion_event(self):
        events = []
        done = threading.Event()

        def published(event_type, *_args, **_kwargs):
            events.append(event_type)
            if events.count("job_complete") == 2:
                done.set()

        sched = self._make_scheduler(event_cb=published)

        def finish(job, **_kwargs):
            job.record_state(JobState.COMPLETE)
            return JobState.COMPLETE, "shared-password"

        with (
            mock.patch.object(sched.executor, "execute", side_effect=finish),
            mock.patch.object(sched.executor, "cleanup_job_artifacts"),
        ):
            jobs = [Job(path=f"encrypted-{index}.7z") for index in range(2)]
            for job in jobs:
                sched.submit(job)
            sched.start()
            sched.enable_processing()

            try:
                self.assertTrue(done.wait(3))
            finally:
                self.assertTrue(sched.stop())

        self.assertTrue(all(job.state == JobState.COMPLETE for job in jobs))
        self.assertEqual(events.count("password_promoted"), 1)

    def test_queued_jobs_run_smallest_first_with_stable_ties(self):
        sched = self._make_scheduler()
        paths = []
        for name, size in (
            ("large.zip", 40),
            ("small-first.zip", 5),
            ("middle.zip", 20),
            ("small-second.zip", 5),
        ):
            path = Path(self._scheduler_temp.name, name)
            path.write_bytes(b"x" * size)
            paths.append(path)

        execution_order = []

        def finish(job, **_kwargs):
            execution_order.append(Path(job.path).name)
            job.record_state(JobState.COMPLETE)
            return JobState.COMPLETE, None

        jobs = [Job(path=str(path)) for path in paths]
        with (
            mock.patch.object(sched.executor, "execute", side_effect=finish),
            mock.patch.object(sched.executor, "cleanup_job_artifacts"),
        ):
            for job in jobs:
                self.assertTrue(sched.submit(job))
            sched.start()
            sched.enable_processing()

            deadline = time.time() + 3
            while (
                any(job.state != JobState.COMPLETE for job in jobs)
                and time.time() < deadline
            ):
                time.sleep(0.01)

        self.assertTrue(all(job.state == JobState.COMPLETE for job in jobs))
        self.assertEqual(
            execution_order,
            [
                "small-first.zip",
                "small-second.zip",
                "middle.zip",
                "large.zip",
            ],
        )

    def test_processing_latch_closes_after_batch_and_requires_new_start(self):
        sched = self._make_scheduler()
        def finish(job, **_kwargs):
            job.record_state(JobState.COMPLETE)
            return JobState.COMPLETE, None

        execute = mock.Mock(side_effect=finish)
        with (
            mock.patch.object(sched.executor, "execute", execute),
            mock.patch.object(sched.executor, "cleanup_job_artifacts"),
        ):
            sched.start()
            try:
                first = Job(path="first.zip")
                sched.submit(first)
                sched.enable_processing()

                deadline = time.time() + 3
                while first.state != JobState.COMPLETE and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(first.state, JobState.COMPLETE)
                self.assertFalse(sched.processing_enabled.is_set())

                second = Job(path="second.zip")
                sched.submit(second)
                time.sleep(0.15)
                self.assertEqual(second.state, JobState.QUEUED)
                self.assertEqual(execute.call_count, 1)

                sched.enable_processing()
                deadline = time.time() + 3
                while second.state != JobState.COMPLETE and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(second.state, JobState.COMPLETE)
                self.assertEqual(execute.call_count, 2)
            finally:
                sched.stop()

    def test_empty_start_does_not_arm_a_future_batch(self):
        sched = self._make_scheduler()

        sched.enable_processing()

        self.assertFalse(sched.processing_enabled.is_set())
        queued = Job(path="queued-later.zip")
        sched.submit(queued)
        self.assertFalse(sched.processing_enabled.is_set())
        self.assertEqual(queued.state, JobState.QUEUED)

    def test_deferred_terminal_actions_close_processing_latch(self):
        sched = self._make_scheduler()
        password_job = Job(path="password.zip")
        password_job.state = JobState.PASSWORD_REQUIRED
        sched.password_pending[password_job.task_id] = password_job
        sched.processing_enabled.set()

        with mock.patch.object(sched.executor, "cleanup_job_artifacts"):
            sched.skip_password_job(password_job)

        self.assertFalse(sched.processing_enabled.is_set())

        stego_job = Job(path="stego.bin")
        stego_job.state = JobState.STEGO_CANDIDATE_REVIEW
        sched.stego_pending[stego_job.task_id] = stego_job
        sched.processing_enabled.set()

        with mock.patch.object(sched.executor, "cleanup_job_artifacts"):
            sched.submit_stego_selection(stego_job, None)

        self.assertFalse(sched.processing_enabled.is_set())

    def test_cancelling_last_selected_job_closes_processing_latch(self):
        sched = self._make_scheduler()
        queued = Job(path="cancel-me.zip")
        sched.submit(queued)
        sched.enable_processing()

        with mock.patch.object(sched.executor, "cleanup_job_artifacts"):
            cancelled = sched.cancel_jobs({queued.task_id})

        self.assertEqual(cancelled, [queued.task_id])
        self.assertEqual(queued.state, JobState.INTERRUPTED)
        self.assertFalse(sched.processing_enabled.is_set())


class TestJobRuntimeFields(unittest.TestCase):
    def test_nested_fields(self):
        j = Job(path="a.zip", nested_depth=1, ancestry=["p.zip"])
        self.assertEqual(j.nested_depth, 1)
        self.assertFalse(j.is_terminal)
        j.state = JobState.COMPLETE
        self.assertTrue(j.is_terminal)

    def test_from_task_dict_no_password(self):
        d = {"path": "a.zip", "retry_stage": 1, "nested_depth": 2}
        j = Job.from_task_dict(d)
        self.assertFalse(hasattr(j, "manual_password"))
        self.assertEqual(j.nested_depth, 2)


class TestStegoAutoSelectPolicy(unittest.TestCase):
    def test_conservative_auto_select(self):
        from executor import Executor
        from sevenzip import SevenZipRunner

        ex = Executor(SevenZipRunner("7z.exe"), dict(DEFAULT_CONFIG))
        low = ArchiveCandidate(embedded_format="zip", confidence=Confidence.LOW, start_offset=0, end_offset=10)
        self.assertIsNone(ex._auto_select_candidate([low]))
        high = ArchiveCandidate(
            embedded_format="zip", confidence=Confidence.HIGH,
            start_offset=0, end_offset=100,
            validation_flags=[
                "central_directory_valid", "comment_bounds_valid",
                "all_central_entries_valid", "all_local_headers_valid",
                "entry_count_matches", "local_header_valid",
            ],
        )
        self.assertIs(ex._auto_select_candidate([high]), high)
        high2 = ArchiveCandidate(
            embedded_format="zip", confidence=Confidence.HIGH, start_offset=10, end_offset=200,
            validation_flags=["local_header_valid"],
        )
        self.assertIsNone(ex._auto_select_candidate([high, high2]))


class TestEntryPoint(unittest.TestCase):
    def test_smart7z_bootstrap_imports(self):
        import smart7z
        self.assertTrue(hasattr(smart7z, "main"))
        src = Path(smart7z.__file__).read_text(encoding="utf-8")
        self.assertNotIn("class ExtractionWorker", src)
        self.assertNotIn("class Smart7zApp:", src)
        self.assertIn("run_app", src)

    def test_existing_instance_is_forwarded_before_qt_import(self):
        import launch_ipc
        import smart7z

        request = launch_ipc.ExternalIntakeRequest((r"C:\\input.zip",))
        with (
            mock.patch.object(launch_ipc, "parse_launch_args", return_value=request),
            mock.patch.object(
                launch_ipc,
                "_forward_launch_request",
                return_value=mock.Mock(accepted=True),
            ),
            mock.patch.dict(sys.modules, {"ui_qt": None}),
        ):
            self.assertEqual(smart7z.main(["--context-menu", r"C:\\input.zip"]), 0)

    def test_fast_ipc_import_avoids_full_runtime_and_windows_integration(self):
        source_dir = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(source_dir)
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import launch_ipc, sys; "
                    "blocked={'config','models','runtime_ipc','windows_adapters'}; "
                    "raise SystemExit(bool(blocked.intersection(sys.modules)))"
                ),
            ],
            cwd=source_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr or probe.stdout)


class TestInstallerPolicy(unittest.TestCase):
    def test_upgrade_context_menu_uses_main_executable(self):
        source = (
            Path(__file__).resolve().parents[1] / "smart7z_installer.iss"
        ).read_text(encoding="utf-8")
        self.assertIn("""UpdatedCommand := '"' + MainExecutable +""", source)
        self.assertNotIn("LauncherExecutable", source)

    def test_upgrade_and_uninstall_preserve_password_book(self):
        source = (
            Path(__file__).resolve().parents[1] / "smart7z_installer.iss"
        ).read_text(encoding="utf-8")
        self.assertIn('Excludes: "code.txt"', source)
        password_line = next(
            line
            for line in source.splitlines()
            if 'Source: "{#SourceDir}\\code.txt"' in line
        )
        self.assertIn("onlyifdoesntexist", password_line)
        self.assertIn("uninsneveruninstall", password_line)


if __name__ == "__main__":
    unittest.main()
