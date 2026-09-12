"""Real archive workflows and deterministic scheduler race regressions.

Only disposable fixtures are used. Observer wrappers call the original methods;
barriers delay real work without inventing executor results or child jobs.
"""

import hashlib
import io
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DEFAULT_CONFIG, find_sevenzip
from models import Job, JobState
from scheduler import Scheduler
from sevenzip import SevenZipRunner
from stego_candidates import is_exact_high_confidence_candidate


WAIT_SECONDS = 20


class TestWorkflowRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sevenzip_path = find_sevenzip(DEFAULT_CONFIG)
        if not cls.sevenzip_path:
            raise RuntimeError("Workflow verification requires a real 7-Zip executable")

    def setUp(self):
        self.maxDiff = 1000
        self.temp = tempfile.TemporaryDirectory(prefix="smart7z-workflow-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.events = []
        self.events_lock = threading.Lock()
        self.stopped_schedulers = set()
        self.config = {
            **DEFAULT_CONFIG,
            "7z_path": self.sevenzip_path,
            "temp_dir": str(self.root / "staging"),
            "target_dir": str(self.root / "output"),
            "password_file": str(self.root / "code.txt"),
            "_recovery_journal_path": str(self.root / "recovery.json"),
            "extract_to_source": False,
            "cleanup_policy": "keep",
            "wait_disk_space": False,
            "nested_extraction": False,
            "deep_scan": False,
        }

    def _scheduler(self, **overrides):
        scheduler = Scheduler(
            self.sevenzip_path,
            {**self.config, **overrides},
            event_cb=self._record_event,
        )
        self.addCleanup(self._stop_scheduler, scheduler)
        return scheduler

    def _stop_scheduler(self, scheduler):
        if scheduler in self.stopped_schedulers:
            return
        self.assertTrue(scheduler.stop(), "Scheduler worker failed to stop")
        self.stopped_schedulers.add(scheduler)

    def _record_event(self, kind, job, *args, **kwargs):
        # Store no mutable Job objects, diagnostics, or password-bearing arguments.
        with self.events_lock:
            self.events.append((kind, job.task_id))

    def _event_snapshot(self):
        with self.events_lock:
            return list(self.events)

    def _wait(self, predicate, message):
        deadline = time.monotonic() + WAIT_SECONDS
        pause = threading.Event()
        while time.monotonic() < deadline:
            if predicate():
                return
            pause.wait(0.01)
        self.fail(message)

    def _wait_idle(self, scheduler):
        self._wait(
            lambda: scheduler.stats()["current"] is None
            and scheduler.queue_size() == 0
            and not scheduler.processing_enabled.is_set(),
            "Scheduler did not finish publishing and become idle",
        )

    @staticmethod
    def _zip_bytes(name, payload):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(name, payload)
        return stream.getvalue()

    def _assert_payload(self, path, expected):
        self.assertTrue(Path(path).is_file(), "Committed payload is missing")
        self.assertEqual(
            hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            hashlib.sha256(expected).hexdigest(),
            "Committed payload differs from its isolated fixture",
        )

    def _assert_complete(self, job, expected):
        self.assertEqual(job.state, JobState.COMPLETE)
        self.assertTrue(job.commit_verified)
        self.assertTrue(job.commit_records)
        self.assertTrue(all(record.verified for record in job.commit_records))
        files = [record for record in job.commit_records if record.expected_size >= 0]
        self.assertEqual(len(files), 1, "Fixture must commit exactly one payload file")
        self._assert_payload(files[0].destination, expected)
        self.assertTrue(Path(job.original_path or job.path).exists())

    def _cleanup_policy_workflow(self, original, updated, *, active, explicit=False):
        payload = b"cleanup policy fixture\n"
        source = self.root / "original.zip"
        later_source = self.root / "later.zip"
        source.write_bytes(self._zip_bytes("original.txt", payload))
        later_source.write_bytes(self._zip_bytes("later.txt", payload))
        scheduler = self._scheduler(cleanup_policy=updated if explicit else original)
        job = Job(path=str(source), cleanup_policy_snapshot=original if explicit else "")
        later = Job(path=str(later_source))
        extracting = threading.Event()
        release = threading.Event()
        real_extract = scheduler.runner.extract

        def gated_extract(*args, **kwargs):
            if scheduler.current_job is job:
                extracting.set()
                if not release.wait(WAIT_SECONDS):
                    raise TimeoutError("Cleanup policy regression gate timed out")
            return real_extract(*args, **kwargs)

        with mock.patch.object(scheduler.runner, "extract", new=gated_extract):
            try:
                self.assertTrue(scheduler.submit(job))
                if active:
                    scheduler.start()
                    scheduler.enable_processing()
                    self.assertTrue(extracting.wait(WAIT_SECONDS))
                    self.assertEqual(job.state, JobState.EXTRACTING)
                scheduler.refresh_config(
                    {
                        **scheduler.config,
                        "cleanup_policy": updated,
                        "nested_extraction": True,
                    }
                )
                self.assertTrue(scheduler.submit(later))
                release.set()
                if not active:
                    scheduler.start()
                scheduler.enable_processing()
                self._wait_idle(scheduler)
            finally:
                release.set()
                self._stop_scheduler(scheduler)

        for item, archive, expected_policy in (
            (job, source, original),
            (later, later_source, updated),
        ):
            with self.subTest(policy=expected_policy, path=archive.name):
                self.assertEqual(item.state, JobState.COMPLETE)
                self.assertTrue(item.commit_verified)
                files = [record for record in item.commit_records if record.expected_size >= 0]
                self.assertEqual(len(files), 1)
                self.assertTrue(files[0].verified)
                self._assert_payload(files[0].destination, payload)
                self.assertEqual(archive.exists(), expected_policy == "keep")
                self.assertEqual(item.cleanup_policy_snapshot, expected_policy)

    def test_queued_keep_survives_switch_to_permanent(self):
        self._cleanup_policy_workflow("keep", "permanent", active=False)

    def test_queued_permanent_survives_switch_to_keep(self):
        self._cleanup_policy_workflow("permanent", "keep", active=False)

    def test_active_keep_survives_switch_to_permanent(self):
        self._cleanup_policy_workflow("keep", "permanent", active=True)

    def test_active_permanent_survives_switch_to_keep(self):
        self._cleanup_policy_workflow("permanent", "keep", active=True)

    def test_queued_explicit_keep_survives_unrelated_config_change(self):
        self._cleanup_policy_workflow("keep", "permanent", active=False, explicit=True)

    def test_active_explicit_keep_survives_unrelated_config_change(self):
        self._cleanup_policy_workflow("keep", "permanent", active=True, explicit=True)

    def _independent_archive_with_neighbor(self, selected_name, neighbor_name, *, text_neighbor=False):
        payload = b"selected independent archive\n"
        selected = self.root / selected_name
        neighbor = self.root / neighbor_name
        selected.write_bytes(self._zip_bytes("selected.txt", payload))
        neighbor_bytes = (
            b"unrelated sidecar\n" if text_neighbor else
            self._zip_bytes("unselected.txt", b"unselected archive\n")
        )
        neighbor.write_bytes(neighbor_bytes)
        scheduler = self._scheduler(cleanup_policy="permanent")
        job = Job(path=str(selected))
        self.assertTrue(scheduler.submit(job))
        scheduler.start()
        scheduler.enable_processing()
        self._wait_idle(scheduler)
        self._stop_scheduler(scheduler)
        self.assertEqual(job.state, JobState.COMPLETE, job.error_message)
        self.assertTrue(job.commit_verified)
        files = [record for record in job.commit_records if record.expected_size >= 0]
        self.assertEqual(len(files), 1)
        self._assert_payload(files[0].destination, payload)
        self.assertFalse(selected.exists())
        self.assertEqual(neighbor.read_bytes(), neighbor_bytes)
        self.assertEqual(job.archive_set.volumes, [str(selected)])

    def test_selected_independent_z01_does_not_extract_or_delete_same_named_zip(self):
        self._independent_archive_with_neighbor("book.z01", "book.zip")

    def test_selected_zip_does_not_delete_same_named_independent_z01(self):
        self._independent_archive_with_neighbor("book.zip", "book.z01")

    def test_selected_zip_does_not_delete_unrelated_z01_text(self):
        self._independent_archive_with_neighbor("book.zip", "book.z01", text_neighbor=True)

    def test_real_split_zip_preserves_grouping_and_cleans_verified_volumes(self):
        from archive_classifier import has_independent_archive_structure
        from discovery import detect_archive_set, is_multipart_child

        payload = b"split ZIP payload\n" * 128
        archive = self._zip_bytes("split.txt", payload)
        end = len(archive) - 22
        central_start = struct.unpack_from("<L", archive, end + 16)[0]
        tail = bytearray(archive[central_start:])
        # Standard split ZIP: local data on disk 0, central directory on disk 1.
        struct.pack_into("<L", tail, 42, 4)
        end -= central_start
        struct.pack_into("<HH", tail, end + 4, 1, 1)
        struct.pack_into("<L", tail, end + 16, 0)
        first = self.root / "split.z01"
        main = self.root / "split.zip"
        first.write_bytes(b"PK\x07\x08" + archive[:central_start])
        main.write_bytes(tail)
        self.assertFalse(has_independent_archive_structure(str(first)))
        self.assertFalse(has_independent_archive_structure(str(main)))
        self.assertTrue(is_multipart_child(str(first)))
        self.assertEqual(detect_archive_set(str(first)).main_path, str(main))
        scheduler = self._scheduler(cleanup_policy="permanent")
        scheduler.start()
        job = Job(path=str(first), explicit_input=True, cleanup_policy_snapshot="permanent")
        self.assertTrue(scheduler.submit(job))
        scheduler.enable_processing()
        self._wait_idle(scheduler)
        self.assertEqual(job.state, JobState.COMPLETE, job.error_message)
        self.assertEqual(len(job.archive_set.volumes), 2)
        files = [record for record in job.commit_records if record.expected_size >= 0]
        self.assertEqual(len(files), 1)
        self._assert_payload(files[0].destination, payload)
        self.assertFalse(first.exists())
        self.assertFalse(main.exists())

    def _retained_commit_workflow(self, error, expected_state):
        payload = b"recoverable output after publication failure\n"
        archive = self.root / "retained.zip"
        archive.write_bytes(self._zip_bytes("retained.txt", payload))
        scheduler = self._scheduler(cleanup_policy="permanent")
        job = Job(path=str(archive))
        with (
            mock.patch.object(scheduler.executor, "_publish_stage_resilient", side_effect=error),
            mock.patch.object(scheduler.executor, "_recover_commit_stage", return_value=None),
        ):
            self.assertTrue(scheduler.submit(job))
            scheduler.start()
            scheduler.enable_processing()
            self._wait_idle(scheduler)
            self._stop_scheduler(scheduler)
        self.assertEqual(job.state, expected_state)
        self.assertTrue(archive.exists())
        self.assertIsNone(job.temp_root)
        self.assertTrue(job.final_destination)
        retained = Path(job.final_destination, "retained.txt")
        self._assert_payload(retained, payload)
        restarted = self._scheduler()
        self.assertTrue(restarted.recovery_messages)
        self._assert_payload(retained, payload)
        self._stop_scheduler(restarted)
        self._assert_payload(retained, payload)

    def test_failed_commit_stage_survives_terminal_cleanup_and_next_start(self):
        self._retained_commit_workflow(OSError("fixture publication blocked"), JobState.FAILED)

    def test_cancelled_commit_stage_survives_terminal_cleanup_and_next_start(self):
        self._retained_commit_workflow(InterruptedError("fixture cancellation"), JobState.INTERRUPTED)

    def _password_workflow(self, archive_format):
        shared = "fixture-only-shared"
        wrong = "fixture-only-wrong"
        payload = b"same-batch isolated payload\n"
        source = self.root / "payload.txt"
        source.write_bytes(payload)
        first_path = self.root / ("first." + archive_format)
        switches = ["-mhe=on"] if archive_format == "7z" else ["-mem=AES256"]
        result = SevenZipRunner(self.sevenzip_path).raw(
            [
                "a", "-t" + archive_format, "-mx=0", "-y",
                "-p" + shared, *switches, str(first_path), str(source),
            ],
            timeout=WAIT_SECONDS,
        )
        self.assertEqual(result.return_code, 0, "Encrypted fixture creation failed")
        second_path = self.root / ("second." + archive_format)
        second_path.write_bytes(first_path.read_bytes())
        book = Path(self.config["password_file"])
        book.write_text(wrong + "\n" + shared + "\n", encoding="utf-8")
        scheduler = self._scheduler()
        first, second = Job(path=str(first_path)), Job(path=str(second_path))
        attempts = []
        book_ready_for_second = []
        real_list = scheduler.runner.list_with_fallback
        real_extract = scheduler.runner.extract

        def password_label(password):
            if password is None:
                return "none"
            return "working" if password == shared else "wrong"

        def observe_list(path, *args, **kwargs):
            attempts.append(("list", Path(path).name, password_label(kwargs.get("password"))))
            if Path(path) == second_path:
                book_ready_for_second.append(
                    book.read_text(encoding="utf-8").splitlines() == [shared, wrong]
                )
            return real_list(path, *args, **kwargs)

        def observe_extract(path, *args, **kwargs):
            attempts.append(("extract", Path(path).name, password_label(kwargs.get("password"))))
            return real_extract(path, *args, **kwargs)

        # new= installs plain observers, so Mock does not retain plaintext call args.
        with (
            mock.patch.object(scheduler.runner, "list_with_fallback", new=observe_list),
            mock.patch.object(scheduler.runner, "extract", new=observe_extract),
        ):
            try:
                self.assertTrue(scheduler.submit(first))
                self.assertTrue(scheduler.submit(second))
                scheduler.start()
                scheduler.enable_processing()
                self._wait_idle(scheduler)
            finally:
                self._stop_scheduler(scheduler)

        self._assert_complete(first, payload)
        self._assert_complete(second, payload)
        expected_first = (
            [("list", "none"), ("list", "wrong"), ("list", "working"), ("extract", "working")]
            if archive_format == "7z"
            else [("list", "none"), ("extract", "wrong"), ("extract", "working")]
        )
        self.assertEqual(
            [(action, label) for action, name, label in attempts if name == first_path.name],
            expected_first,
        )
        self.assertEqual(
            [(action, label) for action, name, label in attempts if name == second_path.name],
            [("list", "working"), ("extract", "working")],
        )
        self.assertEqual(
            [name for action, name, _label in attempts if action == "extract"],
            [first_path.name] * (1 if archive_format == "7z" else 2) + [second_path.name],
        )
        self.assertTrue(
            book.read_text(encoding="utf-8").splitlines() == [shared, wrong],
            "Password book was not reordered and deduplicated correctly",
        )
        self.assertEqual(book_ready_for_second, [True])
        kinds = [kind for kind, _task_id in self._event_snapshot()]
        self.assertEqual(kinds.count("password_promoted"), 1)
        self.assertEqual(kinds.count("job_complete"), 2)
        self.assertNotIn("password_required", kinds)
        self.assertEqual(second.phase_metrics.listing_attempts, 1)
        self.assertEqual(second.phase_metrics.extraction_attempts, 1)

    def test_header_encrypted_7z_promotes_password_before_next_queued_job(self):
        self._password_workflow("7z")

    def test_payload_encrypted_zip_promotes_password_before_next_queued_job(self):
        self._password_workflow("zip")

    def _nested_workflow(self, discard_mode=None):
        payload = b"nested isolated payload\n"
        inner_bytes = self._zip_bytes("inside.txt", payload)
        outer = self.root / "outer.zip"
        outer.write_bytes(self._zip_bytes("inner.zip", inner_bytes))
        scheduler = self._scheduler(nested_extraction=True)
        parent = Job(path=str(outer))
        reached_submit = threading.Event()
        release_submit = threading.Event()
        self.addCleanup(release_submit.set)
        children = []
        accepted = []
        gate_timeouts = []
        real_submit = scheduler.executor.nested_submit

        def delayed_submit(child):
            children.append(child)
            reached_submit.set()
            if not release_submit.wait(WAIT_SECONDS):
                gate_timeouts.append(True)
                return False
            result = real_submit(child)
            accepted.append(result)
            return result

        with mock.patch.object(scheduler.executor, "nested_submit", new=delayed_submit):
            try:
                self.assertTrue(scheduler.submit(parent))
                scheduler.start()
                scheduler.enable_processing()
                self.assertTrue(reached_submit.wait(WAIT_SECONDS), "Real nested scan did not submit")
                self.assertTrue(parent.commit_verified)
                self.assertEqual(scheduler.stats()["current"], parent.task_id)
                if discard_mode == "selected":
                    self.assertEqual(scheduler.discard_jobs({parent.task_id}), [parent.task_id])
                elif discard_mode == "remaining":
                    self.assertEqual(scheduler.discard_remaining(), [])
                release_submit.set()
                self._wait_idle(scheduler)
                # Capture live invariants before stop() can prune batch state.
                live_stats = scheduler.stats()
                live_closed_batches = set(scheduler._closed_nested_batches)
                live_discarded_batches = set(scheduler._discarded_nested_batches)
            finally:
                release_submit.set()
                self._stop_scheduler(scheduler)

        self.assertFalse(gate_timeouts, "Nested barrier timed out")
        self.assertEqual(len(children), 1, "Fixture must generate exactly one real child")
        child = children[0]
        self.assertEqual(child.nested_depth, 1)
        self.assertEqual(child.nested_budget_id, parent.task_id)
        self.assertTrue(Path(child.path).exists(), "Committed inner archive was deleted")
        self.assertTrue(outer.exists())
        self.assertFalse(scheduler.password_pending)
        self.assertFalse(scheduler.stego_pending)
        events = self._event_snapshot()
        if discard_mode is None:
            self.assertEqual(accepted, [True])
            self._assert_complete(child, payload)
            self.assertIn(("job_complete", child.task_id), events)
        else:
            self.assertEqual(accepted, [False])
            self.assertFalse(scheduler.has_job(child.task_id))
            self.assertFalse(scheduler.is_lifecycle_finished(child.task_id))
            self.assertFalse(any(task_id == child.task_id for _kind, task_id in events))
            self.assertFalse(child.final_destination)
            self.assertFalse(list(Path(self.config["target_dir"]).rglob("inside.txt")))
            self.assertEqual(live_stats["submitted"], 1)
            self.assertEqual(live_stats["finished"], 0 if discard_mode == "selected" else 1)
            self.assertEqual(scheduler.has_job(parent.task_id), discard_mode == "remaining")
            if discard_mode == "selected":
                for kind in ("job_complete", "job_interrupted", "password_required", "stego_review_required"):
                    self.assertNotIn((kind, parent.task_id), events)
            else:
                self.assertIn(("job_complete", parent.task_id), events)
        self.assertFalse(live_closed_batches)
        self.assertFalse(live_discarded_batches)

    def test_nested_fixture_really_extracts_child_without_discard(self):
        self._nested_workflow()

    def test_discard_active_parent_rejects_real_child_already_at_submit_boundary(self):
        self._nested_workflow("selected")

    def test_discard_remaining_closes_nested_batch_but_keeps_current_parent(self):
        self._nested_workflow("remaining")

    def test_discard_after_dequeue_before_current_publication_does_not_resurrect(self):
        archive = self.root / "queued.zip"
        payload = b"explicit resubmission remains usable\n"
        archive.write_bytes(self._zip_bytes("queued.txt", payload))
        scheduler = self._scheduler()
        removed = Job(path=str(archive))
        dequeued = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        gate_timeouts = []
        real_take = scheduler._take_next_queued_item

        def delayed_take(timeout):
            item = real_take(timeout)
            if item is removed:
                dequeued.set()
                if not release.wait(WAIT_SECONDS):
                    gate_timeouts.append(True)
            return item

        with mock.patch.object(scheduler, "_take_next_queued_item", new=delayed_take):
            try:
                self.assertTrue(scheduler.submit(removed))
                scheduler.start()
                scheduler.enable_processing()
                self.assertTrue(dequeued.wait(WAIT_SECONDS), "Worker did not dequeue fixture")
                self.assertIsNone(scheduler.stats()["current"])
                self.assertEqual(scheduler.discard_jobs({removed.task_id}), [removed.task_id])
                release.set()
                # Processing is already cleared by discard; a new public submission
                # is a completion fence and also proves the source key was released.
                replacement = Job(path=str(archive))
                self.assertTrue(scheduler.submit(replacement))
                scheduler.enable_processing()
                self._wait_idle(scheduler)
            finally:
                release.set()
                self._stop_scheduler(scheduler)

        self.assertFalse(gate_timeouts, "Dequeue barrier timed out")
        self.assertFalse(scheduler.has_job(removed.task_id))
        self.assertEqual(removed.state, JobState.QUEUED)
        self.assertEqual(removed.phase_metrics.listing_attempts, 0)
        self.assertEqual(removed.phase_metrics.extraction_attempts, 0)
        self.assertEqual(
            [kind for kind, task_id in self._event_snapshot() if task_id == removed.task_id],
            ["job_submitted"],
        )
        self._assert_complete(replacement, payload)

    def test_real_exact_zip_ignores_signature_noise_and_carves_exact_bytes(self):
        archive_bytes = self._zip_bytes("clean.txt", b"real candidate payload\n")
        host = self.root / "single.bin"
        prefix = b"isolated host prefix\n" * 4
        host.write_bytes(prefix + archive_bytes + b"Rar!\x1a\x07\x00" + b"tail" * 30)
        scheduler = self._scheduler()
        job = Job(path=str(host), explicit_input=True)
        self.addCleanup(scheduler.executor.cleanup_job_artifacts, job)

        self.assertIsNone(scheduler.executor._prepare_stego_candidate(job))

        self.assertEqual(job.stego_triage_decision, "DEFAULT_AUTO")
        self.assertEqual(len(job.stego_candidates), 1)
        self.assertTrue(job.stego_ignored_candidates, "Fixture did not produce competing noise")
        self.assertIsNotNone(job.selected_candidate)
        self.assertEqual(job.selected_candidate.start_offset, len(prefix))
        self.assertEqual(job.selected_candidate.end_offset, len(prefix) + len(archive_bytes))
        self._assert_payload(job.temp_zip, archive_bytes)
        self.assertTrue(host.exists())

    def test_real_nested_zip_ranges_remain_competitors_not_duplicates(self):
        inner = self._zip_bytes("inner.txt", b"inner candidate\n")
        outer = self._zip_bytes("inner.zip", inner)
        host = self.root / "nested-candidates.bin"
        host.write_bytes(b"isolated prefix\n" * 4 + outer + b"isolated tail\n")
        scheduler = self._scheduler()
        job = Job(path=str(host), explicit_input=True)
        self.addCleanup(scheduler.executor.cleanup_job_artifacts, job)

        # The warning-only path must not auto-carve by dropping a competitor.
        self.assertIsNone(scheduler.executor._prepare_stego_candidate(job, exact_only=True))
        self.assertIsNone(job.temp_zip)
        self.assertEqual(job.stego_triage_decision, "REVIEW")
        self.assertEqual(
            scheduler.executor._prepare_stego_candidate(job),
            JobState.STEGO_CANDIDATE_REVIEW,
        )
        ranges = sorted((item.start_offset, item.end_offset) for item in job.stego_candidates)
        self.assertEqual(len(ranges), 2, "Both real archive ranges must survive triage")
        self.assertTrue(all(is_exact_high_confidence_candidate(item) for item in job.stego_candidates))
        self.assertLess(ranges[0][0], ranges[1][0])
        self.assertGreater(ranges[0][1], ranges[1][1])
        self.assertIsNone(job.stego_recommended_index)
        self.assertIsNone(job.selected_candidate)
        self.assertIsNone(job.temp_zip)
        self.assertFalse(list(self.root.rglob("carve_*")))
        self.assertTrue(host.exists())


if __name__ == "__main__":
    unittest.main()
