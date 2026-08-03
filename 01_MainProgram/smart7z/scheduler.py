"""Size-priority serial scheduler with password and candidate deferral."""

from __future__ import annotations

import logging
import os
import queue
import tempfile
import threading
from collections import OrderedDict, deque
from typing import Callable, Dict, List, Optional, Set, Tuple

from config import cleanup_policy_from_config
from models import Job, JobState, ErrorCategory, TERMINAL_STATES
from recovery import RecoveryJournal
from sevenzip import SevenZipRunner
from executor import Executor
from windows_adapters import create_owned_session, cleanup_owned_session

logger = logging.getLogger(__name__)
_STOP = object()
DEFAULT_DEFERRED_INTAKE_LIMIT = 4096


class Scheduler:
    def __init__(
        self,
        sevenzip_path: str,
        config: dict,
        event_cb: Optional[Callable] = None,
    ):
        self._lock = threading.RLock()
        self.config = dict(config)
        self.recovery_journal = RecoveryJournal(
            self.config.get("_recovery_journal_path") or None
        )
        if not self.recovery_journal.available:
            detail = self.recovery_journal.load_error or "exclusive lock unavailable"
            self.recovery_journal.close()
            raise OSError(
                "Persistent recovery state is unavailable; another Smart7z "
                f"instance may still be running: {detail}"
            )
        source_conflict_mode = str(
            self.config.get("_source_conflict_mode", "visible") or "visible"
        )
        if source_conflict_mode not in {"visible", "hidden"}:
            source_conflict_mode = "visible"
        self.recovery_messages = self.recovery_journal.recover(
            source_conflict_mode=source_conflict_mode
        )
        session_root, session_token = create_owned_session(
            self.config.get("temp_dir") or tempfile.gettempdir()
        )
        self._session_root = session_root
        self._session_roots: Dict[str, str] = {session_root: session_token}
        self._session_journal_entries: Dict[str, Optional[str]] = {
            session_root: self.recovery_journal.register_session(
                session_root, session_token, os.getpid()
            )
        }
        if self._session_journal_entries[session_root] is None:
            self.recovery_messages.append(
                "Session recovery registration failed; legacy marker cleanup remains active"
            )
        self.config["_session_root"] = session_root
        self.event_cb = event_cb or (lambda *a, **k: None)
        self.cancel_event = threading.Event()
        self.intake_paused = threading.Event()
        self._io_busy = threading.Event()  # set while 7z/transfer owns the slot
        self.processing_enabled = threading.Event()

        self.runner = SevenZipRunner(
            sevenzip_path, cancel_check=self.cancel_event.is_set
        )
        self.executor = Executor(
            self.runner,
            self.config,
            event_cb=self._on_executor_event,
            nested_submit=self.submit,
            recovery_journal=self.recovery_journal,
        )

        self.task_queue: queue.Queue = queue.Queue()
        self._deferred_intake = deque()
        self._deferred_intake_limit = max(
            1,
            int(
                self.config.get(
                    "deferred_intake_limit", DEFAULT_DEFERRED_INTAKE_LIMIT
                )
                or DEFAULT_DEFERRED_INTAKE_LIMIT
            ),
        )
        self.password_pending: "OrderedDict[str, Job]" = OrderedDict()
        self.stego_pending: "OrderedDict[str, Job]" = OrderedDict()
        # Candidate values live in the scheduler/executor handoff and are not
        # attached to the long-lived Job model.
        self._manual_passwords: Dict[str, str] = {}
        self._session_main_password: Optional[str] = None
        self._password_lock = threading.Lock()
        self.current_job: Optional[Job] = None
        self._jobs: Dict[str, Job] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._tasks_submitted = 0
        self._tasks_finished = 0
        self._queue_sequence: Dict[str, int] = {}
        self._next_queue_sequence = 0
        self._source_keys: Dict[str, str] = {}
        self._terminal_ids: Set[str] = set()
        self._cancel_requested: Set[str] = set()
        self._job_batches: Dict[str, str] = {}
        self._closed_nested_batches: Set[str] = set()

    def _on_executor_event(self, event_type, job, *args, **kwargs):
        self.event_cb(event_type, job, *args, **kwargs)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.cancel_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="Smart7zWorker", daemon=True
        )
        self._thread.start()

    def stop(self) -> bool:
        with self._lock:
            self._running = False
            self.cancel_event.set()
            self.processing_enabled.set()
        self.runner.cancel_current()
        self.cancel_remaining()
        self.processing_enabled.set()
        with self._lock:
            self.task_queue.put(_STOP)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._thread and self._thread.is_alive():
            logger.error("Scheduler worker did not stop within the shutdown timeout")
            return False
        with self._lock:
            self.current_job = None
            self._thread = None
            jobs = list(self._jobs.values())
        for job in jobs:
            self.executor.cleanup_job_artifacts(job, terminal=True)
        self.executor.retain_nested_batches(set())
        with self._password_lock:
            self._manual_passwords.clear()
            self._session_main_password = None
        self.cleanup_session_roots()
        self.recovery_journal.close()
        return True

    def enable_processing(self) -> None:
        # Start applies to the batch that already exists.  Pressing Start on
        # an empty queue must not arm a later GUI-only enqueue.
        with self._lock:
            if (
                self.current_job is not None
                or not self.task_queue.empty()
                or self._deferred_intake
            ):
                self.processing_enabled.set()

    def disable_processing(self) -> None:
        """Pause before the next queued job; the active job is untouched."""
        self.processing_enabled.clear()

    def set_session_main_password(self, password: Optional[str]) -> bool:
        normalized = password if password else None
        with self._password_lock:
            changed = self._session_main_password != normalized
            self._session_main_password = normalized
        return changed

    def refresh_config(self, config: dict) -> None:
        with self._lock:
            requested = dict(config)
            requested_base = os.path.abspath(
                requested.get("temp_dir") or tempfile.gettempdir()
            )
            current_base = os.path.dirname(self._session_root)
            if os.path.normcase(requested_base) != os.path.normcase(current_base):
                session_root, session_token = create_owned_session(requested_base)
                self._session_root = session_root
                self._session_roots[session_root] = session_token
                self._session_journal_entries[session_root] = (
                    self.recovery_journal.register_session(
                        session_root, session_token, os.getpid()
                    )
                )
            requested["_session_root"] = self._session_root
            self.config = requested
            self.executor.update_config(self.config)

    def cleanup_session_roots(self) -> bool:
        with self._lock:
            owned = list(self._session_roots.items())
        all_cleaned = True
        for path, token in owned:
            try:
                cleaned = cleanup_owned_session(path, token)
            except OSError:
                logger.exception("Owned session cleanup failed: %s", path)
                cleaned = False
            if cleaned:
                self.recovery_journal.unregister_session(path)
                with self._lock:
                    self._session_roots.pop(path, None)
                    self._session_journal_entries.pop(path, None)
            else:
                all_cleaned = False
        return all_cleaned

    def submit(self, job: Job) -> bool:
        source_key = self._job_source_key(job)
        event_after_submit: Optional[str] = None
        duplicate: Optional[Job] = None
        with self._lock:
            if not job.cleanup_policy_snapshot:
                job.cleanup_policy_snapshot = cleanup_policy_from_config(
                    self.config
                ).value
            batch_id = job.task_id
            if job.nested_depth > 0 and self.current_job is not None:
                batch_id = self._job_batches.get(
                    self.current_job.task_id, self.current_job.task_id
                )
            if job.nested_depth > 0 and batch_id in self._closed_nested_batches:
                job.record_state(JobState.INTERRUPTED)
                job.error_category = ErrorCategory.CANCELLED
                job.error_message = "Nested submission rejected after batch cancellation"
                job.source_retention_reason = "batch_cancelled"
                self._jobs[job.task_id] = job
                self._job_batches[job.task_id] = batch_id
                self._tasks_submitted += 1
                self._finish_job(job)
                event_after_submit = "job_interrupted"
            else:
                existing_id = self._source_keys.get(source_key)
                if existing_id:
                    existing = self._jobs.get(existing_id)
                    if (
                        existing is not None
                        and existing_id not in self._terminal_ids
                    ):
                        duplicate = existing
                if duplicate is None and self.intake_paused.is_set():
                    if len(self._deferred_intake) >= self._deferred_intake_limit:
                        event_after_submit = "intake_full"
                    else:
                        job.record_state(JobState.QUEUED)
                        self._jobs[job.task_id] = job
                        self._remember_queue_sequence_locked(job)
                        self._source_keys[source_key] = job.task_id
                        self._job_batches[job.task_id] = batch_id
                        self._tasks_submitted += 1
                        self._deferred_intake.append(job)
                        event_after_submit = "job_deferred"
                elif duplicate is None:
                    job.record_state(JobState.QUEUED)
                    self._jobs[job.task_id] = job
                    self._remember_queue_sequence_locked(job)
                    self._source_keys[source_key] = job.task_id
                    self._job_batches[job.task_id] = batch_id
                    self._tasks_submitted += 1
                    # Registration and publication are one scheduler
                    # transaction so cancellation cannot fall between them.
                    self.task_queue.put(job)

        if duplicate is not None:
            self.event_cb("job_duplicate", duplicate)
            return False
        if event_after_submit:
            if event_after_submit == "intake_full":
                self.event_cb(event_after_submit, job)
                return False
            self.event_cb("job_submitted", job)
            self.event_cb(event_after_submit, job)
            return event_after_submit == "job_deferred"
        self.event_cb("job_submitted", job)
        return True

    def submit_password_response(self, job: Job, password: str) -> None:
        with self._lock:
            pending = self.password_pending.pop(job.task_id, None)
            if pending is None:
                logger.warning(
                    "Ignoring password response for non-pending job %s", job.task_id
                )
                return
            target = pending
            with self._password_lock:
                self._manual_passwords[target.task_id] = password
            target.password_candidates_exhausted = False
            target.record_state(JobState.QUEUED)
            target.error_message = ""
            self.task_queue.put(target)
            # A password prompt belongs to the active batch.  Wake the worker
            # even if it cleared the idle latch while the user was typing.
            self.processing_enabled.set()
        self.event_cb("job_resubmitted", target)

    def skip_password_job(self, job: Job) -> None:
        with self._lock:
            pending = self.password_pending.pop(job.task_id, None)
        if pending is None:
            return
        pending.record_state(JobState.SKIPPED)
        pending.error_category = ErrorCategory.BAD_PASSWORD
        pending.error_message = "Skipped by user"
        pending.cleanup_eligible = False
        pending.source_retention_reason = "password_skipped"
        self.executor.cleanup_job_artifacts(pending, terminal=True)
        self._finish_job(pending)
        self.event_cb("job_skipped", pending)
        self._disable_processing_when_idle()

    def submit_stego_selection(
        self, job: Job, candidate_index: Optional[int]
    ) -> None:
        with self._lock:
            pending = self.stego_pending.pop(job.task_id, None)
            if pending is None:
                logger.warning(
                    "Ignoring candidate response for non-pending job %s", job.task_id
                )
                return
            target = pending
        if candidate_index is None:
            target.record_state(JobState.SKIPPED)
            target.error_message = "Stego candidate skipped"
            self.executor.cleanup_job_artifacts(target, terminal=True)
            self._finish_job(target)
            self.event_cb("job_skipped", target)
            self._disable_processing_when_idle()
            return
        if 0 <= candidate_index < len(target.stego_candidates):
            with self._lock:
                if target.task_id in self._terminal_ids:
                    return
                target.selected_candidate = target.stego_candidates[candidate_index]
                target.stego_selection_pending = True
                target.record_state(JobState.QUEUED)
                target.error_message = ""
                self.task_queue.put(target)
                self.processing_enabled.set()
            self.event_cb("job_resubmitted", target)
        else:
            target.record_state(JobState.FAILED)
            target.error_message = "Invalid candidate index"
            self._finish_job(target)
            self.event_cb("job_failed", target)
            self._disable_processing_when_idle()

    def cancel_current(self) -> None:
        with self._lock:
            current = self.current_job
            if current is not None:
                self.cancel_event.set()
        if current is not None:
            self.runner.cancel_current()

    def cancel_jobs(self, task_ids: Set[str]) -> List[str]:
        """Cancel selected queued/deferred jobs as one scheduler transaction."""
        if not task_ids:
            return []
        with self._lock:
            current_id = self.current_job.task_id if self.current_job else None
            selected = {
                task_id
                for task_id in task_ids
                if task_id != current_id and task_id not in self._terminal_ids
            }
            self._cancel_requested.update(selected)
            self._drain_queue_locked(selected)
            self._drain_deferred_locked(selected)
            for pending in (self.password_pending, self.stego_pending):
                for task_id in selected:
                    pending.pop(task_id, None)
            cancelled = self._mark_interrupted_locked(
                selected, "Cancelled (selected)"
            )
        for job in cancelled:
            self.executor.cleanup_job_artifacts(job, terminal=True)
            self.event_cb("job_interrupted", job)
        self._disable_processing_when_idle()
        return [job.task_id for job in cancelled]

    def cancel_remaining(self) -> None:
        """Cancel every non-current job visible at one linearization point."""
        with self._lock:
            current_id = self.current_job.task_id if self.current_job else None
            if current_id is not None:
                batch_id = self._job_batches.get(current_id, current_id)
                self._closed_nested_batches.add(batch_id)
            selected = {
                task_id
                for task_id in self._jobs
                if task_id != current_id and task_id not in self._terminal_ids
            }
            self._cancel_requested.update(selected)
            self._drain_queue_locked(selected)
            self._drain_deferred_locked(selected)
            self.password_pending.clear()
            self.stego_pending.clear()
            cancelled = self._mark_interrupted_locked(
                selected, "Cancelled (remaining)"
            )
            # Cancellation closes this batch.  A later explicit submission can
            # queue for a future Start, while descendants of the current batch
            # remain rejected.
            self.processing_enabled.clear()
        for job in cancelled:
            self.executor.cleanup_job_artifacts(job, terminal=True)
            self.event_cb("job_interrupted", job)

    def clear_finished(self, task_ids: Optional[Set[str]] = None) -> List[str]:
        removed = []
        with self._lock:
            current_id = self.current_job.task_id if self.current_job else None
            eligible = set(self._terminal_ids)
            if task_ids is not None:
                eligible.intersection_update(task_ids)
            if current_id is not None:
                eligible.discard(current_id)
            for tid in eligible:
                if tid not in self._jobs:
                    continue
                removed.append(tid)
                del self._jobs[tid]
                self._queue_sequence.pop(tid, None)
                self._terminal_ids.discard(tid)
                self._cancel_requested.discard(tid)
                self._job_batches.pop(tid, None)
                for source_key, owner_id in list(self._source_keys.items()):
                    if owner_id == tid:
                        del self._source_keys[source_key]
            active_batches = {
                batch_id
                for task_id, batch_id in self._job_batches.items()
                if task_id not in self._terminal_ids
            }
            self._closed_nested_batches.intersection_update(active_batches)
        self.executor.retain_nested_batches(active_batches)
        return removed

    def is_lifecycle_finished(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._terminal_ids

    def has_job(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._jobs

    def _drain_queue_locked(self, task_ids: Set[str]) -> None:
        retained: List[object] = []
        while True:
            try:
                item = self.task_queue.get_nowait()
            except queue.Empty:
                break
            self.task_queue.task_done()
            if item is _STOP or item.task_id not in task_ids:
                retained.append(item)
        for item in retained:
            self.task_queue.put(item)

    def _drain_deferred_locked(self, task_ids: Set[str]) -> None:
        self._deferred_intake = deque(
            job for job in self._deferred_intake if job.task_id not in task_ids
        )

    def _mark_interrupted_locked(
        self, task_ids: Set[str], message: str
    ) -> List[Job]:
        cancelled: List[Job] = []
        for task_id in task_ids:
            job = self._jobs.get(task_id)
            if job is None or task_id in self._terminal_ids:
                continue
            job.record_state(JobState.INTERRUPTED)
            job.error_category = ErrorCategory.CANCELLED
            job.error_message = message
            job.cleanup_eligible = False
            job.source_retention_reason = "interrupted"
            self._finish_job(job)
            cancelled.append(job)
        return cancelled

    def pause_intake(self) -> None:
        self.intake_paused.set()

    def resume_intake(self) -> int:
        released: List[Job] = []
        with self._lock:
            self.intake_paused.clear()
            while self._deferred_intake:
                job = self._deferred_intake.popleft()
                if (
                    job.task_id in self._terminal_ids
                    or job.task_id in self._cancel_requested
                ):
                    continue
                self.task_queue.put(job)
                released.append(job)
        return len(released)

    def is_io_busy(self) -> bool:
        return self._io_busy.is_set()

    def queue_size(self) -> int:
        with self._lock:
            return self.task_queue.qsize() + len(self._deferred_intake)

    def deferred_intake_size(self) -> int:
        with self._lock:
            return len(self._deferred_intake)

    def stats(self) -> dict:
        with self._lock:
            return {
                "submitted": self._tasks_submitted,
                "finished": self._tasks_finished,
                "queued": self.task_queue.qsize(),
                "deferred_intake": len(self._deferred_intake),
                "password_pending": len(self.password_pending),
                "stego_pending": len(self.stego_pending),
                "current": self.current_job.task_id if self.current_job else None,
            }

    def _run(self) -> None:
        while True:
            while self._running and not self.processing_enabled.wait(timeout=0.2):
                continue
            try:
                job = self._take_next_queued_item(timeout=0.5)
            except queue.Empty:
                self._disable_processing_when_idle()
                continue

            if job is _STOP:
                self.task_queue.task_done()
                break

            newly_interrupted = False
            with self._lock:
                if job.task_id in self._terminal_ids:
                    should_execute = False
                    self._cancel_requested.discard(job.task_id)
                elif not self._running or job.task_id in self._cancel_requested:
                    should_execute = False
                    job.record_state(JobState.INTERRUPTED)
                    job.error_category = ErrorCategory.CANCELLED
                    job.error_message = (
                        "Scheduler stopped"
                        if not self._running
                        else "Cancelled before execution"
                    )
                    job.source_retention_reason = (
                        "scheduler_stopped"
                        if not self._running
                        else "interrupted"
                    )
                    self._finish_job(job)
                    newly_interrupted = True
                else:
                    # Cancellation initialization and current-job publication
                    # are atomic with cancel_current/cancel_remaining.
                    self.cancel_event.clear()
                    self.current_job = job
                    should_execute = True

            if not should_execute:
                if newly_interrupted:
                    self.executor.cleanup_job_artifacts(job, terminal=True)
                    self.event_cb("job_interrupted", job)
                self.task_queue.task_done()
                self._disable_processing_when_idle()
                continue

            self._io_busy.set()
            manual_password, main_password = self._password_inputs_for(job)
            try:
                final_state, promoted_password = self.executor.execute(
                    job,
                    manual_password=manual_password,
                    session_main_password=main_password,
                )
                if promoted_password:
                    if self.set_session_main_password(promoted_password):
                        self.event_cb("password_promoted", job)
            except Exception:
                logger.exception("Unhandled executor failure")
                final_state = JobState.FAILED
                job.record_state(JobState.FAILED)
                job.error_category = ErrorCategory.INTERNAL_ERROR
            finally:
                manual_password = None
                main_password = None
                self._io_busy.clear()

            if final_state == JobState.PASSWORD_REQUIRED:
                job.record_state(JobState.PASSWORD_REQUIRED)
                with self._lock:
                    self.password_pending[job.task_id] = job
                self.event_cb("password_required", job)

            elif final_state == JobState.STEGO_CANDIDATE_REVIEW:
                job.record_state(JobState.STEGO_CANDIDATE_REVIEW)
                with self._lock:
                    self.stego_pending[job.task_id] = job
                self.event_cb("stego_review_required", job)

            elif final_state == JobState.INTERRUPTED:
                job.record_state(JobState.INTERRUPTED)
                self.executor.cleanup_job_artifacts(job, terminal=True)
                self._finish_job(job)
                self.event_cb("job_interrupted", job)

            elif final_state == JobState.COMPLETE:
                self.executor.cleanup_job_artifacts(job, terminal=True)
                self._finish_job(job)
                self.event_cb("job_complete", job)

            elif final_state == JobState.PARTIAL_RECOVERY:
                self.executor.cleanup_job_artifacts(job, terminal=True)
                self._finish_job(job)
                self.event_cb("job_partial", job)

            elif final_state == JobState.SKIPPED:
                self.executor.cleanup_job_artifacts(job, terminal=True)
                self._finish_job(job)
                self.event_cb("job_skipped", job)

            else:
                job.record_state(
                    final_state if final_state in TERMINAL_STATES else JobState.FAILED
                )
                self.executor.cleanup_job_artifacts(job, terminal=True)
                self._finish_job(job)
                self.event_cb("job_failed", job)

            with self._lock:
                if self.current_job is job:
                    self.current_job = None
            self.task_queue.task_done()
            self._disable_processing_when_idle()

    def _take_next_queued_item(self, timeout: float):
        """Take the smallest queued archive without changing active work."""

        first = self.task_queue.get(timeout=timeout)
        with self._lock:
            available = [first]
            while True:
                try:
                    available.append(self.task_queue.get_nowait())
                except queue.Empty:
                    break

            selected_index = min(
                range(len(available)),
                key=lambda index: self._queue_item_priority(
                    available[index]
                ),
            )
            selected = available[selected_index]
            for index, item in enumerate(available):
                if index == selected_index:
                    continue
                self.task_queue.task_done()
                self.task_queue.put(item)
            return selected

    def _queue_item_priority(self, item) -> Tuple[int, int, int]:
        if item is _STOP:
            return (2, 0, 0)
        interactive_resume = bool(
            item.attempt_count > 0 or item.stego_selection_pending
        )
        return (
            0 if interactive_resume else 1,
            self._job_size_bytes(item),
            self._queue_sequence.get(item.task_id, 0),
        )

    def _remember_queue_sequence_locked(self, job: Job) -> None:
        if job.task_id in self._queue_sequence:
            return
        self._queue_sequence[job.task_id] = self._next_queue_sequence
        self._next_queue_sequence += 1

    @staticmethod
    def _job_size_bytes(job: Job) -> int:
        volumes = (
            list(job.archive_set.volumes)
            if job.archive_set and job.archive_set.volumes
            else [job.original_path or job.path]
        )
        total = 0
        try:
            for path in volumes:
                total += max(0, int(os.path.getsize(path)))
        except OSError:
            return (1 << 63) - 1
        return total

    def _disable_processing_when_idle(self) -> None:
        """Close the per-batch processing latch once no work can resume it."""

        with self._lock:
            if self.current_job is not None:
                return
            if self.password_pending or self.stego_pending:
                return
            if self._deferred_intake:
                return
            if not self.task_queue.empty():
                return
            self.processing_enabled.clear()

    def _password_inputs_for(self, job: Job) -> Tuple[Optional[str], Optional[str]]:
        with self._password_lock:
            return (
                self._manual_passwords.pop(job.task_id, None),
                self._session_main_password,
            )

    def _finish_job(self, job: Job) -> None:
        newly_finished = False
        with self._lock:
            with self._password_lock:
                self._manual_passwords.pop(job.task_id, None)
            if job.task_id not in self._terminal_ids:
                self._terminal_ids.add(job.task_id)
                self._tasks_finished += 1
                newly_finished = True
            active_batches = {
                batch_id
                for task_id, batch_id in self._job_batches.items()
                if task_id not in self._terminal_ids
            }
            self._closed_nested_batches.intersection_update(active_batches)
        if newly_finished:
            self.executor.retain_nested_batches(active_batches)

    @staticmethod
    def _canonical_path(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    def _job_source_key(self, job: Job) -> str:
        try:
            from discovery import logical_archive_key

            return logical_archive_key(job.path)
        except (OSError, ValueError):
            return self._canonical_path(job.path)
