"""Deterministic Smart7z job executor.

The executor owns one job lifecycle at a time. Password candidates are plain
transient inputs, verified output is committed transactionally, and sources
are cleaned only after a clean commit.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import windows_adapters
from config import cleanup_policy_from_config, get_password_file_path
from discovery import detect_archive_set
from models import (
    ArchiveCandidate,
    ArchiveManifest,
    ArchiveMember,
    CleanupPolicy,
    CommitRecord,
    Confidence,
    ErrorCategory,
    ExtractionResult,
    Job,
    JobState,
    SourceIdentity,
    USER_NOTICE_LIMIT,
    VerificationResult,
)
from path_safety import is_reparse_escape, is_safe_output_path
from recovery import RecoveryJournal
from user_messages import format_user_message
from windows_adapters import flush_file_to_disk, move_no_replace_durable
from sevenzip import (
    EXIT_SUCCESS,
    EXIT_WARNING,
    MAX_PARSED_MEMBERS,
    SevenZipError,
    SevenZipRunner,
    classify_return_code,
    decode_output,
)

logger = logging.getLogger(__name__)

PARTIAL_RECOVERY_DIR = "非完全恢复"
SAFETY_MARGIN = 256 * 1024 * 1024
OUTPUT_TOLERANCE_MIN = 16 * 1024 * 1024
OUTPUT_TOLERANCE_MAX = 256 * 1024 * 1024
UNKNOWN_OUTPUT_GUARD_MIN = 1 * 1024 * 1024
UNKNOWN_OUTPUT_GUARD_MAX = 64 * 1024 * 1024
OUTPUT_MONITOR_INTERVAL = 0.10
OUTPUT_MONITOR_NEAR_INTERVAL = 0.05
PASSWORD_FILE_MAX_BYTES = 4 * 1024 * 1024
PASSWORD_MAX_CANDIDATES = 10_000
PASSWORD_MAX_CHARS = 4096
COPY_BUFFER_SIZE = 1024 * 1024

_UNSAFE_KIND_LABELS: Dict[str, Tuple[str, str]] = {
    "path_traversal": ("路径穿越", "path-traversal"),
    "absolute_path": ("绝对路径", "absolute-path"),
    "reparse_point": ("重解析点", "reparse-point"),
    "alternate_stream": ("NTFS 备用数据流", "NTFS alternate-stream"),
    "link_entry": ("符号链接或硬链接", "symbolic/hard-link"),
    "anti_entry": ("反向删除条目", "anti-item deletion"),
    "device_name": ("Windows 保留设备名", "reserved Windows device-name"),
    "normalized_collision": ("Windows 路径冲突", "Windows path-collision"),
    "invalid_windows_path": ("Windows 不兼容路径", "Windows-incompatible path"),
}
_UNSAFE_KIND_PRIORITY = tuple(_UNSAFE_KIND_LABELS)

_PASSWORD_FILE_LOCK = threading.RLock()


def _unsafe_reason_kind(reason: str) -> str:
    normalized = str(reason).casefold()
    if "path traversal" in normalized or "escapes root" in normalized:
        return "path_traversal"
    if "absolute path" in normalized:
        return "absolute_path"
    if "reparse point" in normalized:
        return "reparse_point"
    if "alternate data stream" in normalized:
        return "alternate_stream"
    if "device name" in normalized:
        return "device_name"
    return "invalid_windows_path"


def _unsafe_manifest_message(
    violations: List[Tuple[str, str]],
) -> Tuple[str, str]:
    unique_violations = list(dict.fromkeys(violations))
    kinds = [
        kind
        for kind in _UNSAFE_KIND_PRIORITY
        if any(item_kind == kind for item_kind, _path in unique_violations)
    ]
    primary = kinds[0] if kinds else "invalid_windows_path"
    sample_path = next(
        (path for kind, path in unique_violations if kind == primary),
        "",
    )
    sample = repr(str(sample_path))
    if len(sample) > 200:
        sample = sample[:197] + "..."

    zh_labels = "、".join(_UNSAFE_KIND_LABELS[kind][0] for kind in kinds)
    en_labels = ", ".join(_UNSAFE_KIND_LABELS[kind][1] for kind in kinds)
    count = len(unique_violations)
    if count == 1:
        zh_detail = f"{zh_labels}条目（{sample}）"
        en_detail = f"{en_labels} entry ({sample})"
    else:
        zh_detail = f"{zh_labels}条目（共 {count} 项，首项 {sample}）"
        en_detail = f"{en_labels} entries ({count} total; first: {sample})"
    return (
        f"安全拦截：压缩包包含{zh_detail}；已跳过且未解压。 / "
        f"Security block: the archive contains {en_detail}; it was skipped "
        "without extraction.",
        f"unsafe_{primary}",
    )


class Executor:
    def __init__(
        self,
        runner: SevenZipRunner,
        config: Dict[str, Any],
        event_cb: Optional[Callable] = None,
        nested_submit: Optional[Callable] = None,
        recovery_journal: Optional[RecoveryJournal] = None,
    ):
        self.runner = runner
        self._config_lock = threading.RLock()
        self._configured = dict(config)
        self._active_config: Optional[Dict[str, Any]] = None
        self.event_cb = event_cb or (lambda *a, **k: None)
        self.nested_submit = nested_submit
        self.recovery_journal = recovery_journal
        self._nested_extractor = None
        self._nested_budget_lock = threading.RLock()
        self._nested_budgets: Dict[str, int] = {}

    def update_config(self, config: Dict[str, Any]) -> None:
        with self._config_lock:
            self._configured = dict(config)

    @property
    def config(self) -> Dict[str, Any]:
        """Current immutable-per-execution configuration view."""
        with self._config_lock:
            return self._active_config or self._configured

    def _emit(
        self,
        job: Job,
        state: JobState,
        message: str = "",
        progress: int = -1,
        error_category: Optional[ErrorCategory] = None,
    ) -> None:
        job.record_state(state)
        if state == JobState.COMPLETE:
            job.error_category = None
            job.error_message = ""
        elif error_category is not None:
            job.error_category = error_category
        if message:
            if state != JobState.COMPLETE:
                job.error_message = message
            if state in {
                JobState.COMPLETE,
                JobState.PARTIAL_RECOVERY,
                JobState.FAILED,
                JobState.SKIPPED,
                JobState.INTERRUPTED,
            }:
                job.terminal_diagnostics.append(message)
                del job.terminal_diagnostics[:-50]
        if progress >= 0:
            job.progress = max(0, min(100, int(progress)))
        self.event_cb("state_change", job, state, message, progress)

    def _notify_user(self, job: Job, message: str) -> None:
        job.user_notices.append(str(message))
        del job.user_notices[:-USER_NOTICE_LIMIT]
        self.event_cb("user_notice", job, str(message))

    @staticmethod
    def _elapsed_ms(started_ns: int) -> float:
        return max(0.0, (time.perf_counter_ns() - started_ns) / 1_000_000.0)

    def _record_listing_metrics(
        self,
        job: Job,
        source,
        measured_wall_ms: float,
    ) -> None:
        metrics = job.phase_metrics
        metrics.listing_wall_ms += max(0.0, float(measured_wall_ms))
        attempts = max(1, int(getattr(source, "listing_attempts", 0) or 0))
        metrics.listing_attempts += attempts
        metrics.parse_cpu_ms += max(
            0.0,
            float(getattr(source, "parse_cpu_ms", 0.0) or 0.0),
        )
        early_abort_reason = str(
            getattr(source, "early_abort_reason", "") or ""
        )
        if early_abort_reason:
            metrics.early_abort_reason = early_abort_reason

    def _manifest_entry_limit(self) -> int:
        manifest_limit = max(
            1,
            int(self.config.get("max_manifest_entries", MAX_PARSED_MEMBERS)),
        )
        output_limit = max(
            1,
            int(self.config.get("max_output_files", MAX_PARSED_MEMBERS)),
        )
        return min(manifest_limit, output_limit, MAX_PARSED_MEMBERS)

    def _can_reuse_encrypted_manifest(self, job: Job, target: str) -> bool:
        manifest = job.manifest
        if (
            not job.reuse_manifest_on_password_retry
            or job.temp_zip
            or manifest is None
            or not manifest.is_encrypted
            or manifest.summary_mode
            or manifest.early_abort_reason
            or manifest.entry_count != len(manifest.members)
            or manifest.listing_return_code not in (EXIT_SUCCESS, EXIT_WARNING)
        ):
            return False

        volumes = (
            list(job.archive_set.volumes)
            if job.archive_set and job.archive_set.volumes
            else [target]
        )
        for volume in volumes:
            key = self._source_identity_key(volume)
            expected = job.source_identities.get(key)
            if expected is None or self._read_source_identity(volume) != expected:
                return False
        return True

    def _timed_extract(self, job: Job, password: Optional[str]) -> ExtractionResult:
        started_ns = time.perf_counter_ns()
        job.phase_metrics.extraction_attempts += 1
        try:
            return self._extract(job, password)
        finally:
            job.phase_metrics.extraction_wall_ms += self._elapsed_ms(started_ns)

    def _publish_phase_metrics(self, job: Job) -> None:
        summary = job.phase_metrics.summary()
        logger.debug("Phase metrics task=%s %s", job.task_id, summary)
        if not job.is_terminal:
            return
        job.terminal_diagnostics[:] = [
            value
            for value in job.terminal_diagnostics
            if not str(value).startswith("[TIMING]")
        ]
        job.terminal_diagnostics.append(summary)
        del job.terminal_diagnostics[:-50]

    def execute(
        self,
        job: Job,
        manual_password: Optional[str] = None,
        session_main_password: Optional[str] = None,
    ) -> Tuple[JobState, Optional[str]]:
        """Execute *job* and return ``(terminal_or_deferred_state, promoted)``.

        ``manual_password`` and ``session_main_password`` are transient call
        frame values.  The optional promoted value is returned to the
        scheduler's session-level candidate store.
        """
        with self._config_lock:
            if self._active_config is not None:
                return self._fail(
                    job,
                    "Executor does not permit overlapping jobs",
                    ErrorCategory.INTERNAL_ERROR,
                    "executor_overlap",
                ), None
            self._active_config = dict(self._configured)
        execution_started_ns = time.perf_counter_ns()
        try:
            return self._run_state_machine(
                job,
                manual_password=manual_password,
                session_main_password=session_main_password,
            )
        except Exception as exc:
            error = str(exc)
            logger.error(
                "Executor failure task=%s state=%s path=%s error=%s",
                job.task_id,
                job.state.value,
                job.path,
                error,
            )
            self._emit(
                job,
                JobState.FAILED,
                error or "Internal executor error",
                error_category=ErrorCategory.INTERNAL_ERROR,
            )
            self._cleanup_temp_root(job)
            job.cleanup_eligible = False
            job.source_retention_reason = "internal_error"
            return JobState.FAILED, None
        finally:
            job.phase_metrics.total_wall_ms += self._elapsed_ms(execution_started_ns)
            self._publish_phase_metrics(job)
            with self._config_lock:
                self._active_config = None

    def _run_state_machine(
        self,
        job: Job,
        manual_password: Optional[str],
        session_main_password: Optional[str],
    ) -> Tuple[JobState, Optional[str]]:
        if not job.cleanup_policy_snapshot:
            job.cleanup_policy_snapshot = cleanup_policy_from_config(
                self.config
            ).value
        self._emit(job, JobState.DISCOVERING, "Discovering archive structure")
        if self._cancelled():
            return self._mark_interrupted(job, "Cancelled before start"), None
        if not os.path.isfile(job.path):
            return self._fail(
                job, "Archive file not found", ErrorCategory.NOT_ARCHIVE, "not_found"
            ), None

        archive_set = detect_archive_set(job.path)
        job.archive_set = archive_set
        if archive_set.main_path:
            job.path = archive_set.main_path
        self._remember_source_identities(job)
        if len(archive_set.volumes) > 1:
            detail = f"Multi-volume set: {len(archive_set.volumes)} volume(s)"
            if not archive_set.is_complete:
                detail += f"; missing indexes {archive_set.missing_indexes}"
            self._emit(job, JobState.GROUPED, detail)
        else:
            self._emit(job, JobState.STANDALONE, "Single archive")

        if not archive_set.is_complete:
            missing = ", ".join(str(index) for index in archive_set.missing_indexes)
            return self._fail(
                job,
                f"Archive volume set is incomplete; missing: {missing or 'unknown'}",
                ErrorCategory.MISSING_VOLUME,
                "missing_volume",
            ), None

        if job.stego_selection_pending:
            selected = job.selected_candidate
            job.stego_selection_pending = False
            if selected is None:
                return self._fail(
                    job,
                    "Reviewed structural candidate is missing",
                    ErrorCategory.NOT_ARCHIVE,
                    "stego_selection_missing",
                ), None
            job.stego_ambiguous = True
            job.stego_provisional = self._candidate_is_provisional(selected)
            carved = self._carve_candidate(job, selected)
            if not carved:
                if job.state == JobState.INTERRUPTED:
                    return JobState.INTERRUPTED, None
                return self._fail(
                    job,
                    "Selected structural candidate failed validation",
                    ErrorCategory.NOT_ARCHIVE,
                    "stego_candidate_invalid",
                ), None
            job.original_path = job.original_path or job.path
            job.original_basename = (
                job.original_basename or Path(job.original_path).name
            )
            job.temp_zip = carved

        target = job.temp_zip or job.path
        if self._can_reuse_encrypted_manifest(job, target):
            manifest = job.manifest
            working_password = None
            listing_error = None
            self._emit(
                job,
                JobState.LISTING,
                "Reusing complete encrypted archive manifest",
            )
        else:
            job.reuse_manifest_on_password_retry = False
            manifest, working_password, _listed_password, listing_error = self._try_listing(
                job,
                target,
                manual_password=manual_password,
                session_main_password=session_main_password,
            )

        if (
            manifest is None
            and listing_error is not None
            and listing_error.category == ErrorCategory.MISSING_VOLUME
        ):
            return self._fail(
                job,
                str(listing_error) or "Archive volume is missing",
                ErrorCategory.MISSING_VOLUME,
                "missing_volume",
            ), None

        if (
            manifest is not None
            and manifest.listing_return_code == EXIT_WARNING
            and not job.temp_zip
            and job.nested_depth == 0
        ):
            direct_diagnostics = list(manifest.diagnostics)
            state = self._prepare_stego_candidate(
                job,
                require_embedded=True,
                exact_only=True,
            )
            if state == JobState.STEGO_CANDIDATE_REVIEW:
                return state, None
            if state == JobState.INTERRUPTED:
                return state, None
            if job.temp_zip:
                manifest, working_password, _listed_password, listing_error = self._try_listing(
                    job,
                    job.temp_zip,
                    manual_password=manual_password,
                    session_main_password=session_main_password,
                )
                if manifest is not None:
                    job.terminal_diagnostics.extend(
                        ["Direct host listing warned; exact candidate took over"]
                        + direct_diagnostics[-10:]
                    )
                    del job.terminal_diagnostics[:-50]

        # Direct host opening is authoritative.  Structural scanning happens
        # only after a non-password open failure and only when explicitly opted
        # in through deep scan or an explicit external input.
        if manifest is None and job.state != JobState.INTERRUPTED:
            may_scan = self._may_scan_structure(job)
            password_failure = bool(
                listing_error
                and listing_error.category == ErrorCategory.BAD_PASSWORD
            )
            # A plain host can contain an encrypted appended archive; some 7-Zip
            # versions report that as a password failure rather than NOT_ARCHIVE.
            if (
                not job.temp_zip
                and may_scan
                and not (
                    listing_error
                    and listing_error.category == ErrorCategory.VERIFY_FAILED
                )
            ):
                state = self._prepare_stego_candidate(
                    job, require_embedded=password_failure
                )
                if state == JobState.STEGO_CANDIDATE_REVIEW:
                    return state, None
                if state == JobState.INTERRUPTED:
                    return state, None
                if job.temp_zip:
                    manifest, working_password, _listed_password, listing_error = self._try_listing(
                        job,
                        job.temp_zip,
                        manual_password=manual_password,
                        session_main_password=session_main_password,
                    )
            if manifest is None and password_failure and not job.temp_zip:
                job.password_candidates_exhausted = True
                self._emit(
                    job,
                    JobState.PASSWORD_REQUIRED,
                    "Password required or all supplied candidates failed",
                    error_category=ErrorCategory.BAD_PASSWORD,
                )
                return JobState.PASSWORD_REQUIRED, None

        if manifest is None:
            if job.state == JobState.INTERRUPTED:
                return JobState.INTERRUPTED, None
            if listing_error and listing_error.category == ErrorCategory.BAD_PASSWORD:
                job.password_candidates_exhausted = True
                self._emit(
                    job,
                    JobState.PASSWORD_REQUIRED,
                    "Password required or all supplied candidates failed",
                    error_category=ErrorCategory.BAD_PASSWORD,
                )
                return JobState.PASSWORD_REQUIRED, None
            category = listing_error.category if listing_error else ErrorCategory.NOT_ARCHIVE
            message = str(listing_error) if listing_error else "Cannot open input as archive"
            retention_reason = (
                "manifest_line_limit"
                if listing_error
                and listing_error.early_abort_reason
                == "manifest_line_limit_exceeded"
                else "listing_failed"
            )
            return self._fail(job, message, category, retention_reason), None

        job.manifest = manifest
        job.reuse_manifest_on_password_retry = bool(
            manifest.is_encrypted
            and not job.temp_zip
            and not manifest.summary_mode
            and not manifest.early_abort_reason
            and manifest.entry_count == len(manifest.members)
            and manifest.listing_return_code in (EXIT_SUCCESS, EXIT_WARNING)
        )
        self._apply_manifest_volume_info(job, manifest)
        preflight_started_ns = time.perf_counter_ns()
        try:
            preflight_state = self._preflight(job, manifest)
        finally:
            job.phase_metrics.preflight_wall_ms += self._elapsed_ms(
                preflight_started_ns
            )
        if preflight_state is not None:
            return preflight_state, None

        if manifest.is_encrypted and not self._password_candidates(
            manual_password,
            session_main_password,
            include_no_password=False,
        ):
            job.password_candidates_exhausted = True
            self._emit(
                job,
                JobState.PASSWORD_REQUIRED,
                "Password required or all supplied candidates failed",
                error_category=ErrorCategory.BAD_PASSWORD,
            )
            return JobState.PASSWORD_REQUIRED, None

        self._emit(
            job,
            JobState.PLANNED,
            (
                f"Manifest: {manifest.entry_count or len(manifest.members)} entries, "
                f"{manifest.total_size} bytes; output cap {job.approved_output_bytes}"
            ),
        )
        if not self._wait_for_space(job):
            if self._cancelled():
                return self._mark_interrupted(
                    job, "Cancelled while waiting for disk space"
                ), None
            return JobState.FAILED, None

        extraction, successful_password = self._extract_with_password_candidates(
            job,
            working_password,
            manual_password=manual_password,
            session_main_password=session_main_password,
        )
        job.extraction_result = extraction
        working_password = None

        if extraction.error_category == ErrorCategory.CANCELLED:
            self._cleanup_temp_root(job)
            return self._mark_interrupted(job, "Cancelled during extraction"), None

        if extraction.error_category == ErrorCategory.BAD_PASSWORD:
            self._cleanup_temp_root(job)
            job.password_candidates_exhausted = True
            self._emit(
                job,
                JobState.PASSWORD_REQUIRED,
                "Password required or all supplied candidates failed",
                error_category=ErrorCategory.BAD_PASSWORD,
            )
            return JobState.PASSWORD_REQUIRED, None

        job.reuse_manifest_on_password_retry = False

        if (
            extraction.quota_exceeded
            and job.nested_depth > 0
            and job.nested_budget_limit > 0
        ):
            self._cleanup_temp_root(job)
            return self._fail(
                job,
                "Nested output budget was exceeded during extraction",
                ErrorCategory.DISK_FULL,
                "nested_output_quota_runtime",
            ), None

        output_scan_started_ns = time.perf_counter_ns()
        try:
            self._scan_extracted_tree(job)
        finally:
            job.phase_metrics.output_scan_wall_ms += self._elapsed_ms(
                output_scan_started_ns
            )
        has_recoverable_output = bool(
            extraction.extracted_paths
            or (
                extraction.temp_output_dir
                and os.path.isdir(extraction.temp_output_dir)
                and os.listdir(extraction.temp_output_dir)
            )
        )
        if extraction.unsafe_entries:
            self._remove_unsafe_outputs(extraction)

        if not extraction.success and not has_recoverable_output:
            self._cleanup_temp_root(job)
            detail = extraction.diagnostics[-1] if extraction.diagnostics else "Extraction failed"
            return self._fail(
                job,
                detail,
                extraction.error_category or ErrorCategory.INTERNAL_ERROR,
                "extract_failed",
            ), None

        verification = self._verify(job)
        job.verification_result = verification
        if verification.verified:
            final_state = self._commit(job, partial=False)
        else:
            final_state = self._handle_partial_recovery(job)

        if final_state in (JobState.COMPLETE, JobState.PARTIAL_RECOVERY):
            self._account_nested_output(job)
        if final_state == JobState.COMPLETE:
            self._maybe_cleanup_sources(job)
        if final_state in (JobState.COMPLETE, JobState.PARTIAL_RECOVERY):
            self._maybe_nested(job)
        promoted = successful_password if final_state == JobState.COMPLETE else None
        if promoted:
            self._promote_password(promoted)
        return final_state, promoted

    # ------------------------------------------------------------------
    # Listing and transient password handling
    # ------------------------------------------------------------------

    def _try_listing(
        self,
        job: Job,
        target: str,
        manual_password: Optional[str],
        session_main_password: Optional[str],
    ) -> Tuple[
        Optional[ArchiveManifest],
        Optional[str],
        Optional[str],
        Optional[SevenZipError],
    ]:
        candidates = self._password_candidates(manual_password, session_main_password)
        last_error: Optional[SevenZipError] = None
        for index, password in enumerate(candidates):
            if self._cancelled():
                self._mark_interrupted(job, "Cancelled during archive listing")
                return None, None, None, None
            job.password_attempt_index = index
            job.attempt_count += 1
            self._emit(
                job,
                JobState.PASSWORD_ATTEMPT if password is not None else JobState.LISTING,
                f"Archive listing attempt #{job.attempt_count}",
            )
            listing_started_ns = time.perf_counter_ns()
            try:
                manifest = self.runner.list_with_fallback(
                    target,
                    password=password,
                    manifest_entry_limit=self._manifest_entry_limit(),
                )
            except SevenZipError as exc:
                self._record_listing_metrics(
                    job,
                    exc,
                    self._elapsed_ms(listing_started_ns),
                )
                last_error = exc
                if exc.category == ErrorCategory.BAD_PASSWORD:
                    continue
                if exc.category == ErrorCategory.CANCELLED:
                    self._mark_interrupted(job, "Cancelled during archive listing")
                return None, None, None, exc

            self._record_listing_metrics(
                job,
                manifest,
                self._elapsed_ms(listing_started_ns),
            )
            job.password_candidates_exhausted = False
            return manifest, password, password if password else None, None

        return None, None, None, last_error

    def _password_candidates(
        self,
        manual_password: Optional[str],
        session_main_password: Optional[str],
        *,
        include_no_password: bool = True,
    ) -> List[Optional[str]]:
        candidates: List[Optional[str]] = []
        seen: Set[str] = set()

        def add(value: Optional[str]) -> None:
            normalized: Optional[str] = value
            if normalized == "":
                normalized = None
            key = normalized if normalized is not None else "<NO_PASSWORD>"
            if key in seen or len(candidates) >= PASSWORD_MAX_CANDIDATES:
                return
            if normalized is not None and len(normalized) > PASSWORD_MAX_CHARS:
                return
            seen.add(key)
            candidates.append(normalized)

        add(manual_password)
        add(session_main_password)
        if include_no_password:
            add(None)
        for value in self._read_password_file():
            add(value)
        return candidates

    def _read_password_file(self) -> List[str]:
        try:
            path = get_password_file_path(self.config)
        except (KeyError, TypeError, ValueError):
            return []
        if not path or not os.path.isfile(path):
            return []
        with _PASSWORD_FILE_LOCK:
            try:
                with open(path, "rb") as stream:
                    raw = stream.read(PASSWORD_FILE_MAX_BYTES + 1)
            except OSError as exc:
                logger.warning("Password file read failed: %s", exc)
                return []
        if len(raw) > PASSWORD_FILE_MAX_BYTES:
            logger.warning("Password file ignored because it exceeds the safety limit")
            return []
        text = decode_output(raw)
        values: List[str] = []
        for line in text.splitlines():
            value = line.strip()
            if value and len(value) <= PASSWORD_MAX_CHARS:
                values.append(value)
                if len(values) >= PASSWORD_MAX_CANDIDATES:
                    break
        return values

    def _extract_with_password_candidates(
        self,
        job: Job,
        listing_password: Optional[str],
        manual_password: Optional[str],
        session_main_password: Optional[str],
    ) -> Tuple[ExtractionResult, Optional[str]]:
        manifest = job.manifest
        if manifest is None or not manifest.is_encrypted:
            extraction = self._timed_extract(job, listing_password)
            return extraction, None

        candidates: List[Optional[str]] = []
        seen: Set[Optional[str]] = set()
        for candidate in [
            listing_password,
            *self._password_candidates(
                manual_password,
                session_main_password,
                include_no_password=False,
            ),
        ]:
            if candidate is None:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)

        last_bad_password: Optional[ExtractionResult] = None
        for index, password in enumerate(candidates):
            if self._cancelled():
                cancelled = ExtractionResult(error_category=ErrorCategory.CANCELLED)
                cancelled.diagnostics.append("Cancelled before encrypted extraction")
                return cancelled, None
            job.password_attempt_index = index
            job.attempt_count += 1
            self._emit(
                job,
                JobState.PASSWORD_ATTEMPT,
                f"Encrypted extraction attempt #{job.attempt_count}",
            )
            extraction = self._timed_extract(job, password)
            job.extraction_result = extraction
            if extraction.error_category != ErrorCategory.BAD_PASSWORD:
                promoted = password if password and extraction.success else None
                job.password_candidates_exhausted = False
                return extraction, promoted

            last_bad_password = extraction
            if not self._cleanup_temp_root(job):
                extraction.diagnostics.append(
                    "Could not clean a failed password attempt; further attempts were stopped"
                )
                return extraction, None

        if last_bad_password is None:
            last_bad_password = ExtractionResult(
                error_category=ErrorCategory.BAD_PASSWORD
            )
        last_bad_password.temp_output_dir = ""
        last_bad_password.extracted_paths.clear()
        return last_bad_password, None

    def _promote_password(self, password: str) -> None:
        """Move a successful user candidate to the front of plaintext code.txt."""
        if not password or len(password) > PASSWORD_MAX_CHARS:
            return
        try:
            path = get_password_file_path(self.config)
        except (KeyError, TypeError, ValueError):
            return
        parent = os.path.dirname(os.path.abspath(path))
        with _PASSWORD_FILE_LOCK:
            existing = self._read_password_file()
            ordered = [password] + [item for item in existing if item != password]
            fd = -1
            tmp_path = ""
            try:
                os.makedirs(parent, exist_ok=True)
                fd, tmp_path = tempfile.mkstemp(
                    prefix="smart7z_passwords_", suffix=".tmp", dir=parent
                )
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    fd = -1
                    for item in ordered[:PASSWORD_MAX_CANDIDATES]:
                        stream.write(item + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp_path, path)
            except OSError as exc:
                logger.warning("Password promotion failed: %s", exc)
                if fd >= 0:
                    os.close(fd)
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    # Structural candidate handling
    # ------------------------------------------------------------------

    def _prepare_stego_candidate(
        self,
        job: Job,
        require_embedded: bool = False,
        exact_only: bool = False,
    ) -> Optional[JobState]:
        if self._cancelled():
            return self._mark_interrupted(job, "Cancelled before structural scan")
        candidates = self._find_stego_candidates(job)
        if self._cancelled():
            return self._mark_interrupted(job, "Cancelled during structural scan")
        if require_embedded:
            try:
                host_size = os.path.getsize(job.path)
            except OSError:
                return None
            candidates = [
                candidate
                for candidate in candidates
                if candidate.start_offset > 0 or candidate.end_offset < host_size
            ]
        if exact_only:
            from stego_candidates import is_exact_high_confidence_candidate

            candidates = [
                candidate
                for candidate in candidates
                if is_exact_high_confidence_candidate(candidate)
            ]
        if not candidates:
            return None
        job.stego_candidates = candidates
        selected = self._auto_select_candidate(candidates)
        if selected is None:
            job.stego_ambiguous = True
            self._emit(
                job,
                JobState.STEGO_CANDIDATE_REVIEW,
                f"Found {len(candidates)} structural candidates; review required",
            )
            return JobState.STEGO_CANDIDATE_REVIEW
        job.selected_candidate = selected
        job.stego_ambiguous = False
        job.stego_provisional = self._candidate_is_provisional(selected)
        carved = self._carve_candidate(job, selected)
        if carved:
            job.original_path = job.original_path or job.path
            job.original_basename = job.original_basename or Path(job.original_path).name
            job.temp_zip = carved
        return None

    def _find_stego_candidates(self, job: Job) -> List[ArchiveCandidate]:
        try:
            from stego_candidates import find_candidates

            return find_candidates(job.path, cancel_check=self._cancelled)
        except (OSError, ValueError, EOFError):
            logger.exception("Structural candidate scan failed for task=%s", job.task_id)
            return []

    @staticmethod
    def _auto_select_candidate(
        candidates: List[ArchiveCandidate],
    ) -> Optional[ArchiveCandidate]:
        high = [candidate for candidate in candidates if candidate.confidence == Confidence.HIGH]
        return high[0] if len(high) == 1 else None

    @staticmethod
    def _candidate_is_provisional(candidate: ArchiveCandidate) -> bool:
        flags = {flag.lower() for flag in candidate.validation_flags}
        return (
            candidate.mode == "signature_only"
            or "boundary_provisional" in flags
            or "end_provisional" in flags
            or candidate.end_offset <= candidate.start_offset
        )

    def _carve_candidate(
        self, job: Job, candidate: ArchiveCandidate
    ) -> Optional[str]:
        host = job.path
        try:
            host_size = os.path.getsize(host)
            start = int(candidate.start_offset)
            end = int(candidate.end_offset or host_size)
            if start < 0 or start >= host_size or end <= start or end > host_size:
                raise ValueError("Candidate range is outside the host file")
            temp_dir = os.path.abspath(
                self.config.get("temp_dir") or tempfile.gettempdir()
            )
            session_root = os.path.abspath(
                self.config.get("_session_root") or temp_dir
            )
            out_dir = os.path.join(session_root, "stego")
            os.makedirs(out_dir, exist_ok=True)
            extension = "." + re.sub(r"[^A-Za-z0-9]", "", candidate.embedded_format)
            if extension == ".":
                extension = ".bin"
            out_path = os.path.join(
                out_dir,
                f"carve_{job.task_id[:8]}_{start}_{uuid.uuid4().hex[:8]}{extension}",
            )
            with open(host, "rb") as source, open(out_path, "xb") as destination:
                source.seek(start)
                remaining = end - start
                while remaining:
                    if self._cancelled():
                        raise InterruptedError("Candidate carving cancelled")
                    chunk = source.read(min(COPY_BUFFER_SIZE, remaining))
                    if not chunk:
                        raise EOFError("Candidate ended before its validated boundary")
                    destination.write(chunk)
                    remaining -= len(chunk)
            try:
                self.runner.list_with_fallback(out_path)
            except SevenZipError as exc:
                # An encrypted archive that asks for a password is still a
                # successfully recognized carved archive.
                if exc.category != ErrorCategory.BAD_PASSWORD:
                    raise
            if not self._track_artifact(
                job,
                out_path,
                artifact_kind="carved_candidate",
                name_prefix="carve_",
                disposition="delete",
            ):
                raise OSError("Persistent recovery registration failed for carved output")
            return out_path
        except InterruptedError:
            self._mark_interrupted(job, "Cancelled while carving candidate")
        except (OSError, ValueError, EOFError, SevenZipError) as exc:
            logger.warning("Candidate validation failed task=%s: %s", job.task_id, exc)
        if "out_path" in locals():
            try:
                os.remove(out_path)
            except OSError:
                pass
        return None

    # ------------------------------------------------------------------
    # Preflight, quotas, extraction and verification
    # ------------------------------------------------------------------

    def _preflight(
        self, job: Job, manifest: ArchiveManifest
    ) -> Optional[JobState]:
        entry_count = manifest.entry_count or len(manifest.members)
        manifest_limit = max(
            1,
            int(self.config.get("max_manifest_entries", MAX_PARSED_MEMBERS)),
        )
        output_file_limit = max(1, int(self.config.get("max_output_files", 200_000)))
        stopped_at_entry_limit = (
            manifest.early_abort_reason == "manifest_limit_exceeded"
        )
        effective_listing_limit = min(
            manifest_limit,
            output_file_limit,
            MAX_PARSED_MEMBERS,
        )

        if entry_count > manifest_limit or (
            stopped_at_entry_limit
            and manifest_limit == effective_listing_limit
        ):
            count_text = (
                f"至少 {entry_count}"
                if stopped_at_entry_limit
                else str(entry_count)
            )
            english_count = (
                f"at least {entry_count}"
                if stopped_at_entry_limit
                else str(entry_count)
            )
            return self._fail(
                job,
                (
                    "安全拦截：压缩包清单包含 "
                    f"{count_text} 个条目，超过 max_manifest_entries="
                    f"{manifest_limit}；已跳过且未解压。 / Safety block: the "
                    f"archive manifest has {english_count} entries, exceeding "
                    f"max_manifest_entries={manifest_limit}; it was skipped "
                    "without extraction."
                ),
                ErrorCategory.VERIFY_FAILED,
                "manifest_limit",
            )
        if entry_count > output_file_limit or (
            stopped_at_entry_limit
            and output_file_limit == effective_listing_limit
        ):
            count_text = (
                f"至少 {entry_count}" if stopped_at_entry_limit else str(entry_count)
            )
            english_count = (
                f"at least {entry_count}"
                if stopped_at_entry_limit
                else str(entry_count)
            )
            return self._fail(
                job,
                (
                    "资源拦截：压缩包可能生成 "
                    f"{count_text} 个项目，超过 max_output_files="
                    f"{output_file_limit}；已跳过且未解压。 / Resource block: "
                    f"the archive may create {english_count} items, exceeding "
                    f"max_output_files={output_file_limit}; it was skipped "
                    "without extraction."
                ),
                ErrorCategory.DISK_FULL,
                "output_file_quota",
            )
        if entry_count > MAX_PARSED_MEMBERS or stopped_at_entry_limit:
            count_text = (
                f"至少 {entry_count}" if stopped_at_entry_limit else str(entry_count)
            )
            english_count = (
                f"at least {entry_count}"
                if stopped_at_entry_limit
                else str(entry_count)
            )
            return self._fail(
                job,
                (
                    "安全拦截：压缩包清单包含 "
                    f"{count_text} 个条目，超过内部清单解析安全上限 "
                    f"{MAX_PARSED_MEMBERS}；即使配置值更高也不会绕过此上限，"
                    "已跳过且未解压。 / Safety block: the archive manifest has "
                    f"{english_count} entries, exceeding the internal manifest "
                    f"parsing safety limit of {MAX_PARSED_MEMBERS}; higher "
                    "configuration values do not bypass this limit, and the "
                    "archive was skipped without extraction."
                ),
                ErrorCategory.VERIFY_FAILED,
                "manifest_parser_limit",
            )
        if manifest.summary_mode:
            # A truncated/summary manifest cannot prove path confinement for
            # entries that were not retained.  Never extract it automatically.
            return self._fail(
                job,
                (
                    "安全拦截：压缩包清单不完整，无法逐项验证输出路径；"
                    "已跳过且未解压。 / Safety block: the archive manifest is "
                    "incomplete, so every output path cannot be verified; it was "
                    "skipped without extraction."
                ),
                ErrorCategory.VERIFY_FAILED,
                "summary_manifest_blocked",
            )

        root = os.path.abspath(self._get_dest_root(job))
        seen: Set[str] = set()
        unsafe: List[str] = []
        violations: List[Tuple[str, str]] = []
        violation_keys: Set[Tuple[str, str]] = set()

        def record_violation(kind: str, path: str, reason: str) -> None:
            key = (kind, str(path))
            if key in violation_keys:
                return
            violation_keys.add(key)
            violations.append(key)
            unsafe.append(f"{path!r}: {reason}")

        regular_members = [member for member in manifest.members if not member.is_dir]
        for member in manifest.members:
            ok, reason = is_safe_output_path(member.path, root)
            normalized = self._normalized_member_key(member.path)
            if not ok:
                record_violation(
                    _unsafe_reason_kind(reason), member.path, reason
                )
            elif normalized in seen:
                record_violation(
                    "normalized_collision",
                    member.path,
                    "duplicate normalized path",
                )
            else:
                seen.add(normalized)
            if member.is_link:
                record_violation(
                    "link_entry", member.path, "symbolic/hard link entry"
                )
            if member.is_anti:
                record_violation(
                    "anti_entry", member.path, "anti-item deletion entry"
                )
            if member.is_alt_stream:
                record_violation(
                    "alternate_stream", member.path, "alternate-stream entry"
                )
        if unsafe:
            job.terminal_diagnostics.extend(unsafe[:50])
            message, retention_reason = _unsafe_manifest_message(violations)
            return self._fail(
                job,
                message,
                ErrorCategory.UNSAFE_PATH,
                retention_reason,
            )

        all_sizes_known = all(member.size_known for member in regular_members)
        configured_byte_cap = max(0, int(self.config.get("max_output_bytes", 0) or 0))
        total_size = max(0, manifest.total_size)
        if all_sizes_known:
            tolerance = min(
                OUTPUT_TOLERANCE_MAX,
                max(OUTPUT_TOLERANCE_MIN, total_size // 100),
            )
            approved_bytes = total_size + tolerance
            if configured_byte_cap:
                if total_size > configured_byte_cap:
                    return self._fail(
                        job,
                        (
                            "资源拦截：压缩包预计输出 "
                            f"{total_size} 字节，超过 max_output_bytes="
                            f"{configured_byte_cap}；已跳过且未解压。 / "
                            f"Resource block: the archive declares {total_size} "
                            "output bytes, exceeding max_output_bytes="
                            f"{configured_byte_cap}; it was skipped without "
                            "extraction."
                        ),
                        ErrorCategory.DISK_FULL,
                        "output_byte_quota",
                    )
                approved_bytes = min(approved_bytes, configured_byte_cap)
        else:
            approved_bytes = self._unknown_output_cap(job)
            if configured_byte_cap:
                approved_bytes = min(approved_bytes, configured_byte_cap)
            manifest.diagnostics.append("Output size is not fully known")

        nested_remaining = self._nested_output_remaining(job)
        if nested_remaining is not None:
            if all_sizes_known and total_size > nested_remaining:
                return self._fail(
                    job,
                    (
                        "资源拦截：内层压缩包预计输出 "
                        f"{total_size} 字节，超过本批次剩余预算 "
                        f"{nested_remaining} 字节；已跳过且未解压。 / "
                        f"Resource block: the nested archive declares {total_size} "
                        f"output bytes, exceeding the remaining batch budget of "
                        f"{nested_remaining}; it was skipped without extraction."
                    ),
                    ErrorCategory.DISK_FULL,
                    "nested_output_quota",
                )
            approved_bytes = min(approved_bytes, nested_remaining)
            manifest.diagnostics.append(
                f"Nested output budget remaining: {nested_remaining}"
            )

        if approved_bytes <= 0:
            return self._fail(
                job,
                (
                    "资源拦截：目标位置没有可安全批准的输出容量；已跳过且未解压。 / "
                    "Resource block: no output capacity can be approved safely; "
                    "the archive was skipped without extraction."
                ),
                ErrorCategory.DISK_FULL,
                "no_output_capacity",
            )
        job.approved_output_bytes = approved_bytes
        job.approved_file_count = output_file_limit
        return None

    def _unknown_output_cap(self, job: Job) -> int:
        roots = [self._get_dest_root(job)]
        if self.config.get("extract_mode", "staging") == "staging":
            roots.append(self.config.get("temp_dir") or tempfile.gettempdir())
        capacities: List[int] = []
        for root in roots:
            probe = os.path.abspath(root)
            while not os.path.exists(probe):
                parent = os.path.dirname(probe)
                if parent == probe:
                    break
                probe = parent
            try:
                capacities.append(max(0, shutil.disk_usage(probe).free - SAFETY_MARGIN))
            except OSError:
                continue
        return min(capacities) if capacities else 0

    def _wait_for_space(self, job: Job) -> bool:
        if not self.config.get("wait_disk_space", True):
            return True
        required = job.approved_output_bytes + SAFETY_MARGIN
        mode = self.config.get("extract_mode", "staging")
        roots = [self._get_dest_root(job)]
        if mode == "staging":
            roots.append(self.config.get("temp_dir") or tempfile.gettempdir())
        for root in roots:
            os.makedirs(root, exist_ok=True)
        started = time.monotonic()
        timeout = max(0, int(self.config.get("space_wait_timeout", 7200) or 0))
        while True:
            enough = True
            for root in roots:
                try:
                    if shutil.disk_usage(root).free < required:
                        enough = False
                        break
                except OSError as exc:
                    return self._fail(
                        job,
                        f"Cannot determine free space: {exc}",
                        ErrorCategory.DISK_FULL,
                        "space_check_failed",
                    ) == JobState.COMPLETE
            if enough:
                return True
            self._emit(job, JobState.SPACE_WAIT, "Waiting for sufficient disk space")
            if self._cancelled():
                return False
            if timeout and time.monotonic() - started >= timeout:
                self._fail(
                    job,
                    "Timed out waiting for disk space",
                    ErrorCategory.DISK_FULL,
                    "space_wait_timeout",
                )
                return False
            time.sleep(0.5)

    def _extract(self, job: Job, password: Optional[str]) -> ExtractionResult:
        self._emit(job, JobState.EXTRACTING, "Starting extraction", progress=0)
        result = ExtractionResult()
        mode = self.config.get("extract_mode", "staging")
        destination_root = self._get_dest_root(job)
        temp_root = self._create_temp_root(job, destination_root, mode)
        job.temp_root = temp_root
        result.temp_output_dir = temp_root
        monitor_interval = [OUTPUT_MONITOR_INTERVAL]
        monitor_stop_reason = [""]
        monitor_diagnostics: List[str] = []
        scanner_failure = [""]
        slow_scan_reported = [False]
        monitor_lock = threading.Lock()
        scanner_stop = threading.Event()
        initial_scan_done = threading.Event()
        guard_bytes = (
            self._output_guard_bytes(job.approved_output_bytes)
            if self._manifest_has_unknown_sizes(job.manifest)
            else 0
        )
        stop_threshold = max(0, job.approved_output_bytes - guard_bytes)

        def progress_cb(percent: int) -> None:
            self._emit(
                job,
                JobState.EXTRACTING,
                f"Extracting {percent}%",
                progress=percent,
            )

        def set_monitor_stop(reason: str, quota: bool = False) -> None:
            with monitor_lock:
                if not monitor_stop_reason[0]:
                    monitor_stop_reason[0] = reason
                if quota:
                    result.quota_exceeded = True

        def scan_health(total: int, count: int) -> bool:
            if scanner_stop.is_set():
                return False
            with monitor_lock:
                if total > stop_threshold or count > job.approved_file_count:
                    result.quota_exceeded = True
                    if guard_bytes and total > stop_threshold:
                        monitor_stop_reason[0] = (
                            "Unknown-size output guard reached "
                            f"({total} > {stop_threshold}; guard={guard_bytes}; "
                            f"approved_cap={job.approved_output_bytes})"
                        )
                    else:
                        monitor_stop_reason[0] = "Approved output quota exceeded"
                    return False
                return True

        def scanner_worker() -> None:
            try:
                while not scanner_stop.is_set():
                    scan_started = time.monotonic()
                    total, count = self._measure_output(
                        temp_root, stop_cb=scan_health
                    )
                    scan_elapsed = time.monotonic() - scan_started
                    if scanner_stop.is_set():
                        break
                    with monitor_lock:
                        result.output_bytes = total
                        result.output_file_count = count
                        if (
                            scan_elapsed > OUTPUT_MONITOR_INTERVAL
                            and not slow_scan_reported[0]
                        ):
                            slow_scan_reported[0] = True
                            message = (
                                "Output quota scan was slow "
                                f"({scan_elapsed:.3f}s); scanner remains isolated "
                                "from the free-space watchdog"
                            )
                            monitor_diagnostics.append(message)
                            logger.warning(message)
                        near_bytes = bool(
                            stop_threshold
                            and total
                            >= max(
                                0,
                                stop_threshold
                                - max(
                                    UNKNOWN_OUTPUT_GUARD_MIN,
                                    stop_threshold // 20,
                                ),
                            )
                        )
                        near_files = bool(
                            job.approved_file_count
                            and count
                            >= max(1, job.approved_file_count * 9 // 10)
                        )
                        monitor_interval[0] = (
                            OUTPUT_MONITOR_NEAR_INTERVAL
                            if slow_scan_reported[0] or near_bytes or near_files
                            else OUTPUT_MONITOR_INTERVAL
                        )
                    if not scan_health(total, count):
                        break
                    initial_scan_done.set()
                    if scanner_stop.wait(monitor_interval[0]):
                        break
            except Exception as exc:
                message = (
                    "Output quota scan failed internally "
                    f"({type(exc).__name__}): {exc}"
                )
                with monitor_lock:
                    scanner_failure[0] = message
                    if not monitor_stop_reason[0]:
                        monitor_stop_reason[0] = message
                    monitor_diagnostics.append(message)
                logger.error("%s", message)
            finally:
                initial_scan_done.set()

        def monitor_cb() -> bool:
            try:
                free_bytes = shutil.disk_usage(temp_root).free
            except OSError as exc:
                set_monitor_stop(f"Output free-space check failed: {exc}")
                return False
            if free_bytes < SAFETY_MARGIN:
                set_monitor_stop(
                    "Output filesystem reached the reserved free-space margin"
                )
                return False
            with monitor_lock:
                return not monitor_stop_reason[0]

        scanner_thread = threading.Thread(
            target=scanner_worker,
            name=f"Smart7zQuotaScan-{job.task_id[:8]}",
            daemon=True,
        )
        scanner_thread.start()
        initial_scan_done.wait(timeout=1.0)
        try:
            sevenzip_result = self.runner.extract(
                job.temp_zip or job.path,
                temp_root,
                password=password,
                type_switch=job.manifest.used_switch if job.manifest else "",
                progress_cb=progress_cb,
                monitor_cb=monitor_cb,
            )
        finally:
            scanner_stop.set()
            scanner_thread.join()
        result.return_code = (
            EXIT_WARNING
            if sevenzip_result.return_code == EXIT_SUCCESS
            and sevenzip_result.warning_detected
            else sevenzip_result.return_code
        )
        if sevenzip_result.diagnostic_tail:
            result.diagnostics = sevenzip_result.diagnostic_tail.splitlines()[-50:]
        result.diagnostics.extend(monitor_diagnostics)
        if scanner_failure[0]:
            result.quota_exceeded = False
            result.error_category = ErrorCategory.INTERNAL_ERROR
            if scanner_failure[0] not in result.diagnostics:
                result.diagnostics.append(scanner_failure[0])
            return result
        if sevenzip_result.cancelled:
            result.error_category = ErrorCategory.CANCELLED
            return result
        if sevenzip_result.timed_out:
            result.error_category = ErrorCategory.TIMEOUT
            result.diagnostics.append("Extraction timed out")
            return result
        if sevenzip_result.monitor_stopped or result.quota_exceeded:
            result.quota_exceeded = True
            result.error_category = ErrorCategory.DISK_FULL
            result.diagnostics.append(
                monitor_stop_reason[0] or "Approved output quota exceeded"
            )
            return result
        if sevenzip_result.bad_password_detected:
            result.error_category = ErrorCategory.BAD_PASSWORD
            result.diagnostics.append("7-Zip rejected the supplied password")
            return result

        total, count = self._measure_output(temp_root)
        result.output_bytes = total
        result.output_file_count = count
        if total > job.approved_output_bytes or count > job.approved_file_count:
            result.quota_exceeded = True
            result.error_category = ErrorCategory.DISK_FULL
            result.diagnostics.append("Approved output quota exceeded after extraction")
            return result
        if result.return_code not in (EXIT_SUCCESS, EXIT_WARNING):
            _ok, category = classify_return_code(result.return_code)
            result.error_category = category
            return result
        result.success = True
        if result.return_code == EXIT_WARNING:
            result.diagnostics.append("7-Zip reported a warning")
        return result

    @staticmethod
    def _manifest_has_unknown_sizes(manifest: Optional[ArchiveManifest]) -> bool:
        if manifest is None:
            return True
        regular_members = [member for member in manifest.members if not member.is_dir]
        return any(not member.size_known for member in regular_members)

    @staticmethod
    def _output_guard_bytes(approved_cap: int) -> int:
        cap = max(0, int(approved_cap or 0))
        if cap <= 0:
            return 0
        return min(
            UNKNOWN_OUTPUT_GUARD_MAX,
            max(UNKNOWN_OUTPUT_GUARD_MIN, cap // 100),
            cap // 4,
        )

    def _measure_output(
        self,
        root: str,
        stop_cb: Optional[Callable[[int, int], bool]] = None,
    ) -> Tuple[int, int]:
        total = 0
        count = 0
        try:
            root_mode = os.stat(root, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return total, count
        if not stat.S_ISDIR(root_mode):
            return total, count
        pending = [root]
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if stop_cb is not None and not stop_cb(total, count):
                            return total, count
                        try:
                            if entry.is_symlink() or is_reparse_escape(entry.path):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            count += 1
                            total += entry.stat(follow_symlinks=False).st_size
                        except FileNotFoundError:
                            continue
                        if total > 2**63 - 1:
                            return 2**63 - 1, count
                        if stop_cb is not None and not stop_cb(total, count):
                            return total, count
            except FileNotFoundError:
                continue
        return total, count

    def _scan_extracted_tree(self, job: Job) -> None:
        extraction = job.extraction_result
        if extraction is None or not extraction.temp_output_dir:
            return
        root = os.path.abspath(extraction.temp_output_dir)
        safe_files: List[str] = []
        safe_directories: List[str] = []
        unsafe: List[str] = []

        def raise_walk_error(error: OSError) -> None:
            raise error

        for current, dirs, files in os.walk(
            root,
            topdown=True,
            onerror=raise_walk_error,
            followlinks=False,
        ):
            retained_dirs = []
            for name in dirs:
                full = os.path.join(current, name)
                rel = os.path.relpath(full, root)
                ok, reason = is_safe_output_path(rel, root)
                if os.path.islink(full) or is_reparse_escape(full):
                    ok, reason = False, "link/reparse output"
                if ok:
                    retained_dirs.append(name)
                    safe_directories.append(full)
                else:
                    unsafe.append(f"{rel}: {reason}")
            dirs[:] = retained_dirs
            for name in files:
                full = os.path.join(current, name)
                rel = os.path.relpath(full, root)
                ok, reason = is_safe_output_path(rel, root)
                if os.path.islink(full) or is_reparse_escape(full):
                    ok, reason = False, "link/reparse output"
                if ok:
                    safe_files.append(full)
                else:
                    unsafe.append(f"{rel}: {reason}")
        extraction.extracted_paths = safe_files
        extraction.extracted_directories = safe_directories
        extraction.unsafe_entries = unsafe
        extraction.output_bytes, extraction.output_file_count = self._measure_output(root)
        extraction.output_directory_count = len(safe_directories)

    def _remove_unsafe_outputs(self, extraction: ExtractionResult) -> None:
        root = os.path.abspath(extraction.temp_output_dir)
        for diagnostic in extraction.unsafe_entries:
            rel = diagnostic.split(": ", 1)[0]
            full = os.path.abspath(os.path.join(root, rel))
            try:
                if os.path.commonpath((root, full)) != root:
                    continue
            except ValueError:
                continue
            try:
                if os.path.islink(full) or os.path.isfile(full):
                    os.unlink(full)
                elif os.path.isdir(full):
                    shutil.rmtree(full)
            except OSError as exc:
                logger.warning("Could not remove unsafe output %s: %s", rel, exc)

    def _verify(self, job: Job) -> VerificationResult:
        self._emit(job, JobState.VERIFYING, "Verifying extracted metadata")
        result = VerificationResult()
        manifest = job.manifest
        extraction = job.extraction_result
        if manifest is None or extraction is None:
            result.diagnostics.append("Manifest or extraction result is missing")
            return result

        expected: Dict[str, ArchiveMember] = {}
        expected_directories: Dict[str, str] = {}
        explicit_directories: Set[str] = set()
        for member in manifest.members:
            if not member.path:
                continue
            key = self._normalized_member_key(member.path)
            display_path = member.path.replace("\\", "/").strip("/")
            if member.is_dir:
                if key in explicit_directories:
                    result.unsafe.append(
                        f"Duplicate normalized manifest directory: {display_path}"
                    )
                explicit_directories.add(key)
                expected_directories[key] = display_path
                continue
            if key in expected:
                result.unsafe.append(
                    f"Duplicate normalized manifest path: {display_path}"
                )
            expected[key] = member
            parts = [part for part in display_path.split("/") if part]
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                expected_directories.setdefault(
                    self._normalized_member_key(parent), parent
                )

        actual: Dict[str, str] = {}
        actual_directories: Dict[str, str] = {}
        root = extraction.temp_output_dir
        for full in extraction.extracted_paths:
            try:
                rel = os.path.relpath(full, root)
            except ValueError:
                result.unsafe.append(full)
                continue
            key = self._normalized_member_key(rel)
            if key in actual:
                result.unsafe.append(f"Duplicate normalized output path: {rel}")
                continue
            actual[key] = full
        for full in extraction.extracted_directories:
            try:
                rel = os.path.relpath(full, root)
            except ValueError:
                result.unsafe.append(full)
                continue
            key = self._normalized_member_key(rel)
            if key in actual_directories:
                result.unsafe.append(f"Duplicate normalized output directory: {rel}")
                continue
            actual_directories[key] = full

        for key, member in expected.items():
            full = actual.get(key)
            if full is None:
                result.missing.append(member.path)
                continue
            if member.size_known:
                try:
                    actual_size = os.path.getsize(full)
                except OSError:
                    result.failed.append(member.path)
                    continue
                if actual_size != member.size:
                    result.size_mismatches.append(
                        f"{member.path}: expected {member.size}, got {actual_size}"
                    )
        for key, full in actual.items():
            if key not in expected:
                result.extra.append(os.path.relpath(full, root))
        for key, expected_path in expected_directories.items():
            if key not in actual_directories:
                result.missing_directories.append(expected_path)
        for key, full in actual_directories.items():
            if key not in expected_directories:
                result.extra_directories.append(os.path.relpath(full, root))
        for key in set(expected).intersection(expected_directories):
            result.unsafe.append(
                "Manifest file/directory path collision: "
                + expected[key].path
            )
        for key in set(actual).intersection(actual_directories):
            result.unsafe.append(
                "Output file/directory path collision: "
                + os.path.relpath(actual[key], root)
            )

        result.expected_count = len(expected)
        result.actual_count = len(actual)
        result.expected_directory_count = len(expected_directories)
        result.actual_directory_count = len(actual_directories)
        result.unsafe.extend(extraction.unsafe_entries)
        if extraction.return_code == EXIT_WARNING:
            result.diagnostics.append("7-Zip extraction warning")
        if extraction.quota_exceeded:
            result.diagnostics.append("Output quota exceeded")
        if manifest.summary_mode:
            result.diagnostics.append("Summary verification cannot authorize cleanup")
        if job.archive_set and not job.archive_set.is_complete:
            result.diagnostics.append(
                f"Incomplete volume set: {job.archive_set.missing_indexes}"
            )

        result.verified = not any(
            (
                result.missing,
                result.extra,
                result.missing_directories,
                result.extra_directories,
                result.failed,
                result.unsafe,
                result.size_mismatches,
                result.crc_mismatches,
            )
        ) and all(
            (
                extraction.success,
                extraction.return_code == EXIT_SUCCESS,
                manifest.listing_return_code == EXIT_SUCCESS,
                not manifest.summary_mode,
                not extraction.quota_exceeded,
                job.archive_set is None or job.archive_set.is_complete,
            )
        )
        return result

    # ------------------------------------------------------------------
    # Transactional commit and source cleanup
    # ------------------------------------------------------------------

    def _commit(self, job: Job, partial: bool = False) -> JobState:
        self._emit(job, JobState.COMMITTING, "Staging verified output for commit")
        extraction = job.extraction_result
        if extraction is None or not extraction.temp_output_dir:
            return self._fail(
                job, "No extraction output to commit", ErrorCategory.VERIFY_FAILED,
                "no_commit_output",
            )
        source_root = os.path.abspath(extraction.temp_output_dir)
        if not os.path.isdir(source_root):
            return self._fail(
                job, "Extraction root disappeared before commit",
                ErrorCategory.VERIFY_FAILED, "missing_temp_root",
            )

        source_snapshot = self._snapshot_tree(source_root)
        if partial and not source_snapshot[0] and not source_snapshot[1]:
            return self._fail(
                job, "No recoverable output was produced", ErrorCategory.VERIFY_FAILED,
                "empty_output",
            )

        destination_root = os.path.abspath(self._get_dest_root(job))
        os.makedirs(destination_root, exist_ok=True)
        stage = os.path.join(
            destination_root,
            f".smart7z_commit_{job.task_id[:8]}_{uuid.uuid4().hex[:8]}",
        )
        try:
            _source_was_copied, crc_mismatches = self._transfer_to_commit_stage(
                job, source_root, stage
            )
            job.temp_root = stage
            extraction.temp_output_dir = stage
            stage_snapshot = self._snapshot_tree(stage)
            if stage_snapshot != source_snapshot:
                raise OSError("Commit-stage verification mismatch")
            if self._cancelled():
                raise InterruptedError
            self._flush_tree_to_disk(stage, job)
            if _source_was_copied:
                if not self._remove_path(source_root):
                    raise OSError(
                        "Could not remove extraction root after durable commit-stage copy"
                    )
            if crc_mismatches:
                if job.verification_result is not None:
                    job.verification_result.crc_mismatches.extend(crc_mismatches)
                partial = True

            final_path, publish_kind, top_item = self._choose_publish_target(
                job, stage, destination_root, partial
            )
            (
                published_path,
                published_kind,
                published_top_item,
                job.commit_records,
                wrapper_removed,
            ) = self._publish_stage_resilient(
                stage,
                final_path,
                publish_kind,
                top_item,
                destination_root,
                job,
                source_snapshot,
            )
            final_path = published_path
            publish_kind = published_kind
            top_item = published_top_item
            if wrapper_removed:
                self._untrack_artifact(stage)
            elif self.recovery_journal is not None:
                self.recovery_journal.set_artifact_disposition(stage, "delete")
            job.temp_root = None if wrapper_removed else stage
            extraction.temp_output_dir = ""
            job.final_destination = final_path
            job.commit_verified = self._verify_commit_records(job.commit_records)
            if not job.commit_verified:
                recovered = self._relocate_unverified_commit(
                    job, final_path, publish_kind, destination_root
                )
                job.cleanup_eligible = False
                job.source_retention_reason = "post_commit_verification_failed"
                if recovered:
                    self._emit(
                        job,
                        JobState.PARTIAL_RECOVERY,
                        f"Commit verification failed; output retained at {recovered}",
                        error_category=ErrorCategory.VERIFY_FAILED,
                    )
                    return JobState.PARTIAL_RECOVERY
                return self._fail(
                    job,
                    "Post-commit verification failed",
                    ErrorCategory.VERIFY_FAILED,
                    "post_commit_verification_failed",
                )
        except InterruptedError:
            stage_owned = bool(
                job.temp_root
                and os.path.normcase(os.path.abspath(job.temp_root))
                == os.path.normcase(os.path.abspath(stage))
            )
            recovered = (
                self._recover_commit_stage(job, stage, destination_root)
                if stage_owned
                else None
            )
            if recovered:
                job.cleanup_eligible = False
                job.source_retention_reason = "commit_cancelled_partial_recovery"
                self._emit(
                    job,
                    JobState.PARTIAL_RECOVERY,
                    f"Commit cancelled; recoverable output retained at {recovered}",
                    error_category=ErrorCategory.CANCELLED,
                )
                return JobState.PARTIAL_RECOVERY
            if stage_owned and os.path.lexists(stage):
                job.cleanup_eligible = False
                job.source_retention_reason = "commit_cancelled_stage_retained"
                self._emit(
                    job,
                    JobState.INTERRUPTED,
                    f"Commit cancelled; hidden commit stage retained at {stage}",
                    error_category=ErrorCategory.CANCELLED,
                )
                return JobState.INTERRUPTED
            self._cleanup_temp_root(job)
            return self._mark_interrupted(job, "Cancelled during output commit")
        except OSError as exc:
            logger.warning("Commit failure task=%s: %s", job.task_id, exc)
            stage_owned = bool(
                job.temp_root
                and os.path.normcase(os.path.abspath(job.temp_root))
                == os.path.normcase(os.path.abspath(stage))
            )
            recovered = (
                self._recover_commit_stage(job, stage, destination_root)
                if stage_owned
                else None
            )
            if recovered:
                self._cleanup_temp_root(job)
                job.cleanup_eligible = False
                job.source_retention_reason = "commit_partial_recovery"
                self._emit(
                    job,
                    JobState.PARTIAL_RECOVERY,
                    f"Commit was incomplete; recoverable output retained at {recovered}",
                    error_category=ErrorCategory.OUTPUT_CONFLICT,
                )
                return JobState.PARTIAL_RECOVERY
            if stage_owned and os.path.lexists(stage):
                job.cleanup_eligible = False
                job.source_retention_reason = "commit_stage_retained"
                self._emit(
                    job,
                    JobState.FAILED,
                    f"Commit failed; hidden commit stage retained at {stage}: {exc}",
                    error_category=ErrorCategory.OUTPUT_CONFLICT,
                )
                return JobState.FAILED
            self._cleanup_temp_root(job)
            return self._fail(
                job,
                f"Commit failed: {exc}",
                ErrorCategory.OUTPUT_CONFLICT,
                "commit_failed",
            )

        job.committed_output_bytes = sum(
            max(0, record.expected_size) for record in job.commit_records
        )
        if partial:
            job.cleanup_eligible = False
            job.source_retention_reason = "partial_recovery"
            self._emit(
                job,
                JobState.PARTIAL_RECOVERY,
                f"Recoverable output committed to {job.final_destination}",
                progress=100,
                error_category=ErrorCategory.VERIFY_FAILED,
            )
            return JobState.PARTIAL_RECOVERY

        job.cleanup_eligible = bool(job.commit_verified)
        job.source_retention_reason = ""
        job.error_category = None
        job.error_message = ""
        self._emit(
            job,
            JobState.COMPLETE,
            f"Verified output committed to {job.final_destination}",
            progress=100,
        )
        return JobState.COMPLETE

    def _handle_partial_recovery(self, job: Job) -> JobState:
        extraction = job.extraction_result
        if extraction is None or not extraction.temp_output_dir:
            return self._fail(
                job,
                "Extraction failed without recoverable output",
                extraction.error_category if extraction else ErrorCategory.VERIFY_FAILED,
                "no_recoverable_output",
            )
        return self._commit(job, partial=True)

    def _snapshot_tree(self, root: str) -> Tuple[Dict[str, int], Set[str]]:
        files: Dict[str, int] = {}
        directories: Set[str] = set()
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            for name in list(dirs):
                full = os.path.join(current, name)
                if os.path.islink(full) or is_reparse_escape(full):
                    raise OSError(f"Unsafe link/reparse point in commit tree: {name}")
                directories.add(self._portable_rel(os.path.relpath(full, root)))
            for name in names:
                full = os.path.join(current, name)
                if os.path.islink(full) or is_reparse_escape(full):
                    raise OSError(f"Unsafe link/reparse point in commit tree: {name}")
                rel = self._portable_rel(os.path.relpath(full, root))
                files[rel] = os.path.getsize(full)
        return files, directories

    def _transfer_to_commit_stage(
        self, job: Job, source: str, stage: str
    ) -> Tuple[bool, List[str]]:
        if os.path.exists(stage):
            raise FileExistsError(stage)
        if self._is_same_filesystem(source, os.path.dirname(stage)):
            prepared = False
            if self.recovery_journal is not None:
                prepared = self.recovery_journal.prepare_artifact_move(
                    source, stage, ".smart7z_commit_"
                )
                if not prepared:
                    raise OSError(
                        "Persistent recovery move intent could not be recorded"
                    )
            try:
                self._atomic_move_no_replace(source, stage)
            except OSError:
                if prepared and self.recovery_journal is not None:
                    self.recovery_journal.cancel_artifact_move(source)
                raise
            job.temp_root = stage
            if prepared and self.recovery_journal is not None:
                if not self.recovery_journal.commit_artifact_move(source, stage):
                    raise OSError(
                        "Persistent recovery move completion could not be recorded"
                    )
            else:
                if not self._track_artifact(
                    job,
                    stage,
                    artifact_kind="commit_stage",
                    name_prefix=".smart7z_commit_",
                    disposition="preserve",
                ):
                    raise OSError(
                        "Persistent recovery registration failed for commit stage"
                    )
                self._untrack_artifact(source)
            return False, []
        os.makedirs(stage)
        if not self._track_artifact(
            job,
            stage,
            artifact_kind="commit_stage",
            name_prefix=".smart7z_commit_",
            disposition="preserve",
        ):
            os.rmdir(stage)
            raise OSError("Persistent recovery registration failed for commit stage")
        job.temp_root = stage
        try:
            crc_mismatches = self._copy_tree_cancellable(source, stage, job)
            if self._cancelled():
                raise InterruptedError
        except (InterruptedError, OSError):
            raise
        return True, crc_mismatches

    def _copy_tree_cancellable(
        self, source: str, destination: str, job: Job
    ) -> List[str]:
        expected_crcs: Dict[str, str] = {}
        if job.manifest is not None:
            for member in job.manifest.members:
                if member.is_dir or not member.path or not member.crc:
                    continue
                crc = str(member.crc).strip().upper()
                if crc.startswith("0X"):
                    crc = crc[2:]
                if re.fullmatch(r"[0-9A-F]{8}", crc):
                    expected_crcs[self._normalized_member_key(member.path)] = crc

        crc_mismatches: List[str] = []
        copied_bytes = 0
        copied_files = 0
        for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
            if self._cancelled():
                raise InterruptedError
            rel_root = os.path.relpath(current, source)
            target_root = destination if rel_root == "." else os.path.join(destination, rel_root)
            os.makedirs(target_root, exist_ok=True)
            for name in dirs:
                src_dir = os.path.join(current, name)
                if os.path.islink(src_dir) or is_reparse_escape(src_dir):
                    raise OSError(f"Refusing to copy link/reparse directory: {name}")
                os.makedirs(os.path.join(target_root, name), exist_ok=True)
            for name in files:
                if self._cancelled():
                    raise InterruptedError
                src_file = os.path.join(current, name)
                if os.path.islink(src_file) or is_reparse_escape(src_file):
                    raise OSError(f"Refusing to copy link/reparse file: {name}")
                dst_file = os.path.join(target_root, name)
                rel_file = self._normalized_member_key(
                    os.path.relpath(src_file, source)
                )
                expected_crc = expected_crcs.get(rel_file)
                checksum = 0
                with open(src_file, "rb") as src, open(dst_file, "xb") as dst:
                    while True:
                        if self._cancelled():
                            raise InterruptedError
                        chunk = src.read(COPY_BUFFER_SIZE)
                        if not chunk:
                            break
                        written = dst.write(chunk)
                        if written != len(chunk):
                            raise OSError(
                                f"Short write while copying {os.path.relpath(src_file, source)}"
                            )
                        if expected_crc is not None:
                            checksum = zlib.crc32(chunk, checksum)
                        copied_bytes += len(chunk)
                        if copied_bytes > job.approved_output_bytes:
                            raise OSError("Commit copy exceeded approved byte quota")
                shutil.copystat(src_file, dst_file, follow_symlinks=False)
                if expected_crc is not None:
                    actual_crc = f"{checksum & 0xFFFFFFFF:08X}"
                    if actual_crc != expected_crc:
                        crc_mismatches.append(
                            f"{rel_file}: expected {expected_crc}, got {actual_crc}"
                        )
                copied_files += 1
                if copied_files > job.approved_file_count:
                    raise OSError("Commit copy exceeded approved file quota")
        return crc_mismatches

    def _flush_tree_to_disk(self, root: str, job: Job) -> None:
        """Persist every regular output file before publication."""

        for current, dirs, files in os.walk(
            root, topdown=True, followlinks=False
        ):
            if self._cancelled():
                raise InterruptedError
            retained_dirs: List[str] = []
            for name in dirs:
                full = os.path.join(current, name)
                if os.path.islink(full) or is_reparse_escape(full):
                    raise OSError(f"Unsafe link/reparse point in commit tree: {name}")
                retained_dirs.append(name)
            dirs[:] = retained_dirs
            for name in files:
                if self._cancelled():
                    raise InterruptedError
                full = os.path.join(current, name)
                if os.path.islink(full) or is_reparse_escape(full):
                    raise OSError(f"Unsafe link/reparse point in commit tree: {name}")
                flush_file_to_disk(full)

    def _choose_publish_target(
        self, job: Job, stage: str, destination_root: str, partial: bool
    ) -> Tuple[str, str, Optional[str]]:
        archive_name = self._get_archive_name(job)
        items = sorted(os.listdir(stage), key=str.casefold)
        if partial:
            base = os.path.join(destination_root, PARTIAL_RECOVERY_DIR, archive_name)
            os.makedirs(os.path.dirname(base), exist_ok=True)
            return self._make_unique_dir(base), "whole", None

        if len(items) == 1:
            item = items[0]
            source_item = os.path.join(stage, item)
            direct_target = os.path.join(destination_root, item)
            if not os.path.exists(direct_target):
                return (
                    direct_target,
                    "single_dir" if os.path.isdir(source_item) else "single_file",
                    item,
                )
        base = os.path.join(destination_root, archive_name)
        return self._make_unique_dir(base), "whole", None

    def _plan_commit_records(
        self,
        stage: str,
        final_path: str,
        publish_kind: str,
        top_item: Optional[str],
        snapshot: Tuple[Dict[str, int], Set[str]],
    ) -> List[CommitRecord]:
        files, directories = snapshot
        records: List[CommitRecord] = []

        if publish_kind == "whole":
            identity = self._read_source_identity(stage)
            if identity is None:
                raise OSError("Commit-stage root disappeared before publication")
            records.append(
                CommitRecord(
                    source=stage,
                    destination=final_path,
                    collision_decision="whole",
                    expected_size=-1,
                    expected_identity=identity,
                )
            )
        if not files and not directories and publish_kind == "whole":
            return records

        def destination_for(rel: str) -> str:
            parts = rel.split("/") if rel else []
            if publish_kind == "whole":
                return os.path.join(final_path, *parts)
            if publish_kind == "single_file":
                return final_path
            if top_item and parts and parts[0].casefold() == top_item.casefold():
                parts = parts[1:]
            return os.path.join(final_path, *parts) if parts else final_path

        for rel in sorted(directories, key=str.casefold):
            source = os.path.join(stage, *rel.split("/"))
            identity = self._read_source_identity(source)
            if identity is None:
                raise OSError(f"Commit-stage directory disappeared: {rel}")
            records.append(
                CommitRecord(
                    source=source,
                    destination=destination_for(rel),
                    collision_decision=publish_kind,
                    expected_size=-1,
                    expected_identity=identity,
                )
            )
        for rel, size in sorted(files.items(), key=lambda item: item[0].casefold()):
            source = os.path.join(stage, *rel.split("/"))
            identity = self._read_source_identity(source)
            if identity is None:
                raise OSError(f"Commit-stage file disappeared: {rel}")
            records.append(
                CommitRecord(
                    source=source,
                    destination=destination_for(rel),
                    collision_decision=publish_kind,
                    expected_size=size,
                    expected_identity=identity,
                )
            )
        return records

    @staticmethod
    def _publish_stage(
        stage: str, final_path: str, publish_kind: str, top_item: Optional[str]
    ) -> bool:
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        if os.path.exists(final_path):
            raise FileExistsError(final_path)
        if publish_kind == "whole":
            Executor._atomic_move_no_replace(stage, final_path)
            return True
        if not top_item:
            raise OSError("Single-item commit has no source item")
        Executor._atomic_move_no_replace(os.path.join(stage, top_item), final_path)
        try:
            os.rmdir(stage)
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            # The payload has already been atomically published.  An empty
            # wrapper held by AV/indexing is a cleanup issue, not a failed
            # commit.  Keep the owned wrapper referenced for terminal cleanup.
            logger.warning(
                "Published output but could not remove stage %s: %s", stage, exc
            )
            return False

    def _publish_stage_resilient(
        self,
        stage: str,
        final_path: str,
        publish_kind: str,
        top_item: Optional[str],
        destination_root: str,
        job: Job,
        snapshot: Tuple[Dict[str, int], Set[str]],
    ) -> Tuple[str, str, Optional[str], List[CommitRecord], bool]:
        attempts = 0
        candidate = final_path
        while True:
            records = self._plan_commit_records(
                stage, candidate, publish_kind, top_item, snapshot
            )
            try:
                wrapper_removed = self._publish_stage(
                    stage, candidate, publish_kind, top_item
                )
                return (
                    candidate,
                    publish_kind,
                    top_item,
                    records,
                    wrapper_removed,
                )
            except FileExistsError:
                attempts += 1
                if attempts >= 100:
                    raise
                if publish_kind == "single_file":
                    # A late member conflict changes the whole-task shape.
                    publish_kind = "whole"
                    top_item = None
                    candidate = self._make_unique_dir(
                        os.path.join(destination_root, self._get_archive_name(job))
                    )
                else:
                    candidate = self._make_unique_dir(final_path)

    @staticmethod
    def _verify_commit_records(records: Iterable[CommitRecord]) -> bool:
        all_verified = True
        for record in records:
            try:
                current = Executor._read_source_identity(record.destination)
                verified = (
                    record.expected_identity is not None
                    and current == record.expected_identity
                    and (
                        os.path.isdir(record.destination)
                        if record.expected_size < 0
                        else os.path.isfile(record.destination)
                    )
                )
            except OSError as exc:
                record.failure_reason = str(exc)
                verified = False
            record.completed = verified
            record.verified = verified
            if not verified and not record.failure_reason:
                record.failure_reason = "Destination missing or identity mismatch"
            all_verified = all_verified and verified
        return all_verified

    def _relocate_unverified_commit(
        self,
        job: Job,
        final_path: str,
        publish_kind: str,
        destination_root: str,
    ) -> Optional[str]:
        if not os.path.exists(final_path):
            return None
        root_record = next(
            (
                record
                for record in job.commit_records
                if os.path.normcase(os.path.abspath(record.destination))
                == os.path.normcase(os.path.abspath(final_path))
            ),
            None,
        )
        if (
            root_record is None
            or root_record.expected_identity is None
            or self._read_source_identity(final_path)
            != root_record.expected_identity
        ):
            return None
        recovery = self._make_unique_dir(
            os.path.join(
                destination_root, PARTIAL_RECOVERY_DIR, self._get_archive_name(job)
            )
        )
        try:
            os.makedirs(os.path.dirname(recovery), exist_ok=True)
            if publish_kind == "single_file":
                os.makedirs(recovery)
                moved_path = os.path.join(recovery, os.path.basename(final_path))
                self._atomic_move_no_replace(final_path, moved_path)
            else:
                moved_path = recovery
                self._atomic_move_no_replace(final_path, moved_path)
            if self._read_source_identity(moved_path) != root_record.expected_identity:
                try:
                    self._atomic_move_no_replace(moved_path, final_path)
                    if publish_kind == "single_file":
                        os.rmdir(recovery)
                except OSError:
                    logger.exception(
                        "Changed destination could only be retained at %s", moved_path
                    )
                return None
            job.final_destination = recovery
            return recovery
        except OSError:
            logger.exception("Could not relocate unverified commit task=%s", job.task_id)
            return None

    def _recover_commit_stage(
        self, job: Job, stage: str, destination_root: str
    ) -> Optional[str]:
        if not os.path.isdir(stage):
            return None
        try:
            if not os.listdir(stage):
                return None
            recovery = self._make_unique_dir(
                os.path.join(
                    destination_root, PARTIAL_RECOVERY_DIR, self._get_archive_name(job)
                )
            )
            os.makedirs(os.path.dirname(recovery), exist_ok=True)
            self._atomic_move_no_replace(stage, recovery)
            self._untrack_artifact(stage)
            job.temp_root = None
            job.final_destination = recovery
            return recovery
        except OSError:
            logger.exception("Could not recover commit stage task=%s", job.task_id)
            return None

    def _maybe_cleanup_sources(self, job: Job) -> None:
        if (
            job.state != JobState.COMPLETE
            or not job.cleanup_eligible
            or not job.commit_verified
        ):
            return
        if job.archive_set and not job.archive_set.is_complete:
            job.source_retention_reason = "incomplete_set"
            return
        if job.archive_set and not job.archive_set.cleanup_safe:
            job.source_retention_reason = (
                "volume_cleanup_unverified:"
                + (job.archive_set.cleanup_reason or "metadata_mismatch")
            )
            return
        if job.stego_ambiguous or job.stego_provisional:
            job.source_retention_reason = "ambiguous_or_provisional_stego"
            return
        try:
            policy = CleanupPolicy(job.cleanup_policy_snapshot)
        except ValueError:
            policy = CleanupPolicy.KEEP
        if policy == CleanupPolicy.KEEP:
            job.source_retention_reason = "policy_keep"
            return
        volumes = (
            list(job.archive_set.volumes)
            if job.archive_set and job.archive_set.volumes
            else [job.original_path or job.path]
        )
        for volume in volumes:
            if not volume or not os.path.lexists(volume):
                job.source_retention_reason = "source_missing"
                job.terminal_diagnostics.append(
                    f"Source retained because a volume disappeared: {volume or '<empty>'}"
                )
                return
            if os.path.islink(volume) or is_reparse_escape(volume):
                job.source_retention_reason = "source_reparse_or_link"
                job.terminal_diagnostics.append(
                    f"Source retained because it is a link/reparse point: {volume}"
                )
                return
            expected = job.source_identities.get(self._source_identity_key(volume))
            current = self._read_source_identity(volume)
            if expected is None or current != expected:
                job.source_retention_reason = "source_identity_changed"
                job.terminal_diagnostics.append(
                    f"Source retained because its identity changed: {volume}"
                )
                return

        if policy == CleanupPolicy.RECYCLE:
            self._recycle_sources_in_place(job, volumes)
            return

        _deleted, failures = self._delete_sources_permanently(
            job, volumes, policy.value
        )
        if not failures:
            job.source_retention_reason = f"cleaned:{policy.value}"

    def _delete_sources_permanently(
        self,
        job: Job,
        volumes: List[str],
        journal_policy: str,
        stop_on_failure: bool = False,
    ) -> Tuple[List[str], List[str]]:
        targets = [
            volume
            for volume in volumes
            if volume and os.path.lexists(volume)
        ]
        staged: List[Tuple[str, str, str, Optional[str]]] = []
        staging_failure_reason = "source_staging_failed"

        try:
            for volume in targets:
                expected = job.source_identities.get(
                    self._source_identity_key(volume)
                )
                if expected is None:
                    staging_failure_reason = "source_identity_changed"
                    raise OSError(f"Source identity is unavailable: {volume}")
                parent = os.path.dirname(os.path.abspath(volume))
                staging_dir = tempfile.mkdtemp(
                    prefix=f".smart7z_cleanup_{job.task_id[:8]}_", dir=parent
                )
                staged_path = os.path.join(staging_dir, os.path.basename(volume))
                journal_entry: Optional[str] = None
                if self.recovery_journal is not None:
                    journal_entry = self.recovery_journal.register_source_stage(
                        task_id=job.task_id,
                        original_path=volume,
                        staged_path=staged_path,
                        staging_dir=staging_dir,
                        expected_identity={
                            "device": int(expected.device),
                            "inode": int(expected.inode),
                            "size": int(expected.size),
                            "mtime_ns": int(expected.mtime_ns),
                            "is_dir": False,
                            "is_file": True,
                            "is_link": False,
                            "is_reparse": False,
                        },
                        cleanup_policy=journal_policy,
                    )
                    if journal_entry is None:
                        os.rmdir(staging_dir)
                        staging_failure_reason = "recovery_journal_unavailable"
                        raise OSError(
                            "Persistent source-cleanup journal registration failed: "
                            + (self.recovery_journal.last_error or "unknown error")
                        )
                    if not self.recovery_journal.source_stage_ready(journal_entry):
                        self.recovery_journal.complete_source_stage(journal_entry)
                        os.rmdir(staging_dir)
                        staging_failure_reason = "source_staging_changed"
                        raise OSError(
                            "Source-cleanup staging changed before the source move"
                        )
                try:
                    self._atomic_move_no_replace(volume, staged_path)
                except OSError:
                    if self.recovery_journal is not None:
                        self.recovery_journal.complete_source_stage(journal_entry)
                    os.rmdir(staging_dir)
                    raise
                staged.append((volume, staged_path, staging_dir, journal_entry))
                if self._read_source_identity(staged_path) != expected:
                    staging_failure_reason = "source_identity_changed"
                    raise OSError(f"Source identity changed during cleanup: {volume}")
        except OSError as exc:
            retained = self._restore_staged_sources(staged)
            job.source_retention_reason = staging_failure_reason
            job.terminal_diagnostics.append(
                f"Source cleanup was safely aborted before deletion: {exc}"
            )
            if retained:
                job.terminal_diagnostics.append(
                    f"A source could only be retained at: {retained}"
                )
            return [], list(targets)

        deleted: List[str] = []
        failures: List[str] = []
        for index, (volume, staged_path, staging_dir, journal_entry) in enumerate(staged):
            failed = False
            try:
                success = windows_adapters.delete_permanently(staged_path)
                if not success or os.path.lexists(staged_path):
                    failures.append(volume)
                    failed = True
                    self._restore_staged_source(
                        volume, staged_path, staging_dir, journal_entry
                    )
                else:
                    os.rmdir(staging_dir)
                    if self.recovery_journal is not None:
                        self.recovery_journal.complete_source_stage(journal_entry)
                    deleted.append(volume)
            except OSError:
                failures.append(volume)
                failed = True
                self._restore_staged_source(
                    volume, staged_path, staging_dir, journal_entry
                )
                logger.exception("Source cleanup failed task=%s", job.task_id)
            if failed and stop_on_failure:
                for remaining in staged[index + 1:]:
                    original, staged_path, staging_dir, journal_entry = remaining
                    failures.append(original)
                    self._restore_staged_source(
                        original, staged_path, staging_dir, journal_entry
                    )
                break
        if failures:
            job.source_retention_reason = f"cleanup_failed:{len(failures)}"
            job.terminal_diagnostics.append(
                f"Source cleanup failed for {len(failures)} volume(s)"
            )
        return deleted, failures

    def _recycle_sources_in_place(self, job: Job, volumes: List[str]) -> None:
        """Recycle strictly, with only policy-approved permanent fallbacks."""

        targets = [
            volume
            for volume in volumes
            if volume and os.path.lexists(volume)
        ]
        plans = []
        try:
            for volume in targets:
                assessment = windows_adapters.assess_recycle_bin(volume)
                if assessment.status not in {
                    windows_adapters.RECYCLE_READY,
                    windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE,
                    windows_adapters.RECYCLE_FALLBACK_TOO_LARGE,
                }:
                    raise OSError(
                        f"Unknown Recycle Bin assessment: {assessment.status!r}"
                    )
                plans.append((volume, assessment.status))
        except OSError:
            logger.exception("Recycle Bin preflight failed task=%s", job.task_id)
            job.source_retention_reason = "recycle_failed:preflight"
            self._notify_user(
                job,
                format_user_message("RECYCLE_FAILED"),
            )
            return

        recycled: List[str] = []
        for volume, status in plans:
            if status != windows_adapters.RECYCLE_READY:
                continue
            expected = job.source_identities.get(self._source_identity_key(volume))
            current = self._read_source_identity(volume)
            if expected is None or current != expected:
                job.source_retention_reason = (
                    f"recycle_partial:{len(recycled)}:source_identity_changed"
                )
                job.terminal_diagnostics.append(
                    f"Recycle Bin cleanup stopped because the source changed: {volume}"
                )
                self._notify_user(
                    job,
                    format_user_message("RECYCLE_FAILED"),
                )
                return
            try:
                success = windows_adapters.send_to_recycle_bin(volume)
            except OSError:
                success = False
                logger.exception("Recycle Bin cleanup failed task=%s", job.task_id)
            if success and not os.path.lexists(volume):
                recycled.append(volume)
                continue
            job.source_retention_reason = (
                f"recycle_partial:{len(recycled)}:1"
            )
            self._notify_user(
                job,
                format_user_message("RECYCLE_FAILED"),
            )
            return

        fallback_plans = [
            (volume, status)
            for volume, status in plans
            if status != windows_adapters.RECYCLE_READY
        ]
        fallback_paths = [volume for volume, _status in fallback_plans]
        deleted, failures = self._delete_sources_permanently(
            job,
            fallback_paths,
            "recycle_fallback",
            stop_on_failure=True,
        )
        deleted_keys = {
            self._source_identity_key(volume) for volume in deleted
        }
        fallback_counts = {
            windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE: 0,
            windows_adapters.RECYCLE_FALLBACK_TOO_LARGE: 0,
        }
        for volume, status in fallback_plans:
            if self._source_identity_key(volume) in deleted_keys:
                fallback_counts[status] += 1

        unavailable_count = fallback_counts[
            windows_adapters.RECYCLE_FALLBACK_UNAVAILABLE
        ]
        if unavailable_count:
            self._notify_user(
                job,
                format_user_message(
                    "RECYCLE_FALLBACK_UNAVAILABLE",
                    count=unavailable_count,
                ),
            )
        too_large_count = fallback_counts[
            windows_adapters.RECYCLE_FALLBACK_TOO_LARGE
        ]
        if too_large_count:
            self._notify_user(
                job,
                format_user_message(
                    "RECYCLE_FALLBACK_TOO_LARGE",
                    count=too_large_count,
                ),
            )

        if failures:
            prior_reason = job.source_retention_reason or "cleanup_failed"
            job.source_retention_reason = (
                "recycle_fallback_failed:" + prior_reason
            )
            self._notify_user(
                job,
                format_user_message("RECYCLE_FALLBACK_DELETE_FAILED"),
            )
            return

        if fallback_paths:
            job.source_retention_reason = (
                f"cleaned:recycle_with_fallback:{len(deleted)}"
            )
        else:
            job.source_retention_reason = "cleaned:recycle"

    def _remember_source_identities(self, job: Job) -> None:
        volumes = (
            list(job.archive_set.volumes)
            if job.archive_set and job.archive_set.volumes
            else [job.original_path or job.path]
        )
        for volume in volumes:
            if not volume:
                continue
            key = self._source_identity_key(volume)
            if key in job.source_identities:
                continue
            identity = self._read_source_identity(volume)
            if identity is not None:
                job.source_identities[key] = identity

    @staticmethod
    def _read_source_identity(path: str) -> Optional[SourceIdentity]:
        try:
            before = os.stat(path, follow_symlinks=False)
            after = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        before_identity = (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_size),
            int(before.st_mtime_ns),
        )
        after_identity = (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(after.st_mtime_ns),
        )
        if before_identity != after_identity:
            return None
        return SourceIdentity(
            device=after_identity[0],
            inode=after_identity[1],
            size=after_identity[2],
            mtime_ns=after_identity[3],
        )

    @staticmethod
    def _source_identity_key(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    @staticmethod
    def _atomic_move_no_replace(source: str, destination: str) -> None:
        move_no_replace_durable(source, destination)

    def _restore_staged_sources(
        self, staged: Iterable[Tuple[str, str, str, Optional[str]]]
    ) -> str:
        retained = ""
        for original, staged_path, staging_dir, journal_entry in reversed(list(staged)):
            restored = self._restore_staged_source(
                original, staged_path, staging_dir, journal_entry
            )
            if restored:
                retained = restored
        return retained

    def _restore_staged_source(
        self,
        original: str,
        staged_path: str,
        staging_dir: str,
        journal_entry: Optional[str] = None,
    ) -> str:
        if os.path.lexists(staged_path):
            try:
                Executor._atomic_move_no_replace(staged_path, original)
            except OSError:
                return staged_path
        try:
            os.rmdir(staging_dir)
        except OSError:
            return staging_dir
        if self.recovery_journal is not None:
            self.recovery_journal.complete_source_stage(journal_entry)
        return ""

    # ------------------------------------------------------------------
    # Nested scheduling and shared helpers
    # ------------------------------------------------------------------

    def _nested_output_remaining(self, job: Job) -> Optional[int]:
        if job.nested_depth <= 0:
            return None
        limit = max(0, int(job.nested_budget_limit or 0))
        if not limit:
            limit = max(
                0, int(self.config.get("max_nested_output_bytes", 0) or 0)
            )
        if not limit:
            return None
        budget_id = job.nested_budget_id or job.task_id
        job.nested_budget_id = budget_id
        job.nested_budget_limit = limit
        with self._nested_budget_lock:
            return self._nested_budgets.setdefault(budget_id, limit)

    def retain_nested_batches(self, active_batch_ids: Set[str]) -> None:
        """Release per-batch nested state as soon as its last job finishes."""

        active = {str(batch_id or "") for batch_id in active_batch_ids}
        with self._nested_budget_lock:
            for batch_id in list(self._nested_budgets):
                if batch_id not in active:
                    del self._nested_budgets[batch_id]
        extractor = self._nested_extractor
        if extractor is not None:
            extractor.retain_batches(active)

    def _account_nested_output(self, job: Job) -> None:
        if job.nested_depth <= 0 or not job.nested_budget_id:
            return
        limit = max(0, int(job.nested_budget_limit or 0))
        if not limit or job.nested_output_accounted > 0:
            return
        extraction = job.extraction_result
        amount = max(
            0,
            int(job.committed_output_bytes or 0),
            int(extraction.output_bytes if extraction else 0),
        )
        with self._nested_budget_lock:
            remaining = self._nested_budgets.setdefault(
                job.nested_budget_id, limit
            )
            self._nested_budgets[job.nested_budget_id] = max(
                0, remaining - amount
            )
        job.nested_output_accounted = amount

    def _may_scan_structure(self, job: Job) -> bool:
        """Nested outputs are archive candidates, never stego scan roots."""

        if job.nested_depth > 0:
            return False
        return bool(job.explicit_input or self.config.get("deep_scan", False))

    def _maybe_nested(self, job: Job) -> None:
        if not self.config.get("nested_extraction", False):
            return
        root = job.final_destination
        if not root or not os.path.exists(root):
            return
        try:
            from nested import NestedExtractor

            job.nested_budget_id = job.nested_budget_id or job.task_id
            nested_limit = max(0, int(job.nested_budget_limit or 0))
            if not nested_limit:
                nested_limit = max(
                    0,
                    int(self.config.get("max_nested_output_bytes", 0) or 0),
                )
            if nested_limit:
                job.nested_budget_limit = nested_limit
                with self._nested_budget_lock:
                    self._nested_budgets.setdefault(
                        job.nested_budget_id, nested_limit
                    )

            if self._nested_extractor is None:
                supported_formats = set()
                query_formats = getattr(self.runner, "supported_formats", None)
                if callable(query_formats):
                    supported_formats = query_formats(timeout=15)
                self._nested_extractor = NestedExtractor(
                    enabled=True,
                    submit_cb=self.nested_submit or (lambda child: None),
                    io_busy=lambda: False,
                    cancel_check=self._cancelled,
                    archive_extensions=supported_formats,
                )
            extractor = self._nested_extractor
            # Limits are live-configurable; counters reset per root batch while
            # content identities remain available for cross-batch cycle checks.
            extractor.enabled = True
            extractor.max_depth = max(
                0, int(self.config.get("max_nested_depth", 2))
            )
            extractor.max_children = max(
                1, int(self.config.get("max_nested_children", 50))
            )
            extractor.max_output_bytes = max(
                0, int(self.config.get("max_nested_output_bytes", 0) or 0)
            )
            extractor.submit_cb = self.nested_submit or (lambda child: None)
            extractor.begin_batch(job.nested_budget_id)
            extractor.scan_and_submit(job, root)
        except (OSError, TypeError, ValueError):
            logger.exception("Nested scheduling failed task=%s", job.task_id)

    def cleanup_job_artifacts(self, job: Job, terminal: bool = True) -> None:
        self._cleanup_temp_root(job)
        if terminal and job.temp_zip:
            temp_zip = job.temp_zip
            try:
                os.remove(temp_zip)
            except FileNotFoundError:
                self._untrack_artifact(temp_zip)
                job.temp_zip = None
            except OSError as exc:
                logger.warning("Carved temporary cleanup failed: %s", exc)
            else:
                self._untrack_artifact(temp_zip)
                job.temp_zip = None

    def _cleanup_temp_root(self, job: Job) -> bool:
        cleaned = True
        if job.temp_root:
            if self._remove_path(job.temp_root):
                job.temp_root = None
            else:
                cleaned = False
        extraction = job.extraction_result
        if extraction and extraction.temp_output_dir:
            path = extraction.temp_output_dir
            if os.path.basename(path).startswith((".smart7z_", "task_")):
                if self._remove_path(path):
                    extraction.temp_output_dir = ""
                else:
                    cleaned = False
            elif not os.path.lexists(path):
                extraction.temp_output_dir = ""
        return cleaned

    def _remove_path(self, path: str) -> bool:
        if not path:
            return True
        try:
            if os.path.islink(path) or os.path.isfile(path):
                os.unlink(path)
            elif os.path.isdir(path):
                self._rmtree_retry(path)
            elif not os.path.lexists(path):
                self._untrack_artifact(path)
                return True
            else:
                logger.warning("Temporary path has an unsupported type: %s", path)
                return False
        except OSError as exc:
            logger.warning("Temporary path cleanup failed for %s: %s", path, exc)
            return False
        removed = not os.path.lexists(path)
        if removed:
            self._untrack_artifact(path)
        return removed

    @staticmethod
    def _rmtree_retry(path: str, attempts: int = 3) -> None:
        for attempt in range(attempts):
            try:
                shutil.rmtree(path)
                return
            except FileNotFoundError:
                return
            except OSError:
                if attempt + 1 >= attempts:
                    raise
                time.sleep(0.25)

    def _create_temp_root(self, job: Job, destination_root: str, mode: str) -> str:
        if mode == "staging":
            base = os.path.abspath(
                self.config.get("_session_root")
                or self.config.get("temp_dir")
                or tempfile.gettempdir()
            )
        else:
            base = os.path.abspath(destination_root)
        os.makedirs(base, exist_ok=True)
        prefix = "task_" if mode == "staging" else ".smart7z_tmp_"
        path = tempfile.mkdtemp(prefix=f"{prefix}{job.task_id[:8]}_", dir=base)
        if not self._track_artifact(
            job,
            path,
            artifact_kind=(
                "session_extract" if mode == "staging" else "direct_extract"
            ),
            name_prefix=prefix,
            disposition="delete",
        ):
            os.rmdir(path)
            raise OSError("Persistent recovery registration failed for extraction root")
        return path

    def _track_artifact(
        self,
        job: Job,
        path: str,
        artifact_kind: str,
        name_prefix: str,
        disposition: str,
    ) -> bool:
        journal = self.recovery_journal
        if journal is None:
            return True
        entry_id = journal.register_artifact(
            path,
            task_id=job.task_id,
            artifact_kind=artifact_kind,
            name_prefix=name_prefix,
            disposition=disposition,
        )
        if entry_id is None:
            diagnostic = (
                f"Persistent recovery registration failed for {path}: "
                f"{journal.last_error or 'unknown error'}"
            )
            logger.warning(diagnostic)
            job.terminal_diagnostics.append(diagnostic)
            del job.terminal_diagnostics[:-50]
            return False
        return True

    def _untrack_artifact(self, path: str) -> None:
        if self.recovery_journal is not None:
            self.recovery_journal.unregister_artifact(path)

    def _get_dest_root(self, job: Job) -> str:
        source = job.original_path or job.path
        if job.extract_to_source_override or self.config.get(
            "extract_to_source", True
        ):
            return os.path.dirname(os.path.abspath(source))
        target = self.config.get("target_dir")
        return os.path.abspath(target) if target else os.path.dirname(os.path.abspath(source))

    def _get_archive_name(self, job: Job) -> str:
        if job.archive_set and job.archive_set.format_family != "standalone":
            base = Path(job.archive_set.main_path).name
        else:
            base = job.original_basename or Path(job.original_path or job.path).name
        base = re.sub(r"\.part0*1\.rar$", "", base, flags=re.IGNORECASE)
        base = re.sub(r"\.r00$", ".rar", base, flags=re.IGNORECASE)
        base = re.sub(r"\.\d{3,}$", "", base, flags=re.IGNORECASE)
        lower = base.lower()
        for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.7z", ".tgz"):
            if lower.endswith(suffix):
                return base[: -len(suffix)] or "archive"
        base = re.sub(r"\.(?:001|rar|zip|7z|tar|gz|bz2|xz)$", "", base, flags=re.IGNORECASE)
        return base.strip(" .") or "archive"

    @staticmethod
    def _normalized_member_key(path: str) -> str:
        normalized = path.replace("\\", "/").strip("/")
        normalized = "/".join(part for part in normalized.split("/") if part not in ("", "."))
        return os.path.normcase(normalized) if os.name == "nt" else normalized

    @staticmethod
    def _portable_rel(path: str) -> str:
        return path.replace("\\", "/")

    @staticmethod
    def _is_same_filesystem(first: str, second: str) -> bool:
        try:
            first_probe = first
            second_probe = second
            while not os.path.exists(first_probe):
                parent = os.path.dirname(first_probe)
                if parent == first_probe:
                    break
                first_probe = parent
            while not os.path.exists(second_probe):
                parent = os.path.dirname(second_probe)
                if parent == second_probe:
                    break
                second_probe = parent
            return os.stat(first_probe).st_dev == os.stat(second_probe).st_dev
        except OSError:
            if os.name == "nt":
                return os.path.splitdrive(os.path.abspath(first))[0].casefold() == os.path.splitdrive(
                    os.path.abspath(second)
                )[0].casefold()
            return False

    @staticmethod
    def _make_unique_path(path: str) -> str:
        if not os.path.exists(path):
            return path
        candidate_path = Path(path)
        for index in range(2, 1_000_000):
            candidate = candidate_path.with_name(
                f"{candidate_path.stem} ({index}){candidate_path.suffix}"
            )
            if not candidate.exists():
                return str(candidate)
        raise OSError("Could not allocate a unique output filename")

    @staticmethod
    def _make_unique_dir(path: str) -> str:
        if not os.path.exists(path):
            return path
        for index in range(2, 1_000_000):
            candidate = f"{path} ({index})"
            if not os.path.exists(candidate):
                return candidate
        raise OSError("Could not allocate a unique output directory")

    @staticmethod
    def _any_member_conflicts(
        source_dir: str, destination_root: str, items: List[str]
    ) -> bool:
        return any(os.path.exists(os.path.join(destination_root, item)) for item in items)

    def _apply_manifest_volume_info(
        self, job: Job, manifest: ArchiveManifest
    ) -> None:
        if not job.archive_set:
            return
        reasons: List[str] = []
        raw_count = manifest.raw_fields.get("Volumes", "")
        try:
            expected = int(raw_count)
        except (TypeError, ValueError):
            expected = 0
        actual = len(job.archive_set.volumes)
        if expected > 0 and expected != actual:
            reasons.append(f"7z_volumes={expected}, discovered={actual}")

        raw_index = manifest.raw_fields.get("Volume Index", "")
        try:
            volume_index = int(raw_index)
        except (TypeError, ValueError):
            volume_index = 0
        if volume_index > 0:
            reasons.append(f"7z_volume_index={volume_index}")

        if reasons:
            reason = "; ".join(reasons)
            job.archive_set.cleanup_safe = False
            job.archive_set.cleanup_reason = reason
            manifest.diagnostics.append(
                "Source volume cleanup disabled: " + reason
            )

    def _cancelled(self) -> bool:
        return bool(self.runner.cancel_check())

    def _mark_interrupted(self, job: Job, message: str) -> JobState:
        self._cleanup_temp_root(job)
        job.cleanup_eligible = False
        job.source_retention_reason = "interrupted"
        self._emit(
            job,
            JobState.INTERRUPTED,
            message,
            error_category=ErrorCategory.CANCELLED,
        )
        return JobState.INTERRUPTED

    def _fail(
        self,
        job: Job,
        message: str,
        category: ErrorCategory,
        retention_reason: str,
    ) -> JobState:
        job.cleanup_eligible = False
        job.source_retention_reason = retention_reason
        self._emit(job, JobState.FAILED, message, error_category=category)
        return JobState.FAILED
