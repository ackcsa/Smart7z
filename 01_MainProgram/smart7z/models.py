"""Portable runtime models for the serialized Smart7z pipeline.

Password candidates stay outside these long-lived job models because they are
only needed during a listing/extraction attempt.
"""

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class JobState(enum.Enum):
    QUEUED = "queued"
    DISCOVERING = "discovering"
    GROUPED = "grouped"
    STANDALONE = "standalone"
    STEGO_CANDIDATE_REVIEW = "stego_candidate_review"
    LISTING = "listing"
    PASSWORD_ATTEMPT = "password_attempt"
    PASSWORD_REQUIRED = "password_required"
    PLANNED = "planned"
    SPACE_WAIT = "space_wait"
    EXTRACTING = "extracting"
    VERIFYING = "verifying"
    COMMITTING = "committing"
    COMPLETE = "complete"
    PARTIAL_RECOVERY = "partial_recovery"
    FAILED = "failed"
    SKIPPED = "skipped"
    INTERRUPTED = "interrupted"


TERMINAL_STATES = frozenset({
    JobState.COMPLETE,
    JobState.PARTIAL_RECOVERY,
    JobState.FAILED,
    JobState.SKIPPED,
    JobState.INTERRUPTED,
})
USER_NOTICE_LIMIT = 50


class ErrorCategory(enum.Enum):
    NOT_ARCHIVE = "not_archive"
    UNSUPPORTED_FORMAT = "unsupported_format"
    BAD_PASSWORD = "bad_password"
    MISSING_VOLUME = "missing_volume"
    CORRUPT_HEADER = "corrupt_header"
    TRUNCATED_INPUT = "truncated_input"
    DISK_FULL = "disk_full"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNSAFE_PATH = "unsafe_path"
    OUTPUT_CONFLICT = "output_conflict"
    VERIFY_FAILED = "verify_failed"
    INTERNAL_ERROR = "internal_error"


class CleanupPolicy(enum.Enum):
    KEEP = "keep"
    RECYCLE = "recycle"
    PERMANENT = "permanent"


class ExtractMode(enum.Enum):
    STAGING = "staging"
    DIRECT = "direct"


class Confidence(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ArchiveCandidate:
    host_format: str = ""
    embedded_format: str = ""
    start_offset: int = 0
    end_offset: int = 0
    mode: str = ""
    confidence: Confidence = Confidence.LOW
    validation_flags: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return max(0, self.end_offset - self.start_offset)


@dataclass
class ArchiveMember:
    path: str = ""
    attributes: str = ""
    size: int = 0
    packed_size: int = 0
    method: str = ""
    encrypted: bool = False
    crc: str = ""
    timestamp: str = ""
    is_dir: bool = False
    size_known: bool = False
    is_link: bool = False
    link_target: str = ""
    is_anti: bool = False
    is_alt_stream: bool = False


@dataclass
class ArchiveManifest:
    format: str = ""
    members: List[ArchiveMember] = field(default_factory=list)
    total_size: int = 0
    is_encrypted: bool = False
    used_switch: str = ""
    raw_fields: Dict[str, str] = field(default_factory=dict)
    summary_mode: bool = False
    listing_return_code: int = -1
    entry_count: int = 0
    diagnostics: List[str] = field(default_factory=list)


@dataclass
class ArchiveSet:
    main_path: str = ""
    volumes: List[str] = field(default_factory=list)
    format_family: str = ""
    missing_indexes: List[int] = field(default_factory=list)
    is_complete: bool = True
    cleanup_safe: bool = True
    cleanup_reason: str = ""


@dataclass(frozen=True)
class SourceIdentity:
    device: int = 0
    inode: int = 0
    size: int = 0
    mtime_ns: int = 0


@dataclass
class ExtractionResult:
    success: bool = False
    return_code: int = -1
    temp_output_dir: str = ""
    extracted_paths: List[str] = field(default_factory=list)
    extracted_directories: List[str] = field(default_factory=list)
    missing_entries: List[str] = field(default_factory=list)
    failed_entries: List[str] = field(default_factory=list)
    unsafe_entries: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    error_category: Optional[ErrorCategory] = None
    output_bytes: int = 0
    output_file_count: int = 0
    output_directory_count: int = 0
    quota_exceeded: bool = False


@dataclass
class VerificationResult:
    verified: bool = False
    expected_count: int = 0
    actual_count: int = 0
    expected_directory_count: int = 0
    actual_directory_count: int = 0
    missing: List[str] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)
    missing_directories: List[str] = field(default_factory=list)
    extra_directories: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    unsafe: List[str] = field(default_factory=list)
    size_mismatches: List[str] = field(default_factory=list)
    crc_mismatches: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)


@dataclass
class CommitRecord:
    source: str = ""
    destination: str = ""
    collision_decision: str = ""
    completed: bool = False
    failure_reason: str = ""
    expected_size: int = -1
    expected_identity: Optional[SourceIdentity] = None
    verified: bool = False


@dataclass
class Job:
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    path: str = ""
    original_path: str = ""
    original_basename: str = ""
    state: JobState = JobState.QUEUED
    retry_stage: int = 0
    # Password attempt bookkeeping contains indexes/counts; values are transient.
    password_attempt_index: int = 0
    password_candidates_exhausted: bool = False
    temp_zip: Optional[str] = None
    archive_set: Optional[ArchiveSet] = None
    manifest: Optional[ArchiveManifest] = None
    stego_candidates: List[ArchiveCandidate] = field(default_factory=list)
    selected_candidate: Optional[ArchiveCandidate] = None
    # A reviewed candidate is carved by the serial worker, never by the Tk
    # callback that records the user's selection.
    stego_selection_pending: bool = False
    extraction_result: Optional[ExtractionResult] = None
    verification_result: Optional[VerificationResult] = None
    commit_records: List[CommitRecord] = field(default_factory=list)
    error_category: Optional[ErrorCategory] = None
    error_message: str = ""
    attempt_count: int = 0
    temp_root: Optional[str] = None
    final_destination: str = ""
    progress: int = 0
    nested_depth: int = 0
    parent_sources: Set[str] = field(default_factory=set)
    ancestry: List[str] = field(default_factory=list)
    nested_budget_id: str = ""
    nested_budget_limit: int = 0
    nested_output_accounted: int = 0
    cleanup_eligible: bool = False
    cleanup_policy_snapshot: str = ""
    extract_to_source_override: bool = False
    source_retention_reason: str = ""
    source_identities: Dict[str, SourceIdentity] = field(default_factory=dict)
    explicit_input: bool = False
    approved_output_bytes: int = 0
    approved_file_count: int = 0
    committed_output_bytes: int = 0
    commit_verified: bool = False
    stego_ambiguous: bool = False
    stego_provisional: bool = False
    terminal_diagnostics: List[str] = field(default_factory=list)
    user_notices: List[str] = field(default_factory=list)
    state_history: List[JobState] = field(default_factory=lambda: [JobState.QUEUED])
    _retrying: bool = False

    @property
    def display_path(self) -> str:
        return self.original_path or self.path

    @property
    def is_stego(self) -> bool:
        return bool(self.original_path) and self.original_path != self.path

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def record_state(self, state: JobState) -> None:
        self.state = state
        if not self.state_history or self.state_history[-1] != state:
            self.state_history.append(state)

    def to_task_dict(self) -> Dict[str, Any]:
        """Return runtime metadata suitable for diagnostics/tests."""
        serialized_identities = {
            str(path): {
                "device": identity.device,
                "inode": identity.inode,
                "size": identity.size,
                "mtime_ns": identity.mtime_ns,
            }
            for path, identity in self.source_identities.items()
        }
        return {
            "path": self.path,
            "task_id": self.task_id,
            "original_path": self.original_path,
            "original_basename": self.original_basename,
            "retry_stage": self.retry_stage,
            "password_attempt_index": self.password_attempt_index,
            "password_candidates_exhausted": self.password_candidates_exhausted,
            "temp_zip": self.temp_zip,
            "nested_depth": self.nested_depth,
            "parent_sources": sorted(self.parent_sources),
            "ancestry": list(self.ancestry),
            "nested_budget_id": self.nested_budget_id,
            "nested_budget_limit": self.nested_budget_limit,
            "nested_output_accounted": self.nested_output_accounted,
            "source_identities": serialized_identities,
            "cleanup_policy_snapshot": self.cleanup_policy_snapshot,
            "extract_to_source_override": self.extract_to_source_override,
            "explicit_input": self.explicit_input,
            "stego_selection_pending": self.stego_selection_pending,
            "user_notices": list(self.user_notices[-USER_NOTICE_LIMIT:]),
            "_retrying": self._retrying,
        }

    @staticmethod
    def from_task_dict(d: Dict[str, Any]) -> "Job":
        source_identities: Dict[str, SourceIdentity] = {}
        raw_identities = d.get("source_identities", {}) or {}
        if isinstance(raw_identities, dict):
            for path, value in raw_identities.items():
                if isinstance(value, SourceIdentity):
                    source_identities[str(path)] = value
                    continue
                if not isinstance(value, dict):
                    continue
                try:
                    source_identities[str(path)] = SourceIdentity(
                        device=int(value.get("device", 0) or 0),
                        inode=int(value.get("inode", 0) or 0),
                        size=int(value.get("size", 0) or 0),
                        mtime_ns=int(value.get("mtime_ns", 0) or 0),
                    )
                except (TypeError, ValueError):
                    continue
        raw_notices = d.get("user_notices", []) or []
        user_notices = (
            [str(value) for value in raw_notices if isinstance(value, str)][
                -USER_NOTICE_LIMIT:
            ]
            if isinstance(raw_notices, list)
            else []
        )
        job = Job(
            path=d.get("path", ""),
            retry_stage=d.get("retry_stage", 0),
            password_attempt_index=int(d.get("password_attempt_index", 0) or 0),
            password_candidates_exhausted=bool(
                d.get("password_candidates_exhausted", False)
            ),
            temp_zip=d.get("temp_zip"),
            nested_depth=d.get("nested_depth", 0),
            parent_sources=set(d.get("parent_sources", set()) or set()),
            ancestry=list(d.get("ancestry", []) or []),
            nested_budget_id=str(d.get("nested_budget_id", "") or ""),
            nested_budget_limit=max(0, int(d.get("nested_budget_limit", 0) or 0)),
            nested_output_accounted=max(
                0, int(d.get("nested_output_accounted", 0) or 0)
            ),
            source_identities=source_identities,
            cleanup_policy_snapshot=str(
                d.get("cleanup_policy_snapshot", "") or ""
            ),
            extract_to_source_override=bool(
                d.get("extract_to_source_override", False)
            ),
            explicit_input=bool(d.get("explicit_input", False)),
            stego_selection_pending=bool(d.get("stego_selection_pending", False)),
            user_notices=user_notices,
            _retrying=d.get("_retrying", False),
        )
        job.task_id = d.get("task_id", job.task_id)
        job.original_path = d.get("original_path", "")
        job.original_basename = d.get("original_basename", "")
        return job


@dataclass
class TaskEvent:
    task_id: str = ""
    job_state: JobState = JobState.QUEUED
    path: str = ""
    progress: int = 0
    message: str = ""
    error_category: Optional[ErrorCategory] = None
    data: Dict[str, Any] = field(default_factory=dict)
