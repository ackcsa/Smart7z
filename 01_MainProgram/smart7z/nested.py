"""Opt-in nested archive extraction with depth/cycle/quota guards."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Set, Tuple

from archive_classifier import classify_automatic_candidate
from discovery import is_multipart_child
from models import Job
from path_safety import is_reparse_escape

logger = logging.getLogger(__name__)

ARCHIVE_EXTENSIONS = frozenset(
    {
        ".7z",
        ".rar",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".iso",
        ".cab",
        ".msi",
        ".dmg",
        ".001",
    }
)


@dataclass
class _NestedBatchState:
    """Mutable scan state isolated to one root extraction batch."""

    visited: Set[Tuple[str, int, int, int, int]] = field(default_factory=set)
    submitted: int = 0
    scanned_bytes: int = 0


class NestedExtractor:
    def __init__(
        self,
        max_depth: int = 2,
        enabled: bool = False,
        submit_cb: Optional[Callable] = None,
        max_children: int = 50,
        max_output_bytes: int = 0,
        io_busy: Optional[Callable[[], bool]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
        archive_extensions: Optional[Iterable[str]] = None,
    ):
        self.max_depth = max(0, max_depth)
        self.enabled = enabled
        self.submit_cb = submit_cb or (lambda *a, **k: None)
        self.max_children = max(1, max_children)
        self.max_output_bytes = max(0, max_output_bytes)
        self.io_busy = io_busy or (lambda: False)
        self.cancel_check = cancel_check or (lambda: False)
        self.archive_extensions = set(ARCHIVE_EXTENSIONS)
        if archive_extensions:
            self.archive_extensions.update(
                extension.casefold()
                for extension in archive_extensions
                if isinstance(extension, str) and extension.startswith(".")
            )
        self.archive_extensions = frozenset(self.archive_extensions)
        self._batch_states: Dict[str, _NestedBatchState] = {}
        self._active_batch_id = ""

    def begin_batch(self, batch_id: str) -> _NestedBatchState:
        normalized = str(batch_id or "")
        self._active_batch_id = normalized
        return self._batch_states.setdefault(normalized, _NestedBatchState())

    def scan_and_submit(self, parent_job: Job, extracted_dir: str) -> int:
        if not self.enabled:
            return 0
        parent_depth = parent_job.nested_depth
        if parent_depth >= self.max_depth:
            return 0

        batch_id = parent_job.nested_budget_id or parent_job.task_id
        state = self.begin_batch(batch_id)

        parent_sources: Set[str] = {
            self._canonical(path) for path in parent_job.parent_sources if path
        }
        if parent_job.original_path:
            parent_sources.add(self._canonical(parent_job.original_path))
        if parent_job.path:
            parent_sources.add(self._canonical(parent_job.path))
        for a in parent_job.ancestry:
            parent_sources.add(self._canonical(a))

        before = state.submitted
        if os.path.isfile(extracted_dir):
            if not self._consume_scan_bytes(extracted_dir, state):
                return 0
            self._consider_file(
                parent_job,
                extracted_dir,
                parent_depth,
                parent_sources,
                state,
            )
        elif os.path.isdir(extracted_dir):
            self._scan_dir(
                parent_job,
                extracted_dir,
                parent_depth,
                parent_sources,
                state,
            )
        return state.submitted - before

    def _scan_dir(
        self,
        parent_job: Job,
        directory: str,
        depth: int,
        parent_sources: Set[str],
        state: _NestedBatchState,
    ) -> None:
        try:
            for root, dirs, files in os.walk(directory, topdown=True, followlinks=False):
                if self.cancel_check():
                    return
                while self.io_busy() and not self.cancel_check():
                    time.sleep(0.1)
                dirs[:] = [
                    name
                    for name in dirs
                    if not os.path.islink(os.path.join(root, name))
                    and not is_reparse_escape(os.path.join(root, name))
                ]
                for fname in files:
                    if self.cancel_check():
                        return
                    if state.submitted >= self.max_children:
                        logger.warning(
                            "Nested child quota reached (%s)", self.max_children
                        )
                        return
                    fpath = os.path.join(root, fname)
                    if not self._consume_scan_bytes(fpath, state):
                        return
                    self._consider_file(
                        parent_job,
                        fpath,
                        depth,
                        parent_sources,
                        state,
                    )
        except OSError:
            logger.exception("Nested scan error")

    def _consider_file(
        self,
        parent_job: Job,
        path: str,
        depth: int,
        parent_sources: Set[str],
        state: _NestedBatchState,
    ) -> bool:
        if state.submitted >= self.max_children or self.cancel_check():
            return False
        if (
            os.path.islink(path)
            or is_reparse_escape(path)
            or not os.path.isfile(path)
        ):
            return False
        norm = self._canonical(path)
        identity = self._identity(path)
        if identity is None or identity in state.visited or norm in parent_sources:
            return False
        if is_multipart_child(path) or not self._is_archive(path):
            return False

        child = Job(
            path=norm,
            original_path=norm,
            original_basename=Path(path).name,
            nested_depth=depth + 1,
            parent_sources=set(parent_sources) | {norm},
            ancestry=[self._canonical(p) for p in parent_job.ancestry if p]
            + [self._canonical(parent_job.path)],
            nested_budget_id=parent_job.nested_budget_id or parent_job.task_id,
            nested_budget_limit=max(0, int(parent_job.nested_budget_limit or 0)),
            cleanup_policy_snapshot=parent_job.cleanup_policy_snapshot,
            extract_to_source_override=parent_job.extract_to_source_override,
            explicit_input=False,
        )
        logger.info("Nested archive found: %s (depth %s)", norm, depth + 1)
        accepted = self.submit_cb(child)
        if accepted is False:
            return False
        state.visited.add(identity)
        state.submitted += 1
        return True

    def _is_archive(self, path: str) -> bool:
        return classify_automatic_candidate(
            path,
            self.archive_extensions,
            cancel_check=self.cancel_check,
        ).should_queue

    def retain_batches(self, active_batch_ids: Set[str]) -> None:
        """Release cycle/quota state once a root batch has no active jobs."""

        active = {str(batch_id or "") for batch_id in active_batch_ids}
        for batch_id in list(self._batch_states):
            if batch_id not in active:
                del self._batch_states[batch_id]
        if self._active_batch_id not in self._batch_states:
            self._active_batch_id = ""

    def reset(self) -> None:
        self._batch_states.clear()
        self._active_batch_id = ""

    def _consume_scan_bytes(
        self, path: str, state: _NestedBatchState
    ) -> bool:
        if not self.max_output_bytes:
            return True
        try:
            size = max(0, os.path.getsize(path))
        except OSError:
            return False
        if state.scanned_bytes + size > self.max_output_bytes:
            logger.warning(
                "Nested session scan byte quota reached (%s)",
                self.max_output_bytes,
            )
            return False
        state.scanned_bytes += size
        return True

    @staticmethod
    def _canonical(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    @classmethod
    def _identity(cls, path: str) -> Optional[Tuple[str, int, int, int, int]]:
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        return (
            cls._canonical(path),
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(info.st_mtime_ns),
        )
