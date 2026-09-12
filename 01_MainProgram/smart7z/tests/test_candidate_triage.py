"""Evidence-based candidate decisions and executor fallback contracts."""

import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DEFAULT_CONFIG
from executor import Executor
from models import ArchiveCandidate, Confidence, Job, JobState
from sevenzip import SevenZipRunner
from stego_candidates import is_exact_high_confidence_candidate, triage_candidates


def exact_candidate(start=10, end=100, **kwargs):
    return ArchiveCandidate(
        start_offset=start, end_offset=end, embedded_format="zip",
        confidence=Confidence.HIGH,
        validation_flags=[
            "central_directory_valid", "comment_bounds_valid",
            "all_central_entries_valid", "all_local_headers_valid",
            "entry_count_matches", "local_header_valid",
        ],
        **kwargs,
    )


class TestCandidateTriage(unittest.TestCase):
    def test_noise_does_not_compete_with_exact(self):
        exact = exact_candidate()
        noise = ArchiveCandidate(
            start_offset=15, end_offset=200, embedded_format="rar5", mode="signature_only"
        )
        result = triage_candidates([noise, exact], 200)
        self.assertEqual(result.decision, "DEFAULT_AUTO")
        self.assertEqual(result.candidates, [exact])
        self.assertEqual(result.ignored, [(noise, "signature_only")])

    def test_high_is_not_sufficient(self):
        candidate = exact_candidate()
        candidate.validation_flags = ["central_directory_valid"]
        result = triage_candidates([candidate], 200)
        self.assertEqual(result.decision, "DEFAULT_PRESELECT")
        self.assertEqual(result.recommended_index, 0)
        self.assertIsNone(Executor._auto_select_candidate([candidate]))

    def test_competitor_blocks_auto_even_when_provisional(self):
        exact = exact_candidate()
        other = exact_candidate(20, 150)
        other.validation_flags = ["local_header_valid", "end_provisional"]
        for items in ([other], [exact, other], [exact, exact_candidate(20, 150)]):
            with self.subTest(items=items):
                result = triage_candidates(items, 200)
                self.assertEqual(result.decision, "REVIEW")
                self.assertIsNone(result.recommended_index)
                self.assertIsNone(Executor._auto_select_candidate(items))

    def test_duplicate_zip64_alias_keeps_stronger_evidence(self):
        exact = exact_candidate()
        duplicate = copy.deepcopy(exact)
        duplicate.embedded_format = "ZIP64"
        duplicate.validation_flags = ["local_header_valid"]
        result = triage_candidates([duplicate, exact], 200)
        self.assertEqual(result.candidates, [exact])
        self.assertEqual(result.decision, "DEFAULT_AUTO")
        self.assertEqual(result.ignored, [(duplicate, "duplicate")])

    def test_invalid_and_evidenceless_candidates_are_ignored(self):
        for start, end in [(-1, 100), (100, 100), (10, 201)]:
            with self.subTest(start=start, end=end):
                result = triage_candidates([exact_candidate(start, end)], 200)
                self.assertEqual(result.decision, "IGNORE")
                self.assertEqual(result.ignored[0][1], "invalid_bounds")
        candidate = exact_candidate()
        candidate.validation_flags = []
        self.assertEqual(triage_candidates([candidate], 200).decision, "IGNORE")

    def test_empty_zip_and_compatible_modes_remain_automatic(self):
        for mode in ("inline", "append", "free_atom", "za", "mkv_attachment"):
            with self.subTest(mode=mode):
                candidate = exact_candidate(mode=mode)
                candidate.validation_flags[-1] = "empty_archive"
                self.assertEqual(triage_candidates([candidate], 200).decision, "DEFAULT_AUTO")

    def test_provisional_or_signature_flags_never_exact(self):
        for flag in ("boundary_provisional", "end_provisional", "signature_only"):
            candidate = exact_candidate()
            candidate.validation_flags.append(flag)
            self.assertFalse(is_exact_high_confidence_candidate(candidate))

    def test_noise_is_cached_without_marking_job_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "host.bin")
            path.write_bytes(b"x" * 200)
            executor = Executor(SevenZipRunner("7z.exe"), dict(DEFAULT_CONFIG))
            noise = ArchiveCandidate(
                start_offset=10, end_offset=200, embedded_format="7z", mode="signature_only"
            )
            job = Job(path=str(path))
            with mock.patch.object(executor, "_find_stego_candidates", return_value=[noise]) as scan:
                self.assertIsNone(executor._prepare_stego_candidate(job))
                self.assertIsNone(executor._prepare_stego_candidate(job))
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(job.state, JobState.QUEUED)
            self.assertEqual(job.stego_triage_decision, "IGNORE")
            self.assertEqual(len(job.stego_ignored_candidates), 1)
            self.assertTrue(path.exists())

    def test_warning_does_not_discard_a_competitor_to_force_auto(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "host.bin")
            path.write_bytes(b"x" * 200)
            executor = Executor(SevenZipRunner("7z.exe"), dict(DEFAULT_CONFIG))
            exact = exact_candidate()
            other = exact_candidate(20, 160)
            other.validation_flags = ["local_header_valid"]
            job = Job(path=str(path), stego_candidates=[exact, other])
            with mock.patch.object(executor, "_carve_candidate") as carve:
                self.assertIsNone(executor._prepare_stego_candidate(job, exact_only=True))
                carve.assert_not_called()
                self.assertEqual(
                    executor._prepare_stego_candidate(job), JobState.STEGO_CANDIDATE_REVIEW
                )
            self.assertEqual(job.stego_candidates, [exact, other])

    def test_auto_candidate_carves_and_recommended_candidate_waits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "host.bin")
            path.write_bytes(b"x" * 200)
            executor = Executor(SevenZipRunner("7z.exe"), dict(DEFAULT_CONFIG))
            candidate = exact_candidate()
            job = Job(path=str(path), stego_candidates=[candidate])
            with mock.patch.object(executor, "_carve_candidate", return_value="carved.zip") as carve:
                self.assertIsNone(executor._prepare_stego_candidate(job))
                carve.assert_called_once_with(job, candidate)
                self.assertEqual(job.temp_zip, "carved.zip")
            candidate = exact_candidate()
            candidate.validation_flags = ["local_header_valid"]
            job = Job(path=str(path), stego_candidates=[candidate])
            with mock.patch.object(executor, "_carve_candidate") as carve:
                self.assertEqual(executor._prepare_stego_candidate(job), JobState.STEGO_CANDIDATE_REVIEW)
                carve.assert_not_called()
                self.assertEqual(job.stego_recommended_index, 0)
