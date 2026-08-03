import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    Job, JobState, ErrorCategory, ArchiveCandidate, ArchiveMember,
    ArchiveManifest, ArchiveSet, ExtractionResult, VerificationResult,
    CommitRecord, CleanupPolicy, Confidence, TaskEvent, USER_NOTICE_LIMIT
)


class TestJob(unittest.TestCase):
    def test_create_job(self):
        job = Job(path="/test/archive.zip")
        self.assertEqual(job.path, "/test/archive.zip")
        self.assertEqual(job.state, JobState.QUEUED)
        self.assertIsNotNone(job.task_id)
        self.assertEqual(job.retry_stage, 0)
        self.assertEqual(job.password_attempt_index, 0)
        self.assertFalse(hasattr(job, 'manual_password'))

    def test_job_display_path(self):
        job = Job(path="/test/archive.zip", original_path="/test/renamed.zip")
        self.assertEqual(job.display_path, "/test/renamed.zip")

    def test_job_display_path_no_original(self):
        job = Job(path="/test/archive.zip")
        self.assertEqual(job.display_path, "/test/archive.zip")

    def test_job_is_stego(self):
        job = Job(path="/tmp/temp.zip", original_path="/test/video.mp4")
        self.assertTrue(job.is_stego)

    def test_job_not_stego(self):
        job = Job(path="/test/archive.zip")
        self.assertFalse(job.is_stego)

    def test_job_to_task_dict(self):
        job = Job(
            path="/test/archive.zip",
            retry_stage=1,
            extract_to_source_override=True,
        )
        d = job.to_task_dict()
        self.assertEqual(d['path'], "/test/archive.zip")
        self.assertEqual(d['retry_stage'], 1)
        self.assertTrue(d['extract_to_source_override'])
        self.assertIn('task_id', d)

    def test_job_from_task_dict(self):
        d = {
            'path': '/test/archive.zip',
            'retry_stage': 2,
            'password_attempt_index': 3,
            'extract_to_source_override': True,
        }
        job = Job.from_task_dict(d)
        self.assertEqual(job.path, "/test/archive.zip")
        self.assertEqual(job.retry_stage, 2)
        self.assertEqual(job.password_attempt_index, 3)
        self.assertTrue(job.extract_to_source_override)

    def test_legacy_source_hash_is_ignored_on_load(self):
        source = "/test/archive.zip"
        job = Job.from_task_dict(
            {
                "path": source,
                "source_identities": {
                    source: {
                        "device": 1,
                        "inode": 2,
                        "size": 3,
                        "mtime_ns": 4,
                        "content_sha256": "legacy",
                    }
                },
            }
        )
        identity = job.source_identities[source]
        self.assertFalse(hasattr(identity, "content_sha256"))
        serialized = job.to_task_dict()["source_identities"][source]
        self.assertNotIn("content_sha256", serialized)

    def test_user_notices_round_trip_with_bounded_history(self):
        notices = [f"notice-{index}" for index in range(USER_NOTICE_LIMIT + 5)]
        job = Job.from_task_dict(
            {
                "path": "/test/archive.zip",
                "user_notices": notices + [123, None],
            }
        )

        self.assertEqual(job.user_notices, notices[-USER_NOTICE_LIMIT:])
        self.assertEqual(
            job.to_task_dict()["user_notices"],
            notices[-USER_NOTICE_LIMIT:],
        )


class TestArchiveCandidate(unittest.TestCase):
    def test_create(self):
        c = ArchiveCandidate(
            embedded_format="zip",
            start_offset=100,
            end_offset=500,
            confidence=Confidence.HIGH
        )
        self.assertEqual(c.embedded_format, "zip")
        self.assertEqual(c.start_offset, 100)
        self.assertEqual(c.end_offset, 500)
        self.assertEqual(c.confidence, Confidence.HIGH)


class TestArchiveManifest(unittest.TestCase):
    def test_empty_manifest(self):
        m = ArchiveManifest()
        self.assertEqual(m.format, "")
        self.assertEqual(len(m.members), 0)
        self.assertEqual(m.total_size, 0)
        self.assertFalse(m.is_encrypted)

    def test_manifest_with_members(self):
        m = ArchiveManifest(format="zip")
        m.members.append(ArchiveMember(path="a.txt", size=100))
        m.members.append(ArchiveMember(path="b.txt", size=200, encrypted=True))
        m.total_size = 300
        m.is_encrypted = True
        self.assertEqual(len(m.members), 2)
        self.assertEqual(m.total_size, 300)
        self.assertTrue(m.is_encrypted)


class TestArchiveSet(unittest.TestCase):
    def test_single_volume(self):
        s = ArchiveSet(main_path="/test/a.zip", volumes=["/test/a.zip"],
                       format_family="standalone")
        self.assertTrue(s.is_complete)
        self.assertEqual(len(s.missing_indexes), 0)

    def test_multi_volume_incomplete(self):
        s = ArchiveSet(main_path="/test/a.001",
                       volumes=["/test/a.001", "/test/a.003"],
                       format_family="numeric_split",
                       missing_indexes=[2],
                       is_complete=False)
        self.assertFalse(s.is_complete)
        self.assertEqual(s.missing_indexes, [2])


class TestExtractionResult(unittest.TestCase):
    def test_default(self):
        r = ExtractionResult()
        self.assertFalse(r.success)
        self.assertEqual(r.return_code, -1)
        self.assertEqual(len(r.extracted_paths), 0)

    def test_success(self):
        r = ExtractionResult(success=True, return_code=0, temp_output_dir="/tmp/out")
        self.assertTrue(r.success)
        self.assertEqual(r.return_code, 0)


class TestVerificationResult(unittest.TestCase):
    def test_verified(self):
        v = VerificationResult(verified=True, expected_count=5, actual_count=5)
        self.assertTrue(v.verified)
        self.assertEqual(len(v.missing), 0)

    def test_with_missing(self):
        v = VerificationResult(verified=False, expected_count=5, actual_count=3,
                               missing=["a.txt", "b.txt"])
        self.assertFalse(v.verified)
        self.assertEqual(len(v.missing), 2)


class TestEnums(unittest.TestCase):
    def test_job_states(self):
        self.assertEqual(JobState.QUEUED.value, "queued")
        self.assertEqual(JobState.COMPLETE.value, "complete")
        self.assertEqual(JobState.PARTIAL_RECOVERY.value, "partial_recovery")

    def test_error_categories(self):
        self.assertEqual(ErrorCategory.BAD_PASSWORD.value, "bad_password")
        self.assertEqual(ErrorCategory.CANCELLED.value, "cancelled")

    def test_cleanup_policy(self):
        self.assertEqual(CleanupPolicy.KEEP.value, "keep")
        self.assertEqual(CleanupPolicy.RECYCLE.value, "recycle")
        self.assertEqual(CleanupPolicy.PERMANENT.value, "permanent")

    def test_confidence(self):
        self.assertEqual(Confidence.HIGH.value, "high")
        self.assertEqual(Confidence.MEDIUM.value, "medium")
        self.assertEqual(Confidence.LOW.value, "low")


if __name__ == '__main__':
    unittest.main()
