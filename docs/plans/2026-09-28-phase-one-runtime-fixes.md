# Phase One Runtime Fixes
Status: complete
Date: 2026-09-28; Base: 8ce4f1a

## Outcome And Scope
Fix malformed IPC requests terminating the listener, premature per-file batch
startup, and retained discard markers. Ordinary queued work runs small to large;
equal sizes retain receipt order, interactive retries retain priority, and active
work is not preempted. Preserve frozen cleanup policies and cancellation races.
Cover ready and initializing windows, files and directory scans.
Independent requests not yet received cannot participate in queue ordering.
No structural refactor, installation, packaging, publishing, or global settings.
ModelTrace remains disabled for this conversation.

## Progress
- [x] Reconcile review findings, working tree, contracts, and project interpreter.
- [x] Add regression tests and demonstrate the original failures.
- [x] Repair IPC parsing, batch startup, and discard state lifetime.
- [x] Run affected checks and record remaining boundaries.

## Decisions And Evidence
- Existing maintenance-document changes and the completed September 14 plan
  belong to prior work and are preserved.
- CodeGraph remains a navigation aid; its truncated source and incomplete caller
  results are checked against current files and tests. Do not rebuild its index.
- Read upstream `skills/stop-that-shit/SKILL.md` from
  https://github.com/lennney/stop-that-shit. Apply its advisory scope and
  verification rules; do not install hooks or change trust/global configuration.
- Prior read-only probes reproduced IPC TypeError escape, 100 stale discard IDs
  after removing 100 queued jobs, and premature large-file execution between
  external submissions. Those probes are not packaged-application acceptance.
- Red run: project interpreter, source cwd, `verify_project.py --pattern
  test_ui_runtime.py --pattern test_ui_qt_behaviors.py --pattern
  test_workflow_regressions.py --report-dir ../../.sandbox-test/phase-one-20260928/red`.
  78 tests, 43 failing assertions/subtests and 3 errors, zero skips. Failures are
  the new IPC listener, file/directory intake, and discard-marker regressions;
  the repeated discard assertions are one root cause, not separate incidents.
- Discarded non-active jobs are rejected by scheduler registration identity,
  including the dequeue/publication gap and candidate-response gap. Only an
  active discarded job needs a transient marker until result publication.
- First repaired-state run: the red selection plus `test_acceptance.py`, 129
  tests passed, zero failures/errors/skips. Added follow-up coverage for startup,
  pending scans, candidate-response cancellation, and actual Qt/7-Zip intake
  routes; final verification must include these later additions.
- Expanded verification exposed test fixtures that bypassed task registration,
  omitted the next scan's active state, or compared Windows paths case-sensitively.
  Corrected those fixtures without weakening behavior assertions. Inspection also
  found that startup auto-start intent must remain attached to pending jobs, so
  cancelling an automatic request cannot arm later manual input; added coverage.
- Final command, source cwd, project Python 3.14.6 / PySide6 6.11.1:
  ```
  .build-venv/Scripts/python.exe -B verify_project.py --pattern "test_*qt*.py" --pattern test_ui_runtime.py --pattern test_workflow_regressions.py --pattern test_acceptance.py --pattern test_runtime_safety.py --pattern test_user_messages.py --pattern test_runtime_startup.py --pattern test_integration_real7z.py --report-dir ../../.sandbox-test/phase-one-20260928/final
  ```
  314 tests passed in 64.75 seconds, zero failures/errors/skips. Input fingerprint:
  `20f45dca09fe2b815d84f6fdcd722296153ab18c2691ddc7aa46fc9b84a87e45`.
  Real Qt/7-Zip cases cover IPC files, CLI files, IPC directories, manual GUI
  scans, and mixed files/directories during initialization; assert small-first
  execution, verified output hashes, and retained source hashes.
- Malformed IPC cases use real loopback sockets and verify a successful request
  after each rejected request. Existing active-parent and dequeue cancellation
  regressions pass; a new barrier covers discard during candidate response.
- `git diff --check` passed. All 59 local manual links/anchors resolve; message
  contracts passed. Browser policy rejected local-file preview, so visual manual
  rendering is unverified; no alternate route was used to bypass that policy.
- Updated the existing user manual and an Unreleased changelog section. No
  version bump, build, installation, release, commit, or global skill/hook changes.

### Carry Forward
- A task's registry identity, not a permanently retained cancellation ID, proves
  whether a dequeued or resuming task still belongs to the scheduler.
- Startup intent belongs to surviving pending jobs/scan requests. Ready-window
  automatic starts can wait for pending scans without a fixed delay.
- Batch ordering applies to work received before selection. Explorer's separate
  launches do not provide a complete selection boundary; strict ordering over
  requests not yet received would require an explicit collection protocol.
  Display-column sorting remains independent of execution ordering.
- IPC state-reader deduplication and optional intake-coordinator extraction remain
  later-stage candidates, not changes authorized or required by this record.

## Resume
Phase-one implementation is complete. Next: user review and selection of the
next stage. Unverified: manual visual rendering and packaged Explorer/installer
acceptance. The affected test selection is not a full release/build gate.
