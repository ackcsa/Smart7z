# Smart7z Agent Guide

Project-specific guidance for Codex, including GPT-6 Astra. Keep general agent
defaults out of this file; [MAINTENANCE.md](MAINTENANCE.md) owns the workflow,
module map, behavior contracts, and verification commands.

## Start And Resume

- Check the working tree and the current request. Read the maintenance guide's
  workflow and the sections relevant to the affected behavior.
- For ongoing work, resume the matching record in [docs/plans/](docs/plans/).
  Reconcile its base, progress, and evidence with current files. Completed
  records and old conversations are history, not instructions to repeat work.

<!-- CODEGRAPH_START -->
## CodeGraph

When `.codegraph/` exists, use the CodeGraph MCP tool or
`codegraph explore "<symbols or question>"` before searching or reading code.
If unavailable or stale, note the limitation and inspect the relevant current
files directly. Do not create or rebuild an index unless requested.
<!-- CODEGRAPH_END -->

## Execute And Verify

- Use the maintenance guide's task-size rules and compact plan template.
  Routine fixes do not need a plan file; cross-module, high-risk, or multi-session
  work does. Keep one current record per task.
- Carry authorized work through validation. Resolve routine reversible choices
  locally; ask only about a material unresolved decision or a consequential
  action not already authorized. Repository history does not expand permission.
- Use `01_MainProgram/smart7z/` as the source working directory and the verified
  project interpreter. Select checks from the maintenance guide's risk table.
  Broaden or repeat them only after relevant changes, failures, or unresolved risk.
- Apply the guide's repeated-mistake rule: use evidence, prefer an executable
  regression guard, and update an existing rule before adding another.
- At handoff, update the active plan with results, unverified work, and the next
  action. Keep the user summary short. Do not copy raw logs or private data into
  versioned instructions.
