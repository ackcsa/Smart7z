# Lightweight Maintenance Workflow

Status: complete
Date: 2026-09-14
Base: `8ce4f1a` (working tree clean before this task)

## Outcome And Scope

Make Smart7z maintenance resumable with concise, repository-local guidance
suited to Codex with GPT-6 Astra. Reuse the existing maintenance guide and
verification entry point. Add no runtime behavior, release artifacts, global
model settings, scheduled automation, or new test framework.

Acceptance: the agent entry point links to one workflow definition; that
definition covers plan selection, resumption, proportionate validation, and
evidence-based handling of repeated mistakes. All local document links resolve.
The changes remain ordinary versionable files outside local evidence folders.

## Progress

- [x] Inspect the current repository, verification gate, and prior release record.
- [x] Fetch official GPT-6 Astra prompting guidance.
- [x] Add the agent entry point and extend the existing maintenance guide.
- [x] Check links, instruction consistency, Git visibility, and the final diff.

## Decisions And Evidence

- Put the plan template and recurrence rule in [MAINTENANCE.md](../../MAINTENANCE.md);
  keep [AGENTS.md](../../AGENTS.md) as the short entry point. Do not add separate
  architecture, lessons, handoff, or prompt-framework files.
- Use `docs/plans/` for short, versionable task records. Keep raw logs and
  private fixtures in the existing ignored `.sandbox-test/` directory.
- Follow [official Astra prompting guidance](https://developers.openai.com/api/docs/guides/latest-model/gpt-6-astra#prompting-best-practices):
  clarify scope, continue authorized work, avoid conflicting instructions,
  and stop expanding verification once the relevant checks pass.
- This task changes maintenance instructions only. Validate those artifacts;
  do not repeat the previous 529-test run, rebuild, or publish.
- Validation on 2026-09-14, from the repository root: `git diff --check` passed;
  `git status --short --untracked-files=all` showed only the three intended
  documents. The base remains `8ce4f1a`; no commit or push was made.
- PowerShell `ConvertFrom-Markdown` and XML/URI parsing resolved all 13 local
  link targets. The existing manual's `options-save` anchor was also checked.
  No trailing whitespace or replacement characters were found.
- Instruction review covered routine fixes without plans, risk-based checks,
  resuming completed work, same-cause recurrence versus retries, immediate
  safeguards for data-loss risk, and preserving authorization boundaries.

## Resume

None. The maintenance workflow is in place. Product tests, packaged-app
acceptance, installation, and release operations were outside this task;
no new product acceptance or model-behavior evaluation is claimed.
