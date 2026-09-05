---
name: qa
description: >
  Run QA tests for ParseCat. Analyzes git diff to determine affected areas,
  runs configured functional flows with configured personas, and generates
  diff-targeted QA evidence for PRs and smoke testing.
---

# QA Orchestrator

**SCOPE: This skill performs manual/functional QA only. Do not run lint, unit tests, type checks, or static analysis.**

## 1) Load config

Read `.factory/skills/qa/config.yaml`.

## 2) Resolve target environment

Use `default_target` unless explicitly overridden.
Respect `environments.<env>.restrictions`.

Preview rule:

- Treat Vercel/Netlify preview URLs as `development` behavior.
- Use dev flows and dev keys on preview URLs.
- Never treat preview URLs as prod/preprod.

## 3) Diff scoping

Run git diff and map changed files using `apps.*.path_patterns`.

- Run app flows only for affected apps.
- Do not load unaffected app modules.
- If no app matches the diff, return `INCONCLUSIVE` with: `No app code changed -- QA not applicable for this diff.`

## 4) App-specific pre-flight only

Run pre-flight checks only for affected apps.

- If a pre-flight fails, mark impacted flow `BLOCKED`, include remediation, and continue with other affected apps.

## 5) Execute only relevant flows

For each affected app, load `.factory/skills/qa-<app-name>/SKILL.md`.

- Choose only flows relevant to the diff.
- Include at least one negative/boundary test related to the changed behavior.
- If no listed flow fits, add an ad-hoc flow for the exact change.

## 6) Evidence capture

Text evidence is primary.

- Web: capture accessibility snapshots; store screenshots in `qa-results/$RUN_ID/`.
- CLI/TUI: use trimmed terminal snapshots.

When `video_evidence: true`:

- Record one WebM per browser flow (max 60s).
- Verify files exist before upload.
- Upload and embed per platform rules.
- If upload fails, fall back to text evidence and artifact references.

## 7) Quality gate

- Prioritize change-specific tests.
- Avoid unrelated flows.
- Keep testing interactive and functional.
- Mark `INCONCLUSIVE` if change intent cannot be determined.

## 8) Failure handling

**Never silently skip a flow. If a flow cannot complete, report it as BLOCKED with what was tried and how the user can fix it.**

## 9) Report output

Write `qa-results/report.md` using `.factory/skills/qa/REPORT-TEMPLATE.md`.

- Keep concise.
- Include table results and actionable items.
- Put all evidence in one collapsed details block.

## 10) Failure learning

Read `failure_learning` from config.

- For `suggest_in_report`, include a `Suggested Skill Updates` section only when genuinely new environment/workflow insights are discovered from BLOCKED/FAIL outcomes.
- Do not suggest updates for selector typos or expected product changes.
