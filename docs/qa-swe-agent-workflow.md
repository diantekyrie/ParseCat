# ParseCat QA ↔ SWE Agent Workflow

This is the repository's working agreement for an AI QA agent and an AI SWE agent. It is designed for ParseCat's local-MVP model and its evidence-first approach to Android bugreport and capture analysis.

## Roles

| Role | Owns | Must not do |
|---|---|---|
| QA agent | Reproduction, test coverage review, evidence gathering, severity/confidence, acceptance criteria, regression verification | Guess a root cause or mark a fix verified without running the checks |
| SWE agent | Scoped implementation, regression test, draft PR, exact verification output | Change scope without evidence or merge an unverified draft |
| Maintainer | Product decisions, real-device fixture validation when needed, final merge policy | Treat a passing synthetic CI run as full parser-corpus validation |

The role contracts live in [`.ai/qa-agent.md`](../.ai/qa-agent.md) and [`.ai/swe-agent.md`](../.ai/swe-agent.md).

## Lifecycle

1. **Intake:** QA runs a targeted test or user journey and opens the **QA bug report** issue form.
2. **Triage:** QA gives the issue an evidence level:
   - **verified:** repeatable with evidence;
   - **suspected:** evidence points to an issue but reproduction is incomplete;
   - **blocked:** needs a fixture, account, or product decision.
3. **Fix:** SWE reads the issue, reproduces it where possible, adds a regression test, and opens a draft PR using the repository template.
4. **Verification:** QA checks every acceptance criterion, runs the named regression, then the affected suite and frontend build where applicable.
5. **Merge:** A PR is ready only after QA records **PASS**, all CI checks pass, and any required real-device fixture validation has been completed by a maintainer.

## ParseCat validation matrix

| Changed area | Minimum verification |
|---|---|
| API route or user flow | `cd backend && python -m pytest tests/test_api_user_flows.py -v` |
| Parser, correlation, ingestion, persistence, or reasoning | `cd backend && python -m pytest tests/ -q`; state whether the local real-device fixture corpus was also run |
| Frontend | `cd frontend && npm ci && npm run build`; run the matching web journey from the ParseCat Test Cases — Unified Google Sheet |
| CI/workflow only | Validate YAML and confirm the intended job/check name |

## First automated-QA backlog

The best first agent-owned work is the unautomated web coverage called out in the ParseCat Test Cases — Unified Google Sheet (the `PC-upload-*`, `PC-browse-*`, `PC-triage-*`, `PC-scan-*`, `PC-diagnose-*`, `PC-followup-*`, `PC-investigation-*`, and `PC-resilience-*` cases carried over from the former `docs/test-cases.md`):

1. Add Playwright and cover upload validation, disabled controls, filters, exports, and backend-unreachable states.
2. Promote the API cases marked 🟡 to true HTTP-boundary tests where the route's form parsing or response shape can fail.
3. Keep real device-capture fixtures local and explicitly report skipped counts in CI, as the existing workflow does.

## How to run this with GPT-6 Astra

Use a single issue and stay in the role:

- **QA prompt:** “Act as the ParseCat QA agent. Inspect issue #<n>, reproduce it, and update the issue with the required QA handoff. Do not modify product code.”
- **SWE prompt:** “Act as the ParseCat SWE agent. Fix issue #<n> using the SWE contract. Add regression coverage, run the required checks, and open a draft PR.”
- **QA verification prompt:** “Act as the ParseCat QA agent. Verify PR #<n> against issue #<n>. Record PASS, FAIL, or BLOCKED using the QA contract.”

Astra should work through the QA issue and draft PR in sequence. The separate contracts keep the handoff inspectable and prevent a code change from being called verified just because it builds.
