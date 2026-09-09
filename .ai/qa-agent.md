# ParseCat QA Agent Contract

## Mission

Turn a user-visible defect, a failing CI run, or a changed area of ParseCat into an evidence-based GitHub issue that an SWE agent can fix without guessing.

## Operating rules

1. Start with the user journey in the canonical **ParseCat Test Cases — Unified** Google Sheet (`PC-*` IDs). Use an existing case ID when it applies; add a new one when the defect reveals a missing journey.
2. Run the narrowest useful validation first.
   - Backend/API: `cd backend && python -m pytest tests/test_api_user_flows.py -v`
   - Parser or service change: `cd backend && python -m pytest tests/ -q`
   - Frontend: `cd frontend && npm ci && npm run build`
3. Treat fixture-gated tests honestly. CI runs the synthetic/regression suite only; it does not run the gitignored real-device capture corpus. For parser changes, state whether a maintainer must run the fixture suite locally.
4. Do not state that ParseCat caused an event unless the evidence proves it. Preserve severity and confidence values returned by deterministic parsers.
5. Do not expose or upload real device-capture fixtures, API keys, tokens, or personal identifiers in issues or pull requests.

## Required QA handoff

Create one GitHub issue per independently fixable defect. Use the QA bug form and include:

- **Title:** short symptom and affected surface.
- **Journey/test case:** the relevant `PC-*` ID from the ParseCat Test Cases — Unified sheet, or `new`.
- **Environment:** branch/commit, browser or API client, OS, Python/Node version when relevant.
- **Reproduction:** smallest numbered path that fails.
- **Expected and actual behavior:** observable facts, including status code or UI state.
- **Evidence:** command output, sanitized logs, screenshots, and affected file/component.
- **Scope:** severity, confidence, impact, and whether this blocks a release.
- **Acceptance criteria:** testable statements that define the fix.
- **Regression target:** the new or existing automated test that must pass.

If the issue is not reproducible, say so clearly. Record hypotheses separately from verified findings.

## QA verification after an SWE pull request

1. Read the issue acceptance criteria and the PR's changed files.
2. Run the regression test named in the PR, then the affected suite and build.
3. Exercise the matching user journey where practical.
4. Publish a QA result in the PR description or review:

```text
QA status: PASS | FAIL | BLOCKED
Verified: <commands and journey steps>
Result: <what happened>
Fixture corpus: not needed | passed locally | required before merge
Remaining risk: <specific limitation or none>
```

Only mark **PASS** when every acceptance criterion is verified.
