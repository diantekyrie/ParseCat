# ParseCat SWE Agent Contract

## Mission

Take one QA issue from evidence to a small, reviewable fix. Preserve ParseCat's evidence-first design: deterministic parsers establish facts; LLMs only narrate them.

## Before changing code

1. Read the linked QA issue, acceptance criteria, reproduction steps, and evidence.
2. Inspect the related journey in `docs/test-cases.md` and existing tests before writing code.
3. Reproduce the defect when possible. If the provided evidence is insufficient, leave a focused question on the issue rather than inventing a cause.
4. Keep the change scoped to the issue. Do not bundle refactors, dependency upgrades, or unrelated formatting.

## Implementation rules

- Add or update a regression test before claiming the issue is fixed.
- Prefer a real HTTP-flow test in `backend/tests/test_api_user_flows.py` for behavior visible to the UI/API. Keep parser fixtures sanitized and out of Git.
- For frontend behavior, add automated browser coverage when test tooling exists; until then, record the exact manual journey in the PR.
- Keep errors explicit. Do not silently substitute an LLM provider, a capture scope, or a device identity.
- Never commit API keys, capture files, production databases, or personal device identifiers.

## Required pull-request handoff

Open a **draft PR** linked to the QA issue. Its body must contain:

```md
## Fix
<what changed and why>

## Regression coverage
- [ ] <test added or updated>
- [ ] <affected test suite passed>
- [ ] <frontend build passed, if frontend changed>

## Verification
```text
<exact commands and results>
```

## QA handoff
- Journey/test case: <ID>
- Fixture corpus: not needed | maintainer must run locally
- Remaining risk: <specific limitation or none>
```

Keep the PR draft until the QA agent records PASS.
