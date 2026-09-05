---
name: qa-backend
description: >
  QA tests for the ParseCat backend API. Verifies upload, summary, diagnosis,
  scan, and investigation endpoints with functional API checks.
---

# QA Module: Backend (API)

## App notes

- Backend stack: FastAPI + SQLModel.
- Entry point: `backend/app/main.py`.
- API routes: `backend/app/api/routes.py`.
- No user-auth middleware detected for API endpoints.

## Testing Target

When testing PR branch code:

1. Start backend locally from checked-out branch code: `cd backend && uvicorn app.main:app --reload`.
2. Use `http://127.0.0.1:8000` as base URL.
3. If service does not boot, mark backend flows `BLOCKED` with startup error.

Do not switch to unrelated remote environments for PR validation.

## Auth and credentials in CI

- API endpoints do not require interactive login.
- LLM provider checks rely on:
  - `ANTHROPIC_API_KEY`
  - `OPENAI_API_KEY`
- Optional model overrides:
  - `OPENAI_MODEL`
  - `OPENAI_CODEX_MODEL`

## Flow menu (pick only diff-relevant flows)

1. **Health and provider discovery**
   - Verify `/api/health` returns status and parsed section metadata.
   - Verify `/api/llm/providers` marks configured providers available.

2. **Capture upload acceptance and validation**
   - POST `/api/captures` with supported format.
   - Confirm response includes `capture_id`, `facts_found`, and warnings as applicable.
   - Negative: unsupported extension must return 400.

3. **Device and capture listing**
   - Verify `/api/devices`, `/api/devices/{label}/captures`, and summary endpoints return consistent capture IDs.

4. **Investigation listing and merged summary**
   - Verify `/api/investigations`, `/api/investigations/{label}/captures`, and merged summary endpoint behavior.

5. **Diagnose endpoint behavior**
   - POST `/api/captures/{id}/diagnose` with question and provider.
   - Verify factual bundle returned even when narration fails.
   - Verify unknown capture returns 404.

6. **Scan endpoint behavior**
   - POST `/api/captures/{id}/scan` and validate ranked findings structure.

7. **Follow-up history handling**
   - Send `history` payload and verify response continuity without treating history as new evidence.
   - Negative: malformed history must degrade safely, not 400.

## Evidence requirements

- Use response body excerpts as primary text evidence.
- Include request/response snippets proving expected and negative-path behavior.

## Known Failure Modes

1. **Fixture-dependent expectations in CI.** Real-device fixture-dependent outcomes can differ when fixtures are absent.
2. **Upload parse failures (422).** Corrupt or unsupported content inside files can fail after extension check.
3. **Narration-provider outages or missing keys.** `/diagnose` may return `report: null` with `llm_error` while verified facts remain usable.
4. **Unknown device/investigation labels.** Summary/list endpoints correctly return 404 for absent labels.
