---
name: qa-web
description: >
  QA tests for the ParseCat frontend web app. Verifies upload, triage views,
  scan/diagnose UI behavior, and investigation workflows through real browser interactions.
---

# QA Module: Web (frontend)

## App notes

- Frontend stack: React + Vite.
- Main UI entry: `frontend/src/App.jsx`.
- API calls are proxied from frontend to backend under `/api`.
- No end-user login/auth flow exists in the product.

## Testing Target (mandatory)

This repository does **not** use detected Vercel/Netlify PR preview deployments.

When testing PR branch code:

1. Start frontend locally from checked-out branch code: `cd frontend && npm run dev`.
2. Confirm backend is reachable at `http://127.0.0.1:8000`.
3. Test against localhost URL from the dev server.

Do **not** fall back to remote dev/staging/prod URLs for PR validation. If local startup fails, mark flows as `BLOCKED`.

## Auth and credentials in CI

- No interactive user login is required.
- LLM narration provider coverage depends on env vars:
  - `ANTHROPIC_API_KEY`
  - `OPENAI_API_KEY`
- These are injected by CI secrets. The agent should not prompt for manual login.

## Flow menu (pick only diff-relevant flows)

1. **Upload and parse captures**
   - Verify file picker accepts `.zip/.txt/.pcap/.pcapng`.
   - Upload one file and confirm capture appears with ID and filename.
   - Negative: unsupported extension should show API error.

2. **Multi-file upload progression**
   - Upload multiple files in one action.
   - Verify progress text updates and latest capture is selected.

3. **Investigation-linked capture flow**
   - Set investigation label before upload.
   - Confirm captures appear under investigation scope.

4. **Scan for problems UI flow**
   - Trigger “Scan for problems.”
   - Verify findings list or valid empty-state language.
   - Verify LLM narration error state still preserves factual findings.

5. **Diagnose capture flow**
   - Ask a capture-level question.
   - Verify claim cards, report rendering, and provider labeling.
   - Negative: attempt diagnose with no selected capture must remain disabled.

6. **Follow-up diagnosis continuity**
   - Ask follow-up after a base diagnosis.
   - Verify follow-up appears and base diagnosis remains intact.

7. **Investigation-wide diagnosis flow**
   - With >=2 linked captures, switch to investigation scope and diagnose.
   - Negative: with <2 captures, investigation diagnose must be unavailable.

8. **Filtering and export utilities**
   - Apply app/timeline/incident filters and verify scoped data changes.
   - Export summary and diagnosis artifacts and verify files download.

## Evidence requirements

- Primary: accessibility snapshots with clear step labels.
- Secondary: screenshots in `qa-results/$RUN_ID/`.
- With `video_evidence: true`, record one WebM per web flow and upload per platform rules.

## Known Failure Modes

1. **Backend not running on expected port.** Frontend API calls fail if `http://127.0.0.1:8000` is unreachable.
2. **No capture selected.** Diagnose/scan actions are intentionally disabled until a capture exists.
3. **Investigation requires at least two captures.** Investigation diagnose controls are gated by linked capture count.
4. **Provider key absent in CI.** Narration can fail while parsed facts remain valid; verify fallback messaging.
