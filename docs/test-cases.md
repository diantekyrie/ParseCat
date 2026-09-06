# ParseCat — User Journey Test Cases

Every existing backend test (`backend/tests/*.py`) calls internal service
functions directly (`diagnose()`, `persist_capture()`, `build_capture_summary()`,
etc.) — none of them go through the actual HTTP API a browser would hit, and
there is no frontend test of any kind. This document is the missing piece:
test cases written from the point of view of someone actually using the app
through the UI (or hitting the API the UI calls), including the negative and
edge paths that are easy to skip when writing tests inside-out from the code.

Each case names the **app** it exercises (`web` = frontend UI, `api` =
backend HTTP endpoint) so it's clear which layer a FAIL points to.

Legend: 🟢 automated as a real HTTP request (`backend/tests/test_api_user_flows.py`) · 🟡 automated, but only at the internal service-function level (existing test files) — the HTTP boundary itself is untested for this case · ⬜ not automated at all.

## 1. Upload & parse a capture

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 1.1 | web/api | Upload a valid `.txt` logcat with a device label | Capture appears with an ID, filename, and non-zero facts-found counts | 🟢
| 1.2 | api | Upload with an unsupported extension (`.log`, `.pdf`) | `400` — "Expected one of: .zip, .txt, .pcap, .pcapng" | 🟢
| 1.3 | api | Upload a `.txt` file with content that isn't a bugreport or logcat (random text) | `200` with an explanatory `parse_warnings` entry, not a crash or empty silent success | 🟢
| 1.4 | api | Upload a corrupt/empty `.zip` claiming to be a bugreport | `422` — "Failed to parse upload: ..." | 🟢
| 1.5 | web | Upload with no device label filled in | Upload button stays disabled — request never fires | ⬜
| 1.6 | web | Select multiple files, upload in one action | Progress text updates per file; the last-uploaded capture becomes selected | ⬜
| 1.7 | web/api | Upload a second capture under an `investigation_label` | Capture is linked and appears under `/investigations/{label}/captures` | 🟢
| 1.8 | web/api | Upload a capture from a device whose stored identity (serial/fingerprint/manufacturer/model) conflicts with an existing capture under the same device label | `409` with a structured mismatch detail — capture is **not** silently merged into the wrong device | 🟡
| 1.9 | api | Upload a capture that has no `device_info` at all (e.g. a `.pcap`) to a device label whose existing captures also have no verifiable identity | `200`, capture persists, and an "identity unverifiable" warning is attached rather than silently trusting the label | 🟡

## 2. Device & investigation browsing

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 2.1 | web/api | `GET /devices` after at least one upload | Device appears in the list | ⬜
| 2.2 | api | `GET /devices/{label}/captures` for a label that was never uploaded | `404` — "Unknown device" | 🟢
| 2.3 | api | `GET /investigations/{label}/captures` for a label that was never used | `404` — "Unknown investigation" | 🟢
| 2.4 | api | `GET /captures/{id}/summary` for an ID that doesn't exist | `404` — "Unknown capture" | 🟢
| 2.5 | web | Select a device, then a specific capture under it | Overview tab populates with that capture's summary | ⬜
| 2.6 | web/api | View a device's merged summary across 2+ captures on file | Merged summary reflects data from all captures, not just the most recent | ⬜

## 3. Triage / overview tab (filters & export)

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 3.1 | web | Type into the "App / package filter" box | Crash/ANR/tombstone/battery/timeline rows scope down to matches only | ⬜
| 3.2 | web | Type into the "Timeline text filter" box | Only matching timeline rows remain | ⬜
| 3.3 | web | Set an incident time + window (e.g. 15 min) | Timeline/crash/ANR rows outside the window are excluded | ⬜
| 3.4 | web | Clear all filters after filtering | Full unfiltered summary reappears | ⬜
| 3.5 | web | Click "Export summary JSON" with a capture selected | A JSON file downloads containing the current (filtered or unfiltered) summary | ⬜
| 3.6 | web | Click "Export summary JSON" with no capture selected | Button is disabled — no export attempted | ⬜

## 4. Scan for problems

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 4.1 | web/api | Trigger a scan on a capture with known crash/ANR/battery evidence | Findings list returns, ranked by computed severity, not LLM-guessed severity | 🟡
| 4.2 | api | Scan an unknown capture ID | `404` — "Unknown capture" | 🟢
| 4.3 | web/api | Scan when the configured LLM provider is unreachable/misconfigured | Ranked findings still return (they're computed, not narrated); narration portion degrades with a visible error, not a blank screen | ⬜
| 4.4 | web | Scan a capture with genuinely no findings | Empty-state message, not an empty table with no explanation | ⬜

## 5. Diagnose (single capture)

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 5.1 | web/api | Ask a capture-scoped question naming a specific app | Claim card for that app includes its own crash/ANR/battery evidence | 🟡
| 5.2 | web/api | Ask a question that doesn't name any app (e.g. "why did the phone crash?") | Response surfaces device-wide evidence without fabricating an app name | 🟡
| 5.3 | web | Try to submit the diagnose form with no capture selected | Submit stays disabled | ⬜
| 5.4 | api | Diagnose an unknown capture ID | `404` — "Unknown capture" | 🟢
| 5.5 | web/api | Ask a question naming a package that has zero evidence on the selected capture but real evidence on *other* captures for the same device | Response discloses "checked N of M captures on file" wording, distinguishing "no evidence" from "no coverage" | 🟡
| 5.6 | web/api | Ask a question naming a specific calendar date that falls **outside** every linked capture's time range | Response quotes the capture's own `capture_coverage.statement` verbatim and flags the date as out-of-range, rather than answering as if the date were covered | 🟡
| 5.7 | web | Explicitly pick a narration provider from the dropdown | Response reports back that exact provider, not a silently substituted one | ⬜
| 5.8 | api | Explicitly request a provider ID that doesn't exist in `list_providers()` | `200`, not a crash: verified facts bundle still returned, `report: null`, `llm_error` names the bad provider, requested provider echoed back (not silently substituted) | 🟢
| 5.9 | web | Click "Export diagnosis" after asking a question | A downloadable file is produced containing the question, report, and claims | ⬜

## 6. Follow-up diagnosis (same capture)

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 6.1 | web/api | Ask a base question, then a follow-up question in the same thread | Follow-up response appears; the original base diagnosis is still visible/intact | ⬜
| 6.2 | api | Send a follow-up with a malformed (non-JSON, or JSON-but-not-a-list) `history` payload | Degrades to "no history" — `200`, not `400` — since history is for conversational continuity only, never a fact source | 🟢
| 6.3 | web/api | Ask a follow-up, then check the bundle passed to the LLM | Prior Q&A pairs are present as *history*, not re-injected as new evidence | 🟡

## 7. Investigation-scope diagnosis

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 7.1 | web/api | With 2+ captures linked to an investigation, ask an investigation-scoped question | Response merges evidence bundles from every linked capture into one answer | 🟡
| 7.2 | web | With fewer than 2 captures linked, try to switch to investigation scope and diagnose | Investigation-diagnose control stays disabled/unavailable in the UI | ⬜
| 7.3 | api | Call `POST /investigations/{label}/diagnose` directly with only 1 (or 0) linked captures | **Not currently enforced server-side** — the route runs regardless of capture count. Confirm with product whether this is intended (API meant to be called only via the gated UI) or should be a `400` at the API layer too | 🟢 (documents current behavior)
| 7.4 | api | Diagnose an unknown investigation label | `404` — "Unknown investigation" | 🟢
| 7.5 | web/api | Ask an investigation-wide question naming a specific date that's outside one linked capture's range but inside another's | Per-capture coverage is disclosed individually — no single merged "bundle-wide" range is invented | 🟡
| 7.6 | web | Click "Export diagnosis" from investigation scope | Download includes all linked captures' contribution, not just one | ⬜

## 8. Investigation follow-up

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 8.1 | web/api | Ask an investigation-scoped follow-up after a base investigation diagnosis | Follow-up appears; base diagnosis remains visible | ⬜

## 9. Cross-cutting / resilience

| # | App | Test Case | Expected Result |
|---|-----|-----------|------------------|
| 9.1 | web | Start two uploads concurrently (or one large upload + one health check) | Neither request stalls the other — uploads run off the event loop | ⬜
| 9.2 | api | `GET /llm/providers` with zero provider keys configured | Returns providers marked unavailable, not an error | 🟢
| 9.3 | web | Load the app with the backend unreachable | Clear error state, not a blank page or infinite spinner | ⬜

---

## Notes for whoever runs these

- Cases marked 🟢 are automated as real HTTP requests in `backend/tests/test_api_user_flows.py` (FastAPI's `TestClient`, not internal function calls). Run with `cd backend && pytest tests/test_api_user_flows.py -v`.
- Cases marked 🟡 already have a passing automated test, but only at the internal service-function level in the existing `backend/tests/*.py` files (mostly `test_end_to_end.py`, `test_device_label_identity.py`, `test_capture_coverage.py`). The underlying logic is verified; the HTTP route wrapping it (form parsing, status code, response shape) is not. Promoting one of these to 🟢 means writing a `test_api_user_flows.py` case that drives it through `client.post(...)` instead of calling the service function directly.
- Cases marked ⬜ have no automated coverage at all. Most of these are `web`-tagged UI interactions (filters, disabled-button states, downloads) that need a real browser — Playwright is the natural next step since there's no frontend test tooling in the repo yet. A few (9.1, 9.3) are cross-cutting resilience cases that are awkward to assert cleanly in either layer and may be worth a manual pass instead.
- 7.3 is written up as a finding, not just a test case: worth a product decision on whether the investigation-diagnose capture-count gate should also live server-side, since right now it's UI-only.
