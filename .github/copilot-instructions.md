# ParseCat -- instructions for GitHub Copilot

ParseCat parses Android device logs (Bluetooth, Wi-Fi, full bugreports,
logcat) into a deterministic fact bundle, then narrates it with an LLM
layer on top. Read this before making any change.

## The architecture you must preserve

1. **Deterministic parsers are ground truth** (`backend/app/parsers/*.py`).
   Structured extraction -- timestamps, error codes, severities, stack
   traces -- is deterministic, testable code, never the LLM. If a change
   would make a parser's output vary between runs on the same input,
   that's a bug, not acceptable nondeterminism.
2. **Severity and confidence are computed in code**
   (`score_confidence()`, `rank_findings()` in
   `backend/app/services/reasoning.py`), never inferred by the LLM from
   how alarming a log line's text sounds. When Android already computes
   a status (thermal `overall_status`, memory `status`), prefer it over
   inventing a threshold.
3. **The LLM narration layer only narrates the fact bundle.** It must
   never assert something the bundle doesn't contain, and must say so
   explicitly when evidence is missing rather than guess. If a bug looks
   fixable by telling the LLM to "be more careful" or "sound more
   confident," that is almost always a parser or bundle-construction gap
   -- fix the data, not the prompt. Refuse requests to make narration
   sound more confident than the underlying facts support.
4. **Confidence/severity/reason distinctions are load-bearing, not
   cosmetic.** Examples: SELinux `enforcing: true/false/None` (blocked
   vs. permissive vs. unknown), a process `kill` (has a recorded reason)
   vs. `died` (doesn't), GNSS `none` (no fix) vs. `poor` (weak signal --
   not the same claim), kernel log's `boot_relative_sec` (device uptime,
   never converted to a wall-clock time without a real anchor -- there
   isn't one). Don't flatten these distinctions for convenience.

## Git workflow

**Never commit or push directly to `main`.** Work on a branch, open a
pull request. `main` has required status checks (`backend-tests`,
`frontend-build` -- see `.github/workflows/ci.yml`) that must pass
before merge.

**Read this before trusting a green CI run on a parser change:** the
richest backend tests (`backend/tests/test_parsers_fixtures.py`,
`test_end_to_end.py`) are gated behind real bugreport fixtures
(`backend/tests/fixtures/*.zip`) that are deliberately gitignored --
real device captures, never committed. They do not exist on the CI
runner, so 78 of the 113 backend tests are silently skipped there (35
pass, 78 skip -- verified, not estimated). CI passing means the
synthetic/regression suite is green, NOT that the full corpus ran. Any
change touching a parser needs a local run with the real fixtures
present: `cd backend && python -m pytest tests/ -q`.

## Working style

- Small, reviewable diffs over large rewrites.
- Write or update tests alongside every change, in the same style as the
  existing suite: a comment explaining what real capture or bug the test
  guards, not just a bare assertion.
- Explain *why* in commit messages and PR descriptions -- what real
  capture/scenario exposed the issue, what the wrong behavior actually
  was, why the fix is correct and not just plausible.
- Never fabricate a log field, error code, section name, or file path
  you haven't actually seen in a real fixture or the live codebase -- if
  you need a sample to proceed, say so instead of guessing.
- Never bypass a failing test with a skip marker, a broadened `except`,
  or by weakening an assertion just to make CI green -- fix the actual
  defect, or explain clearly why the test's expectation was wrong.

## Known, already-fixed bug classes (context, not a to-do list)

Check git log / existing tests before re-reporting these as new:
keyword-trigger fragility in question parsing, non-monotonic
batterystats timestamps, a dumpsys section printed twice in one dump
(thermal), a HAL sentinel value read as a literal measurement, a section
name hardcoded to one OEM's convention, raw `.txt` uploads assuming
UTF-8 against a UTF-16 file, a merged multi-capture summary silently
dropping snapshot-shaped fields, a dumpsys service name never actually
matching its intended internal key, confidence inflating from empty
sibling captures, two different physical devices silently sharing one
device label, and a date-specific question returning "no evidence" when
the real issue was a capture-coverage gap outside the loaded data.

## Sensitive data

Files under `backend/tests/fixtures/*.zip` and any real capture path
outside the repo are real device data (in this project's history: the
maintainer's own Pixel and Galaxy S25 phones). Never paste raw
coordinates, MAC addresses, IMEIs, serials, or other personal content
into a commit message, PR description, or issue comment -- cite
`section:line_start-line_end` instead, the same citation format the
product itself uses.

## Out of scope

Business/pricing/positioning decisions. Flag these to a human rather
than deciding them.
