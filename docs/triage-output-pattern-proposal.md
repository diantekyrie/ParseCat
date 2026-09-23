# Design note: adopting the triage-bot presentation pattern in ParseCat

**Source:** pattern reverse-engineered from three Buganizer-hosted triage-bot comments (see
`buganizer-bot-analysis.md`). That bot happened to be triaging a casting feature — nothing here is
about casting. This note maps the *general* pattern (state-machine diffing, deterministic
cross-device correlation, quantitative reconciliation, structured re-triage) onto ParseCat's actual
domain: crashes/ANRs, Wi-Fi disconnects, SELinux denials, Bluetooth/pairing failures, battery drain,
and process kills, for whatever device problem the user is asking about, not any one feature.

Grounded in the current implementation: `backend/app/services/reasoning.py` (bundle construction,
`SYSTEM_PROMPT`, `rank_findings`), `backend/app/services/correlation.py` (multi-capture history),
`diagnose_investigation()` (multi-device merge).

---

## 1. What ParseCat already does that matches the pattern

Worth naming, because it means most of §1 and §7 of the bot pattern are *already implemented* —
this isn't a from-scratch adoption:

- **Deterministic input framing** — `device_context` (build fingerprint, kernel, security patch) is
  pulled straight from `DeviceInfoRow` inside `build_diagnosis_bundle()`, never guessed by the LLM,
  matching the bot's "restate the header from structured fields before touching logs" step.
- **Confidence is code-computed, never LLM-invented** — `score_confidence()` /
  `evidence_confidence()` compute `HIGH/MEDIUM/LOW` from real corroboration counts, and rule 2 of
  `SYSTEM_PROMPT` forbids the model from upgrading a label. This is *stricter* than the Buganizer
  bot, which writes confidence prose from its own judgment.
- **Negative-check reporting already exists** — `evidence_sources` (rule 12) is the same idea as the
  bot's "Checked the reference doc — no matching issue tracked": a deterministic list of what *was*
  checked, rendered even when a category came back empty, so absence is stated rather than omitted.
- **Cross-device investigations already exist** — `diagnose_investigation()` merges one bundle per
  capture across every device linked to an investigation, which is exactly the "phone + watch"
  two-device case the skill description already advertises.
- **Capture-tagged citation** — every device-wide fact carries `capture_id`, resolved against a
  `captures` filename map (rules 4/6), matching the bot's "grouped by physical device" evidence
  convention.

The gaps below are genuinely additive, not a rewrite.

---

## 2. Gap: no expected-sequence diffing (the bot's core mechanism)

The bot's single most powerful move is the **Happy Path Progression table**: an internal expected
step sequence per role, diffed against the actual log stream, with a 4-state status
(`Matched` / `Failed (Premature)` / `Failed (Unexpected)` / `Not Reached`) that pinpoints the exact
divergence step. ParseCat currently reports facts as an unordered set of findings
(`rank_findings()`) — it never says "step 4 of the expected sequence never happened."

**Proposal — a deterministic `sequence_check` evidence category**, parallel to the existing
`evidence_confidence()` pattern (code-computed, not LLM-authored):

- Define a small number of known-good step sequences ParseCat's parsers already have enough
  structure to recognize, e.g.:
  - **Wi-Fi association**: scan → auth → assoc → DHCP → connected (vs. disconnect reason code with
    no prior auth/assoc = never actually connected).
  - **BT/CDM pairing** (`cdm_pairing.py`, `companion_device.py`): discovery → bond request → bond
    state change → association confirmed (vs. bond request with no state-change row = pairing never
    completed).
  - **ANR lifecycle**: input dispatch timeout logged → trace captured → process either recovered or
    was killed (vs. trace captured but no resolution row = still-open ANR).
  - **App crash → restart**: crash/tombstone → process death → next launch of same package (vs. no
    relaunch row = app never came back).
- Each sequence lives as a small ordered list of `(step_name, row_predicate)` pairs next to the
  parser that produces the rows, so it stays accurate as parsers change.
- `build_diagnosis_bundle()` runs the relevant sequence(s) when their trigger category is active
  (same `want_wifi`/`want_pairing`/etc. gating already in place) and emits:
  ```json
  "sequence_check_evidence": {
    "sequence": "bt_pairing",
    "steps": [
      {"step": "discovery", "status": "matched", "capture_id": 3, "timestamp": "..."},
      {"step": "bond_request", "status": "matched", "capture_id": 3, "timestamp": "..."},
      {"step": "bond_state_change", "status": "not_reached"}
    ]
  }
  ```
- Add one `SYSTEM_PROMPT` rule telling the model to narrate `not_reached`/`failed_*` steps as *"the
  expected next step never appears in the logs"* rather than letting it guess why — the status is
  the fact; causal speculation is explicitly out of scope per rule 1 (see §3).

This is the highest-value, lowest-risk addition: it's pure code (no new inference risk) and it
directly answers the single most common troubleshooting question — "how far did this actually get
before it broke?" — for any subsystem, not one feature.

---

## 3. Gap (deliberately *not* adopted as-is): source-level root-cause inference

The bot's Root Cause section names specific classes/functions (`CoreBle$l2capConnect$job$1`,
`ShareCastSessionManager.kt`) inferred from log-tag text — impressive, but exactly the kind of
unverified inference ParseCat's own design has been actively hardening *against* (see the recent
`#5`/`#22` fixes: never let a plausible-sounding claim outrun its evidence). `SYSTEM_PROMPT` rule 1
("never state a claim not present in the bundle") already forbids this.

**Recommendation: don't copy this part.** Where it's legitimately adoptable without violating rule 1:
- Kernel/native crash logs *do* sometimes carry a real file:line or driver name verbatim
  (`kernel_log_evidence`, tombstone frames) — those are facts already in the bundle, not inference,
  and can already be cited.
- Everywhere else, keep the bot's *structure* (a short "what broke, in order" narrative) but source
  it entirely from `sequence_check_evidence` (§2) plus existing evidence blocks — a "mechanism"
  section built from confirmed steps, not a code-path guess.

---

## 4. Gap: cross-device correlation is left to the LLM, not computed

`diagnose_investigation()` already merges multiple devices' bundles into one list (§1), which is the
structural precondition for what the bot does — but the *correlation itself* (host event at
`T` explained a guest event at `T+46ms`) is left for the LLM to notice in prose. Nothing computes it.

**Proposal — a deterministic `device_wide_correlation_evidence` block**, built once per investigation
after all per-capture bundles exist:

- For pairs of devices in the same investigation, scan for events **within a small configurable
  window** (e.g. ±2s) across categories that are inherently two-sided — pairing/bond events, Wi-Fi
  disconnects that coincide with a companion event on the other device, an ANR/crash on one device
  immediately followed by a disconnect on the paired one.
- Emit matched pairs with both timestamps and the delta, exactly like the bot's "46ms later" evidence
  — computed in code, so the LLM narrates a fact instead of eyeballing two timestamp columns itself:
  ```json
  "device_wide_correlation_evidence": {
    "pairs": [
      {"device_a": "pixel-phone", "event_a": "bond_state_change:BONDED", "ts_a": "...",
       "device_b": "pixel-watch", "event_b": "companion_associated", "ts_b": "...",
       "delta_ms": 340}
    ]
  }
  ```
- This is the single biggest lift in the list, but it's the one that most directly matches the
  skill's own advertised "correlating two devices" use case with something more than co-location in
  one prompt.

---

## 5. Gap: no lightweight classification tag on findings

The bot's fixed category taxonomy + team routing doesn't transfer literally (ParseCat has no
engineering-team inbox to route to), but `rank_findings()` already assigns a `category` per finding
(`crash`, `wifi`, `pairing`, `memory`, …). **Proposal:** surface that existing field as a visible tag
in the rendered report/UI (it's already computed, just not exposed as a facet), so a user scanning a
long report can filter by category the way a triager scans by "Category Matched." No backend change
needed beyond exposing what's already there.

---

## 6. Gap: no quantitative reconciliation for magnitude questions (esp. battery)

The bot's strongest rigor move is refusing to call something Working-As-Intended until the *numbers*
reconcile: input wattage → subsystem draw → integrated mAh → % of pack capacity, checked against the
reported drop. `device_wide_battery_evidence` already carries real per-component mAh figures but
doesn't do this closing arithmetic.

**Proposal:** when the bundle already has both a power-supply/charging snapshot (input current limit,
charging status) and a `batterystats` component breakdown for the same window, compute — in code,
not the LLM — the same reconciliation: `expected drain if input < draw` vs. `observed drain`, and
emit a `reconciled: true/false` + the arithmetic as a `battery_reconciliation` sub-object. This turns
"the battery dropped, here are some numbers" into "the drop is explained by X, computed as Y" for any
long-running-drain question, not a casting-specific one.

---

## 7. Gap: no self-scoped re-triage framing for follow-up questions

The bot's re-triage comments explicitly scope themselves ("Context: analyzing N newly-attached
bugreports") rather than silently re-running the same template. ParseCat's investigation flow already
passes prior-turn `history` into the LLM call (`diagnose_investigation(..., history=...)`), so the
underlying capability exists — this is a **prompt-only** addition:

- When a follow-up question arrives after new captures were added to an investigation since the last
  turn, have `build_diagnosis_bundle`/`diagnose_investigation` note which `capture_id`s are new since
  the referenced prior turn, and add one `SYSTEM_PROMPT` instruction: if the bundle marks captures as
  "new since last answer," open with a one-line scope statement before "## Direct answer" — e.g. *"Answering
  using 2 newly added capture(s) plus the N already on file."* Mirrors the bot's Q&A-block framing at
  near-zero implementation cost since the "what's new" list is just a set difference against
  `history`.

---

## Priority ordering

| # | Addition | Effort | Value |
|---|---|---|---|
| 2 | Deterministic `sequence_check_evidence` (per-subsystem step diffing) | Medium | Highest — answers "how far did it get" for any failure class |
| 4 | Deterministic cross-device `correlation_evidence` | Medium–High | High — the concrete gap vs. the skill's own two-device claim |
| 6 | Battery reconciliation arithmetic | Low–Medium | Medium-high — cheap, numbers are already in the bundle |
| 7 | "New since last turn" scope line | Low | Low-medium, nearly free |
| 5 | Expose existing `category` facet in report/UI | Low | Low-medium, UI-only |
| 3 | (Explicitly not adopting source-inference root-causing) | — | — |

All five additions are deterministic, code-computed evidence — consistent with ParseCat's existing
rule that confidence and structure come from code, never from the model's own narrative judgment.
