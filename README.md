# ParseCat

Device log diagnosis SaaS — MVP. Ingests Android bugreports and returns a
root-cause diagnosis built on **deterministic parsers as ground truth**,
with an LLM reasoning layer on top that narrates already-verified facts
instead of doing retrieval over raw text.

See the original build brief for the full product thesis and the specific
gaps in the incumbent (logcat.ai) this is meant to close.

## Architecture

```
backend/
  app/
    parsers/         deterministic parsers -- the primary technical moat
      section_extractor.py   streams the (100-250MB) flattened bugreport
                              txt out of its zip, slices out only the
                              sections we have parsers for. Handles both
                              bugreport delimiter styles: `DUMP OF SERVICE
                              ... / --------- was the duration of dumpsys`
                              (dumpsys output) and `------ NAME (...) ------
                              / ------ ... was the duration of 'NAME' ------`
                              (captured logcat buffers, getprop, iptables),
                              plus the undelimited plain-text preamble at
                              the top of the file.
      audio_focus.py         DUMP OF SERVICE audio -> MediaFocusControl
                              focus stack + full request/abandon/owner
                              event history
      package_info.py        DUMP OF SERVICE package -> per-package
                              versionCode/minSdk/targetSdk
      media_session.py       DUMP OF SERVICE media_session -> live
                              PlaybackState per app (state, position, active)
      foreground_service.py  DUMP OF SERVICE activity -> ServiceRecord /
                              infoAllowStartForeground (targetSdk at
                              bind/start time, calling package, proc state)
      freeze_events.py       SYSTEM LOG -> ActivityManager process
                              freeze/unfreeze events (cached-process
                              freezer state transitions)
      crash_events.py        SYSTEM LOG -> Java `FATAL EXCEPTION` crashes,
                              including unwrapping the `Caused by:` chain
                              to find the actual root cause under a generic
                              top-level wrapper exception
      device_info.py         plain-text preamble + SYSTEM PROPERTIES
                              (getprop) -> manufacturer/model/build/
                              security patch/kernel/serial/etc.
      tombstone.py            parses tombstone file CONTENT (not just the
                              filename) from FS/data/tombstones/ --
                              signal/code/fault addr, top backtrace frame,
                              and package attribution derived from Cmdline
                              (null, not guessed, for native binaries)
      anr.py                  parses ANR trace files from FS/data/anr/ --
                              the `Subject:` header line alone gives pid,
                              package, and failure reason
      bt_hci.py                parses the on-device Bluetooth HCI snoop log
                              (a filename that varies by OEM/build -- seen as
                              "btsnooz_hci.log", "btsnoop_hci.log.filtered",
                              and rotated ".last" copies of either; see
                              BT_HCI_LOG_CANDIDATES in ingestion.py) -- real
                              binary `btsnoop` framing (verified byte-for-
                              byte against real files, not assumed from any
                              one filename), decoding connection/
                              disconnection/command complete/status events
                              with HCI status-code names from the Bluetooth
                              Core Spec
      wifi.py                 DUMP OF SERVICE wifi -> WifiController/
                              ClientModeImpl state machine log: Wi-Fi
                              disconnection events with IEEE 802.11 reason
                              codes, BSSID association/roam events
      selinux.py               EVENT LOG / SYSTEM LOG -> SELinux AVC
                              denials. `enforcing` is three-state and
                              load-bearing: True (permissive=0) = actually
                              BLOCKED, a real failure; False (permissive=1)
                              = logged but allowed through; None = the log
                              didn't say. Never collapsed into one "a
                              denial happened" number.
      process_kills.py         EVENT LOG -> ActivityManager am_kill /
                              am_proc_died. A "kill" carries a reason; a
                              "died" only records the process went away and
                              does NOT establish the system killed it --
                              counted separately, and only deliberate kills
                              are ranked or timelined.
      cdm_pairing.py           SYSTEM LOG -> Companion Device Manager /
                              Fast Pair pairing-flow events (discovery,
                              association, secure-channel handshake), plus
                              a generic W/E-level catch-all for any other
                              CDM_*-tagged anomaly
      companion_device.py      DUMP OF SERVICE companiondevice -> the CDM
                              service's OWN current-state association
                              snapshot (paired device, mac, connected now
                              or not) -- stronger evidence than reconstructing
                              pairing state from log lines
      logcat_history.py        FS/data/misc/logd/logcat.NN (persistent,
                              rotated on-device log buffers, up to 60+ files
                              per capture) -- reuses the freeze/crash/CDM
                              parsers above on log history that predates the
                              live SYSTEM LOG window, deduplicated where the
                              two genuinely overlap
      packet_analysis.py       real protocol-level dissection of .pcap/
                              .pcapng uploads -- see "Packet capture
                              analysis" below
    services/
      ingestion.py       wires zip -> sections -> parsers -> ParsedCapture;
                          also reads and parses tombstone/ANR files and the
                          Bluetooth HCI log directly from the zip's own
                          file listing (separate files, not text inside the
                          flattened bugreport txt)
      persistence.py     ParsedCapture -> DB rows (facts, not raw blobs)
      correlation.py     multi-capture history queries for one device
      verification.py    independently verifies every app named in a
                          question before any narrative is built --
                          focus stack, media session, targetSdk, its own
                          crash events, freeze/unfreeze counts, its own
                          ANRs and native crashes (tombstones)
      reasoning.py        assembles verified facts + computed confidence
                          into a bundle, hands it to the selected LLM
                          provider to narrate. Crash-shaped questions
                          (crash/ANR/fatal/tombstone) get device-wide
                          crash/ANR/native-crash evidence even when no
                          app is named.
      summary.py          build_capture_summary() assembles one capture's
                          dashboard payload (device info, fact counts,
                          top freeze/unfreeze offenders, crash/ANR/
                          tombstone tables, Bluetooth HCI summary, a
                          merged chronological timeline). build_merged_summary()
                          combines that across every capture on file for a
                          device or investigation into one payload -- the
                          dashboard's default view -- reusing
                          build_capture_summary() per capture rather than
                          re-querying, with every row tagged by which
                          capture it actually came from so nothing reads as
                          "this capture" when it's really a different one.
                          All reads of already-persisted rows.
    llm/                LLMClient interface with four selectable
                         providers (see "LLM providers" below); every
                         implementation only narrates an already-verified
                         fact bundle, none of them see raw bugreport text
    api/                FastAPI routes: upload, list, capture summary,
                         llm provider list, diagnose
  tests/
    fixtures/           real bugreports (not committed -- see .gitignore)
    test_parsers_fixtures.py   parser-level regression tests, pinned to
                                exact source line numbers
    test_end_to_end.py         full pipeline: parse -> persist -> verify
                                -> correlate -> diagnose -> summary

frontend/               React + Vite dashboard: device info panel, stat
                         cards (crashes/freezes/packages/etc.), crash and
                         media-session tables with source citations, a
                         merged event timeline, and an Ask panel with a
                         per-question LLM provider dropdown
```

## How to capture (HCI snoop + bugreport)

For Bluetooth diagnosis, enable **Bluetooth HCI snoop** in Developer options
**before** reproducing the issue, restart Bluetooth, then take a full
**bugreport ZIP** (`adb bugreport` or Developer options → Take bug report).
Plain logcat is usually not enough. Condensed checklist: dashboard sidebar
**How to capture**. Full steps: [`docs/how-to-capture.md`](docs/how-to-capture.md).

## Upload formats

The local dashboard accepts three upload types:

| Extension | Current support |
|---|---|
| `.zip` | Full Android bugreport ZIP ingestion, including flattened bugreport text plus ZIP-contained tombstones, ANRs, and Bluetooth HCI log files. |
| `.txt` | Direct flattened Android bugreport text ingestion. ZIP-only companion files are not available, so tombstones/ANRs/HCI files are reported as unavailable. |
| `.pcap`, `.pcapng` | Container-level metadata (packet count, byte totals, time range, link type) plus real protocol-level dissection -- see "Packet capture analysis" below. |

`.btt` (Ellisys) uploads are explicitly not supported: opening one for
real requires Ellisys's own proprietary software, so accepting the file
here without being able to decode most of it was more misleading than
useful. If a real `.btt` sample or the format spec ever becomes
available, this can be revisited.

Uploads can also be grouped into a named bug folder/investigation so one
local investigation can contain multiple supporting files, such as a
bugreport ZIP, a raw text log, and a packet capture.
The dashboard file picker accepts multiple files at once and uploads each
as a separate capture under the same bug folder.

## Why parsers, not RAG

The section extractor streams the giant flattened bugreport text once and
only buffers the sections we have parsers for. Within those sections,
values are pulled by exact-format regex, not chunk/embedding retrieval --
so a plain-text section like the audio focus stack (which a retrieval-based
tool can silently miss on a long, low-natural-language-signal section) is
never "not found." Every fact carries a `SourceRef` (section + line
range), so every claim in a report can point back at exact lines.

Real parser bugs this discipline caught during development (each pinned as
a regression test against real fixture data, not synthetic data that's too
clean to expose them):

1. Python's default universal-newlines text mode splits on bare `\r` bytes
   embedded in tombstone/crash data elsewhere in the bugreport, which
   silently drifted every subsequent line number by ~43,000 lines while the
   *parsed values* still looked plausible.
2. A bugreport can print a second, heavily time-filtered "SYSTEM LOG"
   section near the very end (a `-T <recent timestamp>` trailer covering
   only the last few seconds), reusing the exact same section name as the
   real, complete one earlier in the file. "Keep last occurrence" (correct
   for a dumpsys CRITICAL/HIGH pass followed by the full dump) silently
   grabbed that tiny trailer instead for this log-style section, dropping
   real crash data entirely.
3. The crash parser's block-scanner, when unwrapping a `Caused by:` chain,
   didn't stop at the next `FATAL EXCEPTION:` header -- so two crashes
   back-to-back with no gap (a real, repeatable case: an app crashing twice
   within 10 seconds) caused the scanner to read straight through the
   boundary into a later, unrelated crash's data and silently overwrite the
   first crash's package and root cause with the wrong crash's fields.
4. Some tombstones omit `ppid:` from the pid/tid header line entirely (a
   real format variant, not malformed data) -- a regex that required it
   silently failed to extract pid/tid for those tombstones.
5. The Bluetooth HCI log's binary framing was initially assumed from the
   file's misleading name ("btsnooz", suggesting AOSP's compressed
   bugreport-inline variant) rather than verified. The first byte-offset
   guess produced identical, clearly-wrong values for both TX and RX
   packets; decoding was only trusted once independently verified against
   the real bytes: H4 type-byte distribution, decoded HCI event codes/
   statuses were all self-consistent with known Bluetooth Core Spec
   semantics, and decoded timestamps landed within minutes of the
   bugreport's own capture time (an earlier epoch-delta constant decoded
   them to 1996).

## Independent verification

`verification.py` extracts every app the question names (literal package
IDs, or exact-segment brand-word matches like "YouTube Music" ->
`com.google.android.apps.youtube.music`) and pulls each one's own parsed
state -- focus stack membership, MediaSession playback state, latest focus
event, targetSdk, its own crash events, freeze/unfreeze counts -- before any
diagnosis narrative is built. The user's framing of "app X caused app Y's
problem" is never taken as fact for either app.

Crash-shaped questions (containing crash/crashed/ANR/fatal/tombstone) also
get device-wide crash evidence attached regardless of whether an app was
named, so "was there a crash?" doesn't come back "unknown" just because the
question didn't name an app.

## Confidence

`reasoning.score_confidence()` labels a claim HIGH/MEDIUM/LOW/UNCONFIRMED
based on how many independent structured facts back it and how many
captures in the device's history were checked -- never from how assertively
something reads. Every fact bundle sent to the LLM carries this computed
label explicitly, including device-wide crash evidence; the system prompt
instructs the model to carry it forward verbatim, but the label itself is
always computed in code, never left for the model to infer or invent (a
real gap found via live A/B testing: GPT-4.1 assigned "HIGH confidence" to
device-wide crash evidence that had no confidence field at all when the
field was originally omitted and left to prompt instructions alone).

## Multi-capture correlation

Captures are associated with a `Device` (by a label you choose, e.g. a
serial number) rather than treated as disposable uploads. Any question
containing trigger words like "never", "across", "history", "week"
triggers `correlation.package_history_across_device()`, which checks a
claim (e.g. "has this app ever requested audio focus") against every
capture on file for the device and reports how many captures backed the
answer -- not just whichever file is in the current request.

## LLM providers

Selectable per-question via a dropdown in the frontend's Ask panel, or via
the `provider` field on `POST /captures/{id}/diagnose`:

| id | Model | Requires |
|---|---|---|
| `anthropic` | Claude (Sonnet by default) | `ANTHROPIC_API_KEY` |
| `openai` | GPT (gpt-4.1 by default, `OPENAI_MODEL` to override) | `OPENAI_API_KEY` |
| `openai-codex` | Codex-family (gpt-5.3-codex by default, `OPENAI_CODEX_MODEL` to override) | `OPENAI_API_KEY` |
| `stub` | No LLM -- deterministically echoes the fact bundle | nothing |

`GET /api/llm/providers` reports which are actually usable given the
current environment, so the dropdown never offers one that will just error.
Omitting `provider` falls back to auto-detection (Anthropic, then OpenAI,
then stub).

Codex-family models use OpenAI's `responses` endpoint, not
`chat.completions` -- they 404 on the latter ("Use the v1/responses endpoint
instead"), confirmed live against the real API rather than assumed.

If narration fails for any reason (bad/missing key, quota, wrong
model/endpoint), the request still returns `200` with the full verified
fact bundle intact and `report: null` / `llm_error: "<the actual error>"` --
narration is a convenience layer on top of the independently-verified
facts, never a single point of failure for them.

## Auto-scan

`POST /captures/{id}/scan` answers "what's wrong with this device?" with no
question required. It calls `build_diagnosis_bundle(include_all_evidence=True)`,
which bypasses every keyword trigger and gathers all evidence categories --
this is also the structural fix for keyword-trigger fragility, which bit
repeatedly in live testing (a "network issue" question that missed the Wi-Fi
trigger; a vague follow-up that matched nothing at all).

`rank_findings()` then turns raw evidence into a severity-ranked list.
Severity is computed **in code from the kind of event**, never by the LLM and
never from how alarming a log line reads -- the same principle as
`score_confidence()`:

| Severity | What earns it |
|---|---|
| CRITICAL | Java crash, native crash (tombstone), ANR |
| HIGH | SELinux denial with `enforcing: true`; Wi-Fi disconnect the device did **not** initiate |
| MEDIUM | W/E-level pairing anomalies, Bluetooth HCI failures, deliberate process kills, packet-capture anomalies |
| LOW | SELinux denial in permissive mode; Wi-Fi disconnect the device initiated itself |

A severity says "this kind of event deserves attention first" -- it does not
assert the event caused any user-visible symptom, and the system prompt
forbids claiming a causal link between two findings unless the bundle states
one.

Identical findings are grouped into one row with an `occurrences` count and
first/last timestamps. Found live: an early run on a real capture produced 36
findings, 24 of them the same "Bluetooth command status: Command Disallowed"
row, which buried the single HIGH Wi-Fi finding. Grouping cut it to 10 rows
and turned the repetition itself into signal (x24 over 14 minutes).

## Report structure

The system prompt requires every report to follow a fixed structure
(`## Direct answer` / `## Findings` / `## Suggested next steps` /
`## Evidence checked`), rendered in the frontend as real headings/lists
instead of raw markdown text. Two pieces of this are deterministic, not
LLM-written:

- `device_context` -- real parsed device info (build fingerprint, kernel,
  security patch, etc.), attached to the bundle straight from
  `DeviceInfoRow`.
- `evidence_sources` -- a code-generated list of which evidence categories
  were actually checked for this specific question and why (which keyword
  trigger matched), computed in `build_diagnosis_bundle()` after the fact
  from which bundle keys actually got populated. This is an honest,
  cheap substitute for a genuine multi-step research trace, which this
  system does not run -- ParseCat parses once, deterministically, then
  makes a single LLM call to narrate; it does not do iterative agentic
  investigation.

"Suggested next steps" is explicitly the one place the LLM is allowed to
go beyond the verified bundle (general troubleshooting knowledge) -- the
system prompt requires it to say so explicitly and never carry a
confidence label, keeping it visually and textually distinct from the
verified findings above it.

**Follow-up questions**: the Ask panel and investigation panel each support
asking a follow-up that builds on the same conversation. The frontend
sends prior turns (`{question, report}` pairs) as a `history` form field;
`_format_history()` prepends them to the LLM prompt labeled as context for
continuity only. Critically, a follow-up still gets its OWN fresh
`build_diagnosis_bundle()` call keyed off the follow-up's own question
text -- prior turns are never treated as evidence. A real, honest tradeoff
found live: a vague follow-up like "should I be worried about that?" has
none of the crash/wifi/battery/pairing trigger keywords in it, so it gets
an *empty* evidence bundle for that turn and the LLM correctly declines to
just restate the previous turn's finding as newly confirmed -- it has to
be asked with a keyword that actually re-triggers the relevant evidence
category.

## Running it

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Put API keys in `backend/.env` (gitignored, loaded automatically):

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Tests (uses the real bugreport fixtures in `backend/tests/fixtures/` if
present; parser tests are skipped otherwise):

```bash
cd backend
pytest -q
```

## Bluetooth / Wi-Fi: what's decoded vs. not

`bt_hci.py` decodes the diagnostically load-bearing HCI event types per-record
(Connection Complete, Disconnection Complete, Command Complete, Command
Status, LE Connection Complete), with HCI status/reason codes named from the
Bluetooth Core Spec. Everything else is counted by event code
(`event_code_counts`) without per-record decoding -- this is HCI-framing-level
visibility (connections, disconnects, command failures), not a full L2CAP/
profile-level protocol dissector.

`wifi.py` decodes `DUMP OF SERVICE wifi`'s WifiController/ClientModeImpl
state-machine transition log: disconnection events with their IEEE 802.11
reason code (named from the spec, e.g. "Deauthenticated: station leaving"),
and BSSID association/roam events. The state machine log has dozens of other
event types (AP capability updates, screen state, scan requests, ...) not
decoded here since they carry no connectivity-failure signal.

## Packet capture analysis

Two backends, tried in this order, both producing the same `PacketAnalysis`
shape (frame-type breakdown, retry rate, RSSI range, SSIDs/BSSIDs seen,
deauth/disassoc/TCP-reset anomalies) so the rest of the system never needs
to know which one ran -- except the LLM-facing bundle, which is always told
via a `backend` field so it can be honest about relative completeness:

- **tshark** (subprocess), when `tshark` is on PATH -- full Wireshark
  dissection, the industry-standard tool for this. Not live-verified in
  this repo's own dev/test environment (no `tshark` installed there, and
  installing it requires admin rights that environment doesn't have);
  verify against a real capture the first time this path actually runs
  somewhere `tshark` is present.
- **Fallback**, when it isn't -- NOT generic scapy packet dissection.
  Benchmarked against a real 297,262-packet 802.11 monitor capture: scapy
  constructing even a single `RadioTap` layer per packet took >120s;
  reading the same file with a hand-rolled radiotap/802.11 header parser
  (same verified-against-real-bytes discipline as `bt_hci.py`) takes ~2s.
  The hand-rolled RSSI extraction was checked byte-for-byte against
  scapy's own `RadioTap.dBm_AntSignal` decoding (0 mismatches across 3000
  real packets) before being trusted for a full-file run. Deauth/disassoc
  reason codes and TCP retransmission analysis are tshark-only -- the
  fallback's `note` field says so explicitly on every result rather than
  silently omitting them. Ethernet/IP-linktype captures (not 802.11
  monitor mode, which is unusually large because it captures every nearby
  device's traffic) use real scapy dissection instead, since those
  captures are typically small enough for scapy's per-packet overhead to
  be fine, with a packet-count safety cap in case that assumption is wrong
  for a given file.

## Explicitly out of scope for this MVP

- Team accounts, SSO, billing tiers.
- Full Bluetooth L2CAP/profile-level protocol decoding beyond core HCI
  framing (see above).
- Wi-Fi driver-level logs (wpa_supplicant.log, kernel driver traces) --
  `wifi.py` covers the framework-level `dumpsys wifi` state machine log,
  which is where connect/disconnect/roam events actually live in a
  bugreport; no driver-level log file was found in the bugreports tested
  against to build a lower-level parser against.
- Apple `sysdiagnose` (or any non-Android device diagnostic format). This
  isn't a small gap like a missing filename match -- it's a fundamentally
  different architecture (Apple's binary Unified Logging `tracev3` format
  instead of logcat text, `.ips` crash reports instead of Java stack
  traces/tombstones, no `dumpsys`-equivalent concept at all). Uploading one
  today fails immediately and loudly (`"No top-level bugreport-*.txt entry
  found in zip"`) rather than silently returning a bad analysis.
