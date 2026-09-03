"""Assembles verified, source-cited facts into a diagnosis report.

Confidence is computed here, from how many independent structured facts
back a claim -- not by the LLM, and not from how assertively anything is
phrased. The LLM only narrates a fact bundle it's handed; it does not get
to invent a confidence level or introduce a claim that isn't already in the
bundle.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass

from sqlmodel import Session

from sqlmodel import select

from app.llm import get_llm_client
from app.models.db_models import (
    AnrBlockingThreadRow,
    AnrMainThreadSnapshotRow,
    AnrRow,
    CpuLoadSnapshotRow,
    KernelLogEventRow,
    ProcessCpuUsageRow,
    ThermalSensorReadingRow,
    ThermalSnapshotRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    CdmPairingEventRow,
    Capture,
    CompanionDeviceAssociationRow,
    CrashEventRow,
    Device,
    DeviceInfoRow,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
    GnssSignalIntervalRow,
    LocationAppUsageRow,
    LocationProviderRow,
    LocationSnapshotRow,
    MemorySnapshotRow,
    ProcessKillEventRow,
    ProcessMemorySampleRow,
    ProcessMemoryUsageRow,
    SelinuxDenialRow,
    TombstoneRow,
    WifiEventRow,
)
from app.services.correlation import PackageHistory, package_history_across_device
from app.services.coverage import build_capture_coverage
from app.services.verification import EntityVerification, verify_question_entities

MULTI_CAPTURE_TRIGGER_RE = re.compile(
    r"\b(never|always|across|history|every capture|all captures|over time|"
    r"week|days|since|before)\b", re.IGNORECASE
)

# MORPHOLOGY RULE for every trigger below: a stem that is unambiguous in
# this domain gets a trailing \w* so its inflected forms all match
# ("crash" -> crashes/crashed/crashing). Short or ambiguous tokens
# ("ram", "bt", "anr") stay whole-word, because a wildcard on them
# false-triggers on ordinary English ("ramen", "anrs" is fine but "bt" in
# "btw" is not).
#
# Every one of these gaps was found the same way -- in a real report where
# a user asked about something the capture HAD and got "unknown" back:
#   * "was there a network issue" missed WIFI (no wifi/drop/roam token),
#     so a real 802.11 disconnect went unreported by two providers.
#   * "tell me about any crashes" missed CRASH, because the pattern listed
#     crash|crashed|crashing but not the plural "crashes" -- the user's own
#     exported report then said crashes were "unknown, not ruled out"
#     while the evidence sat unqueried.
# See test_natural_language_questions_trigger_the_right_evidence for the
# regression corpus that now guards this.
CRASH_TRIGGER_RE = re.compile(
    r"\b(?:crash\w*|fatal\w*|tombstone\w*|exception\w*|anr|anrs)\b", re.IGNORECASE
)
WIFI_TRIGGER_RE = re.compile(
    r"\b(?:wi-?fi\w*|wlan\w*|disconnect\w*|drop\w*|roam\w*|network\w*|internet\w*)\b",
    re.IGNORECASE,
)
BATTERY_TRIGGER_RE = re.compile(
    r"\b(?:batter(?:y|ies)|drain\w*|discharg\w*|power(?:ed|ing|s)?|wakelock\w*|mah)\b",
    re.IGNORECASE,
)
PAIRING_TRIGGER_RE = re.compile(
    r"\b(?:pair\w*|bond\w*|bluetooth\w*|companion\w*|network\w*|connect\w*|"
    r"unpair\w*|bt)\b",
    re.IGNORECASE,
)
MEMORY_TRIGGER_RE = re.compile(
    # Short tokens like "ram"/"oom" are whole-word only; a trailing \w* on
    # them false-triggers on ordinary words ("ramen" -> memory evidence).
    # Longer, unambiguous stems keep the suffix wildcard so "leaking" and
    # "reclaimed" still match.
    r"\b(?:memor\w+|leak\w*|reclaim\w*|kill(?:ed|s|ing)?|lowmemory|"
    r"ram|oom|lmk|pss|rss|cached)\b",
    re.IGNORECASE,
)
# Every noun a user reaches for when positioning misbehaves. "rubber band"
# and "drift" are here because that is what people actually type -- the
# words "GPS" and "geolocation" are the ones they use least.
LOCATION_TRIGGER_RE = re.compile(
    r"\b(?:gps|gnss|geolocat\w*|locat\w+|position\w*|navigat\w*|satellite\w*|"
    r"map\w*|maps|drift\w*|teleport\w*|jump\w*|rubber-?band\w*|"
    r"coordinate\w*|latitude|longitude|compass|geofenc\w*)\b",
    re.IGNORECASE,
)

# Kernel/thermal/cpu are bundled under one trigger, same pattern as
# MEMORY_TRIGGER_RE covering kills+snapshot+growth -- a user asking about
# any one of "it's slow", "it's hot", or "kernel panic" wants the same
# platform-level evidence gathered together.
PLATFORM_TRIGGER_RE = re.compile(
    r"\b(?:kernel\w*|driver\w*|panic\w*|oops|dmesg|watchdog\w*|"
    r"thermal\w*|overheat\w*|throttl\w*|temperature\w*|\btemp\b|hot|"
    r"cpu\w*|schedul\w*|\blag\w*|sluggish\w*|unresponsive\w*|freez\w*|"
    r"\bload\b|slow\w*)\b",
    re.IGNORECASE,
)

SELINUX_TRIGGER_RE = re.compile(
    r"\b(selinux|sepolicy|avc|denial|denied|permission|policy|audit|blocked)\w*\b", re.IGNORECASE
)

SYSTEM_PROMPT = """You are a diagnosis-report writer for Android device logs.

You will be given a JSON bundle of ALREADY-VERIFIED structured facts, each
tagged with a confidence label and a source citation (section + line
numbers). Rules, no exceptions:

1. Never state a claim that is not present in the JSON bundle. If the
   bundle doesn't contain something, say it is unknown -- do not infer it.
2. Always carry each claim's given confidence label forward verbatim. Never
   upgrade "LOW" to "HIGH" because the underlying fact sounds compelling.
3. When the user's question frames one app as having caused a problem for
   another, report BOTH apps' own verified state, even if one of them
   undercuts the question's premise. Do not adopt the user's framing as
   fact.
4. Cite the section + line numbers for every factual claim you make.
5. If a fact was checked across multiple captures, say how many captures it
   was corroborated against, not just "confirmed."
6. Every "device_wide_*" evidence key (crash, wifi, battery, pairing --
   rules 6-9 below) is gathered across EVERY capture on file for this
   device, not just the one the question happened to be asked against --
   each individual entry in these lists carries its own "capture_id"
   saying which capture it actually came from. Resolve that id to a
   filename using the top-level "captures" map (an id -> filename object
   emitted once, so the filename isn't repeated on every fact), and cite
   it alongside the section/line number (rule 4) so a fact found in a
   different capture than the one named in the question is never presented
   as if it came from "this capture." Each device_wide_* block carries one
   "confidence" and "corroboration" pair at the BLOCK level that applies to
   every fact inside it; individual facts repeat only the short confidence
   label. Rule 2's "carry it forward verbatim" still applies -- do not
   recompute or upgrade it.
7. If the bundle includes a top-level "device_wide_crash_evidence" key,
   that's crash/native-crash/ANR evidence across every capture for this
   device, not filtered to any named app -- use it to answer general
   crash/ANR questions, but never claim it proves a specific app crashed
   unless a claim's own crash_events/native_crashes/anrs says so. Native
   crashes carry a `package` field derived from the crashing process; when
   it's null, say attribution is unknown rather than guessing which app it
   was. Never assign a confidence level to anything in this bundle that
   isn't already labeled with one.
8. If the bundle includes a top-level "device_wide_wifi_evidence" key,
   that's every Wi-Fi disconnection event across every capture for this
   device with its 802.11 reason code -- Wi-Fi connectivity is device-wide,
   not per-app, so don't expect it to be attributed to any named app.
9. If the bundle includes a top-level "device_wide_battery_evidence" key,
   or a claim's verified_state has a "battery" field, that's real
   estimated-mAh attribution across every capture for this device, broken
   down by component (cpu/screen/audio/wifi/mobile_radio/wakelock/etc). It
   is a snapshot for each capture's own stats window, not a measured
   cause-and-effect link to any specific user-reported symptom -- report
   the numbers plainly and let them speak for themselves rather than
   asserting they "caused" drain unless the bundle itself frames it that
   way.
10. If the bundle includes "device_wide_pairing_evidence", those are real
    Companion Device Manager / Fast Pair events across every capture for
    this device. A "kind":"anomaly" entry means only that the log level
    (W/E) flagged it, not that its `detail` text has been independently
    interpreted -- quote the detail rather than paraphrasing a cause into
    it. "bt_hci_summary", "packet_capture_summary", and "packet_analysis",
    when present, are each a LIST with one entry per capture that has that
    kind of data (also capture-tagged) -- supporting evidence, not
    necessarily about the same capture as a given pairing event.
    packet_capture_summary is container-level metadata only (packet
    count/time range) and cannot by itself identify what happened.
    packet_analysis is real protocol-level dissection -- its "backend"
    field on each entry says whether it came from full tshark dissection
    or the narrower hand-rolled fallback (see that entry's own "note"
    field for exactly what that backend does and doesn't cover, e.g. the
    fallback backend does not decode deauth/disassoc reason codes or
    detect TCP retransmissions -- never state a reason code or
    retransmission fact unless a packet_analysis entry actually contains
    one). Frame counts, RSSI range, retry rate, SSIDs/BSSIDs, and any
    listed anomalies in packet_analysis are real per-packet facts, not
    inferred. If "device_wide_pairing_evidence" includes a
    "current_associations" list, that's the CDM service's OWN
    current-state record of each paired device at the moment ITS capture
    was taken -- not reconstructed from log messages, so it's the most
    direct answer to "is this device currently paired/connected"
    available in this bundle (check which capture it's tagged with).
10b. If the bundle includes "device_wide_selinux_evidence", those are
    SELinux AVC denials. The `enforcing` field is load-bearing and must
    never be glossed over: `true` means the operation was actually BLOCKED
    (permissive=0) and something genuinely did not work; `false` means it
    was logged but ALLOWED through (permissive=1), which is a warning
    about future enforcement, not a current failure; `null` means the log
    did not record it. Always say which. Report the enforced count
    separately from the total. A denial says an operation was blocked --
    it does NOT by itself establish that any user-visible feature broke,
    so do not assert a functional impact the bundle does not state.
10c. If the bundle includes "device_wide_memory_evidence", those are
    ActivityManager process kills/deaths. Keep kind="kill" (deliberate,
    has a `reason`) distinct from kind="died" (process went away, no
    reason recorded) -- never describe a plain death as the system killing
    something. Processes being killed is normal Android memory management;
    report counts and reasons plainly and do not assert the device is
    "leaking memory" or "under memory pressure" unless a reason field
    actually says so.
10d. If the bundle includes "memory_snapshot_evidence", that is dumpsys
    meminfo. Quote the device's own `status` field for pressure; do not
    derive pressure from free RAM yourself, since free RAM already counts
    reclaimable cached memory. Never sum RSS across processes (shared
    pages are counted in each one) and never compare an RSS figure to a
    PSS figure.
10e. If the bundle includes "memory_growth_evidence", those are repeated
    am_pss samples. NEVER use the words "memory leak" -- these samples
    cannot distinguish a leak from an app legitimately using more memory.
    Say a process "grew from X to Y". Report `monotonic: false` honestly
    as fluctuation, not as steady growth. If `pss_collected` is false,
    say PSS was not collected on this build; do not report it as 0.
10f. If the bundle includes "location_snapshot_evidence", the KPI figures
    are since-boot aggregates -- say so, and never attach them to a
    specific hour. Coordinates are intentionally absent; do not ask for
    them or speculate about where the device was.
10g. If the bundle includes "gnss_signal_evidence", keep the three states
    distinct: "none" is NO FIX (acquiring or GPS off), never bad
    reception. Reception quality is NOT position error -- you may say
    satellite signal was weak for a span, but you may NOT say an app
    received a wrong position, because the logs do not record delivered
    coordinates. Weak GPS indoors, underground, or among tall buildings
    is expected physics: report it as environmental unless other evidence
    says otherwise, and never call it a hardware malfunction.
10h. If the bundle includes "anr_blocking_threads_evidence" or
    "anr_main_thread_evidence", these enrich an ANR already reported
    above -- narrate them as "the trace/binder detail shows...", never as
    an independent event. trace_<N> files could not be filename-matched
    to a specific anr_* record, so describe what a trace showed without
    asserting it caused a particular named ANR unless the bundle links them.
10i. If the bundle includes "kernel_log_evidence", `boot_relative_sec` is
    kernel uptime, NOT a wall-clock time -- never state a clock time for
    these events. Most "warning"-priority lines are routine driver
    chatter, not evidence of a fault; only "err" or worse, or anything
    flagged panic-family, indicates a real problem.
10j. If the bundle includes "thermal_evidence", quote `overall_status`
    verbatim for throttling state; do not infer thermal pressure from raw
    sensor temperatures yourself. "none" means not currently throttled
    and is not worth reporting as a finding.
10k. If the bundle includes "cpu_load_evidence", it is ONE point-in-time
    snapshot, not a time series. Do not describe elevated load as an
    ongoing or persistent problem -- say only what was busy at the moment
    the bugreport was captured, and note that a spike before or after
    this moment would not appear here.
11. If the bundle includes a "device_context" object, that's real parsed
    device info (build fingerprint, kernel, security patch, etc.) -- open
    the report with a short "Device" line or table using it verbatim, not
    reformatted or guessed at. Never invent a device-context field that
    isn't present.
12. If the bundle includes an "evidence_sources" list, that's a
    deterministic, code-generated record of which evidence categories were
    actually checked for this question (not written by you) -- include it
    near the end of the report as a short "Evidence checked" list so the
    reader can see what was and wasn't looked at, using its "category" and
    "detail" fields verbatim.
12b. If the bundle includes a top-level "capture_coverage" object, that is
    a deterministic, code-computed record of which calendar dates the
    loaded captures actually cover -- not written by you. If it has a
    non-null "statement" field, quote that text verbatim at the start of
    "## Direct answer" (before your 1-3 sentence answer). Never invent a
    covered range, a gap, or an out-of-range claim that is not in this
    object. If "statement" is null or absent, do not warn about coverage.
    If "relation" is "inside", the requested date WAS covered; do not
    imply a coverage gap. If "question_date_parse" is "unparsed", say the
    date could not be parsed and make no coverage claim.
13. Structure every report with these sections, in this order, using
    markdown headings (##):
    - "## Direct answer" -- if capture_coverage.statement is present, open
      with it verbatim, then 1-3 sentences answering the literal question
      first, before any supporting detail.
    - "## Findings" -- the verified facts, organized by category (named
      app claims, crash/ANR, Wi-Fi, battery, pairing, packet analysis --
      whichever are actually present in the bundle), each finding stating
      its confidence label verbatim (rule 2) and citing section/line
      (rule 4) and capture (rule 6) as established above.
    - "## Suggested next steps" -- OPTIONAL, only include if there's
      something genuinely actionable to suggest. This section is your own
      general troubleshooting knowledge, NOT verified facts from the
      capture -- head it explicitly with the sentence "These are general
      troubleshooting suggestions based on the findings above, not
      additional verified facts from this capture." Never state a
      confidence label on anything in this section, and never phrase a
      suggestion as something the bundle confirmed.
    - "## Evidence checked" -- render the evidence_sources list per rule 12,
      if present.
    Keep the whole report proportional to how much the bundle actually
    contains -- an empty bundle deserves a few honest sentences, not
    padded-out empty sections.
14. If the user prompt includes a "Prior conversation in this session"
    block, that's earlier turns of the SAME conversation, given for
    continuity only (e.g. so "what about the other one?" can be
    understood) -- it is NEVER itself evidence. Every factual claim in
    your report must still trace back to the JSON fact bundle for THIS
    turn, per rule 1, even when answering a follow-up.
"""


@dataclass
class ScoredClaim:
    label: str            # human-readable claim
    confidence: str        # "HIGH" | "MEDIUM" | "LOW" | "UNCONFIRMED"
    corroboration: str     # explanation of what backs the confidence label
    source: dict | None


def score_confidence(fact_count: int, captures_checked: int) -> tuple[str, str]:
    """Confidence tied to corroboration, not phrasing. fact_count = number of
    independent structured facts backing the claim;
    captures_checked = how many captures those facts actually appeared in
    (not how many captures exist on the device).
    """
    if fact_count == 0:
        return "UNCONFIRMED", "No structured fact in this capture backs this claim; it is an unconfirmed hypothesis."
    if fact_count >= 2 and captures_checked >= 2:
        return "HIGH", f"Backed by {fact_count} independent structured facts, corroborated across {captures_checked} captures."
    if fact_count >= 2 or captures_checked >= 2:
        return "MEDIUM", f"Backed by {fact_count} structured fact(s), checked across {captures_checked} capture(s)."
    return "LOW", f"Backed by {fact_count} structured fact from a single capture only; not yet corroborated across history."


def evidence_confidence(*row_groups) -> tuple[str, str]:
    """Score from the rows that actually exist, not from captures-on-file.

    Two unrelated uploads on the same device label must not upgrade a
    one-off fact from LOW to MEDIUM.
    """
    rows = [r for group in row_groups for r in group]
    n_caps = len({r.capture_id for r in rows})
    return score_confidence(len(rows), n_caps)


DEVICE_CONTEXT_LLM_FIELDS = (
    "manufacturer", "model", "android_release", "sdk_version", "build_id",
    "build_fingerprint", "security_patch", "bootloader", "radio", "network",
    "kernel", "cpu_abi", "hardware", "build_type", "uptime", "timezone",
    "crypto_state", "verified_boot_state", "debuggable",
)


def build_entity_claim(ev: EntityVerification, history: PackageHistory | None) -> dict:
    fact_count = ev.corroborating_fact_count
    captures_checked = history.captures_checked if history else 1
    confidence, corroboration = score_confidence(fact_count, captures_checked)

    claim = {
        "package": ev.package,
        "matched_how": ev.matched_how,
        "confidence": confidence,
        "corroboration": corroboration,
        "verified_state": {
            "is_top_of_audio_focus_stack": ev.is_top_of_focus_stack,
            "media_session_active": ev.media_session_active,
            "media_session_playback_state": ev.media_session_playback_state,
            "media_session_position_ms": ev.media_session_position_ms,
            "media_session_source": ev.media_session_source,
            "latest_focus_event": ev.latest_focus_event,
            "target_sdk": ev.target_sdk,
            "target_sdk_source": ev.target_sdk_source,
            "crash_events": ev.crash_events,
            "freeze_count": ev.freeze_count,
            "unfreeze_count": ev.unfreeze_count,
            "native_crashes": ev.tombstones,
            "anrs": ev.anrs,
            "battery": ev.battery,
        },
    }
    if history is not None:
        claim["cross_capture_history"] = {
            "captures_checked": history.captures_checked,
            "captures_on_file": history.captures_on_file,
            "ever_requested_audio_focus": history.ever_requested_focus,
            "focus_request_count_all_captures": history.focus_request_count,
            "target_sdk_by_capture": history.target_sdk_by_capture,
            "ever_hosted_foreground_service": history.ever_hosted_foreground_service,
        }
    return claim


def _derive_memory_growth(sample_rows, capture_tag, min_delta_kb: int = 20 * 1024) -> list[dict]:
    """Groups repeated am_pss samples per process and reports how RSS moved.

    Deliberately reports the SHAPE of the change, not a verdict. Real data
    from a test capture:

        146MB -> 556MB -> 560MB -> 504MB -> 504MB -> 533MB

    That is +387MB net, and it is also not a leak -- it goes up, down, then
    up again, which is what an app that allocates and releases looks like.
    A tool that called this a "memory leak" would be inventing a
    conclusion the data doesn't support. So `monotonic` is emitted as a
    plain fact (did it only ever increase?) and the full sample sequence
    rides along, letting the reader see the curve. Nothing here uses the
    word leak.

    Grouped by (capture_id, pid, process) rather than package: a pid is
    reused after a process restarts, and a restarted process starting
    small again is not the same process shrinking.
    """
    groups: dict[tuple, list] = defaultdict(list)
    for r in sample_rows:
        if r.rss_kb is None or r.pid is None:
            continue
        groups[(r.capture_id, r.pid, r.process)].append(r)

    growth = []
    for (capture_id, pid, process), rows in groups.items():
        if len(rows) < 2:
            continue  # a single sample says nothing about change over time
        rows.sort(key=lambda r: r.timestamp)
        values = [r.rss_kb for r in rows]
        delta = values[-1] - values[0]
        if delta < min_delta_kb:
            continue
        growth.append({
            "process": process, "package": rows[0].package, "pid": pid,
            "first_rss_kb": values[0], "last_rss_kb": values[-1],
            "peak_rss_kb": max(values), "delta_kb": delta,
            "sample_count": len(values),
            # True only if RSS never once decreased between samples. False
            # means it fluctuated, which is normal allocate/release
            # behavior and must not be described as unbounded growth.
            "monotonic": all(b >= a for a, b in zip(values, values[1:])),
            "first_timestamp": rows[0].timestamp, "last_timestamp": rows[-1].timestamp,
            "samples": [{"timestamp": r.timestamp, "rss_kb": r.rss_kb} for r in rows],
            **capture_tag(capture_id),
            "source": {"section": rows[0].source_section,
                       "line_start": rows[0].source_line_start,
                       "line_end": rows[-1].source_line_end},
        })
    growth.sort(key=lambda g: g["delta_kb"], reverse=True)
    return growth


def build_diagnosis_bundle(
    session: Session, capture_id: int, device_label: str, question: str,
    include_all_evidence: bool = False,
) -> dict:
    """Everything diagnose() needs except the actual LLM call -- pulled out
    so investigation-level diagnosis (see diagnose_investigation()) can
    build one bundle per capture and merge them before a single LLM call,
    without duplicating the per-capture fact-gathering logic.

    include_all_evidence=True gathers EVERY evidence category regardless of
    what the question's keywords matched -- used by auto-scan (scan_capture),
    where there is no question to trigger off. Keyword triggers exist to keep
    a targeted question's bundle small and relevant; when the whole point is
    "tell me everything wrong with this device", that filtering is exactly
    what we don't want. This also sidesteps the keyword-trigger fragility
    found repeatedly in live testing (a "network issue" question missing the
    Wi-Fi trigger; a vague follow-up matching nothing at all).
    """
    entities = verify_question_entities(session, capture_id, question)
    want_history = bool(MULTI_CAPTURE_TRIGGER_RE.search(question))
    want_crash = include_all_evidence or bool(CRASH_TRIGGER_RE.search(question))
    want_wifi = include_all_evidence or bool(WIFI_TRIGGER_RE.search(question))
    want_battery = include_all_evidence or bool(BATTERY_TRIGGER_RE.search(question))
    want_pairing = include_all_evidence or bool(PAIRING_TRIGGER_RE.search(question))
    want_selinux = include_all_evidence or bool(SELINUX_TRIGGER_RE.search(question))
    want_memory = include_all_evidence or bool(MEMORY_TRIGGER_RE.search(question))
    want_location = include_all_evidence or bool(LOCATION_TRIGGER_RE.search(question))
    want_platform = include_all_evidence or bool(PLATFORM_TRIGGER_RE.search(question))

    claims = []
    for ev in entities:
        history = package_history_across_device(session, device_label, ev.package) if want_history else None
        claims.append(build_entity_claim(ev, history))

    bundle = {
        "question": question,
        "entities_independently_verified": [c["package"] for c in claims],
        "claims": claims,
    }

    # Deterministic, not LLM-generated -- straight from DeviceInfoRow, so
    # there's no invention risk in giving the report the same device
    # context table a human analyst would want up front (build fingerprint,
    # kernel, security patch, etc.) rather than making the LLM guess at or
    # omit it.
    device_info_row = session.exec(
        select(DeviceInfoRow).where(DeviceInfoRow.capture_id == capture_id)
    ).first()
    if device_info_row:
        bundle["device_context"] = {
            k: getattr(device_info_row, k)
            for k in DEVICE_CONTEXT_LLM_FIELDS
            if getattr(device_info_row, k, None) is not None
        }

    # Process-transparency list: which evidence categories were actually
    # checked for this question and why, computed here (not by the LLM) as
    # each block below is populated -- an honest, cheap substitute for a
    # genuine multi-step research trace, which this system doesn't run.
    evidence_sources: list[dict] = []
    if claims:
        evidence_sources.append({
            "category": "named app verification", "reason": "app(s) named in the question",
            "detail": f"{len(claims)} app(s) independently verified: {', '.join(c['package'] for c in claims)}",
        })

    # Real gap found live: "device-wide" evidence (crash/wifi/battery/
    # pairing, below) was actually scoped to just the ONE capture_id passed
    # in -- so asking the identical question against two different captures
    # uploaded for the same device (e.g. a phone's bugreport vs. a watch's,
    # both filed under one shared device label) could come back with
    # completely different answers depending purely on which capture
    # happened to be selected in the UI at the time, even though both were
    # "the same device"'s data. Every block below now searches every
    # capture on file for this device, not just the selected one, and tags
    # each individual fact with which capture it actually came from so
    # citations stay traceable. Confidence is upgraded accordingly by
    # captures_checked (see score_confidence) -- checking N captures for a
    # device-wide fact is real corroboration, not just checking one.
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    sibling_captures = (
        session.exec(select(Capture).where(Capture.device_id == device.id)).all()
        if device else []
    )
    sibling_capture_ids = [c.id for c in sibling_captures] or [capture_id]
    capture_filenames = {c.id: c.original_filename for c in sibling_captures}
    captures_checked = len(sibling_capture_ids)

    # Facts carry only capture_id; the id -> filename map is emitted ONCE at
    # the top of the bundle as "captures". Measured on a real scan: the
    # filename was repeated 109 times (8.1% of the whole bundle) and the
    # identical corroboration sentence 138 times (15.6%) -- ~24% of every
    # scan's tokens were pure duplication. Both are now hoisted, with no
    # information lost.
    def _capture_tag(row_capture_id: int) -> dict:
        return {"capture_id": row_capture_id}

    bundle["captures"] = dict(capture_filenames) or {capture_id: None}

    # Deterministic coverage of loaded captures vs. any date in the question.
    # The LLM may quote capture_coverage.statement; it must not invent ranges.
    bundle["capture_coverage"] = build_capture_coverage(
        session, sibling_captures, question,
    )

    if want_crash:
        # Device-wide crash evidence, surfaced regardless of whether it's
        # attributable to a named app -- so a crash question never comes
        # back "unknown" when there's a real crash on the device that
        # simply wasn't named. Native crash files (tombstones) are binary;
        # we don't parse their contents, so which app crashed is honestly
        # reported as not determined by this system, not silently omitted.
        java_crash_count = session.exec(
            select(CrashEventRow).where(CrashEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        tombstone_count = session.exec(
            select(TombstoneRow).where(TombstoneRow.capture_id.in_(sibling_capture_ids))
        ).all()
        anr_count = session.exec(
            select(AnrRow).where(AnrRow.capture_id.in_(sibling_capture_ids))
        ).all()
        # Each event is exactly one structured fact -- computed the same way
        # entity claims are, rather than leaving confidence for the LLM to
        # infer (an earlier version left this field out entirely and relied
        # on the system prompt telling the model not to invent one; that
        # worked for one provider but not another live-tested one, which
        # assigned "HIGH confidence" to evidence that had none. Computing it
        # removes the ambiguity instead of hoping every model infers it the
        # same way). captures_checked reflects every capture actually
        # searched for this device, not just the one that happened to be
        # selected.
        crash_confidence, crash_corroboration = evidence_confidence(
            java_crash_count, tombstone_count, anr_count)
        bundle["device_wide_crash_evidence"] = {
                "confidence": crash_confidence,
                "corroboration": crash_corroboration,
            "note": (
                f"Not filtered to a named app -- includes every crash/ANR found across all "
                f"{captures_checked} capture(s) on file for this device, each tagged with which "
                f"capture it came from."
            ),
            "java_crashes": [
                {"timestamp": c.timestamp, "package": c.package, "exception_class": c.exception_class,
                 "message": c.message, "root_cause_class": c.root_cause_class,
                 "root_cause_message": c.root_cause_message, "root_cause_frame": c.root_cause_frame,
                 "confidence": crash_confidence,
                 **_capture_tag(c.capture_id),
                 "source": {"section": c.source_section, "line_start": c.source_line_start, "line_end": c.source_line_end}}
                for c in java_crash_count
            ],
            "native_crashes": [
                {"timestamp": t.timestamp, "package": t.package, "executable": t.executable,
                 "signal_name": t.signal_name, "signal_code": t.signal_code, "top_frame": t.top_frame,
                 "confidence": crash_confidence,
                 **_capture_tag(t.capture_id)}
                for t in tombstone_count
            ],
            "native_crash_attribution_note": (
                "Tombstone `package` is derived from the crashing process's Cmdline; it is null "
                "when the process was a native binary/service rather than an app package -- that "
                "is reported as null, not guessed."
            ),
            "anrs": [
                {"timestamp": a.timestamp, "package": a.package, "reason": a.reason,
                 "timeout_ms": a.timeout_ms, "rss_kb": a.rss_kb,
                 "confidence": crash_confidence,
                 **_capture_tag(a.capture_id)}
                for a in anr_count
            ],
        }

        blocking_rows = session.exec(
            select(AnrBlockingThreadRow).where(AnrBlockingThreadRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if blocking_rows:
            # Grouped by which anr_* file they came from -- each group is
            # every binder thread of ONE ANR'd process caught mid-transaction
            # at the moment Android declared the ANR. elapsed_ms is read
            # directly off the transaction record, not inferred from timing.
            by_file: dict[str, list] = {}
            for bt in blocking_rows:
                by_file.setdefault(bt.anr_filename, []).append(bt)
            bundle["anr_blocking_threads_evidence"] = {
                "confidence": crash_confidence,
                "corroboration": crash_corroboration,
                "note": (
                    "Binder threads of an ANR'd process caught mid-transaction, from the "
                    "'dumping pid' block Android writes into the ANR record itself. "
                    "`elapsed_ms` is how long that specific transaction had been unanswered "
                    "when the ANR fired -- this is what the process was actually stuck on, "
                    "not a guess from thread state. Present only for the binder-starvation "
                    "flavor of ANR (a stuck service/broadcast); not every ANR has this."
                ),
                "by_anr_file": {
                    fname: sorted(
                        [{"thread_id": bt.thread_id, "from_pid": bt.from_pid,
                          "elapsed_ms": bt.elapsed_ms} for bt in rows],
                        key=lambda r: -(r["elapsed_ms"] or 0),
                    )[:10]
                    for fname, rows in by_file.items()
                },
            }

        trace_rows = session.exec(
            select(AnrMainThreadSnapshotRow).where(AnrMainThreadSnapshotRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if trace_rows:
            # trace_<N> files are NOT filename-linked to any anr_* record in
            # real captures observed -- reported as its own evidence rather
            # than force-matched to a specific ANR event.
            bundle["anr_main_thread_evidence"] = {
                "confidence": crash_confidence,
                "corroboration": crash_corroboration,
                "note": (
                    "The main thread's own state, read directly from a trace_<N> file (a full "
                    "thread dump written for an ANR'd process) -- this says what the thread was "
                    "actually doing, not a guess. These traces could not be linked to a specific "
                    "anr_* record by filename, so report them as their own evidence: 'the trace "
                    "shows...', not 'this ANR was caused by...'. `held_mutexes` empty string "
                    "means the trace explicitly showed the thread holding nothing, which is "
                    "different from this field being unknown."
                ),
                "snapshots": [
                    {"pid": t.pid, "process": t.process, "state": t.state,
                     "held_mutexes": t.held_mutexes,
                     "top_frames": json.loads(t.top_frames_json),
                     **_capture_tag(t.capture_id),
                     "source": {"section": t.source_section, "line_start": t.source_line_start,
                                "line_end": t.source_line_end}}
                    for t in trace_rows
                ],
            }

    if want_wifi:
        # Wi-Fi connectivity is device-wide, not attributable to a named
        # app, so this always surfaces regardless of whether any app was
        # named -- same principle as device_wide_crash_evidence.
        disconnections = session.exec(
            select(WifiEventRow).where(
                WifiEventRow.capture_id.in_(sibling_capture_ids), WifiEventRow.kind == "disconnection"
            )
        ).all()
        wifi_confidence, wifi_corroboration = evidence_confidence(disconnections)
        bundle["device_wide_wifi_evidence"] = {
                "confidence": wifi_confidence,
                "corroboration": wifi_corroboration,
            "note": (
                f"Every Wi-Fi disconnection event found across all {captures_checked} capture(s) on "
                f"file for this device (not just the one currently selected), with its 802.11 reason "
                f"code and which capture it came from."
            ),
            "disconnections": [
                {"timestamp": w.timestamp, "ssid": w.ssid, "bssid": w.bssid,
                 "reason_code": w.reason_code, "reason_name": w.reason_name,
                 "locally_generated": w.locally_generated,
                 "confidence": wifi_confidence,
                 **_capture_tag(w.capture_id),
                 "source": {"section": w.source_section, "line_start": w.source_line_start, "line_end": w.source_line_end}}
                for w in disconnections
            ],
        }

    if want_battery:
        # Battery attribution is per-UID, not automatically tied to a named
        # app in the question -- surfaced device-wide (top consumers) so a
        # battery question always gets real evidence, same principle as
        # crash/wifi triggers. Live-tested gap this closes: a battery-drain
        # question naming two apps used to come back "no battery data
        # exists in this bundle" even when the parsed capture had real
        # per-app mAh attribution the whole time -- there was simply no
        # battery-stats parser wiring it into the bundle at all.
        top_consumers = session.exec(
            select(BatteryUidStatRow)
            .where(BatteryUidStatRow.capture_id.in_(sibling_capture_ids))
            .order_by(BatteryUidStatRow.total_mah.desc())
            .limit(15)
        ).all()
        battery_confidence, battery_corroboration = evidence_confidence(top_consumers)
        bundle["device_wide_battery_evidence"] = {
                "confidence": battery_confidence,
                "corroboration": battery_corroboration,
            "note": (
                f"Top battery consumers by estimated mAh across all {captures_checked} capture(s) "
                f"on file for this device, not filtered to a named app. `package` is null for UIDs "
                f"that are shared by multiple system packages (e.g. the \"system\" UID) or have no "
                f"matching installed package -- attribution is not guessed in that case."
            ),
            "top_consumers": [
                {"package": b.package, "uid_token": b.uid_token, "total_mah": b.total_mah,
                 "components_mah": json.loads(b.components_mah_json),
                 "confidence": battery_confidence,
                 **_capture_tag(b.capture_id),
                 "source": {"section": b.source_section, "line_start": b.source_line_start, "line_end": b.source_line_end}}
                for b in top_consumers
            ],
        }

    if want_memory:
        # Process kills are how memory pressure becomes observable. An
        # am_kill carries a reason; an am_proc_died only records that the
        # process went away, so the two are counted separately rather than
        # summed into one "N processes killed" number that would overstate
        # what the log actually says.
        kill_rows = session.exec(
            select(ProcessKillEventRow).where(ProcessKillEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        memory_confidence, memory_corroboration = evidence_confidence(kill_rows)
        if kill_rows:
            kills = [k for k in kill_rows if k.kind == "kill"]
            bundle["device_wide_memory_evidence"] = {
                "confidence": memory_confidence,
                "corroboration": memory_corroboration,
                "note": (
                    f"ActivityManager process kills and deaths across all {captures_checked} "
                    f"capture(s) on file for this device. kind=\"kill\" (am_kill) means the system "
                    f"deliberately killed the process and recorded a `reason`; kind=\"died\" "
                    f"(am_proc_died) only records that the process went away and does NOT by "
                    f"itself establish the system killed it. `oom_adj` is the raw killability "
                    f"score (roughly 0 = foreground/critical, up toward ~1000 = empty cached) -- "
                    f"the exact bands vary by Android version, so do not interpret a specific "
                    f"value beyond 'higher means more disposable'."
                ),
                "total_events": len(kill_rows),
                "deliberate_kills": len(kills),
                "events": [
                    {"timestamp": k.timestamp, "kind": k.kind, "process": k.process,
                     "package": k.package, "pid": k.pid, "oom_adj": k.oom_adj,
                     "reason": k.reason, "rss_kb": k.rss_kb, "proc_state": k.proc_state,
                     "confidence": memory_confidence,
                     **_capture_tag(k.capture_id),
                     "source": {"section": k.source_section, "line_start": k.source_line_start,
                                "line_end": k.source_line_end}}
                    for k in kill_rows
                ],
            }

        # The snapshot answers "was the device actually short on memory?",
        # which the kill list alone cannot -- Android kills cached processes
        # routinely on a perfectly healthy device.
        snap_row = session.exec(
            select(MemorySnapshotRow).where(MemorySnapshotRow.capture_id == capture_id)
        ).first()
        if snap_row is not None:
            usage_rows = session.exec(
                select(ProcessMemoryUsageRow)
                .where(ProcessMemoryUsageRow.capture_id == capture_id)
                .order_by(ProcessMemoryUsageRow.metric, ProcessMemoryUsageRow.rank)
            ).all()
            bundle["memory_snapshot_evidence"] = {
                "confidence": memory_confidence,
                "corroboration": memory_corroboration,
                "note": (
                    "System-wide memory at the moment the bugreport was taken, from "
                    "`dumpsys meminfo`. `status` is the device's own assessment "
                    "(normal/moderate/low/critical) -- prefer it over inferring pressure "
                    "from the raw numbers. Free RAM already counts cached memory as free, "
                    "because cached pages are reclaimable on demand; a low 'truly_free_kb' "
                    "next to a large 'cached_pss_kb' is normal and is NOT memory pressure. "
                    "RSS and PSS measure different things -- RSS counts every page the "
                    "process has resident including shared ones, so RSS figures double-count "
                    "across processes and must never be summed; PSS divides shared pages by "
                    "how many processes share them. A process high in swap is compressed, "
                    "not lost. Any null field means this build did not report it."
                ),
                "ram": {k: v for k, v in snap_row.__dict__.items()
                        if not k.startswith("_")
                        and k not in ("id", "capture_id", "source_section",
                                      "source_line_start", "source_line_end")},
                "top_processes_by_rss": [
                    {"rank": u.rank, "process": u.process, "pid": u.pid,
                     "rss_kb": u.memory_kb, "state": u.state}
                    for u in usage_rows if u.metric == "rss"
                ][:10],
                "top_processes_by_pss": [
                    {"rank": u.rank, "process": u.process, "pid": u.pid,
                     "pss_kb": u.memory_kb, "swap_kb": u.swap_kb, "state": u.state}
                    for u in usage_rows if u.metric == "pss"
                ][:10],
                "source": {"section": snap_row.source_section,
                           "line_start": snap_row.source_line_start,
                           "line_end": snap_row.source_line_end},
            }

        sample_rows = session.exec(
            select(ProcessMemorySampleRow)
            .where(ProcessMemorySampleRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if sample_rows:
            growth = _derive_memory_growth(sample_rows, _capture_tag)
            pss_collected = any(r.pss_kb is not None for r in sample_rows)
            bundle["memory_growth_evidence"] = {
                "confidence": memory_confidence,
                "corroboration": memory_corroboration,
                "note": (
                    f"Per-process memory sampled repeatedly over the life of the log "
                    f"(am_pss events), across all {captures_checked} capture(s) for this "
                    f"device. Only processes whose RSS rose by at least 20 MB between first "
                    f"and last sample are listed. "
                    + ("" if pss_collected else
                       "This build did NOT collect PSS -- every sample reported RSS only, so "
                       "PSS is unavailable here rather than zero. ")
                    + "CRITICAL: growth is not a leak. `monotonic: true` means RSS never "
                    "decreased between samples; `monotonic: false` means it rose and fell, "
                    "which is ordinary allocate-and-release behavior. Describe what the "
                    "`samples` sequence shows and do NOT call any of this a memory leak -- "
                    "these samples cannot distinguish a leak from an app legitimately using "
                    "more memory as it does more work. Sampling is irregular, so the gap "
                    "between two samples is not a fixed interval."
                ),
                "processes_sampled": len({(r.capture_id, r.pid) for r in sample_rows}),
                "total_samples": len(sample_rows),
                "pss_collected": pss_collected,
                "growing_processes": growth[:10],
            }

    if want_location:
        # Two complementary sources. The dumpsys snapshot says who was using
        # location and how the hardware performed since boot; the battery
        # history says WHEN reception was good or poor. Only the second can
        # be lined up against "it misbehaved at lunchtime".
        location_confidence, location_corroboration = score_confidence(1, 1)

        loc_row = session.exec(
            select(LocationSnapshotRow).where(LocationSnapshotRow.capture_id == capture_id)
        ).first()
        if loc_row is not None:
            provider_rows = session.exec(
                select(LocationProviderRow).where(LocationProviderRow.capture_id == capture_id)
            ).all()
            usage_rows = session.exec(
                select(LocationAppUsageRow)
                .where(LocationAppUsageRow.capture_id == capture_id)
                .order_by(LocationAppUsageRow.locations.desc())
            ).all()
            bundle["location_snapshot_evidence"] = {
                "confidence": location_confidence,
                "corroboration": location_corroboration,
                "note": (
                    "Location state from `dumpsys location`. The KPI figures are "
                    "aggregates over the ENTIRE time since the device last booted -- they "
                    "cannot be attributed to any particular hour, and saying otherwise "
                    "invents precision they do not have. `cn0_*` values are satellite "
                    "carrier-to-noise ratios: higher is better, and the device classifies "
                    "reception as good above `cn0_threshold_dbhz` and poor below it. "
                    "Coordinates are deliberately omitted from this bundle -- the last "
                    "known fix is the user's real physical location and the diagnostic "
                    "value is in the accuracy radius and provider, not the latitude. "
                    "`locations` per app is the count DELIVERED, so an app requesting 1 Hz "
                    "that received far fewer was not served at the rate it asked for; that "
                    "is a fact about delivery rate, NOT proof the positions were wrong."
                ),
                "location_enabled": loc_row.location_enabled,
                "gnss_hardware_model": loc_row.gnss_hardware_model,
                "kpi_since_boot": {
                    "location_failure_pct": loc_row.location_failure_pct,
                    "ttff_mean_sec": loc_row.ttff_mean_sec,
                    "ttff_stddev_sec": loc_row.ttff_stddev_sec,
                    "accuracy_mean_m": loc_row.accuracy_mean_m,
                    "accuracy_stddev_m": loc_row.accuracy_stddev_m,
                    "cn0_mean_dbhz": loc_row.cn0_mean_dbhz,
                    "cn0_threshold_dbhz": loc_row.cn0_threshold_dbhz,
                    "cn0_time_above_threshold_min": loc_row.cn0_time_above_threshold_min,
                    "cn0_time_below_threshold_min": loc_row.cn0_time_below_threshold_min,
                    "constellations": loc_row.constellations,
                },
                "providers": [
                    {"name": pr.name, "last_fix_provider": pr.last_fix_provider,
                     "horizontal_accuracy_m": pr.horizontal_accuracy_m,
                     "satellites": pr.satellites, "mean_cn0": pr.mean_cn0,
                     "coordinates": "omitted (sensitive; available locally)"}
                    for pr in provider_rows
                ],
                "top_apps_by_locations_delivered": [
                    {"package": u.package, "provider": u.provider,
                     "foreground_duration": u.foreground_duration,
                     "requested_interval": f"{u.min_interval}/{u.max_interval}",
                     "locations_delivered": u.locations}
                    for u in usage_rows
                ][:12],
                "source": {"section": loc_row.source_section,
                           "line_start": loc_row.source_line_start,
                           "line_end": loc_row.source_line_end},
            }

        interval_rows = session.exec(
            select(GnssSignalIntervalRow)
            .where(GnssSignalIntervalRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if interval_rows:
            degraded = [iv for iv in interval_rows if iv.quality == "poor"]
            good = [iv for iv in interval_rows if iv.quality == "good"]
            bundle["gnss_signal_evidence"] = {
                "confidence": location_confidence,
                "corroboration": location_corroboration,
                "note": (
                    "Time-resolved GPS reception from the batterystats history, across all "
                    f"{captures_checked} capture(s) for this device. Three states, and the "
                    "difference matters: \"good\" and \"poor\" are real reception readings "
                    "thresholded on satellite carrier-to-noise ratio, while \"none\" means "
                    "NO FIX -- either still acquiring or GPS switched off -- and must never "
                    "be described as bad reception. CRITICAL: reception quality is not "
                    "position error. A poor span means weak satellite signal; it does NOT "
                    "establish that any app received an incorrect position, because these "
                    "logs never record the coordinates delivered to an app. Weak reception "
                    "indoors, underground, or between tall buildings is expected physics, "
                    "not a device fault -- do not describe it as a malfunction. "
                    "`active_uids` lists which apps held GPS open during the span, which is "
                    "what connects a reception dip to something the user was doing."
                ),
                "total_intervals": len(interval_rows),
                "degraded_intervals": len(degraded),
                "total_degraded_sec": sum(iv.duration_sec for iv in degraded),
                "total_good_sec": sum(iv.duration_sec for iv in good),
                "degraded_spans": [
                    {"start": iv.start_timestamp, "end": iv.end_timestamp,
                     "duration_sec": iv.duration_sec, "active_uids": iv.active_uids,
                     "gps_active": iv.gps_active,
                     "confidence": location_confidence,
                     **_capture_tag(iv.capture_id),
                     "source": {"section": iv.source_section,
                                "line_start": iv.source_line_start,
                                "line_end": iv.source_line_end}}
                    for iv in sorted(degraded, key=lambda a: -a.duration_sec)
                ][:15],
            }

    if want_platform:
        kernel_rows = session.exec(
            select(KernelLogEventRow).where(KernelLogEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        platform_confidence, platform_corroboration = evidence_confidence(kernel_rows)
        if kernel_rows:
            err_or_worse = [k for k in kernel_rows if k.priority <= 3 or k.is_panic_family]
            bundle["kernel_log_evidence"] = {
                "confidence": platform_confidence,
                "corroboration": platform_corroboration,
                "note": (
                    f"Kernel ring buffer lines at warning severity or worse, across all "
                    f"{captures_checked} capture(s) for this device. `boot_relative_sec` is the "
                    f"KERNEL's own timestamp (seconds since boot), NOT wall-clock time -- there "
                    f"is no reliable way to convert it, so do not state a clock time for these "
                    f"events, only their relative order and how far apart they were. Most "
                    f"'warning'-priority lines are routine driver chatter (radio/wifi firmware "
                    f"debug output logged at warning level by convention) and are NOT evidence "
                    f"of a fault by themselves -- 'err' priority or worse, or anything flagged "
                    f"`is_panic_family`, is what actually indicates a real driver/kernel problem."
                ),
                "total_warning_or_worse": len(kernel_rows),
                "err_or_worse_count": len(err_or_worse),
                "panic_family_count": sum(k.is_panic_family for k in kernel_rows),
                "err_or_worse_events": [
                    {"boot_relative_sec": k.boot_relative_sec, "priority_name": k.priority_name,
                     "thread": k.thread, "message": k.message, "is_panic_family": k.is_panic_family,
                     "confidence": platform_confidence,
                     **_capture_tag(k.capture_id),
                     "source": {"section": k.source_section, "line_start": k.source_line_start,
                                "line_end": k.source_line_end}}
                    for k in err_or_worse
                ][:60],
            }

        thermal_row = session.exec(
            select(ThermalSnapshotRow).where(ThermalSnapshotRow.capture_id == capture_id)
        ).first()
        if thermal_row is not None:
            sensor_rows = session.exec(
                select(ThermalSensorReadingRow).where(ThermalSensorReadingRow.capture_id == capture_id)
            ).all()
            bundle["thermal_evidence"] = {
                "confidence": platform_confidence,
                "corroboration": platform_corroboration,
                "note": (
                    "Point-in-time thermal state from `dumpsys thermalservice`. "
                    "`overall_status_name` is Android's own already-computed throttling "
                    "severity -- prefer it over eyeballing individual sensor temperatures, the "
                    "same way meminfo's `status` field is preferred over raw free-RAM math. "
                    "'none' means not currently throttled, which is the normal case and not "
                    "itself worth reporting as a finding."
                ),
                "overall_status": thermal_row.overall_status_name,
                "hottest_sensors": [
                    {"name": r.name, "value_c": r.value_c, "type_name": r.type_name,
                     "status_name": r.status_name}
                    # A None reading (HAL sentinel-for-no-data, not a real
                    # temperature) sorts last rather than crashing the sort
                    # or, worse, sorting first as if it were the hottest.
                    for r in sorted(sensor_rows, key=lambda r: -(r.value_c if r.value_c is not None else float("-inf")))[:8]
                ],
                "throttled_sensors": [
                    {"name": r.name, "value_c": r.value_c, "type_name": r.type_name,
                     "status_name": r.status_name}
                    for r in sensor_rows if r.status_code > 0
                ],
                "source": {"section": thermal_row.source_section,
                           "line_start": thermal_row.source_line_start,
                           "line_end": thermal_row.source_line_end},
            }

        cpu_row = session.exec(
            select(CpuLoadSnapshotRow).where(CpuLoadSnapshotRow.capture_id == capture_id)
        ).first()
        if cpu_row is not None:
            proc_rows = session.exec(
                select(ProcessCpuUsageRow)
                .where(ProcessCpuUsageRow.capture_id == capture_id)
                .order_by(ProcessCpuUsageRow.cpu_pct.desc())
            ).all()
            bundle["cpu_load_evidence"] = {
                "confidence": platform_confidence,
                "corroboration": platform_corroboration,
                "note": (
                    "A `top`-style CPU snapshot at the MOMENT the bugreport was taken -- a "
                    "single point-in-time reading, not a time series. It can show what was busy "
                    "right then; it says nothing about a spike five minutes earlier or a minute "
                    "later. Elevated load here does NOT by itself indicate a persistent "
                    "performance problem -- do not report this as a finding on its own, only as "
                    "context if the user is asking what was running at capture time. "
                    "`total_pct` can exceed 100 on a multi-core device (e.g. 800% means up to 8 "
                    "cores fully busy) and is kept exactly as printed."
                ),
                "total_pct": cpu_row.total_pct, "user_pct": cpu_row.user_pct,
                "sys_pct": cpu_row.sys_pct, "idle_pct": cpu_row.idle_pct,
                "iowait_pct": cpu_row.iowait_pct,
                "threads_total": cpu_row.threads_total, "threads_running": cpu_row.threads_running,
                "top_processes": [
                    {"command": p.command, "user": p.user, "cpu_pct": p.cpu_pct, "state": p.state}
                    for p in proc_rows[:10]
                ],
                "source": {"section": cpu_row.source_section,
                           "line_start": cpu_row.source_line_start,
                           "line_end": cpu_row.source_line_end},
            }

    if want_selinux:
        # An SELinux denial with permissive=0 is a real, already-happened
        # functional failure: the kernel blocked the operation. permissive=1
        # means it was logged but allowed. Those are reported as separate
        # counts rather than one "denials" number, because collapsing them
        # is the main way SELinux findings get overstated.
        denial_rows = session.exec(
            select(SelinuxDenialRow).where(SelinuxDenialRow.capture_id.in_(sibling_capture_ids))
        ).all()
        selinux_confidence, selinux_corroboration = evidence_confidence(denial_rows)
        if denial_rows:
            enforced = [d for d in denial_rows if d.enforcing is True]
            bundle["device_wide_selinux_evidence"] = {
                "confidence": selinux_confidence,
                "corroboration": selinux_corroboration,
                "note": (
                    f"Every SELinux AVC denial found across all {captures_checked} capture(s) on "
                    f"file for this device. `enforcing: true` means the operation was actually "
                    f"BLOCKED (permissive=0) -- a real failure. `enforcing: false` means it was "
                    f"logged but allowed through (permissive=1) -- a warning about what would "
                    f"break under enforcement, not a current failure. `enforcing: null` means the "
                    f"log line did not record it. Never describe a permissive denial as something "
                    f"that broke."
                ),
                "total_denials": len(denial_rows),
                "enforced_denials": len(enforced),
                "denials": [
                    {"timestamp": d.timestamp, "verdict": d.verdict, "permissions": d.permissions,
                     "source_domain": d.source_domain, "target_type": d.target_type,
                     "target_class": d.target_class, "comm": d.comm, "target_name": d.target_name,
                     "app": d.app, "enforcing": d.enforcing,
                     "confidence": selinux_confidence,
                     **_capture_tag(d.capture_id),
                     "source": {"section": d.source_section, "line_start": d.source_line_start,
                                "line_end": d.source_line_end}}
                    for d in denial_rows
                ],
            }

    if want_pairing:
        # Real gap found live: a "network error while pairing" question
        # between two devices came back "unknown" from two different LLM
        # providers, even though the actual pairing session -- Fast Pair
        # discovery, Companion Device Manager association, secure-channel
        # handshake -- was sitting in the system log the whole time, along
        # with a concrete, repeated failure
        # ("Action REQUEST_TRANSPORT FAILED to activate") that a generic
        # W/E-level catch-all found even though it wasn't hand-anticipated.
        # Also include the raw Bluetooth HCI and packet-capture summaries
        # here (previously computed and shown on the dashboard but never
        # actually reached the LLM bundle at all) since a pairing/network
        # question is exactly when they're relevant.
        pairing_events = session.exec(
            select(CdmPairingEventRow).where(CdmPairingEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        pairing_confidence, pairing_corroboration = evidence_confidence(pairing_events)
        bundle["device_wide_pairing_evidence"] = {
                "confidence": pairing_confidence,
                "corroboration": pairing_corroboration,
            "note": (
                f"Companion Device Manager / Fast Pair events across all {captures_checked} "
                f"capture(s) on file for this device, not filtered to a named app. "
                f"kind=\"anomaly\" entries are any W/E-level CDM_* log line whose specific "
                "message wasn't individually decoded -- the log level flags it as worth attention, "
                "the raw text is in `detail`."
            ),
            "events": [
                {"timestamp": e.timestamp, "level": e.level, "tag": e.tag, "kind": e.kind,
                 "mac_address": e.mac_address, "display_name": e.display_name,
                 "package_name": e.package_name, "association_id": e.association_id,
                 "detail": _truncate_detail(e.detail), "confidence": pairing_confidence,
                 **_capture_tag(e.capture_id),
                 "source": {"section": e.source_section, "line_start": e.source_line_start, "line_end": e.source_line_end}}
                for e in pairing_events
            ],
        }
        # The service's own current-state association snapshot -- a
        # materially stronger source than the log-line events above, since
        # it's not reconstructed from a sequence of messages but reported
        # directly by CDM at the moment the bugreport was taken. Real gap
        # found live: this "DUMP OF SERVICE companiondevice" section was
        # being extracted from the bugreport but never had a parser wired
        # to it at all, so "is this device currently paired/connected" had
        # to be inferred from log anomalies even when the authoritative
        # answer was sitting a few hundred lines away the whole time.
        associations = session.exec(
            select(CompanionDeviceAssociationRow).where(CompanionDeviceAssociationRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if associations:
            bundle["device_wide_pairing_evidence"]["current_associations"] = [
                {"association_id": a.association_id, "mac_address": a.mac_address,
                 "display_name": a.display_name, "package_name": a.package_name,
                 "device_profile": a.device_profile, "revoked": a.revoked, "pending": a.pending,
                 "trusted": a.trusted, "time_approved": a.time_approved,
                 "last_time_connected": a.last_time_connected,
                 "currently_connected": a.currently_connected,
                 "confidence": pairing_confidence,
                 **_capture_tag(a.capture_id),
                 "source": {"section": a.source_section, "line_start": a.source_line_start, "line_end": a.source_line_end}}
                for a in associations
            ]
        bt_rows = session.exec(
            select(BtHciSummaryRow).where(BtHciSummaryRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if bt_rows:
            bundle["bt_hci_summary"] = []
            for bt_row in bt_rows:
                bt_events = session.exec(
                    select(BtHciEventRow).where(BtHciEventRow.capture_id == bt_row.capture_id)
                ).all()
                bundle["bt_hci_summary"].append({
                    "total_packets": bt_row.total_packets, "command_count": bt_row.command_count,
                    "event_count": bt_row.event_count, "first_timestamp": bt_row.first_timestamp,
                    "last_timestamp": bt_row.last_timestamp,
                    **_capture_tag(bt_row.capture_id),
                    # Each notable event carries the same computed confidence
                    # every other evidence category does. Found live: without
                    # this, auto-scan's Bluetooth findings were the only ones
                    # reporting "confidence: null", and the LLM (correctly,
                    # per rule 2) called that out in the report instead of
                    # labeling them itself.
                    "notable_events": [
                        {"timestamp": e.timestamp, "kind": e.kind, "status_name": e.status_name,
                         "reason_name": e.reason_name, "handle": e.handle,
                         "confidence": pairing_confidence}
                        for e in bt_events if e.kind == "disconnection_complete" or (e.status_code or 0) != 0
                    ],
                })
        pcap_rows = session.exec(
            select(PacketCaptureSummaryRow).where(PacketCaptureSummaryRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if pcap_rows:
            bundle["packet_capture_summary"] = [
                {"format": p.format, "linktype_name": p.linktype_name,
                 "total_packets": p.total_packets, "first_timestamp": p.first_timestamp,
                 "last_timestamp": p.last_timestamp, **_capture_tag(p.capture_id),
                 "note": "Container-level metadata only -- see packet_analysis for protocol-level facts."}
                for p in pcap_rows
            ]
        pa_rows = session.exec(
            select(PacketAnalysisRow).where(PacketAnalysisRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if pa_rows:
            bundle["packet_analysis"] = [
                {"backend": pa_row.backend, "link_layer": pa_row.link_layer,
                 "packets_analyzed": pa_row.packets_analyzed,
                 "retry_count": pa_row.retry_count, "retry_rate_pct": pa_row.retry_rate_pct,
                 "rssi_min_dbm": pa_row.rssi_min_dbm, "rssi_max_dbm": pa_row.rssi_max_dbm,
                 "rssi_avg_dbm": pa_row.rssi_avg_dbm, **_capture_tag(pa_row.capture_id),
                 "frame_type_breakdown": json.loads(pa_row.frame_type_breakdown_json),
                 "identity_signals": json.loads(pa_row.identity_signals_json),
                 "anomalies": json.loads(pa_row.anomalies_json),
                 "note": pa_row.note}
                for pa_row in pa_rows
            ]

    _EVIDENCE_LABELS = {
        "device_wide_crash_evidence": "crash / ANR / native-crash evidence",
        "device_wide_wifi_evidence": "Wi-Fi disconnection evidence",
        "device_wide_battery_evidence": "battery consumption evidence",
        "device_wide_selinux_evidence": "SELinux policy denials",
        "device_wide_memory_evidence": "process kill / memory pressure evidence",
        "anr_blocking_threads_evidence": "ANR binder-transaction detail",
        "anr_main_thread_evidence": "ANR main-thread trace snapshots",
        "kernel_log_evidence": "kernel ring buffer (warning severity or worse)",
        "thermal_evidence": "thermal sensor state and throttling status",
        "cpu_load_evidence": "CPU load snapshot at capture time",
        "location_snapshot_evidence": "location providers and GNSS performance (dumpsys location)",
        "gnss_signal_evidence": "GPS reception quality over time (batterystats history)",
        "memory_snapshot_evidence": "system-wide RAM snapshot (dumpsys meminfo)",
        "memory_growth_evidence": "per-process memory sampled over time (am_pss)",
        "device_wide_pairing_evidence": "Bluetooth / Companion Device Manager pairing evidence",
        "bt_hci_summary": "Bluetooth HCI packet log",
        "packet_capture_summary": "packet capture container metadata",
        "packet_analysis": "packet capture protocol-level analysis",
    }
    for key, label in _EVIDENCE_LABELS.items():
        if bundle.get(key):
            evidence_sources.append({
                "category": label,
                "reason": (
                    "auto-scan: every evidence category is checked"
                    if include_all_evidence
                    else "question matched a keyword trigger for this evidence category"
                ),
                "detail": f"checked across {captures_checked} capture(s) on file for this device",
            })
    coverage = bundle.get("capture_coverage") or {}
    if coverage.get("statement"):
        evidence_sources.append({
            "category": "capture date coverage",
            "reason": (
                "question named a calendar date"
                if coverage.get("question_date_parse") == "parsed"
                else "question looked date-specific but the date could not be parsed"
            ),
            "detail": coverage["statement"],
        })
    bundle["evidence_sources"] = evidence_sources

    return bundle


DETAIL_MAX_CHARS = 600


def _truncate_detail(detail: str | None) -> str | None:
    """Caps a raw log line's free text. Some framework lines (e.g. a
    WindowManager TransitionRequestInfo dump) run to 2,600+ characters of
    window geometry for what is diagnostically just "the Fast Pair UI
    opened" -- shipping those verbatim to the LLM costs real tokens and
    adds no signal. Truncation is marked explicitly so a reader can tell
    the text was cut rather than the log being short, and the full line is
    always still reachable via the fact's own source citation.
    """
    if detail is None or len(detail) <= DETAIL_MAX_CHARS:
        return detail
    return detail[:DETAIL_MAX_CHARS] + f"... [truncated, {len(detail)} chars total; see source citation for the full line]"


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _duration(seconds: int) -> str:
    """Human-readable span for finding text."""
    if seconds < 60:
        return f"{seconds}s"
    m, sec = divmod(seconds, 60)
    return f"{m}m {sec}s" if sec else f"{m}m"


def _mb(kb: int | None) -> str:
    """Formats KB as MB for human-facing finding text. Returns "unknown"
    for None so a missing measurement never renders as "0 MB"."""
    return "unknown" if kb is None else f"{kb / 1024:,.0f} MB"


def rank_findings(bundle: dict) -> list[dict]:
    """Turns a bundle's raw evidence into a severity-ranked findings list.

    Severity is computed HERE, in code, from what kind of event it is --
    never by the LLM, and never from how alarming a log line's text sounds.
    Same principle as score_confidence(): a crash is CRITICAL because it is
    a crash, not because a model decided it read as serious. Confidence and
    citations are carried through from the underlying evidence verbatim, so
    a ranked finding is still fully traceable to its source lines.

    A finding's severity says "this kind of event deserves attention first";
    it does NOT assert the event caused any particular user-visible symptom.
    """
    findings: list[dict] = []
    capture_names = bundle.get("captures") or {}

    def add(severity: str, category: str, title: str, detail: str, row: dict) -> None:
        cid = row.get("capture_id")
        findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "confidence": row.get("confidence"),
            "corroboration": row.get("corroboration"),
            "capture_id": cid,
            # Resolved here rather than duplicated on every raw fact -- the
            # findings list is short, so naming the file is cheap and keeps
            # each finding readable on its own.
            "original_filename": row.get("original_filename")
                                 or capture_names.get(cid)
                                 or capture_names.get(str(cid)),
            "source": row.get("source"),
            "timestamp": row.get("timestamp"),
        })

    crash = bundle.get("device_wide_crash_evidence") or {}
    for c in crash.get("java_crashes", []):
        root = c.get("root_cause_class") or c.get("exception_class") or "exception"
        add("CRITICAL", "crash", f"Java crash in {c.get('package') or 'unknown package'}",
            f"{c.get('exception_class') or 'exception'}"
            + (f" -- root cause: {root}: {c.get('root_cause_message') or ''}".rstrip(": ") if c.get("root_cause_class") else "")
            + (f" ({c.get('message')})" if c.get("message") else ""), c)
    for t in crash.get("native_crashes", []):
        who = t.get("package") or t.get("executable") or "unattributed process"
        add("CRITICAL", "native_crash", f"Native crash in {who}",
            f"signal {t.get('signal_name') or 'unknown'}"
            + (f" ({t.get('signal_code')})" if t.get("signal_code") else "")
            + (f", top frame {t.get('top_frame')}" if t.get("top_frame") else ""), t)
    for a in crash.get("anrs", []):
        detail = a.get("reason") or "no reason recorded"
        if a.get("timeout_ms"):
            detail += f"; timed out after {a['timeout_ms']:,}ms"
        if a.get("rss_kb"):
            detail += f"; process RSS {a['rss_kb']:,} kB at the time"
        add("CRITICAL", "anr", f"ANR in {a.get('package') or 'unknown package'}", detail, a)

    blocking = bundle.get("anr_blocking_threads_evidence") or {}
    for fname, threads in blocking.get("by_anr_file", {}).items():
        if not threads:
            continue
        # The longest-waiting transaction is what actually explains the ANR
        # -- folded into one finding per ANR file rather than one finding
        # per thread, since a starved process typically has many threads
        # stuck on the same root cause and listing each separately would
        # just be the same fact repeated.
        worst = threads[0]
        add("HIGH", "anr",
            f"Binder thread starvation in ANR record {fname}",
            f"longest-blocked thread waited {worst['elapsed_ms']:,}ms for a transaction "
            f"from pid {worst.get('from_pid')}; {len(threads)} thread(s) were stuck when the "
            f"ANR fired",
            {"confidence": blocking.get("confidence"), "corroboration": blocking.get("corroboration")})

    wifi = bundle.get("device_wide_wifi_evidence") or {}
    for w in wifi.get("disconnections", []):
        # A disconnect the device asked for is routine; one it did not is the
        # interesting case (AP kicked us, or the link failed).
        locally = w.get("locally_generated")
        add("HIGH" if locally is False else "LOW", "wifi",
            f"Wi-Fi disconnect from {w.get('ssid') or 'unknown SSID'}"
            + ("" if locally is False else " (locally initiated)"),
            f"802.11 reason {w.get('reason_code')} ({w.get('reason_name')})", w)

    pairing = bundle.get("device_wide_pairing_evidence") or {}
    for e in pairing.get("events", []):
        if e.get("kind") != "anomaly":
            continue
        # Log level is the only signal here -- the detail text is NOT
        # independently interpreted (same caveat the LLM is given).
        add("HIGH" if e.get("level") == "E" else "MEDIUM", "pairing",
            f"{e.get('tag')} logged a {'error' if e.get('level') == 'E' else 'warning'}-level anomaly",
            e.get("detail") or "", e)

    memory = bundle.get("device_wide_memory_evidence") or {}
    for k in memory.get("events", []):
        # A deliberate kill with a recorded reason is the actionable case.
        # A bare death is informational -- processes dying is normal Android
        # lifecycle, so ranking every one as a problem would be noise.
        if k.get("kind") != "kill":
            continue
        rss = k.get("rss_kb")
        add("MEDIUM", "memory",
            f"System killed {k.get('process') or 'unknown process'}",
            f"reason: {k.get('reason') or 'not recorded'}"
            + (f", oom_adj {k.get('oom_adj')}" if k.get("oom_adj") is not None else "")
            + (f", {rss} kB RSS" if rss else ""), k)

    kernel = bundle.get("kernel_log_evidence") or {}
    for k in kernel.get("err_or_worse_events", []):
        # panic-family or the worst syslog priorities (emerg/alert/crit) are
        # CRITICAL; plain "err" is MEDIUM -- a real driver-level failure
        # worth surfacing, but most of these (suspend failures, DBI access
        # while powered down) are transient and often self-recovering, so
        # they don't warrant the same severity as an actual panic/oops.
        severity = "CRITICAL" if k.get("is_panic_family") else "MEDIUM"
        # detail deliberately excludes boot_relative_sec/thread -- those
        # differ on every occurrence of an otherwise-identical driver
        # message (found live: the same "Preventing invalid attempt to
        # read DBI while powered down" line fired dozens of times and,
        # with per-event timing baked into detail, produced 46 near-
        # duplicate findings instead of collapsing via the shared
        # (severity, category, title, detail) grouping key below). Timing
        # for each occurrence is still available from the source citation.
        add(severity, "kernel", f"Kernel: {k.get('message', '')[:80]}",
            f"{k.get('priority_name', 'unknown')}-level kernel log line "
            "(see source citation for boot-relative timing of each occurrence)", k)

    thermal = bundle.get("thermal_evidence") or {}
    status = (thermal.get("overall_status") or "").lower()
    if status and status != "none":
        # Ranked on Android's own already-computed throttling severity --
        # same principle as meminfo's status field driving memory severity,
        # never a temperature threshold invented here.
        severity = {"light": "MEDIUM", "moderate": "MEDIUM", "severe": "HIGH",
                    "critical": "CRITICAL", "emergency": "CRITICAL", "shutdown": "CRITICAL"}.get(status, "MEDIUM")
        hottest = thermal.get("throttled_sensors") or thermal.get("hottest_sensors") or []
        top = hottest[0] if hottest else {}
        # top.get("value_c") is None when the HAL reported a sentinel-for-
        # no-data value rather than a real temperature -- reported as
        # "reading unavailable", never formatted as a fabricated number.
        detail = "status reported without individual sensor detail"
        if top:
            value = top.get("value_c")
            temp_str = f"{value:.1f}\u00b0C" if value is not None else "reading unavailable"
            detail = f"hottest throttled sensor: {top.get('name')} at {temp_str} ({top.get('type_name')})"
        add(severity, "thermal", f"Device reported thermal status \"{thermal.get('overall_status')}\"",
            detail,
            {"confidence": thermal.get("confidence"), "corroboration": thermal.get("corroboration")})

    snapshot = bundle.get("memory_snapshot_evidence") or {}
    ram = snapshot.get("ram") or {}
    # Severity comes from the device's OWN status field, not from a
    # threshold invented here. Android already computes this, and second-
    # guessing it with a "free RAM below X%" rule would flag healthy
    # devices -- cached memory counts as free precisely because it is
    # reclaimable on demand.
    status = (ram.get("status") or "").lower()
    if status and status != "normal":
        add({"critical": "CRITICAL", "low": "HIGH", "moderate": "MEDIUM"}.get(status, "MEDIUM"),
            "memory", f"Device reported memory status \"{ram.get('status')}\"",
            f"total RAM {_mb(ram.get('total_ram_kb'))}, free {_mb(ram.get('free_ram_kb'))}, "
            f"used {_mb(ram.get('used_ram_kb'))} -- status is the device's own assessment",
            snapshot)

    growth = bundle.get("memory_growth_evidence") or {}
    for g in growth.get("growing_processes", []):
        # Ranked on the size of the rise, with `monotonic` reported rather
        # than used to escalate. A steady climb and a sawtooth can produce
        # the same delta, and neither one proves a leak -- so the title
        # says "grew", the detail shows the shape, and the word leak is
        # never used.
        delta = g.get("delta_kb") or 0
        severity = "MEDIUM" if delta >= 256 * 1024 else "LOW"
        shape = ("rose steadily, never dropped" if g.get("monotonic")
                 else "rose and fell between samples (normal allocate/release)")
        add(severity, "memory",
            f"{g.get('process') or 'unknown process'} grew {_mb(delta)} in RSS",
            f"{_mb(g.get('first_rss_kb'))} -> {_mb(g.get('last_rss_kb'))} "
            f"(peak {_mb(g.get('peak_rss_kb'))}) over {g.get('sample_count')} samples; {shape}",
            g)

    loc = bundle.get("location_snapshot_evidence") or {}
    if loc.get("location_enabled") is False:
        # Unambiguous and actionable: nothing can get a position at all.
        # This is the one location finding that is a real device-state fault
        # rather than physics.
        add("HIGH", "location", "Location services were turned off",
            "The system location setting was disabled, so no app could obtain a "
            "position from any provider", loc)

    gnss = bundle.get("gnss_signal_evidence") or {}
    for span in gnss.get("degraded_spans", []):
        # Ranked purely on how long reception stayed weak while an app was
        # actively asking for fixes. Severity stops at MEDIUM on purpose:
        # weak GPS indoors or underground is expected physics, not a device
        # fault, and a HIGH here would tell users to chase a hardware problem
        # that isn't there.
        secs = span.get("duration_sec") or 0
        if secs < 60:
            continue  # sub-minute dips are ordinary and would be pure noise
        severity = "MEDIUM" if secs >= 300 else "LOW"
        who = span.get("active_uids")
        add(severity, "location",
            f"GPS reception degraded for {_duration(secs)}",
            f"{span.get('start')} to {span.get('end')}"
            + (f", with uid(s) {who} holding GPS open" if who else "")
            + " -- weak satellite signal, which is expected indoors or underground "
              "and does not by itself mean any position was wrong",
            span)

    selinux = bundle.get("device_wide_selinux_evidence") or {}
    for d in selinux.get("denials", []):
        # Enforced (permissive=0) means it was actually blocked -- a real
        # failure. Permissive denials are logged-but-allowed, so they rank
        # lower: worth knowing, not currently broken.
        enforced = d.get("enforcing") is True
        perms = d.get("permissions") or "?"
        who = d.get("app") or d.get("comm") or d.get("source_domain") or "unknown"
        add("HIGH" if enforced else "LOW", "selinux",
            f"SELinux {'blocked' if enforced else 'logged (permissive)'} "
            f"{{{perms}}} on {d.get('target_type') or '?'} for {who}",
            f"{d.get('source_domain')} -> {d.get('target_type')} "
            f"(class {d.get('target_class')})"
            + (f", name={d.get('target_name')}" if d.get("target_name") else ""), d)

    for bt in (bundle.get("bt_hci_summary") or []):
        for ev in bt.get("notable_events", []):
            status = ev.get("status_name")
            reason = ev.get("reason_name")
            if status and status != "Success":
                add("MEDIUM", "bluetooth", f"Bluetooth {ev.get('kind', '').replace('_', ' ')}: {status}",
                    f"handle {ev.get('handle')}" if ev.get("handle") is not None else "",
                    {**ev, "capture_id": bt.get("capture_id"), "original_filename": bt.get("original_filename")})
            elif reason and "Failed" in reason:
                add("MEDIUM", "bluetooth", f"Bluetooth connection failure: {reason}",
                    f"handle {ev.get('handle')}" if ev.get("handle") is not None else "",
                    {**ev, "capture_id": bt.get("capture_id"), "original_filename": bt.get("original_filename")})

    for pa in (bundle.get("packet_analysis") or []):
        anomalies = pa.get("anomalies") or []
        by_kind: dict[str, int] = {}
        for a in anomalies:
            by_kind[a.get("kind", "anomaly")] = by_kind.get(a.get("kind", "anomaly"), 0) + 1
        for kind, count in by_kind.items():
            add("MEDIUM", "packet_capture",
                f"{count} {kind.replace('_', ' ')} frame(s) in packet capture",
                pa.get("note") or "",
                {"capture_id": pa.get("capture_id"), "original_filename": pa.get("original_filename"),
                 "confidence": "LOW",
                 "corroboration": "Counted directly from one packet capture's own decoded frames."})

    # Collapse repeats. Found live on a real capture: a single scan produced
    # 24 identical "Bluetooth command status: Command Disallowed" rows, which
    # buried the one HIGH Wi-Fi finding under near-duplicate noise. A repeated
    # event is one finding that happened N times, not N findings -- and the
    # repetition itself is signal worth showing (occurrences + time span),
    # so it's surfaced rather than silently dropped.
    grouped: dict[tuple, dict] = {}
    for f in findings:
        key = (f["severity"], f["category"], f["title"], f["detail"], f.get("original_filename"))
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = {**f, "occurrences": 1, "first_timestamp": f.get("timestamp"),
                            "last_timestamp": f.get("timestamp")}
            continue
        existing["occurrences"] += 1
        stamps = [s for s in (existing.get("first_timestamp"), existing.get("last_timestamp"),
                              f.get("timestamp")) if s]
        if stamps:
            existing["first_timestamp"] = min(stamps)
            existing["last_timestamp"] = max(stamps)

    out = list(grouped.values())
    # Within a severity, show the most-repeated first -- a failure happening
    # 24 times is more worth looking at than the same-severity one-off.
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["occurrences"],
                            f.get("first_timestamp") or ""))
    return out


SCAN_SYSTEM_PROMPT = SYSTEM_PROMPT + """
15. This is an AUTO-SCAN, not an answer to a specific user question: every
    evidence category was gathered unconditionally, and the bundle includes
    a "ranked_findings" list whose "severity" values (CRITICAL / HIGH /
    MEDIUM / LOW) were computed in code from the KIND of each event -- not
    by you, and not from how alarming any log text reads. Carry each
    severity forward verbatim exactly as rule 2 requires for confidence,
    and never re-rank or re-label. A severity means "this kind of event
    deserves attention first"; it does NOT assert the event caused any
    particular user-visible symptom, so do not claim a causal link between
    two findings unless the bundle itself states one. Each finding carries
    an "occurrences" count (identical repeats are grouped into one finding)
    with "first_timestamp"/"last_timestamp" -- when occurrences > 1, say how
    many times it happened and over what span, since a failure repeating 24
    times reads very differently from a one-off.
16. For an auto-scan, replace the "## Direct answer" section with a
    "## Summary" section: how many findings at each severity, and what the
    most serious ones are. Then "## Findings" walks the ranked list in
    order. If ranked_findings is empty, say plainly that no crashes, ANRs,
    disconnects, or pairing/Bluetooth anomalies were found in the captures
    checked -- and say that this means nothing was found in the categories
    ParseCat parses, not that the device is problem-free.
"""


def scan_capture(
    session: Session, capture_id: int, device_label: str, provider: str | None = None,
) -> dict:
    """Auto-scan: gather every evidence category with no question at all,
    rank the findings by computed severity, and narrate. This is the
    "upload and get answers without knowing what to ask" path.
    """
    question = "Full automatic scan: what problems are present on this device?"
    bundle = build_diagnosis_bundle(
        session, capture_id, device_label, question, include_all_evidence=True,
    )
    bundle["ranked_findings"] = rank_findings(bundle)
    bundle["scan"] = True
    report_text, llm_error = _run_llm(bundle, SCAN_SYSTEM_PROMPT, provider)
    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}


def _format_history(history: list[dict] | None) -> str:
    """Prior turns of the same conversation, for continuity only -- see
    SYSTEM_PROMPT rule 14. Each item is {"question": str, "report": str};
    items missing either (e.g. a turn where narration failed) are skipped
    rather than injecting an empty/garbled turn.
    """
    if not history:
        return ""
    turns = [
        f"Q: {h['question']}\nA: {h['report']}"
        for h in history if h.get("question") and h.get("report")
    ]
    if not turns:
        return ""
    return (
        "Prior conversation in this session (for continuity only -- NOT new "
        "evidence; the verified fact bundle below is still the only source "
        "of facts for this turn):\n\n" + "\n\n".join(turns) + "\n\n"
    )


def _run_llm(
    bundle: dict, system_prompt: str, provider: str | None, history: list[dict] | None = None,
) -> tuple[str | None, str | None]:
    user_prompt = (
        _format_history(history) +
        "Verified fact bundle (JSON):\n\n" + json.dumps(bundle, indent=2, default=str) +
        "\n\nWrite a diagnosis report answering the question above using only these facts."
    )
    try:
        llm = get_llm_client(provider)
        return llm.narrate(system_prompt, user_prompt), None
    except Exception as exc:  # noqa: BLE001 -- LLM narration is a convenience
        # layer on top of already-computed, independently verified facts.
        # A provider outage, quota error, or bad key should degrade to
        # "here are the facts, narration failed" -- never a 500 that hides
        # the verification work that already succeeded.
        return None, str(exc)


def diagnose(
    session: Session, capture_id: int, device_label: str, question: str,
    provider: str | None = None, history: list[dict] | None = None,
) -> dict:
    bundle = build_diagnosis_bundle(session, capture_id, device_label, question)
    report_text, llm_error = _run_llm(bundle, SYSTEM_PROMPT, provider, history)
    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}


INVESTIGATION_SYSTEM_PROMPT = SYSTEM_PROMPT + """
15. This bundle covers MULTIPLE captures, possibly from different physical
    devices, grouped under one investigation. The top-level "captures" array
    has one entry per capture, each tagged with "capture_id",
    "original_filename", and "device_label" -- always say which capture/
    device a fact came from, never merge facts from different captures into
    one unlabeled claim. When the question is about something happening
    "between" or "on one of" multiple devices, look across all entries and
    say which capture(s) actually show relevant evidence, rather than only
    reporting on the first one. Each capture entry has its own
    "device_context" and "evidence_sources" (rules 11-12) -- when rendering
    the "## Device" and "## Evidence checked" sections, show them per
    capture/device, not merged into one.
16. Rule 12b's "capture_coverage" object is NOT top-level in this bundle --
    here it lives nested inside EACH entry of "captures" (captures[i].
    capture_coverage), one per capture, because each capture has its own
    date range. If the question names or implies a specific date, check
    every capture entry's own capture_coverage and disclose per capture
    whether that date falls inside/outside/in-gap for THAT capture's
    range -- do not look for a single bundle-wide range, and do not skip
    coverage disclosure just because it isn't at the top level. Quote each
    capture's capture_coverage.statement verbatim the same way rule 12b
    requires for the single-capture case; never invent or merge ranges
    across captures.
"""


def diagnose_investigation(
    session: Session, investigation_id: int, question: str, provider: str | None = None,
    history: list[dict] | None = None,
) -> dict:
    """Runs diagnosis across every capture linked to one investigation,
    merging each capture's independently-built bundle into one combined
    bundle before a single LLM call -- so a question naming "one of these
    N devices" can actually be answered by looking across all of them,
    instead of being scoped to whichever single capture happened to be
    selected.
    """
    from app.models.db_models import Capture, Device, InvestigationCaptureLink

    capture_rows = session.exec(
        select(Capture)
        .join(InvestigationCaptureLink, InvestigationCaptureLink.capture_id == Capture.id)
        .where(InvestigationCaptureLink.investigation_id == investigation_id)
    ).all()

    captures_bundle = []
    for capture in capture_rows:
        device = session.get(Device, capture.device_id)
        device_label = device.label if device else "unknown"
        per_capture = build_diagnosis_bundle(session, capture.id, device_label, question)
        captures_bundle.append({
            "capture_id": capture.id,
            "original_filename": capture.original_filename,
            "device_label": device_label,
            **per_capture,
        })

    bundle = {"question": question, "captures": captures_bundle}
    report_text, llm_error = _run_llm(bundle, INVESTIGATION_SYSTEM_PROMPT, provider, history)
    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}
