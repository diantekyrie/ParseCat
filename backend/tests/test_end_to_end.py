"""End-to-end pipeline test against the real fixtures: parse -> persist ->
verify named entities -> multi-capture correlation -> diagnosis bundle.

Uses an in-memory SQLite DB so it doesn't touch the real parsecat.db.
Runs the case study from the build brief: does the system independently
verify the "victim" app's own state, does it find the focus stack without
hedging, and does a "never requested focus" claim get checked across every
capture on file for the device rather than just the current upload.
"""
from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.llm import get_llm_client, list_providers
from app.services.correlation import package_history_across_device
from app.services.ingestion import parse_bugreport_zip
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose, diagnose_investigation
from app.services.summary import build_capture_summary, build_merged_summary
from app.services.verification import verify_question_entities

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE_1 = FIXTURES / "bugreport_2026-08-13.zip"
CAPTURE_2 = FIXTURES / "bugreport_2026-08-19.zip"

pytestmark = pytest.mark.skipif(not CAPTURE_1.exists(), reason="real bugreport fixtures not present")


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _ingest(session, device_label, path):
    parsed = parse_bugreport_zip(path)
    return persist_capture(session, device_label, path.name, parsed)


def test_verification_surfaces_both_named_apps_independently(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)

    question = "Did YouTube Music fail to pause when Apple Music started playing?"
    entities = verify_question_entities(session, capture.id, question)
    matched = {e.package for e in entities}

    # Both the "accused" and the app that started playing get independently
    # checked -- the question's framing is not taken as given.
    assert "com.google.android.apps.youtube.music" in matched
    assert "com.apple.android.music" in matched

    yt = next(e for e in entities if e.package == "com.google.android.apps.youtube.music")
    # Ground truth: YouTube Music's own MediaSession state shows PAUSED,
    # contradicting a premise that it was playing and failed to pause.
    assert yt.media_session_playback_state == "PAUSED"
    assert yt.media_session_source is not None  # citable


def test_focus_stack_found_without_hedging(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    entities = verify_question_entities(session, capture.id, "com.apple.android.music focus")
    top = next(e for e in entities if e.package == "com.apple.android.music")
    assert top.is_top_of_focus_stack is True


def test_multi_capture_correlation_checks_full_history(session):
    _ingest(session, "frankel-pixel", CAPTURE_1)
    if CAPTURE_2.exists():
        _ingest(session, "frankel-pixel", CAPTURE_2)
        expected_captures = 2
    else:
        expected_captures = 1

    history = package_history_across_device(session, "frankel-pixel", "com.disney.disneyplus")
    assert history.captures_checked == expected_captures
    # Whatever the finding, it must say how many captures backed it --
    # never a silent single-file guess dressed up as a stronger claim.


def test_diagnose_returns_confidence_tied_to_corroboration(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "Has com.disney.disneyplus ever requested audio focus across all captures?",
    )
    claims = result["bundle"]["claims"]
    assert len(claims) >= 1
    for c in claims:
        assert c["confidence"] in {"HIGH", "MEDIUM", "LOW", "UNCONFIRMED"}
        assert "cross_capture_history" in c  # "across all captures" triggered history lookup
    assert "[stub LLM" in result["report"]


def test_summary_reflects_persisted_facts_not_a_reparse(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    summary = build_capture_summary(session, capture.id)

    assert summary["device_info"]["model"] == "Pixel 10"
    assert summary["device_info"]["security_patch"] == "2026-08-05"
    assert summary["counts"]["java_crashes"] == 1
    assert summary["counts"]["native_crashes"] > 0
    assert summary["counts"]["freeze_events"] + summary["counts"]["unfreeze_events"] > 0
    assert len(summary["crash_events"]) == 1
    assert summary["crash_events"][0]["package"] == "com.android.systemui"
    # Every timeline entry must carry a source citation back to the raw log.
    with_source = [e for e in summary["timeline"] if e["source"] is not None]
    assert with_source  # at least some entries (crashes, focus events) carry citations
    assert all(e["source"]["line_start"] > 0 for e in with_source)


def test_crash_question_surfaces_device_wide_evidence_without_naming_an_app(session):
    # Regression: "Was there a crash?" previously came back "unknown" even
    # though the capture has a real, source-cited crash -- because
    # verification only ever looked at apps named in the question, and this
    # question doesn't name one. Crash-shaped questions now get device-wide
    # crash evidence regardless of whether any app was named.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    assert result["bundle"]["claims"] == []
    evidence = result["bundle"]["device_wide_crash_evidence"]
    assert len(evidence["java_crashes"]) == 1
    assert evidence["java_crashes"][0]["package"] == "com.android.systemui"
    assert len(evidence["native_crashes"]) > 0


def test_named_app_crash_data_included_in_its_own_claim(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did com.android.systemui crash?")
    claim = next(c for c in result["bundle"]["claims"] if c["package"] == "com.android.systemui")
    assert len(claim["verified_state"]["crash_events"]) == 1
    assert claim["verified_state"]["crash_events"][0]["exception_class"] == "DeadSystemException"


def test_explicit_provider_selection_is_honored_and_reported_back(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash?", provider="stub")
    assert result["provider"] == "stub"
    assert "[stub LLM" in result["report"]


def test_list_providers_reports_availability_from_env():
    ids = {p["id"] for p in list_providers()}
    assert ids == {"anthropic", "openai", "openai-codex", "stub"}
    stub = next(p for p in list_providers() if p["id"] == "stub")
    assert stub["available"] is True  # never requires a key


def test_unknown_provider_raises_rather_than_silently_falling_back():
    with pytest.raises(ValueError):
        get_llm_client("not-a-real-provider")


def test_named_app_anr_data_included_in_its_own_claim(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did com.disney.wdpro.dlr ANR?")
    claim = next(c for c in result["bundle"]["claims"] if c["package"] == "com.disney.wdpro.dlr")
    assert len(claim["verified_state"]["anrs"]) == 2
    assert "failed to complete startup" in claim["verified_state"]["anrs"][0]["reason"]


def test_wifi_question_surfaces_device_wide_disconnection_evidence(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did Wi-Fi drop or disconnect?")
    evidence = result["bundle"]["device_wide_wifi_evidence"]
    assert len(evidence["disconnections"]) == 3
    assert any(d["ssid"] == "amzn-www" and d["reason_code"] == 3 for d in evidence["disconnections"])


def test_bt_hci_summary_persisted_and_queryable(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    summary = build_capture_summary(session, capture.id)
    bt = summary["bt_hci_summary"]
    assert bt is not None
    assert bt["total_packets"] > 0
    assert bt["command_count"] > 0 and bt["event_count"] > 0
    # A real anomaly this parser found in the fixture: a Command Complete
    # with a non-Success status should show up among notable events.
    assert any(e["status_name"] != "Success" for e in bt["notable_events"])


def test_two_word_brand_names_concatenated_in_package_ids_are_found(session):
    # Regression: "Disney Plus" and "Proton VPN" both matched ZERO
    # installed packages even though com.disney.disneyplus and
    # ch.protonvpn.android are both installed on this capture -- the
    # exact-segment-equality rule (added to stop "and" false-matching
    # inside "android") required a single question word to equal an
    # entire package segment, but these brand names collapse two words
    # into one segment with no separator ("disneyplus", "protonvpn").
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "The phone was draining battery fast and I'm wondering if it was from "
        "watching Disney Plus while connected to VPN using Proton VPN.",
    )
    claims = {c["package"]: c for c in result["bundle"]["claims"]}
    assert "com.disney.disneyplus" in claims
    assert "ch.protonvpn.android" in claims
    # Both entities turn out to have real, independently-verified state --
    # Disney+ was actively PLAYING, and Proton VPN shows freeze/unfreeze
    # cycling -- genuinely relevant corroborating context. Neither is a
    # battery-drain measurement (there's no battery-stats parser), so
    # confidence is MEDIUM (backed by real facts) rather than fabricated
    # HIGH or a battery-specific causal claim.
    assert claims["com.disney.disneyplus"]["verified_state"]["media_session_playback_state"] == "PLAYING"
    assert claims["ch.protonvpn.android"]["verified_state"]["freeze_count"] > 0
    for c in claims.values():
        assert c["confidence"] in {"LOW", "MEDIUM"}  # never HIGH from single-capture, non-cross-checked facts


def test_single_word_brand_name_with_no_space_is_found_when_unique(session):
    # Regression, found live immediately after the two-word fix above:
    # "ProtonVPN" typed as ONE word (no space) exactly equals
    # ch.protonvpn.android's one non-generic segment, but the >=2-hit rule
    # still discarded it since a single word only produces 1 hit. Fixed by
    # trusting a lone exact-segment match when that segment is unique to
    # one installed package (unlike a generic word such as "music", which
    # legitimately appears in multiple installed packages' segments and
    # must still require a second word to disambiguate).
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "was the battery drained quickly due to using Disney Plus and ProtonVPN at the same time?",
    )
    matched = {c["package"] for c in result["bundle"]["claims"]}
    assert "ch.protonvpn.android" in matched
    assert "com.disney.disneyplus" in matched


def test_battery_question_surfaces_real_per_app_mah_attribution(session):
    # Regression: this exact question previously came back "no battery
    # data exists in this bundle" from both live LLM providers -- not
    # because the capture lacked the data (it has real per-app mAh
    # attribution the whole time), but because nothing parsed batterystats
    # or wired it into the bundle at all.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "was the battery drained quickly due to using Disney Plus and ProtonVPN at the same time?",
    )
    claims = {c["package"]: c for c in result["bundle"]["claims"]}
    assert claims["com.disney.disneyplus"]["verified_state"]["battery"]["total_mah"] > 0
    assert claims["ch.protonvpn.android"]["verified_state"]["battery"]["total_mah"] > 0
    evidence = result["bundle"]["device_wide_battery_evidence"]
    assert len(evidence["top_consumers"]) > 0
    assert evidence["top_consumers"][0]["total_mah"] >= evidence["top_consumers"][-1]["total_mah"]
    # Regression: "battery" (from this exact question) is the one unique
    # segment of an unrelated installed app, com.oceanwing.battery.cam --
    # the user never meant that app, and it must not appear as a matched
    # entity just because a diagnostic topic word happens to also be a
    # package fragment.
    assert "com.oceanwing.battery.cam" not in claims


def test_diagnose_investigation_merges_bundles_across_all_linked_captures(session):
    # This exercises the mechanics with the only two real fixtures on hand
    # (both the same physical device, 6 days apart) -- the actual live find
    # (a phone+watch pairing failure only visible by comparing two DIFFERENT
    # devices' captures) needs the third-device fixtures that aren't
    # committed here, but the merge/tagging behavior itself is what this
    # pins: every capture linked to an investigation gets its own bundle,
    # tagged with which capture/device it came from, in one combined result.
    from app.models.db_models import Investigation

    capture1 = persist_capture(
        session, "frankel-pixel", CAPTURE_1.name, parse_bugreport_zip(CAPTURE_1),
        investigation_label="test-investigation",
    )
    if CAPTURE_2.exists():
        persist_capture(
            session, "frankel-pixel", CAPTURE_2.name, parse_bugreport_zip(CAPTURE_2),
            investigation_label="test-investigation",
        )
        expected_captures = 2
    else:
        expected_captures = 1

    investigation = session.exec(
        select(Investigation).where(Investigation.label == "test-investigation")
    ).first()
    result = diagnose_investigation(session, investigation.id, "Was there a crash on this device?")

    assert len(result["bundle"]["captures"]) == expected_captures
    first = result["bundle"]["captures"][0]
    assert first["capture_id"] == capture1.id
    assert first["device_label"] == "frankel-pixel"
    assert first["original_filename"] == CAPTURE_1.name
    # Crash-triggering question -> device-wide crash evidence per capture.
    assert "device_wide_crash_evidence" in first


def test_diagnose_bundle_includes_real_device_context(session):
    # Deterministic, not LLM-generated -- straight from DeviceInfoRow, so a
    # report can open with real build fingerprint/kernel/security-patch
    # info instead of the LLM guessing at or omitting it.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    device_context = result["bundle"]["device_context"]
    assert device_context["manufacturer"]
    assert device_context["build_fingerprint"]
    assert "capture_id" not in device_context  # only real DeviceInfoRow fields, no bookkeeping leaked in


def test_diagnose_bundle_evidence_sources_reflects_what_was_actually_checked(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)

    crash_result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    categories = {e["category"] for e in crash_result["bundle"]["evidence_sources"]}
    assert "crash / ANR / native-crash evidence" in categories
    assert "Wi-Fi disconnection evidence" not in categories  # question never mentioned wifi

    wifi_result = diagnose(session, capture.id, "frankel-pixel", "Did Wi-Fi drop?")
    categories = {e["category"] for e in wifi_result["bundle"]["evidence_sources"]}
    assert "Wi-Fi disconnection evidence" in categories
    assert "crash / ANR / native-crash evidence" not in categories


def test_diagnose_history_is_passed_to_llm_but_not_treated_as_new_evidence(session):
    # A follow-up question with none of the crash/wifi/battery/pairing
    # trigger keywords should get an EMPTY evidence bundle for that turn --
    # prior conversation is context for narration only (SYSTEM_PROMPT rule
    # 14), never a substitute for this turn's own verified facts. This is
    # the real, honest tradeoff of per-turn keyword-triggered evidence:
    # a vague follow-up doesn't inherit the parent question's evidence
    # categories automatically.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    first = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    followup = diagnose(
        session, capture.id, "frankel-pixel", "Should I be worried about that?",
        history=[{"question": first["bundle"]["question"], "report": first["report"]}],
    )
    assert followup["bundle"]["evidence_sources"] == []
    assert "device_wide_crash_evidence" not in followup["bundle"]


def test_auto_scan_gathers_every_evidence_category_without_a_question(session):
    # The point of auto-scan: no question means no keyword triggers, so
    # every category must be gathered unconditionally. This is also the
    # structural fix for the keyword-trigger fragility found repeatedly in
    # live testing (a "network issue" question missing the Wi-Fi trigger).
    from app.services.reasoning import scan_capture

    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = scan_capture(session, capture.id, "frankel-pixel")
    bundle = result["bundle"]

    assert bundle["scan"] is True
    for key in ("device_wide_crash_evidence", "device_wide_wifi_evidence",
                "device_wide_battery_evidence", "device_wide_pairing_evidence"):
        assert key in bundle, f"auto-scan must gather {key} with no question asked"
    categories = {e["category"] for e in bundle["evidence_sources"]}
    assert len(categories) >= 4
    assert all("auto-scan" in e["reason"] for e in bundle["evidence_sources"])


def test_ranked_findings_severity_is_computed_and_repeats_are_grouped():
    # Severity comes from the KIND of event, in code -- never from how
    # alarming the text reads, and never from the LLM. Repeats collapse into
    # one finding with an occurrences count (found live: a real capture
    # produced 24 identical Bluetooth rows that buried the one HIGH finding).
    from app.services.reasoning import rank_findings

    bundle = {
        "device_wide_crash_evidence": {
            "java_crashes": [{"package": "com.example.app", "exception_class": "NullPointerException",
                              "confidence": "LOW", "timestamp": "01-01 00:00:01"}],
            "native_crashes": [], "anrs": [],
        },
        "device_wide_wifi_evidence": {
            "disconnections": [
                {"ssid": "net-a", "reason_code": 3, "reason_name": "Deauthenticated",
                 "locally_generated": False, "confidence": "LOW", "timestamp": "01-01 00:00:02"},
                {"ssid": "net-b", "reason_code": 3, "reason_name": "Deauthenticated",
                 "locally_generated": True, "confidence": "LOW", "timestamp": "01-01 00:00:03"},
            ],
        },
        "bt_hci_summary": [{
            "capture_id": 1, "original_filename": "cap.zip",
            "notable_events": [
                {"kind": "command_status", "status_name": "Command Disallowed", "handle": None,
                 "confidence": "LOW", "timestamp": f"01-01 00:00:1{i}"} for i in range(5)
            ],
        }],
    }
    findings = rank_findings(bundle)

    # Crash outranks the not-locally-generated Wi-Fi drop, which outranks BT.
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["category"] == "crash"
    assert findings[1]["severity"] == "HIGH"
    assert findings[1]["category"] == "wifi"

    # A device-initiated disconnect is routine -> LOW, not HIGH.
    local = [f for f in findings if "net-b" in f["title"]]
    assert len(local) == 1 and local[0]["severity"] == "LOW"

    # Five identical BT events collapse to one finding counted five times.
    bt = [f for f in findings if f["category"] == "bluetooth"]
    assert len(bt) == 1
    assert bt[0]["occurrences"] == 5
    assert bt[0]["first_timestamp"] != bt[0]["last_timestamp"]

    # Every finding carries a confidence label forward (no nulls).
    assert all(f["confidence"] for f in findings)


def test_every_keyword_trigger_regex_actually_matches_its_own_keywords():
    # Regression: MEMORY_TRIGGER_RE was once written with a literal
    # backspace (0x08) where \b was intended, so it silently matched
    # NOTHING. Nothing caught it, because auto-scan bypasses triggers
    # entirely and no test asked a memory-worded question. This asserts
    # each trigger fires on a word it exists to catch, and that no pattern
    # contains a stray control character.
    from app.services import reasoning as r

    cases = [
        (r.CRASH_TRIGGER_RE, "was there a crash?"),
        (r.WIFI_TRIGGER_RE, "did wifi disconnect?"),
        (r.BATTERY_TRIGGER_RE, "what drained the battery?"),
        (r.PAIRING_TRIGGER_RE, "did bluetooth pairing fail?"),
        (r.SELINUX_TRIGGER_RE, "any selinux denials?"),
        (r.MEMORY_TRIGGER_RE, "was there a memory leak?"),
        (r.MULTI_CAPTURE_TRIGGER_RE, "has it ever happened across all captures?"),
    ]
    for regex, sample in cases:
        assert regex.search(sample), f"{regex.pattern!r} failed to match {sample!r}"
        assert not any(ord(ch) < 32 for ch in regex.pattern), \
            f"control character in pattern {regex.pattern!r}"


def test_memory_question_surfaces_process_kill_evidence(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did anything get killed for memory?")
    evidence = result["bundle"].get("device_wide_memory_evidence")
    if evidence is None:
        pytest.skip("fixture has no am_kill/am_proc_died events")
    # Deliberate kills are counted separately from plain process deaths --
    # summing them would overstate what the log actually records.
    assert evidence["deliberate_kills"] <= evidence["total_events"]
    assert all(e["kind"] in {"kill", "died"} for e in evidence["events"])
    for e in evidence["events"]:
        if e["kind"] == "died":
            assert e["reason"] is None  # am_proc_died carries no reason


def test_natural_language_questions_trigger_the_right_evidence():
    # Regression corpus for the recurring keyword-trigger gap. Every entry
    # here is a phrasing a real user would type; each was (or could have
    # been) a live failure where the capture HAD the evidence and the
    # report said "unknown" because the pattern missed a word form.
    #
    # The one that actually shipped: "tell me about any crashes, network
    # disconnects, and bluetooth issues." -- the plural "crashes" did not
    # match crash|crashed|crashing, so crash evidence was never gathered
    # and the exported report told the user crashes were "unknown, not
    # ruled out" while the evidence sat unqueried.
    from app.services import reasoning as r

    must_match = [
        ("tell me about any crashes, network disconnects, and bluetooth issues.",
         {"CRASH", "WIFI", "PAIRING"}),
        ("was there a network issue on these devices?", {"WIFI", "PAIRING"}),
        ("did the app crash?", {"CRASH"}),
        ("any ANRs?", {"CRASH"}),
        ("what exceptions were thrown?", {"CRASH"}),
        ("why did wifi keep dropping?", {"WIFI"}),
        ("are there dropped connections?", {"WIFI", "PAIRING"}),
        ("what drained the battery?", {"BATTERY"}),
        ("battery discharging fast", {"BATTERY"}),
        ("any wakelocks holding it awake?", {"BATTERY"}),
        ("did bluetooth pairing fail?", {"PAIRING"}),
        ("show me failed pairings", {"PAIRING"}),
        ("any selinux denials?", {"SELINUX"}),
        ("was anything blocked by policy?", {"SELINUX"}),
        ("was there a memory leak?", {"MEMORY"}),
        ("what processes got killed?", {"MEMORY"}),
    ]
    names = ["CRASH", "WIFI", "BATTERY", "PAIRING", "SELINUX", "MEMORY"]
    for question, expected in must_match:
        fired = {n for n in names if getattr(r, f"{n}_TRIGGER_RE").search(question)}
        missing = expected - fired
        assert not missing, f"{question!r} should trigger {sorted(missing)} but fired {sorted(fired)}"

    # Ordinary English that merely contains a substring must NOT trigger --
    # an earlier pattern matched "ramen" because of a wildcarded "ram".
    for word in ["ramen", "skillet", "btw", "killer feature"]:
        fired = {n for n in names if getattr(r, f"{n}_TRIGGER_RE").search(word)}
        assert not fired, f"{word!r} should trigger nothing but fired {sorted(fired)}"


def test_crash_evidence_is_gathered_for_a_plural_crashes_question(session):
    # End-to-end proof of the fix: the exact phrasing from a real exported
    # report that came back with no crash evidence at all.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "tell me about any crashes, network disconnects, and bluetooth issues.",
    )
    bundle = result["bundle"]
    assert "device_wide_crash_evidence" in bundle, \
        "a question about 'crashes' must gather crash evidence"
    assert len(bundle["device_wide_crash_evidence"]["java_crashes"]) == 1
    categories = {e["category"] for e in bundle["evidence_sources"]}
    assert "crash / ANR / native-crash evidence" in categories


def test_merged_summary_carries_snapshot_fields_the_single_capture_view_has(session):
    # Found live: a real device's Overview page showed "Thermal status: n/a"
    # for a capture this same session had just confirmed was genuinely
    # thermally throttled (severe). build_merged_summary only ever merged
    # `counts` and a handful of named lists, silently dropping
    # thermal_status/location_snapshot/memory_snapshot/cpu_snapshot_present/
    # gnss_degraded_spans -- present in every single-capture summary,
    # absent from the device-level (merged) one the app actually lands on
    # right after upload. Guards all five at once, since they all broke
    # via the exact same omission.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    single = build_capture_summary(session, capture.id)
    merged = build_merged_summary(session, [capture.id])

    for field in ("thermal_status", "location_snapshot", "memory_snapshot",
                  "cpu_snapshot_present", "gnss_degraded_spans"):
        assert field in merged, f"{field!r} missing from merged summary entirely"

    # With exactly one capture merged, the single-capture and merged views
    # must agree -- there's no aggregation ambiguity to resolve yet.
    assert merged["thermal_status"] == single["thermal_status"]
    assert merged["cpu_snapshot_present"] == single["cpu_snapshot_present"]
    assert (merged["location_snapshot"] is not None) == (single["location_snapshot"] is not None)
    assert (merged["memory_snapshot"] is not None) == (single["memory_snapshot"] is not None)
    assert len(merged["gnss_degraded_spans"]) == len(single["gnss_degraded_spans"])
